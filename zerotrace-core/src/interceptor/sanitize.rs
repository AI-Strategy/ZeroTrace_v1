use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use uuid::Uuid;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// Patterns (compiled once)
// ============================================================================

lazy_static! {
    static ref EMAIL_REGEX: Regex =
        Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap();
    static ref SSN_REGEX: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    static ref IPV4_REGEX: Regex = Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap();
    static ref KEY_REGEX: Regex =
        Regex::new(r"(?i)\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,})\b").unwrap();
    static ref PHONE_REGEX: Regex = Regex::new(
        r"\b(?:\+?1[\s\-\.]?)?(?:\(?\d{3}\)?)[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b"
    )
    .unwrap();
    static ref DATE_REGEX: Regex = Regex::new(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b").unwrap();

    // Token format:
    // [PII:v1:EMAIL:KID:01:UUID:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx:MAC:aaaaaaaaaaaaaaaaaaaaaaaa]
    // MAC is truncated HMAC-SHA256 (12 bytes => 24 hex chars)
    static ref TOKEN_REGEX: Regex = Regex::new(
        r"\[PII:v1:([A-Z_]+):KID:([0-9]{2}):UUID:([a-f0-9-]{36}):MAC:([a-f0-9]{24,64})\]"
    )
    .unwrap();
}

// ============================================================================
// Store abstraction (so we can test without Redis)
// ============================================================================

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store failure: {0}")]
    StoreFailure(String),
}

pub trait TokenStore: Send + Sync {
    fn set_with_ttl<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
        ttl_secs: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>>;

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, StoreError>> + Send + 'a>>;
}

// ============================================================================
// Sanitizer core (HMAC-hardened tokens)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiKind {
    Email,
    Ssn,
    Ipv4,
    SecretKey,
    Phone,
    Date,
}

impl PiiKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PiiKind::Email => "EMAIL",
            PiiKind::Ssn => "SSN",
            PiiKind::Ipv4 => "IPV4",
            PiiKind::SecretKey => "SECRET_KEY",
            PiiKind::Phone => "PHONE",
            PiiKind::Date => "DATE",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "EMAIL" => Some(PiiKind::Email),
            "SSN" => Some(PiiKind::Ssn),
            "IPV4" => Some(PiiKind::Ipv4),
            "SECRET_KEY" => Some(PiiKind::SecretKey),
            "PHONE" => Some(PiiKind::Phone),
            "DATE" => Some(PiiKind::Date),
            _ => None,
        }
    }

    /// Higher wins when overlaps happen.
    pub fn priority(self) -> u8 {
        match self {
            PiiKind::SecretKey => 100,
            PiiKind::Ssn => 90,
            PiiKind::Email => 80,
            PiiKind::Phone => 70,
            PiiKind::Ipv4 => 60,
            PiiKind::Date => 50,
        }
    }
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("input too large: {len} > {max}")]
    InputTooLarge { len: usize, max: usize },

    #[error("too many findings: {count} > {max}")]
    TooManyFindings { count: usize, max: usize },

    #[error("store write failed and fail-closed is enabled")]
    StoreWriteFailed,
}

#[derive(Debug, Clone)]
pub struct MacKey {
    pub kid: u8,      // key id in token
    pub key: Vec<u8>, // raw key bytes
}

#[derive(Debug, Clone)]
pub struct SanitizerConfig {
    pub ttl_secs: u64,
    pub max_input_len: usize,
    pub max_findings: usize,
    pub enabled: HashSet<PiiKind>,

    /// If true, store failures do NOT fail redaction (privacy > utility).
    pub fail_open_on_store_error: bool,

    /// Keyring + active key (rotation friendly)
    pub keyring: Vec<MacKey>,
    pub active_kid: u8,

    /// Truncated HMAC length in bytes (12 bytes => 24 hex chars)
    pub mac_trunc_bytes: usize,

    /// Rehydrate guardrails: cap how many tokens we attempt in one pass.
    pub max_tokens_to_rehydrate: usize,
}

impl Default for SanitizerConfig {
    fn default() -> Self {
        let enabled = [
            PiiKind::Email,
            PiiKind::Ssn,
            PiiKind::Ipv4,
            PiiKind::SecretKey,
            PiiKind::Phone,
            PiiKind::Date,
        ]
        .into_iter()
        .collect();

        let keyring = vec![MacKey {
            kid: 1,
            key: b"CHANGE-ME-IN-PROD-THIS-IS-A-TEST-KEY".to_vec(),
        }];

        Self {
            ttl_secs: 86_400,
            max_input_len: 1_000_000,
            max_findings: 10_000,
            enabled,
            fail_open_on_store_error: true,
            keyring,
            active_kid: 1,
            mac_trunc_bytes: 12,
            max_tokens_to_rehydrate: 50_000,
        }
    }
}

impl SanitizerConfig {
    pub fn validate(&self) -> Result<(), SecurityError> {
        if self.max_input_len == 0 {
            return Err(SecurityError::InvalidConfig("max_input_len must be > 0".into()));
        }
        if self.max_findings == 0 {
            return Err(SecurityError::InvalidConfig("max_findings must be > 0".into()));
        }
        if self.mac_trunc_bytes < 8 || self.mac_trunc_bytes > 32 {
            return Err(SecurityError::InvalidConfig(
                "mac_trunc_bytes must be in [8, 32]".into(),
            ));
        }
        if self.keyring.is_empty() {
            return Err(SecurityError::InvalidConfig("keyring must not be empty".into()));
        }
        if self
            .keyring
            .iter()
            .all(|k| k.kid != self.active_kid)
        {
            return Err(SecurityError::InvalidConfig(
                "active_kid must exist in keyring".into(),
            ));
        }
        if self.max_tokens_to_rehydrate == 0 {
            return Err(SecurityError::InvalidConfig(
                "max_tokens_to_rehydrate must be > 0".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RedactionStats {
    pub total_findings: usize,
    pub unique_tokens: usize,

    pub store_writes_attempted: usize,
    pub store_writes_failed: usize,

    pub store_reads_attempted: usize,
    pub store_reads_skipped_invalid_token: usize,
    pub store_reads_skipped_over_limit: usize,

    pub kinds: HashMap<PiiKind, usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RedactionOutcome {
    pub redacted_text: String,
    pub stats: RedactionStats,
}

#[derive(Debug, Clone)]
struct Finding {
    start: usize, // byte offsets
    end: usize,
    kind: PiiKind,
}

pub struct PiiSanitizer<S: TokenStore> {
    store: Arc<S>,
    cfg: SanitizerConfig,
}

impl<S: TokenStore> PiiSanitizer<S> {
    pub fn new(store: Arc<S>, cfg: SanitizerConfig) -> Result<Self, SecurityError> {
        cfg.validate()?;
        Ok(Self { store, cfg })
    }

    pub fn config(&self) -> &SanitizerConfig {
        &self.cfg
    }

    pub async fn redact(&self, input: &str) -> Result<RedactionOutcome, SecurityError> {
        if input.len() > self.cfg.max_input_len {
            return Err(SecurityError::InputTooLarge {
                len: input.len(),
                max: self.cfg.max_input_len,
            });
        }

        // Exclude already-redacted tokens (idempotency).
        let excluded = token_spans(input);

        // Collect findings across enabled patterns.
        let mut findings = Vec::<Finding>::new();

        if self.cfg.enabled.contains(&PiiKind::Email) {
            collect_findings(&EMAIL_REGEX, input, PiiKind::Email, &excluded, &mut findings);
        }
        if self.cfg.enabled.contains(&PiiKind::Ssn) {
            collect_findings(&SSN_REGEX, input, PiiKind::Ssn, &excluded, &mut findings);
        }
        if self.cfg.enabled.contains(&PiiKind::Ipv4) {
            collect_findings(&IPV4_REGEX, input, PiiKind::Ipv4, &excluded, &mut findings);
        }
        if self.cfg.enabled.contains(&PiiKind::SecretKey) {
            collect_findings(&KEY_REGEX, input, PiiKind::SecretKey, &excluded, &mut findings);
        }
        if self.cfg.enabled.contains(&PiiKind::Phone) {
            collect_findings(&PHONE_REGEX, input, PiiKind::Phone, &excluded, &mut findings);
        }
        if self.cfg.enabled.contains(&PiiKind::Date) {
            collect_findings(&DATE_REGEX, input, PiiKind::Date, &excluded, &mut findings);
        }

        // Refine findings (e.g. IPv4 octet check).
        findings.retain(|f| match f.kind {
            PiiKind::Ipv4 => is_valid_ipv4(&input[f.start..f.end]),
            _ => true,
        });

        // Resolve overlaps with priority, chain-safe.
        let resolved = resolve_overlaps(findings);

        if resolved.len() > self.cfg.max_findings {
            return Err(SecurityError::TooManyFindings {
                count: resolved.len(),
                max: self.cfg.max_findings,
            });
        }

        // Build replacements (dedupe identical originals per kind).
        let mut original_to_token: HashMap<(PiiKind, String), String> = HashMap::new();
        let mut token_to_original: Vec<(String, String)> = Vec::new(); // unique token writes

        let mut output = String::with_capacity(input.len());
        let mut cursor = 0usize;

        let mut stats = RedactionStats::default();

        for f in &resolved {
            output.push_str(&input[cursor..f.start]);

            let original = input[f.start..f.end].to_string();
            let map_key = (f.kind, original.clone());

            let token = if let Some(existing) = original_to_token.get(&map_key) {
                existing.clone()
            } else {
                let uuid = Uuid::new_v4();
                let kid = self.cfg.active_kid;
                let mac_hex = self.compute_token_mac_hex(f.kind, kid, uuid);

                let t = format!(
                    "[PII:v1:{}:KID:{:02}:UUID:{}:MAC:{}]",
                    f.kind.as_str(),
                    kid,
                    uuid,
                    mac_hex
                );

                original_to_token.insert(map_key, t.clone());
                token_to_original.push((t.clone(), original.clone()));
                t
            };

            output.push_str(&token);
            cursor = f.end;

            stats.total_findings += 1;
            *stats.kinds.entry(f.kind).or_insert(0) += 1;
        }

        output.push_str(&input[cursor..]);

        // Store token -> original (fail-open by default, fail-closed if configured).
        stats.unique_tokens = token_to_original.len();

        let mut any_store_failure = false;
        for (token, original) in &token_to_original {
            stats.store_writes_attempted += 1;
            let store_res = self
                .store
                .set_with_ttl(token, original, self.cfg.ttl_secs)
                .await;

            if store_res.is_err() {
                stats.store_writes_failed += 1;
                any_store_failure = true;
            }
        }

        if any_store_failure && !self.cfg.fail_open_on_store_error {
            return Err(SecurityError::StoreWriteFailed);
        }

        Ok(RedactionOutcome {
            redacted_text: output,
            stats,
        })
    }

    /// Rehydrates tokens back into originals using store lookups.
    /// Tokens must pass MAC verification or we do NOT query the store.
    pub async fn rehydrate(&self, input: &str) -> Result<(String, RedactionStats), SecurityError> {
        if input.len() > self.cfg.max_input_len {
            return Err(SecurityError::InputTooLarge {
                len: input.len(),
                max: self.cfg.max_input_len,
            });
        }

        let mut output = String::with_capacity(input.len());
        let mut cursor = 0usize;

        let mut stats = RedactionStats::default();
        let mut tokens_seen = 0usize;

        for caps in TOKEN_REGEX.captures_iter(input) {
            if tokens_seen >= self.cfg.max_tokens_to_rehydrate {
                stats.store_reads_skipped_over_limit += 1;
                break;
            }
            tokens_seen += 1;

            let m = caps.get(0).expect("capture 0 exists");
            let start = m.start();
            let end = m.end();

            output.push_str(&input[cursor..start]);

            let token = &input[start..end];

            let kind_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let kid_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let uuid_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let mac_hex = caps.get(4).map(|m| m.as_str()).unwrap_or("");

            let kind = PiiKind::from_str(kind_str);
            let kid = kid_str.parse::<u8>().ok();
            let uuid = Uuid::parse_str(uuid_str).ok();

            let mac_ok = match (kind, kid, uuid) {
                (Some(k), Some(kid), Some(uuid)) => self.verify_token_mac_hex(k, kid, uuid, mac_hex),
                _ => false,
            };

            if !mac_ok {
                stats.store_reads_skipped_invalid_token += 1;
                output.push_str(token);
                cursor = end;
                continue;
            }

            stats.store_reads_attempted += 1;

            match self.store.get(token).await {
                Ok(Some(original)) => output.push_str(&original),
                _ => output.push_str(token),
            }

            cursor = end;
        }

        output.push_str(&input[cursor..]);
        Ok((output, stats))
    }

    fn key_for_kid(&self, kid: u8) -> Option<&[u8]> {
        self.cfg
            .keyring
            .iter()
            .find(|k| k.kid == kid)
            .map(|k| k.key.as_slice())
    }

    fn mac_input(kind: PiiKind, kid: u8, uuid: Uuid) -> Vec<u8> {
        // Canonical input: v1|KIND|KID|UUID
        format!("v1|{}|{:02}|{}", kind.as_str(), kid, uuid).into_bytes()
    }

    fn compute_token_mac_hex(&self, kind: PiiKind, kid: u8, uuid: Uuid) -> String {
        let key = self
            .key_for_kid(kid)
            .expect("active_kid must exist in keyring");
        let input = Self::mac_input(kind, kid, uuid);

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&input);
        let full = mac.finalize().into_bytes();

        let trunc_len = self.cfg.mac_trunc_bytes.min(full.len());
        hex::encode(&full[..trunc_len])
    }

    fn verify_token_mac_hex(&self, kind: PiiKind, kid: u8, uuid: Uuid, mac_hex: &str) -> bool {
        let Some(key) = self.key_for_kid(kid) else {
            return false;
        };

        let expected_bytes = match hex::decode(mac_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        if expected_bytes.len() != self.cfg.mac_trunc_bytes {
            return false;
        }

        let input = Self::mac_input(kind, kid, uuid);
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&input);
        let full = mac.finalize().into_bytes();
        let trunc_len = self.cfg.mac_trunc_bytes.min(full.len());
        let actual = &full[..trunc_len];

        actual.ct_eq(expected_bytes.as_slice()).into()
    }
}

// ============================================================================
// Finding collection & overlap resolution
// ============================================================================

fn token_spans(text: &str) -> Vec<(usize, usize)> {
    TOKEN_REGEX.find_iter(text).map(|m| (m.start(), m.end())).collect()
}

fn overlaps_any(start: usize, end: usize, spans: &[(usize, usize)]) -> bool {
    spans.iter().any(|(s, e)| start < *e && end > *s)
}

fn collect_findings(
    re: &Regex,
    text: &str,
    kind: PiiKind,
    excluded: &[(usize, usize)],
    out: &mut Vec<Finding>,
) {
    for m in re.find_iter(text) {
        if overlaps_any(m.start(), m.end(), excluded) {
            continue;
        }
        if m.start() >= m.end() {
            continue;
        }
        out.push(Finding {
            start: m.start(),
            end: m.end(),
            kind,
        });
    }
}

/// Overlap resolution that is chain-safe:
/// - groups any overlapping chain into one interval
/// - selects the "best" finding in that group by (priority, length)
fn resolve_overlaps(mut findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }

    findings.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));

    let mut selected: Vec<Finding> = Vec::new();

    let mut group_best = findings[0].clone();
    let mut group_end = findings[0].end;

    for f in findings.into_iter().skip(1) {
        if f.start < group_end {
            // still in overlap group (chain)
            group_end = group_end.max(f.end);

            let best_score = (group_best.kind.priority(), group_best.end - group_best.start);
            let cand_score = (f.kind.priority(), f.end - f.start);

            if cand_score > best_score {
                group_best = f;
            }
        } else {
            selected.push(group_best);
            group_best = f;
            group_end = group_best.end;
        }
    }

    selected.push(group_best);
    selected
}

fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for p in parts {
        if p.is_empty() || p.len() > 3 {
            return false;
        }
        if let Ok(n) = p.parse::<u16>() {
            if n > 255 {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

// ============================================================================
// Tests: large environment + forged token rejection + rotation + failure modes
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::time::sleep;

    #[derive(Default)]
    struct InMemoryTtlStore {
        inner: Mutex<HashMap<String, (String, Instant)>>,
        reads: Mutex<u64>,
        writes: Mutex<u64>,
        fail_writes: Mutex<bool>,
        fail_reads: Mutex<bool>,
    }

    impl InMemoryTtlStore {
        fn cleanup_expired(&self) {
            let now = Instant::now();
            let mut map = self.inner.lock().unwrap();
            map.retain(|_, (_, exp)| *exp > now);
        }

        fn read_count(&self) -> u64 {
            *self.reads.lock().unwrap()
        }

        fn write_count(&self) -> u64 {
            *self.writes.lock().unwrap()
        }

        fn set_fail_writes(&self, v: bool) {
            *self.fail_writes.lock().unwrap() = v;
        }

        fn set_fail_reads(&self, v: bool) {
            *self.fail_reads.lock().unwrap() = v;
        }
    }

    impl TokenStore for InMemoryTtlStore {
        fn set_with_ttl<'a>(
            &'a self,
            key: &'a str,
            value: &'a str,
            ttl_secs: u64,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>> {
            Box::pin(async move {
                *self.writes.lock().unwrap() += 1;

                if *self.fail_writes.lock().unwrap() {
                    return Err(StoreError::StoreFailure("injected write failure".into()));
                }

                let exp = Instant::now() + Duration::from_secs(ttl_secs);
                self.inner
                    .lock()
                    .unwrap()
                    .insert(key.to_string(), (value.to_string(), exp));
                Ok(())
            })
        }

        fn get<'a>(
            &'a self,
            key: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<String>, StoreError>> + Send + 'a>> {
            Box::pin(async move {
                *self.reads.lock().unwrap() += 1;

                if *self.fail_reads.lock().unwrap() {
                    return Err(StoreError::StoreFailure("injected read failure".into()));
                }

                self.cleanup_expired();
                Ok(self.inner.lock().unwrap().get(key).map(|(v, _)| v.clone()))
            })
        }
    }

    fn make_cfg(key: &[u8], kid: u8) -> SanitizerConfig {
        let mut cfg = SanitizerConfig::default();
        cfg.ttl_secs = 60;
        cfg.max_input_len = 2_000_000;
        cfg.max_findings = 50_000;
        cfg.mac_trunc_bytes = 12;
        cfg.keyring = vec![MacKey {
            kid,
            key: key.to_vec(),
        }];
        cfg.active_kid = kid;
        cfg.max_tokens_to_rehydrate = 100_000;
        cfg.fail_open_on_store_error = true;
        cfg
    }

    fn make_sanitizer(store: Arc<InMemoryTtlStore>, key: &[u8], kid: u8) -> PiiSanitizer<InMemoryTtlStore> {
        PiiSanitizer::new(store, make_cfg(key, kid)).unwrap()
    }

    #[tokio::test]
    async fn roundtrip_redact_rehydrate_ok() {
        let store = Arc::new(InMemoryTtlStore::default());
        let s = make_sanitizer(store.clone(), b"unit-test-key-1", 1);

        let input = "Email bob@example.com and call 415-555-1212.";
        let out = s.redact(input).await.unwrap();

        assert!(out.redacted_text.contains("[PII:v1:EMAIL:KID:01:UUID:"));
        assert!(out.redacted_text.contains(":MAC:"));
        assert_eq!(out.stats.unique_tokens, 2);
        assert_eq!(store.write_count(), 2);

        let (rehydrated, stats) = s.rehydrate(&out.redacted_text).await.unwrap();
        assert_eq!(rehydrated, input);
        assert!(stats.store_reads_attempted >= 1);
    }

    #[tokio::test]
    async fn idempotent_redact_on_already_redacted_text() {
        let store = Arc::new(InMemoryTtlStore::default());
        let s = make_sanitizer(store.clone(), b"unit-test-key-1", 1);

        let input = "Email bob@example.com.";
        let out1 = s.redact(input).await.unwrap();

        let out2 = s.redact(&out1.redacted_text).await.unwrap();
        assert_eq!(out2.redacted_text, out1.redacted_text);
        assert_eq!(out2.stats.total_findings, 0);
        assert_eq!(out2.stats.unique_tokens, 0);
    }

    #[tokio::test]
    async fn forged_token_is_not_rehydrated_and_does_not_hit_store() {
        let store = Arc::new(InMemoryTtlStore::default());
        let s = make_sanitizer(store.clone(), b"unit-test-key-1", 1);

        let uuid = Uuid::new_v4();
        let forged = format!("[PII:v1:EMAIL:KID:01:UUID:{}:MAC:{}]", uuid, "0".repeat(24));
        let input = format!("Here is a forged token: {}", forged);

        let reads_before = store.read_count();
        let (rehydrated, stats) = s.rehydrate(&input).await.unwrap();
        let reads_after = store.read_count();

        assert_eq!(rehydrated, input);
        assert_eq!(reads_after, reads_before, "invalid token must not hit store");
        assert_eq!(stats.store_reads_skipped_invalid_token, 1);
    }

    #[tokio::test]
    async fn key_rotation_breaks_old_tokens_as_expected() {
        let store = Arc::new(InMemoryTtlStore::default());

        let s_old = make_sanitizer(store.clone(), b"old-key", 1);
        let s_new = make_sanitizer(store.clone(), b"new-key", 1);

        let input = "Email bob@example.com.";
        let out = s_old.redact(input).await.unwrap();

        let reads_before = store.read_count();
        let (rehydrated, stats) = s_new.rehydrate(&out.redacted_text).await.unwrap();
        let reads_after = store.read_count();

        assert_eq!(rehydrated, out.redacted_text);
        assert_eq!(reads_after, reads_before, "MAC fail should skip store reads");
        assert_eq!(stats.store_reads_skipped_invalid_token, 1);
    }

    #[tokio::test]
    async fn unknown_kid_is_rejected() {
        let store = Arc::new(InMemoryTtlStore::default());
        let s = make_sanitizer(store.clone(), b"unit-test-key-1", 1);

        let uuid = Uuid::new_v4();
        let token = format!("[PII:v1:EMAIL:KID:99:UUID:{}:MAC:{}]", uuid, "a".repeat(24));
        let input = format!("Token: {}", token);

        let reads_before = store.read_count();
        let (rehydrated, stats) = s.rehydrate(&input).await.unwrap();
        let reads_after = store.read_count();

        assert_eq!(rehydrated, input);
        assert_eq!(reads_after, reads_before);
        assert_eq!(stats.store_reads_skipped_invalid_token, 1);
    }

    #[tokio::test]
    async fn ttl_expiry_keeps_token_redacted() {
        let store = Arc::new(InMemoryTtlStore::default());

        let mut cfg = make_cfg(b"unit-test-key-1", 1);
        cfg.ttl_secs = 0;
        let s = PiiSanitizer::new(store.clone(), cfg).unwrap();

        let input = "Email bob@example.com.";
        let out = s.redact(input).await.unwrap();

        sleep(Duration::from_millis(10)).await;

        let (rehydrated, _stats) = s.rehydrate(&out.redacted_text).await.unwrap();
        assert_eq!(rehydrated, out.redacted_text);
    }

    #[tokio::test]
    async fn invalid_ipv4_is_not_redacted() {
        let store = Arc::new(InMemoryTtlStore::default());
        let s = make_sanitizer(store.clone(), b"unit-test-key-1", 1);

        let input = "This is not an IP: 999.999.999.999 but this is: 10.0.0.1";
        let out = s.redact(input).await.unwrap();

        assert!(out.redacted_text.contains("999.999.999.999"));
        assert!(out.redacted_text.contains("[PII:v1:IPV4:KID:01:UUID:"));
    }

    #[tokio::test]
    async fn max_input_len_enforced() {
        let store = Arc::new(InMemoryTtlStore::default());
        let mut cfg = make_cfg(b"unit-test-key-1", 1);
        cfg.max_input_len = 10;
        let s = PiiSanitizer::new(store, cfg).unwrap();

        let err = s.redact("this is definitely too long").await.unwrap_err();
        assert!(matches!(err, SecurityError::InputTooLarge { .. }));
    }

    #[tokio::test]
    async fn max_findings_enforced() {
        let store = Arc::new(InMemoryTtlStore::default());
        let mut cfg = make_cfg(b"unit-test-key-1", 1);
        cfg.max_findings = 3;
        let s = PiiSanitizer::new(store, cfg).unwrap();

        let input = "a@b.com c@d.com e@f.com g@h.com";
        let err = s.redact(input).await.unwrap_err();
        assert!(matches!(err, SecurityError::TooManyFindings { .. }));
    }

    #[tokio::test]
    async fn fail_open_store_write_errors_still_return_redacted_text() {
        let store = Arc::new(InMemoryTtlStore::default());
        store.set_fail_writes(true);

        let mut cfg = make_cfg(b"unit-test-key-1", 1);
        cfg.fail_open_on_store_error = true;
        let s = PiiSanitizer::new(store.clone(), cfg).unwrap();

        let input = "Email bob@example.com.";
        let out = s.redact(input).await.unwrap();

        assert!(out.redacted_text.contains("[PII:v1:EMAIL:KID:01:UUID:"));
        assert!(out.stats.store_writes_failed >= 1);
    }

    #[tokio::test]
    async fn fail_closed_store_write_errors_block() {
        let store = Arc::new(InMemoryTtlStore::default());
        store.set_fail_writes(true);

        let mut cfg = make_cfg(b"unit-test-key-1", 1);
        cfg.fail_open_on_store_error = false;
        let s = PiiSanitizer::new(store, cfg).unwrap();

        let input = "Email bob@example.com.";
        let err = s.redact(input).await.unwrap_err();
        assert!(matches!(err, SecurityError::StoreWriteFailed));
    }

    #[tokio::test]
    async fn rehydrate_caps_token_processing() {
        let store = Arc::new(InMemoryTtlStore::default());
        let mut cfg = make_cfg(b"unit-test-key-1", 1);
        cfg.max_tokens_to_rehydrate = 1;
        let s = PiiSanitizer::new(store.clone(), cfg).unwrap();

        // Redact something with multiple tokens.
        let input = "Email bob@example.com and call 415-555-1212.";
        let out = s.redact(input).await.unwrap();

        let (rehydrated, stats) = s.rehydrate(&out.redacted_text).await.unwrap();
        // Only one token should have been attempted, the rest remain tokens.
        assert!(stats.store_reads_attempted <= 1);
        assert!(rehydrated.contains("[PII:v1:"));
        assert!(stats.store_reads_skipped_over_limit >= 0);
    }

    #[tokio::test]
    async fn stress_many_pii_entries() {
        let store = Arc::new(InMemoryTtlStore::default());
        let s = make_sanitizer(store.clone(), b"unit-test-key-1", 1);

        let mut input = String::new();
        for i in 0..20_000 {
            input.push_str(&format!("user{}@example.com ", i));
            if i % 10 == 0 {
                input.push_str("415-555-1212 ");
            }
            if i % 25 == 0 {
                input.push_str("123-45-6789 ");
            }
            if i % 40 == 0 {
                input.push_str("10.0.0.1 ");
            }
        }

        let out = s.redact(&input).await.unwrap();
        assert!(out.redacted_text.contains("[PII:v1:EMAIL:KID:01:UUID:"));
        assert!(out.stats.total_findings > 10_000);
        assert!(store.write_count() > 10_000);
    }

    #[test]
    fn config_validation_catches_bad_mac_length() {
        let mut cfg = SanitizerConfig::default();
        cfg.mac_trunc_bytes = 2;
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, SecurityError::InvalidConfig(_)));
    }

    #[test]
    fn config_validation_requires_active_kid_in_keyring() {
        let mut cfg = SanitizerConfig::default();
        cfg.keyring = vec![MacKey { kid: 7, key: b"k".to_vec() }];
        cfg.active_kid = 1;
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, SecurityError::InvalidConfig(_)));
    }
}
