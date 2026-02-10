use blake3;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};

type HmacSha256 = Hmac<Sha256>;

/// Token format (opaque, MAC-verified, does not reveal secret name):
/// ZT:v1:KID:01:AG:<16hex>:SC:<16hex>:UUID:<uuid>:EXP:<ms>:MAC:<24hex>
///
/// - AG/SC are short hashes (8 bytes => 16 hex chars) of agent_id and secret_name.
/// - MAC is truncated HMAC-SHA256 (12 bytes => 24 hex chars).
const TOKEN_VERSION: &str = "v1";
const MAC_TRUNC_BYTES_DEFAULT: usize = 12;
const SHORT_TAG_BYTES: usize = 8;

#[derive(Debug, Error)]
pub enum VaultProxyError {
    #[error("invalid agent_id")]
    InvalidAgentId,
    #[error("invalid secret_name")]
    InvalidSecretName,
    #[error("invalid token format")]
    InvalidTokenFormat,
    #[error("unknown key id: {0}")]
    UnknownKeyId(u8),
    #[error("token MAC verification failed")]
    InvalidMac,
    #[error("token expired")]
    TokenExpired,
    #[error("token not found or revoked")]
    TokenNotFound,
    #[error("token does not belong to this agent")]
    AgentMismatch,
    #[error("token scope mismatch")]
    ScopeMismatch,
    #[error("token already used")]
    TokenAlreadyUsed,
    #[error("secret provider error: {0}")]
    SecretProvider(String),
}

pub trait SecretProvider: Send + Sync {
    fn get_secret(&self, name: &str) -> Result<String, String>;
}

/// Time source abstraction for deterministic tests.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// Default system clock. (You can replace this with a monotonic clock if you prefer.)
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        now.as_millis() as u64
    }
}

#[derive(Debug, Clone)]
pub struct MacKey {
    pub kid: u8,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VaultProxyConfig {
    pub default_ttl_ms: u64,
    pub mac_trunc_bytes: usize,
    pub keyring: Vec<MacKey>,
    pub active_kid: u8,
}

impl Default for VaultProxyConfig {
    fn default() -> Self {
        // If you ship this key, please also ship a written apology.
        let keyring = vec![MacKey {
            kid: 1,
            key: b"CHANGE-ME-IN-PROD-THIS-IS-A-TEST-KEY".to_vec(),
        }];

        Self {
            default_ttl_ms: 60_000,
            mac_trunc_bytes: MAC_TRUNC_BYTES_DEFAULT,
            keyring,
            active_kid: 1,
        }
    }
}

#[derive(Debug, Clone)]
struct TokenRecord {
    agent_tag_hex: String,
    scope_tag_hex: String,
    secret_name: String,
    expires_at_ms: u64,
    one_time: bool,
    used: bool,
}

pub struct VaultProxy<P: SecretProvider, C: Clock> {
    cfg: VaultProxyConfig,
    provider: Arc<P>,
    clock: Arc<C>,
    // token -> record
    scoped_tokens: HashMap<String, TokenRecord>,
}

impl<P: SecretProvider, C: Clock> VaultProxy<P, C> {
    pub fn new(cfg: VaultProxyConfig, provider: Arc<P>, clock: Arc<C>) -> Result<Self, VaultProxyError> {
        validate_config(&cfg)?;
        Ok(Self {
            cfg,
            provider,
            clock,
            scoped_tokens: HashMap::new(),
        })
    }

    pub fn config(&self) -> &VaultProxyConfig {
        &self.cfg
    }

    /// Issues a scoped token for (agent_id, secret_name).
    /// - The agent never sees the secret value.
    /// - The token is MAC-protected to reject forged tokens.
    pub fn issue_scoped_token(
        &mut self,
        agent_id: &str,
        secret_name: &str,
        ttl_ms: Option<u64>,
        one_time: bool,
    ) -> Result<String, VaultProxyError> {
        validate_agent_id(agent_id)?;
        validate_secret_name(secret_name)?;

        let ttl = ttl_ms.unwrap_or(self.cfg.default_ttl_ms);
        let now = self.clock.now_ms();
        let exp = now.saturating_add(ttl);

        let agent_tag = short_tag_hex(agent_id);
        let scope_tag = short_tag_hex(secret_name);

        let kid = self.cfg.active_kid;
        let uuid = Uuid::new_v4();

        let mac_hex = self.compute_token_mac_hex(kid, &agent_tag, &scope_tag, uuid, exp);

        let token = format!(
            "ZT:{ver}:KID:{kid:02}:AG:{ag}:SC:{sc}:UUID:{uuid}:EXP:{exp}:MAC:{mac}",
            ver = TOKEN_VERSION,
            kid = kid,
            ag = agent_tag,
            sc = scope_tag,
            uuid = uuid,
            exp = exp,
            mac = mac_hex
        );

        self.scoped_tokens.insert(
            token.clone(),
            TokenRecord {
                agent_tag_hex: agent_tag,
                scope_tag_hex: scope_tag,
                secret_name: secret_name.to_string(),
                expires_at_ms: exp,
                one_time,
                used: false,
            },
        );

        Ok(token)
    }

    /// Revoke a token (removes it).
    pub fn revoke_token(&mut self, token: &str) -> bool {
        self.scoped_tokens.remove(token).is_some()
    }

    /// Remove expired tokens.
    pub fn cleanup_expired(&mut self) -> usize {
        let now = self.clock.now_ms();
        let before = self.scoped_tokens.len();
        self.scoped_tokens.retain(|_, rec| rec.expires_at_ms > now);
        before - self.scoped_tokens.len()
    }

    /// Resolve a scoped token to the actual secret at the edge boundary.
    ///
    /// Security properties:
    /// - Rejects invalid/forged tokens via MAC check BEFORE record lookup.
    /// - Enforces expiry.
    /// - Enforces agent binding + scope binding.
    /// - Optional one-time usage.
    pub fn resolve_token(
        &mut self,
        agent_id: &str,
        token: &str,
    ) -> Result<String, VaultProxyError> {
        validate_agent_id(agent_id)?;

        let parsed = parse_token(token)?;
        if parsed.version != TOKEN_VERSION {
            return Err(VaultProxyError::InvalidTokenFormat);
        }

        // Verify MAC before any lookup (reject forged tokens early).
        if !self.verify_token_mac_hex(
            parsed.kid,
            &parsed.agent_tag_hex,
            &parsed.scope_tag_hex,
            parsed.uuid,
            parsed.exp_ms,
            &parsed.mac_hex,
        ) {
            return Err(VaultProxyError::InvalidMac);
        }

        // Expiry check from token itself (cheap gate)
        let now = self.clock.now_ms();
        if now >= parsed.exp_ms {
            // Clean up if present
            self.scoped_tokens.remove(token);
            return Err(VaultProxyError::TokenExpired);
        }

        // Now lookup record (must exist).
        let rec = self
            .scoped_tokens
            .get_mut(token)
            .ok_or(VaultProxyError::TokenNotFound)?;

        // Record expiry check (defense-in-depth)
        if now >= rec.expires_at_ms {
            self.scoped_tokens.remove(token);
            return Err(VaultProxyError::TokenExpired);
        }

        // Agent binding: compare short tag
        let expected_agent_tag = short_tag_hex(agent_id);
        if expected_agent_tag != rec.agent_tag_hex || expected_agent_tag != parsed.agent_tag_hex {
            return Err(VaultProxyError::AgentMismatch);
        }

        // Scope binding: compare short tag
        let expected_scope_tag = rec.scope_tag_hex.clone();
        if expected_scope_tag != parsed.scope_tag_hex {
            return Err(VaultProxyError::ScopeMismatch);
        }

        // One-time token enforcement
        if rec.one_time {
            if rec.used {
                return Err(VaultProxyError::TokenAlreadyUsed);
            }
            rec.used = true;
        }

        // Fetch secret from provider
        self.provider
            .get_secret(&rec.secret_name)
            .map_err(VaultProxyError::SecretProvider)
    }

    fn key_for_kid(&self, kid: u8) -> Option<&[u8]> {
        self.cfg
            .keyring
            .iter()
            .find(|k| k.kid == kid)
            .map(|k| k.key.as_slice())
    }

    fn mac_input(kid: u8, agent_tag_hex: &str, scope_tag_hex: &str, uuid: Uuid, exp_ms: u64) -> Vec<u8> {
        // Canonical stable input:
        // v1|kid|ag|sc|uuid|exp
        format!(
            "{ver}|{kid:02}|{ag}|{sc}|{uuid}|{exp}",
            ver = TOKEN_VERSION,
            kid = kid,
            ag = agent_tag_hex,
            sc = scope_tag_hex,
            uuid = uuid,
            exp = exp_ms
        )
        .into_bytes()
    }

    fn compute_token_mac_hex(
        &self,
        kid: u8,
        agent_tag_hex: &str,
        scope_tag_hex: &str,
        uuid: Uuid,
        exp_ms: u64,
    ) -> String {
        let key = self
            .key_for_kid(kid)
            .expect("active_kid must exist in keyring");

        let input = Self::mac_input(kid, agent_tag_hex, scope_tag_hex, uuid, exp_ms);

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&input);
        let full = mac.finalize().into_bytes();

        let trunc_len = self.cfg.mac_trunc_bytes.min(full.len());
        hex::encode(&full[..trunc_len])
    }

    fn verify_token_mac_hex(
        &self,
        kid: u8,
        agent_tag_hex: &str,
        scope_tag_hex: &str,
        uuid: Uuid,
        exp_ms: u64,
        mac_hex: &str,
    ) -> bool {
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

        let input = Self::mac_input(kid, agent_tag_hex, scope_tag_hex, uuid, exp_ms);

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&input);
        let full = mac.finalize().into_bytes();

        let trunc_len = self.cfg.mac_trunc_bytes.min(full.len());
        let actual = &full[..trunc_len];

        actual.ct_eq(expected_bytes.as_slice()).into()
    }

    /// Intercepts environment variable access.
    /// Strict allowlist. Everything else is silently blocked.
    pub fn access_env(var_name: &str) -> Option<String> {
        if !is_allowed_env_var(var_name) {
            return None;
        }
        std::env::var(var_name).ok()
    }
}

// ============================================================================
// Token parsing + validation helpers
// ============================================================================

fn validate_config(cfg: &VaultProxyConfig) -> Result<(), VaultProxyError> {
    if cfg.mac_trunc_bytes == 0 || cfg.mac_trunc_bytes > 32 {
        return Err(VaultProxyError::InvalidTokenFormat);
    }
    if cfg.keyring.is_empty() {
        return Err(VaultProxyError::InvalidTokenFormat);
    }
    if cfg.keyring.iter().all(|k| k.kid != cfg.active_kid) {
        return Err(VaultProxyError::UnknownKeyId(cfg.active_kid));
    }
    Ok(())
}

fn validate_agent_id(agent_id: &str) -> Result<(), VaultProxyError> {
    if agent_id.is_empty() || agent_id.len() > 128 {
        return Err(VaultProxyError::InvalidAgentId);
    }
    if !agent_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
    {
        return Err(VaultProxyError::InvalidAgentId);
    }
    Ok(())
}

fn validate_secret_name(secret_name: &str) -> Result<(), VaultProxyError> {
    if secret_name.is_empty() || secret_name.len() > 256 {
        return Err(VaultProxyError::InvalidSecretName);
    }
    // Allow reasonable secret name characters (paths included).
    if !secret_name.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || b == b'_'
            || b == b'-'
            || b == b'.'
            || b == b'/'
            || b == b':'
    }) {
        return Err(VaultProxyError::InvalidSecretName);
    }
    Ok(())
}

fn short_tag_hex(s: &str) -> String {
    let h = blake3::hash(s.as_bytes());
    hex::encode(&h.as_bytes()[..SHORT_TAG_BYTES])
}

#[derive(Debug, Clone)]
struct ParsedToken {
    version: String,
    kid: u8,
    agent_tag_hex: String,
    scope_tag_hex: String,
    uuid: Uuid,
    exp_ms: u64,
    mac_hex: String,
}

fn parse_token(token: &str) -> Result<ParsedToken, VaultProxyError> {
    // Expected parts separated by ':'
    // ZT v1 KID 01 AG <hex> SC <hex> UUID <uuid> EXP <ms> MAC <hex>
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 14 {
        return Err(VaultProxyError::InvalidTokenFormat);
    }
    if parts[0] != "ZT" {
        return Err(VaultProxyError::InvalidTokenFormat);
    }

    let version = parts[1].to_string();
    if parts[2] != "KID" || parts[4] != "AG" || parts[6] != "SC" || parts[8] != "UUID" || parts[10] != "EXP" || parts[12] != "MAC" {
        return Err(VaultProxyError::InvalidTokenFormat);
    }

    let kid = parts[3].parse::<u8>().map_err(|_| VaultProxyError::InvalidTokenFormat)?;
    let agent_tag_hex = parts[5].to_string();
    let scope_tag_hex = parts[7].to_string();
    let uuid = Uuid::parse_str(parts[9]).map_err(|_| VaultProxyError::InvalidTokenFormat)?;
    let exp_ms = parts[11].parse::<u64>().map_err(|_| VaultProxyError::InvalidTokenFormat)?;
    let mac_hex = parts[13].to_string();

    // Quick sanity on tag + MAC lengths
    if agent_tag_hex.len() != SHORT_TAG_BYTES * 2 || scope_tag_hex.len() != SHORT_TAG_BYTES * 2 {
        return Err(VaultProxyError::InvalidTokenFormat);
    }
    if !agent_tag_hex.bytes().all(|b| (b as char).is_ascii_hexdigit())
        || !scope_tag_hex.bytes().all(|b| (b as char).is_ascii_hexdigit())
        || !mac_hex.bytes().all(|b| (b as char).is_ascii_hexdigit())
    {
        return Err(VaultProxyError::InvalidTokenFormat);
    }

    Ok(ParsedToken {
        version,
        kid,
        agent_tag_hex,
        scope_tag_hex,
        uuid,
        exp_ms,
        mac_hex,
    })
}

// ============================================================================
// Env allowlist (no allocations)
// ============================================================================

fn is_allowed_env_var(name: &str) -> bool {
    matches!(name, "RUST_LOG" | "PORT")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct InMemoryProvider {
        secrets: HashMap<String, String>,
    }
    impl SecretProvider for InMemoryProvider {
        fn get_secret(&self, name: &str) -> Result<String, String> {
            self.secrets
                .get(name)
                .cloned()
                .ok_or_else(|| "not found".to_string())
        }
    }

    struct MockClock {
        now: AtomicU64,
    }
    impl MockClock {
        fn new(start_ms: u64) -> Self {
            Self {
                now: AtomicU64::new(start_ms),
            }
        }
        fn advance(&self, delta_ms: u64) {
            self.now.fetch_add(delta_ms, Ordering::SeqCst);
        }
    }
    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    fn make_proxy(start_ms: u64) -> (VaultProxy<InMemoryProvider, MockClock>, Arc<MockClock>) {
        let mut provider = InMemoryProvider::default();
        provider.secrets.insert("API_KEY".to_string(), "supersecret".to_string());
        provider.secrets.insert("DB_PASS".to_string(), "horse-battery-staple".to_string());

        let provider = Arc::new(provider);
        let clock = Arc::new(MockClock::new(start_ms));

        let cfg = VaultProxyConfig {
            default_ttl_ms: 1_000,
            mac_trunc_bytes: 12,
            keyring: vec![
                MacKey { kid: 1, key: b"unit-test-key-1".to_vec() },
                MacKey { kid: 2, key: b"unit-test-key-2".to_vec() },
            ],
            active_kid: 1,
        };

        (VaultProxy::new(cfg, provider, clock.clone()).unwrap(), clock)
    }

    #[test]
    fn issue_and_resolve_happy_path() {
        let (mut p, _clock) = make_proxy(1_000_000);

        let token = p.issue_scoped_token("agent_01", "API_KEY", None, false).unwrap();
        assert!(token.starts_with("ZT:v1:KID:01:AG:"));
        assert!(token.contains(":SC:"));
        assert!(token.contains(":UUID:"));
        assert!(token.contains(":EXP:"));
        assert!(token.contains(":MAC:"));

        let secret = p.resolve_token("agent_01", &token).unwrap();
        assert_eq!(secret, "supersecret");
    }

    #[test]
    fn agent_mismatch_is_blocked() {
        let (mut p, _clock) = make_proxy(1_000_000);

        let token = p.issue_scoped_token("agent_01", "API_KEY", None, false).unwrap();
        let err = p.resolve_token("agent_02", &token).unwrap_err();
        assert!(matches!(err, VaultProxyError::AgentMismatch));
    }

    #[test]
    fn revoked_token_is_blocked() {
        let (mut p, _clock) = make_proxy(1_000_000);

        let token = p.issue_scoped_token("agent_01", "API_KEY", None, false).unwrap();
        assert!(p.revoke_token(&token));
        let err = p.resolve_token("agent_01", &token).unwrap_err();
        assert!(matches!(err, VaultProxyError::TokenNotFound));
    }

    #[test]
    fn expiry_is_enforced_and_token_is_cleaned_up() {
        let (mut p, clock) = make_proxy(1_000_000);

        let token = p.issue_scoped_token("agent_01", "API_KEY", Some(100), false).unwrap();
        clock.advance(101);

        let err = p.resolve_token("agent_01", &token).unwrap_err();
        assert!(matches!(err, VaultProxyError::TokenExpired));

        // After expiry, it should be removed if it existed.
        let err2 = p.resolve_token("agent_01", &token).unwrap_err();
        assert!(matches!(err2, VaultProxyError::InvalidMac | VaultProxyError::TokenNotFound | VaultProxyError::TokenExpired));
    }

    #[test]
    fn forged_token_invalid_mac_is_rejected_before_lookup() {
        let (mut p, _clock) = make_proxy(1_000_000);

        // Create a well-formed token string but with a garbage MAC.
        // Note: It won't be in the store anyway, but we want the failure mode to be InvalidMac (early reject).
        let agent_tag = short_tag_hex("agent_01");
        let scope_tag = short_tag_hex("API_KEY");
        let uuid = Uuid::new_v4();
        let exp = 1_000_999;

        let forged = format!(
            "ZT:v1:KID:01:AG:{ag}:SC:{sc}:UUID:{uuid}:EXP:{exp}:MAC:{mac}",
            ag = agent_tag,
            sc = scope_tag,
            uuid = uuid,
            exp = exp,
            mac = "0".repeat(24),
        );

        let err = p.resolve_token("agent_01", &forged).unwrap_err();
        assert!(matches!(err, VaultProxyError::InvalidMac));
    }

    #[test]
    fn unknown_kid_is_rejected_via_mac_verification() {
        let (mut p, _clock) = make_proxy(1_000_000);

        let agent_tag = short_tag_hex("agent_01");
        let scope_tag = short_tag_hex("API_KEY");
        let uuid = Uuid::new_v4();
        let exp = 1_001_000;

        // KID:99 is not in keyring
        let token = format!(
            "ZT:v1:KID:99:AG:{ag}:SC:{sc}:UUID:{uuid}:EXP:{exp}:MAC:{mac}",
            ag = agent_tag,
            sc = scope_tag,
            uuid = uuid,
            exp = exp,
            mac = "a".repeat(24),
        );

        let err = p.resolve_token("agent_01", &token).unwrap_err();
        // Unknown KID manifests as MAC verification failure (no key to verify with).
        assert!(matches!(err, VaultProxyError::InvalidMac));
    }

    #[test]
    fn one_time_token_enforced() {
        let (mut p, _clock) = make_proxy(1_000_000);

        let token = p.issue_scoped_token("agent_01", "DB_PASS", None, true).unwrap();

        let secret1 = p.resolve_token("agent_01", &token).unwrap();
        assert_eq!(secret1, "horse-battery-staple");

        let err = p.resolve_token("agent_01", &token).unwrap_err();
        assert!(matches!(err, VaultProxyError::TokenAlreadyUsed));
    }

    #[test]
    fn cleanup_expired_removes_only_expired() {
        let (mut p, clock) = make_proxy(1_000_000);

        let t1 = p.issue_scoped_token("agent_01", "API_KEY", Some(50), false).unwrap();
        let t2 = p.issue_scoped_token("agent_01", "DB_PASS", Some(500), false).unwrap();

        clock.advance(60);
        let removed = p.cleanup_expired();
        assert_eq!(removed, 1);

        // t1 should be expired now
        let err1 = p.resolve_token("agent_01", &t1).unwrap_err();
        assert!(matches!(err1, VaultProxyError::InvalidMac | VaultProxyError::TokenNotFound | VaultProxyError::TokenExpired));

        // t2 should still work
        let secret2 = p.resolve_token("agent_01", &t2).unwrap();
        assert_eq!(secret2, "horse-battery-staple");
    }

    // --- Env allowlist tests (global state, so guard with a mutex) ---
    static ENV_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn access_env_allows_only_allowlist() {
        let _g = env_guard();

        std::env::set_var("RUST_LOG", "info");
        std::env::set_var("SECRET_STUFF", "nope");

        assert_eq!(VaultProxy::<InMemoryProvider, MockClock>::access_env("RUST_LOG"), Some("info".to_string()));
        assert_eq!(VaultProxy::<InMemoryProvider, MockClock>::access_env("SECRET_STUFF"), None);

        // clean up
        std::env::remove_var("RUST_LOG");
        std::env::remove_var("SECRET_STUFF");
    }

    #[test]
    fn rejects_bad_agent_and_secret_names() {
        let (mut p, _clock) = make_proxy(1_000_000);

        assert!(matches!(
            p.issue_scoped_token("", "API_KEY", None, false).unwrap_err(),
            VaultProxyError::InvalidAgentId
        ));

        assert!(matches!(
            p.issue_scoped_token("agent_01", "API KEY WITH SPACES", None, false).unwrap_err(),
            VaultProxyError::InvalidSecretName
        ));
    }

    #[test]
    fn parse_token_rejects_garbage() {
        assert!(matches!(parse_token("nope"), Err(VaultProxyError::InvalidTokenFormat)));
        assert!(matches!(parse_token("ZT:v1:KID:xx"), Err(VaultProxyError::InvalidTokenFormat)));
    }
}
