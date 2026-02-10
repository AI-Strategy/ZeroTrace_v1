//! Production-grade Typosquat / Homograph Scanner
//!
//! Why this exists (not just what it does):
//! - Prevents brand/domain impersonation in user-provided text (links, emails, prompts).
//! - Provides audit-friendly, structured findings without leaking raw user input into logs.
//! - Hardens against malicious inputs (very large strings, token floods, unicode tricks).
//!
//! Design notes:
//! - Domain parsing is intentionally conservative: if we cannot normalize/validate safely, we skip.
//! - Homograph detection here focuses on mixed-script labels (common real-world abuse).
//! - If you want eTLD+1 correctness (co.uk, etc.), integrate `publicsuffix` or `psl`.
//!
//! Suggested dependencies (Cargo.toml):
//! strsim = "0.11"
//! tracing = "0.1"
//! tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
//! thiserror = "1"
//! unicode-normalization = "0.1"
//! unicode-script = "0.5"
//! idna = "0.5"
//! blake3 = "1"

use std::{
    collections::HashMap,
    num::{NonZeroUsize},
    sync::OnceLock,
};

use idna::{domain_to_ascii, domain_to_unicode};
use strsim::levenshtein;
use thiserror::Error;
use tracing::{debug, info, warn};
use unicode_normalization::UnicodeNormalization;
use unicode_script::{Script, UnicodeScript};

/// Initialize JSON logging (call once early in your binary).
///
/// Why:
/// - Makes logs SIEM-friendly.
/// - Prevents “someone changed the formatter” surprises.
pub fn init_json_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .with_current_span(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .try_init();
}

/// Strongly validated domain input used for protected targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtectedDomain(String);

impl ProtectedDomain {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Policy/config for typosquat detection.
///
/// Defensive knobs:
/// - caps to avoid O(n*m) explosions on untrusted input
/// - ratio heuristics to reduce false positives
#[derive(Debug, Clone)]
pub struct TyposquatPolicy {
    pub max_input_bytes: NonZeroUsize,
    pub max_candidates: NonZeroUsize,
    pub max_protected_domains: NonZeroUsize,
    pub min_domain_len: NonZeroUsize,
    pub max_edit_distance: usize,
    /// Maximum edit-distance ratio allowed: distance / len(base_domain)
    pub max_edit_ratio: f32,
    /// Treat subdomains of protected domains as authorized (skip).
    pub allow_subdomains_of_protected: bool,
    /// Enable mixed-script detection (homograph-style).
    pub enable_mixed_script_detection: bool,
}

impl Default for TyposquatPolicy {
    fn default() -> Self {
        Self {
            max_input_bytes: NonZeroUsize::new(64 * 1024).expect("non-zero const"),
            max_candidates: NonZeroUsize::new(256).expect("non-zero const"),
            max_protected_domains: NonZeroUsize::new(10_000).expect("non-zero const"),
            min_domain_len: NonZeroUsize::new(5).expect("non-zero const"),
            max_edit_distance: 2,
            max_edit_ratio: 0.34,
            allow_subdomains_of_protected: true,
            enable_mixed_script_detection: true,
        }
    }
}

/// A structured finding you can feed into metrics, audits, or enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub candidate_raw: String,
    pub candidate_domain: String,
    pub candidate_base: String,
    pub target_domain: Option<String>,
    pub edit_distance: Option<usize>,
    pub input_hash: String,
}

/// Types of findings produced by the scanner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingKind {
    /// Candidate domain is a close edit-distance match to a protected target.
    TyposquatLikely,
    /// Candidate uses mixed scripts in a label (common homograph indicator).
    MixedScriptDomain,
}

/// Error type intentionally safe to show to callers (no stack traces, no internals).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScanError {
    #[error("Input too large")]
    InputTooLarge,

    #[error("Invalid policy configuration")]
    InvalidPolicy,

    #[error("Too many protected domains")]
    TooManyProtectedDomains,
}

/// Internal representation of a normalized domain plus precomputed helpers.
#[derive(Debug, Clone)]
struct ProtectedEntry {
    full: String, // normalized ascii
    base: String, // base domain (heuristic: last 2 labels)
    len: usize,   // base length
}

/// Production-grade typosquat engine.
///
/// Key properties:
/// - validated inputs
/// - bounded work
/// - structured logging
pub struct TyposquatEngine {
    policy: TyposquatPolicy,
    protected: Vec<ProtectedEntry>,
    // length -> indices into protected vec (reduces comparisons).
    length_index: HashMap<usize, Vec<usize>>,
}

impl TyposquatEngine {
    /// Construct a new engine from protected domains.
    ///
    /// Why:
    /// - Normalizes and validates all protected domains at startup (fail early, not at runtime).
    /// - Builds indexes to reduce CPU blowups later.
    pub fn new(
        protected_domains: Vec<String>,
        policy: TyposquatPolicy,
    ) -> Result<Self, ScanError> {
        validate_policy(&policy)?;

        if protected_domains.len() > policy.max_protected_domains.get() {
            return Err(ScanError::TooManyProtectedDomains);
        }

        let mut protected = Vec::with_capacity(protected_domains.len());
        for raw in protected_domains {
            if let Some(norm) = normalize_domain_candidate(&raw) {
                let base = base_domain_heuristic(&norm);
                let len = base.len();
                if len >= policy.min_domain_len.get() {
                    protected.push(ProtectedEntry {
                        full: norm,
                        base,
                        len,
                    });
                }
            }
        }

        // De-dup exact protected targets (after normalization).
        protected.sort_by(|a, b| a.full.cmp(&b.full));
        protected.dedup_by(|a, b| a.full == b.full);

        let mut length_index: HashMap<usize, Vec<usize>> = HashMap::new();
        for (i, e) in protected.iter().enumerate() {
            length_index.entry(e.len).or_default().push(i);
        }

        Ok(Self {
            policy,
            protected,
            length_index,
        })
    }

    /// Scan a chunk of text for suspicious domains.
    ///
    /// Complexity:
    /// - Let C = extracted candidate domains (capped), P = protected domains, L = avg domain length.
    /// - Worst-case time: O(C * P * L²) due to Levenshtein.
    /// - Practical time is reduced via length-bucketing + early skips.
    /// - Space: O(P + C).
    pub fn scan_text(&self, input: &str) -> Result<Vec<Finding>, ScanError> {
        if input.as_bytes().len() > self.policy.max_input_bytes.get() {
            return Err(ScanError::InputTooLarge);
        }

        let input_hash = hash_for_logs(input);
        let candidates = extract_domain_candidates(input, self.policy.max_candidates.get());

        debug!(
            event = "typosquat_scan_start",
            input_hash = %input_hash,
            candidate_count = candidates.len(),
            protected_count = self.protected.len(),
        );

        let mut findings = Vec::new();

        for cand in candidates {
            let raw = cand.raw;
            let domain = match normalize_domain_candidate(&cand.domain) {
                Some(d) => d,
                None => continue, // invalid or unsafe => ignore silently
            };

            // Optional: skip if candidate is exactly protected or a subdomain of protected.
            if self.policy.allow_subdomains_of_protected && self.is_authorized(&domain) {
                continue;
            }

            let base = base_domain_heuristic(&domain);
            if base.len() < self.policy.min_domain_len.get() {
                continue;
            }

            // Mixed-script detection (homograph signal).
            // Must convert back to Unicode because 'domain' is Punycode ASCII here.
            let (domain_unicode, _errors) = domain_to_unicode(&domain);
            if self.policy.enable_mixed_script_detection && has_mixed_script_label(&domain_unicode) {
                warn!(
                    event = "typosquat_mixed_script_detected",
                    input_hash = %input_hash,
                    candidate_domain = %domain,
                    candidate_base = %base,
                );
                findings.push(Finding {
                    kind: FindingKind::MixedScriptDomain,
                    candidate_raw: raw.clone(),
                    candidate_domain: domain.clone(),
                    candidate_base: base.clone(),
                    target_domain: None,
                    edit_distance: None,
                    input_hash: input_hash.clone(),
                });
                // Still continue into typosquat checks: mixed scripts often accompany near-misses.
            }

            // Distance checks against similarly-sized protected bases.
            let matches = self.check_candidate_against_protected(&base);

            for m in matches {
                info!(
                    event = "typosquat_detected",
                    input_hash = %input_hash,
                    candidate_domain = %domain,
                    candidate_base = %base,
                    target_domain = %m.target_full,
                    target_base = %m.target_base,
                    distance = m.distance,
                );

                findings.push(Finding {
                    kind: FindingKind::TyposquatLikely,
                    candidate_raw: raw.clone(),
                    candidate_domain: domain.clone(),
                    candidate_base: base.clone(),
                    target_domain: Some(m.target_full),
                    edit_distance: Some(m.distance),
                    input_hash: input_hash.clone(),
                });
            }
        }

        Ok(dedup_findings(findings))
    }

    /// Convenience boolean check.
    pub fn is_typosquat(&self, input: &str) -> Result<bool, ScanError> {
        Ok(!self.scan_text(input)?.is_empty())
    }

    /// Conservative authorization check.
    ///
    /// Why:
    /// - Avoids flagging legitimate subdomains like `accounts.google.com` when `google.com` is protected.
    /// - Still allows typos like `goog1e.com` to be flagged.
    fn is_authorized(&self, candidate: &str) -> bool {
        // Exact match or subdomain match (candidate ends with ".protected")
        self.protected.iter().any(|p| {
            candidate == p.full || candidate.ends_with(&format!(".{}", p.full))
        })
    }

    fn check_candidate_against_protected(&self, candidate_base: &str) -> Vec<ProtectedMatch> {
        let clen = candidate_base.len();
        let max_dist = self.policy.max_edit_distance;

        // Compare only against protected bases within length +- max_dist (cheap pruning).
        let mut possible_indices = Vec::new();
        for len in clen.saturating_sub(max_dist)..=(clen + max_dist) {
            if let Some(ix) = self.length_index.get(&len) {
                possible_indices.extend_from_slice(ix);
            }
        }

        let mut matches = Vec::new();
        for idx in possible_indices {
            let target = &self.protected[idx];

            // Ratio heuristic to reduce “small word” false positives.
            // Also: if edit distance must be <= max_dist, skip when length delta is already > max_dist.
            if target.len.abs_diff(clen) > max_dist {
                continue;
            }

            let d = levenshtein(candidate_base, &target.base);
            if d == 0 || d > max_dist {
                continue;
            }

            let ratio = d as f32 / (clen.max(1) as f32);
            if ratio > self.policy.max_edit_ratio {
                continue;
            }

            matches.push(ProtectedMatch {
                target_full: target.full.clone(),
                target_base: target.base.clone(),
                distance: d,
            });
        }

        matches
    }
}

#[derive(Debug)]
struct ProtectedMatch {
    target_full: String,
    target_base: String,
    distance: usize,
}

/// Public compatibility helper similar to your original `scan_for_anomalies`.
///
/// Why:
/// - Keeps your caller API simple while still using structured internals.
/// - Only returns user-safe strings (no stack traces, no raw input).
pub fn scan_for_anomalies(input: &str) -> Vec<String> {
    static ENGINE: OnceLock<TyposquatEngine> = OnceLock::new();

    let engine = ENGINE.get_or_init(|| {
        // In production: inject this, don’t hardcode.
        let protected = vec![
            "google.com".to_string(),
            "zerotrace.ai".to_string(),
            "openai.com".to_string(),
        ];
        TyposquatEngine::new(protected, TyposquatPolicy::default())
            .expect("engine must initialize (static config)")
    });

    let mut anomalies = Vec::new();

    match engine.scan_text(input) {
        Err(ScanError::InputTooLarge) => {
            anomalies.push("INPUT_TOO_LARGE".to_string());
            return anomalies;
        }
        Err(_) => {
            anomalies.push("SCAN_FAILED".to_string());
            return anomalies;
        }
        Ok(findings) => {
            for f in findings {
                match f.kind {
                    FindingKind::TyposquatLikely => {
                        let target = f.target_domain.unwrap_or_else(|| "unknown".to_string());
                        let dist = f.edit_distance.unwrap_or(usize::MAX);
                        anomalies.push(format!(
                            "TYPOSQUAT_DETECTED: {} (domain {}) targets {} (distance {})",
                            safe_snip(&f.candidate_raw),
                            f.candidate_domain,
                            target,
                            dist
                        ));
                    }
                    FindingKind::MixedScriptDomain => {
                        anomalies.push(format!(
                            "HOMOGRAPH_SUSPECTED: {} (domain {})",
                            safe_snip(&f.candidate_raw),
                            f.candidate_domain
                        ));
                    }
                }
            }
        }
    }

    // Example additional rule (keep it dumb and explicit).
    // If you want “prompt injection detection”, that should be a separate module.
    if contains_case_insensitive(input, "ignore previous instructions") {
        anomalies.push("JAILBREAK_ATTEMPT".to_string());
    }

    anomalies
}

// ----------------------------- Pure helpers -----------------------------

fn validate_policy(policy: &TyposquatPolicy) -> Result<(), ScanError> {
    if policy.max_edit_distance == 0 || policy.max_edit_distance > 10 {
        // 0 is useless, >10 explodes false positives and cost.
        return Err(ScanError::InvalidPolicy);
    }
    if !(0.0..=1.0).contains(&policy.max_edit_ratio) {
        return Err(ScanError::InvalidPolicy);
    }
    Ok(())
}

/// Extract domain-like candidates from text. Conservative, bounded.
///
/// Why:
/// - Inputs are hostile. Splitting on whitespace alone is not robust.
/// - This tries to catch URLs, emails, and bare domains without regex dependencies.
///
/// Returns at most `max` candidates.
fn extract_domain_candidates(input: &str, max: usize) -> Vec<DomainCandidate> {
    let mut out = Vec::new();

    for raw_tok in input.split_whitespace() {
        if out.len() >= max {
            break;
        }

        let tok = trim_wrapping_punct(raw_tok);

        // URL-like: scheme://host/path
        if let Some(host) = extract_host_from_url(tok) {
            out.push(DomainCandidate {
                raw: raw_tok.to_string(),
                domain: host,
            });
            continue;
        }

        // Email-like: user@domain
        if let Some(host) = extract_host_from_email(tok) {
            out.push(DomainCandidate {
                raw: raw_tok.to_string(),
                domain: host,
            });
            continue;
        }

        // Bare domain-like: something.with.dots
        if looks_like_domain(tok) {
            out.push(DomainCandidate {
                raw: raw_tok.to_string(),
                domain: tok.to_string(),
            });
        }
    }

    out
}

#[derive(Debug)]
struct DomainCandidate {
    raw: String,
    domain: String,
}

/// Normalize candidate domain into safe ASCII:
/// - NFKC normalize (reduces unicode trickery)
/// - lowercase
/// - remove ports and trailing dot
/// - IDNA to ASCII (punycode)
/// - validate label constraints
///
/// Returns None if unsafe/invalid.
fn normalize_domain_candidate(raw: &str) -> Option<String> {
    let mut s = raw.nfkc().collect::<String>();
    s.make_ascii_lowercase();

    // strip surrounding punctuation again (some tokens are messy)
    let s = trim_wrapping_punct(&s);

    // Remove scheme if someone passed full URL.
    let s = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);

    // Cut off path/query/fragment.
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);

    // Strip brackets for IPv6 literals. We don't support IP literals here.
    let s = s.trim_matches(['[', ']'].as_ref());

    // Remove port if present (example.com:443)
    let host = s.split(':').next().unwrap_or(s);

    let host = host.trim_end_matches('.').trim_start_matches('.');

    // Quick sanity: must contain at least one dot.
    if !host.contains('.') {
        return None;
    }

    // IDNA to ASCII (punycode). If it fails, bail.
    let ascii = domain_to_ascii(host).ok()?;

    // Validate basic DNS-ish constraints.
    if ascii.len() > 253 {
        return None;
    }

    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 {
        return None;
    }

    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        // Conservative allowed set: LDH
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }

    Some(ascii)
}

/// Heuristic “base domain” extraction: last 2 labels.
///
/// Why:
/// - Avoids flagging subdomains by comparing the registrable-ish portion.
/// - Limitation: not correct for multi-part TLDs (co.uk etc.). Use PSL if you care.
fn base_domain_heuristic(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    }
}

/// Detect mixed scripts in any label (Latin + Cyrillic, etc).
///
/// Why:
/// - Common homograph pattern is mixing confusable scripts.
/// - We treat `Common`/`Inherited` as neutral.
fn has_mixed_script_label(domain_ascii_or_unicode: &str) -> bool {
    // If it’s ASCII-only, it's not a mixed-script unicode label.
    if domain_ascii_or_unicode.is_ascii() {
        return false;
    }

    // For any label, gather scripts used.
    for label in domain_ascii_or_unicode.split('.') {
        let mut script_seen: Option<Script> = None;
        for ch in label.chars() {
            let sc = ch.script();
            if sc == Script::Common || sc == Script::Inherited {
                continue;
            }
            match script_seen {
                None => script_seen = Some(sc),
                Some(prev) if prev == sc => {}
                Some(_) => return true,
            }
        }
    }
    false
}

fn looks_like_domain(token: &str) -> bool {
    // Minimal checks. Full validation happens in normalize().
    // - contains dot
    // - no spaces
    // - not absurdly short
    token.contains('.') && !token.contains(char::is_whitespace) && token.len() >= 4
}

fn extract_host_from_url(token: &str) -> Option<String> {
    let tok = token;
    let scheme_pos = tok.find("://")?;
    let after = &tok[(scheme_pos + 3)..];
    if after.is_empty() {
        return None;
    }
    let host = after.split(['/', '?', '#']).next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

fn extract_host_from_email(token: &str) -> Option<String> {
    // Very conservative: take substring after '@' if it looks domain-ish
    let at = token.rfind('@')?;
    let host = &token[(at + 1)..];
    let host = trim_wrapping_punct(host);
    if looks_like_domain(host) {
        Some(host.to_string())
    } else {
        None
    }
}

fn trim_wrapping_punct(s: &str) -> &str {
    s.trim_matches(|c: char| {
        matches!(
            c,
            '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '"' | '\'' | ',' | ';' | ':' | '!' | '?' | '.'
        )
    })
}

/// Case-insensitive substring check without allocations.
fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    // Cheap, not locale-sensitive. Security-wise, that's a feature.
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Hash input for logs without leaking contents.
fn hash_for_logs(input: &str) -> String {
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// De-dup findings (same kind + candidate_domain + target_domain).
fn dedup_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        (
            &a.kind,
            &a.candidate_domain,
            &a.target_domain,
            &a.edit_distance,
        )
            .cmp(&(
                &b.kind,
                &b.candidate_domain,
                &b.target_domain,
                &b.edit_distance,
            ))
    });
    findings.dedup_by(|a, b| {
        a.kind == b.kind
            && a.candidate_domain == b.candidate_domain
            && a.target_domain == b.target_domain
            && a.edit_distance == b.edit_distance
    });
    findings
}

/// Prevent log/alert spam by snipping crazy-long raw tokens.
fn safe_snip(s: &str) -> String {
    const MAX: usize = 80;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}…", &s[..MAX])
    }
}
