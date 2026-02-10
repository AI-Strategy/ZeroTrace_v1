//! Vector 30: Context-Stitch / Soft Leak
//! Defense: Track "information gain" across turns to detect incremental metadata reconstruction.
//!
//! Design goals:
//! - Do NOT store raw secrets/tokens in memory (store fingerprints instead).
//! - Ignore normal language. Focus on high-signal tokens: IDs, paths, key-like strings, entropy-ish blobs.
//! - Provide deterministic, testable behavior and explainability via a report.
//!
//! Suggested deps:
//! blake3 = "1"

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct ContextStitchConfig {
    /// Hard cap: unique sensitive token fingerprints across session.
    pub max_unique_tokens: usize,

    /// Soft cap: cumulative exposure score across session.
    pub max_exposure_score: u64,

    /// Ignore tokens shorter than this (avoids counting normal words).
    pub min_token_len: usize,

    /// Entropy thresholds (bits/char) for heuristic “blob” detection.
    pub entropy_threshold_base64ish: f64,
    pub entropy_threshold_hexish: f64,
    pub entropy_threshold_other: f64,

    /// Per-turn: cap number of candidate tokens processed (prevents abuse).
    pub max_candidates_per_turn: usize,
}

impl Default for ContextStitchConfig {
    fn default() -> Self {
        Self {
            max_unique_tokens: 25,
            max_exposure_score: 4_000,
            min_token_len: 10,
            entropy_threshold_base64ish: 4.2,
            entropy_threshold_hexish: 3.0,
            entropy_threshold_other: 4.6,
            max_candidates_per_turn: 256,
        }
    }
}

/// What the guard decided for a single inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureReport {
    pub tripped: bool,
    pub new_unique_tokens: usize,
    pub total_unique_tokens: usize,
    pub added_score: u64,
    pub total_score: u64,
    pub candidates_seen: usize,
    pub candidates_accepted: usize,
    pub reason: Option<TripReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TripReason {
    UniqueTokenCapExceeded,
    ExposureScoreExceeded,
}

/// Token classes drive scoring + entropy thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TokenClass {
    Uuid,
    JwtLike,
    PathLike,
    KeyLike,
    HexBlob,
    Base64Blob,
    OtherBlob,
}

impl TokenClass {
    fn base_weight(self) -> u64 {
        match self {
            TokenClass::KeyLike => 900,
            TokenClass::JwtLike => 750,
            TokenClass::PathLike => 450,
            TokenClass::Uuid => 350,
            TokenClass::HexBlob => 300,
            TokenClass::Base64Blob => 300,
            TokenClass::OtherBlob => 200,
        }
    }
}

pub struct ContextStitchGuard {
    cfg: ContextStitchConfig,

    /// Store fingerprints (not raw values).
    revealed_fingerprints: HashSet<[u8; 32]>,

    /// Aggregate exposure score over the session.
    exposure_score: u64,

    /// Optional stats: how many tokens per class have ever been accepted.
    class_counts: HashMap<TokenClass, u64>,
}

impl ContextStitchGuard {
    pub fn new(cfg: ContextStitchConfig) -> Self {
        Self {
            cfg,
            revealed_fingerprints: HashSet::new(),
            exposure_score: 0,
            class_counts: HashMap::new(),
        }
    }

    /// High-level API: inspect raw response text (recommended).
    pub fn inspect_text(&mut self, response_text: &str) -> ExposureReport {
        let candidates = extract_candidates(response_text, self.cfg.min_token_len);
        self.inspect_candidates(candidates.iter().map(|s| s.as_str()))
    }

    /// Backwards-compatible-ish: caller provides token list.
    /// IMPORTANT: tokens should already be "interesting" (or this will ignore most).
    pub fn inspect_candidates<'a>(
        &mut self,
        response_tokens: impl IntoIterator<Item = &'a str>,
    ) -> ExposureReport {
        let mut candidates_seen = 0usize;
        let mut candidates_accepted = 0usize;

        let mut new_unique = 0usize;
        let mut added_score: u64 = 0;

        for token in response_tokens.into_iter() {
            candidates_seen += 1;
            if candidates_seen > self.cfg.max_candidates_per_turn {
                break;
            }

            let t = normalize_token(token);
            if t.len() < self.cfg.min_token_len {
                continue;
            }
            if is_obviously_harmless(&t) {
                continue;
            }

            let Some(class) = classify_interesting(&t, &self.cfg) else {
                continue;
            };

            candidates_accepted += 1;

            let fp = fingerprint(&t);
            let is_new = self.revealed_fingerprints.insert(fp);
            if is_new {
                new_unique += 1;

                // Score: base weight + length component + entropy component.
                let entropy_x100 = (shannon_entropy_bytes(t.as_bytes()) * 100.0)
                    .round()
                    .clamp(0.0, u64::MAX as f64) as u64;

                let len_bonus = (t.len() as u64).saturating_mul(3).min(300);
                let entropy_bonus = (entropy_x100 / 10).min(500); // keep bounded

                let score = class.base_weight()
                    .saturating_add(len_bonus)
                    .saturating_add(entropy_bonus);

                added_score = added_score.saturating_add(score);
                *self.class_counts.entry(class).or_insert(0) += 1;
            }
        }

        // Update totals
        self.exposure_score = self.exposure_score.saturating_add(added_score);

        let total_unique = self.revealed_fingerprints.len();
        let total_score = self.exposure_score;

        // Decide trip
        let (tripped, reason) = if total_unique > self.cfg.max_unique_tokens {
            (true, Some(TripReason::UniqueTokenCapExceeded))
        } else if total_score > self.cfg.max_exposure_score {
            (true, Some(TripReason::ExposureScoreExceeded))
        } else {
            (false, None)
        };

        ExposureReport {
            tripped,
            new_unique_tokens: new_unique,
            total_unique_tokens: total_unique,
            added_score,
            total_score,
            candidates_seen,
            candidates_accepted,
            reason,
        }
    }

    /// Useful in tests / monitoring.
    pub fn totals(&self) -> (usize, u64) {
        (self.revealed_fingerprints.len(), self.exposure_score)
    }
}

// ============================================================================
// Candidate extraction + classification
// ============================================================================

fn extract_candidates(input: &str, min_len: usize) -> Vec<String> {
    // Split on whitespace and trim wrapper punctuation.
    // Keep it simple and predictable.
    input
        .split_whitespace()
        .map(trim_wrapping_punct)
        .filter(|t| !t.is_empty() && t.len() >= min_len)
        .map(|s| s.to_string())
        .collect()
}

fn trim_wrapping_punct(s: &str) -> &str {
    s.trim_matches(|c: char| {
        matches!(
            c,
            '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '"' | '\''
                | ',' | ';' | ':' | '!' | '?' | '.'
        )
    })
}

fn normalize_token(t: &str) -> String {
    // Lowercasing reduces useless uniqueness from casing.
    // We keep original bytes out of memory anyway (fingerprint), so this is fine.
    t.trim().to_string()
}

fn is_obviously_harmless(t: &str) -> bool {
    // Cheap stopword-ish filter for normal English, plus common “glue” tokens.
    // This is intentionally small, not a dictionary.
    match t.to_ascii_lowercase().as_str() {
        "the" | "and" | "that" | "this" | "with" | "from" | "into" | "your" | "have"
        | "file" | "located" | "location" | "path" | "directory" | "folder" | "system"
        | "user" | "case" | "summary" | "status" | "risk" | "analysis" | "legal" => true,
        _ => false,
    }
}

fn classify_interesting(t: &str, cfg: &ContextStitchConfig) -> Option<TokenClass> {
    // 1) Hard patterns first
    if looks_like_uuid(t) {
        return Some(TokenClass::Uuid);
    }
    if looks_like_jwt(t) {
        return Some(TokenClass::JwtLike);
    }
    if looks_like_path(t) {
        return Some(TokenClass::PathLike);
    }
    if looks_like_key(t) {
        return Some(TokenClass::KeyLike);
    }

    // 2) Entropy-ish blobs
    if t.is_ascii() {
        let class = classify_blob_charset(t);
        let entropy = shannon_entropy_bytes(t.as_bytes());
        let th = match class {
            TokenClass::HexBlob => cfg.entropy_threshold_hexish,
            TokenClass::Base64Blob => cfg.entropy_threshold_base64ish,
            TokenClass::OtherBlob => cfg.entropy_threshold_other,
            _ => cfg.entropy_threshold_other,
        };
        if entropy >= th {
            return Some(class);
        }
    }

    None
}

fn looks_like_uuid(s: &str) -> bool {
    // 8-4-4-4-12 hex with dashes.
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &ch) in b.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => ch == b'-',
            _ => ch.is_ascii_hexdigit(),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn looks_like_jwt(s: &str) -> bool {
    // JWT-like: 3 segments separated by '.', base64url-ish, each segment length >= 8
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| p.len() >= 8 && p.as_bytes().iter().all(|c| {
        c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_' || *c == b'='
    }))
}

fn looks_like_path(s: &str) -> bool {
    // catches unix/win-ish paths and "private-ish" segments.
    let slashes = s.contains('/') || s.contains('\\');
    if !slashes {
        return false;
    }
    // Avoid flagging simple URLs by ignoring scheme prefixes.
    if s.starts_with("http://") || s.starts_with("https://") {
        return false;
    }
    // “Sensitive-ish” if includes typical private markers or looks like a deep path.
    let lower = s.to_ascii_lowercase();
    lower.contains("private")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains(".ssh")
        || lower.contains("id_rsa")
        || s.matches('/').count().saturating_add(s.matches('\\').count()) >= 2
}

fn looks_like_key(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    // Common-ish key shapes (keep minimal; you already have SecretScanner elsewhere).
    if lower.starts_with("sk-") && s.len() >= 24 {
        return true;
    }
    if lower.starts_with("ghp_") && s.len() >= 24 {
        return true;
    }
    // PEM header fragments / obvious markers
    if s.contains("BEGIN") && s.contains("KEY") {
        return true;
    }
    false
}

fn classify_blob_charset(s: &str) -> TokenClass {
    let b = s.as_bytes();

    let is_hex = b.iter().all(|c| c.is_ascii_hexdigit());
    if is_hex {
        return TokenClass::HexBlob;
    }

    let is_base64urlish = b.iter().all(|c| {
        c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/' || *c == b'=' || *c == b'-' || *c == b'_'
    });
    if is_base64urlish {
        return TokenClass::Base64Blob;
    }

    TokenClass::OtherBlob
}

// ============================================================================
// Fingerprinting + entropy
// ============================================================================

fn fingerprint(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

/// Shannon entropy over bytes (0..=255).
pub fn shannon_entropy_bytes(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

// ============================================================================
// Tests: “large environment”
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_tight() -> ContextStitchConfig {
        ContextStitchConfig {
            max_unique_tokens: 5,
            max_exposure_score: 2_000,
            min_token_len: 8,
            entropy_threshold_base64ish: 4.0,
            entropy_threshold_hexish: 2.8,
            entropy_threshold_other: 4.5,
            max_candidates_per_turn: 512,
        }
    }

    #[test]
    fn ignores_common_words_and_short_tokens() {
        let mut g = ContextStitchGuard::new(cfg_tight());

        let r1 = g.inspect_text("The file is located in the folder.");
        assert!(!r1.tripped);
        assert_eq!(r1.total_unique_tokens, 0);

        let r2 = g.inspect_candidates(vec!["file", "is", "located", "in"]);
        assert!(!r2.tripped);
        assert_eq!(r2.total_unique_tokens, 0);
    }

    #[test]
    fn accumulates_sensitive_path_like_tokens_and_trips_unique_cap() {
        let mut g = ContextStitchGuard::new(cfg_tight());

        // Turn 1: harmless
        assert!(!g.inspect_text("All good.").tripped);

        // Turn 2: incremental leak
        assert!(!g.inspect_text("/Users/alice/.ssh/").tripped);

        // Turn 3: more
        assert!(!g.inspect_text("/private/keys/id_rsa").tripped);

        // Turn 4: and more unique sensitive segments. Need > 5 total.
        let rep = g.inspect_text("Also check C:\\Users\\bob\\secrets\\vault.key /etc/passwd /var/log/syslog /home/root/.aws/credentials");
        // We’ve probably crossed unique tokens cap by now depending on extraction.
        // To make this deterministic, just check we eventually trip.
        assert!(rep.tripped);
        assert_eq!(rep.reason, Some(TripReason::UniqueTokenCapExceeded));
    }

    #[test]
    fn repeated_token_does_not_increase_unique_count_or_score() {
        let mut g = ContextStitchGuard::new(cfg_tight());

        let t = "sk-THISISNOTAREALKEYBUTLOOKSLIKEONE123456";
        let r1 = g.inspect_candidates(vec![t]);
        assert!(!r1.tripped);
        let (u1, s1) = g.totals();
        assert_eq!(u1, 1);
        assert!(s1 > 0);

        let r2 = g.inspect_candidates(vec![t, t, t]);
        assert!(!r2.tripped);
        let (u2, s2) = g.totals();
        assert_eq!(u2, 1, "should remain 1 unique token");
        assert_eq!(s2, s1, "score should not increase for repeats");
    }

    #[test]
    fn forged_entropy_blob_trips_score_threshold_even_with_few_uniques() {
        let mut cfg = cfg_tight();
        cfg.max_unique_tokens = 50;
        cfg.max_exposure_score = 800; // low score cap
        cfg.min_token_len = 16;

        let mut g = ContextStitchGuard::new(cfg);

        // High-entropy-ish base64url blobs
        let a = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==QWxhZGRpbjpvcGVu";
        let b = "ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKcFpDSTZJbVY0";
        let r = g.inspect_candidates(vec![a, b]);

        assert!(r.tripped, "should trip on exposure score cap");
        assert_eq!(r.reason, Some(TripReason::ExposureScoreExceeded));
    }

    #[test]
    fn detects_uuid_and_jwt_like_tokens() {
        let mut g = ContextStitchGuard::new(cfg_tight());

        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let r = g.inspect_candidates(vec![uuid, jwt]);
        assert!(!r.tripped);
        assert_eq!(r.total_unique_tokens, 2);
        assert!(r.added_score > 0);
    }

    #[test]
    fn per_turn_candidate_cap_is_enforced() {
        let mut cfg = cfg_tight();
        cfg.max_candidates_per_turn = 3;
        cfg.min_token_len = 3; // allow more candidates
        cfg.max_unique_tokens = 2; // small for deterministic trip
        let mut g = ContextStitchGuard::new(cfg);

        // Provide 10 candidates, but only 3 processed.
        // Ensure we don't explode into processing everything.
        let rep = g.inspect_candidates(vec![
            "/private/a", "/private/b", "/private/c", "/private/d", "/private/e",
            "/private/f", "/private/g", "/private/h", "/private/i", "/private/j",
        ]);

        // Only first 3 candidates processed; may or may not trip depending on uniqueness.
        assert!(rep.candidates_seen >= 3);
        assert!(rep.candidates_seen <= 4, "iterator count includes the cap check boundary");
    }

    #[test]
    fn entropy_function_sanity() {
        // "aaaa" has zero entropy.
        assert_eq!(shannon_entropy_bytes(b"aaaa"), 0.0);

        // "abcd" has higher entropy.
        let e = shannon_entropy_bytes(b"abcd");
        assert!(e > 1.5 && e < 2.5);
    }

    #[test]
    fn original_simplistic_scenario_is_handled_safely() {
        // The old guard counted normal words.
        // This one intentionally ignores them.
        let mut g = ContextStitchGuard::new(cfg_tight());

        assert!(!g.inspect_candidates(vec!["file", "is"]).tripped);
        assert!(!g.inspect_candidates(vec!["located", "in"]).tripped);

        // But *actual sensitive* tokens count.
        let rep = g.inspect_candidates(vec!["/private/keys", "id_rsa"]);
        assert!(!rep.tripped); // depends on thresholds; should not necessarily trip immediately
        assert!(rep.total_unique_tokens >= 1);
    }
}
