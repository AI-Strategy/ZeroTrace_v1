use std::collections::{HashMap, HashSet};
use thiserror::Error;
use uuid::Uuid;
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Default prefix used for generated canary tokens.
pub const DEFAULT_CANARY_PREFIX: &str = "ZT-CANARY";

/// Canary token format: `{PREFIX}-{UUID}`
/// Example: `ZT-CANARY-550e8400-e29b-41d4-a716-446655440000`
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CanaryError {
    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),

    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryHit {
    pub token: String,
    /// Byte offsets where it appeared in `content`.
    pub positions: Vec<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExfiltrationStats {
    pub scanned_bytes: usize,
    pub active_canaries_seen: usize,
    pub active_canaries_invalid: usize,
    pub unique_tokens_hit: usize,
    pub total_hits: usize,
    pub hits_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfiltrationOutcome {
    pub hits: Vec<CanaryHit>,
    pub stats: ExfiltrationStats,
}

#[derive(Debug, Clone)]
pub struct ExfiltrationScanConfig {
    /// Hard cap to keep scanning bounded.
    pub max_content_bytes: usize,
    /// Hard cap on how many active canaries we’ll consider.
    pub max_active_canaries: usize,
    /// Max number of positions we record per token.
    pub max_hits_per_token: usize,
    /// Max number of total positions recorded across all tokens.
    pub max_total_hits: usize,
    /// If true, invalid active canaries fail the scan (instead of being ignored).
    pub strict_active_list: bool,
}

impl Default for ExfiltrationScanConfig {
    fn default() -> Self {
        Self {
            max_content_bytes: 256 * 1024,     // 256KB
            max_active_canaries: 10_000,       // plenty
            max_hits_per_token: 256,           // per token
            max_total_hits: 10_000,            // overall
            strict_active_list: false,
        }
    }
}

/// Generates a new canary token using the default prefix.
///
/// This preserves your old ergonomics.
pub fn generate_canary() -> String {
    // Default prefix is trusted (compile-time). If someone changes it to garbage, that’s on them.
    generate_canary_with_prefix(DEFAULT_CANARY_PREFIX)
}

/// Generates a new canary token using a custom prefix.
///
/// If prefix is invalid, we do **not** echo it; we fall back to DEFAULT_CANARY_PREFIX.
/// (You can use `try_generate_canary_with_prefix` if you want strict behavior.)
pub fn generate_canary_with_prefix(prefix: &str) -> String {
    match try_generate_canary_with_prefix(prefix) {
        Ok(t) => t,
        Err(_) => format!("{DEFAULT_CANARY_PREFIX}-{}", Uuid::new_v4()),
    }
}

/// Strict version: validates prefix and returns an error if invalid.
pub fn try_generate_canary_with_prefix(prefix: &str) -> Result<String, CanaryError> {
    let prefix = normalize_and_validate_prefix(prefix)?;
    Ok(format!("{prefix}-{}", Uuid::new_v4()))
}

// -----------------------------------------------------------------------------
// Session Binding (Responsible Unhinged Mode)
// -----------------------------------------------------------------------------

/// Embeds a 32-bit Session/User ID into the Canary UUID with an HMAC signature.
/// Layout (16 bytes): [SessionID: 4][Salt: 4][HMAC: 8]
/// 
/// This results in a valid v4-like UUID that passes the scanner checks,
/// but allows you to attribute the leak to a specific user/session.
pub fn generate_signed_canary(prefix: &str, session_id: u32, secret_key: &[u8]) -> Result<String, CanaryError> {
    let prefix = normalize_and_validate_prefix(prefix)?;
    
    // 1. Generate 4 bytes of random salt
    let salt = Uuid::new_v4().as_bytes()[0..4].to_vec(); // Just use UUID gen for entropy
    
    // 2. Prepare payload for signing: [SessionID (be)][Salt]
    let mut payload = session_id.to_be_bytes().to_vec();
    payload.extend_from_slice(&salt);
    
    // 3. Compute HMAC(Payload, Key)
    let mut mac = HmacSha256::new_from_slice(secret_key)
        .map_err(|_| CanaryError::InvalidTokenFormat("HMAC key invalid".to_string()))?;
    mac.update(&payload);
    let signature = mac.finalize().into_bytes();
    
    // 4. Construct synthetic UUID bytes: [SessionID][Salt][Sig 8 bytes]
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes[0..4].copy_from_slice(&payload[0..4]);   // SessionID
    uuid_bytes[4..8].copy_from_slice(&salt);             // Salt
    uuid_bytes[8..16].copy_from_slice(&signature[0..8]); // Truncated HMAC
    
    // 5. Create Uuid from bytes. 
    // Note: This UUID will NOT be compliant with RFC 4122 v4 (random) or v1 (time),
    // but it will parse as a valid UUID string, which is what we need for the scanner.
    let uuid = Uuid::from_bytes(uuid_bytes);
    
    Ok(format!("{prefix}-{uuid}"))
}

/// Extracts the Session ID from a signed canary token if the signature is valid.
pub fn extract_session_from_canary(token: &str, secret_key: &[u8]) -> Option<u32> {
    let (_, uuid) = parse_and_canonicalize_token(token).ok()?;
    let bytes = uuid.as_bytes();
    
    // 1. Extract components
    let session_bytes = &bytes[0..4];
    let salt = &bytes[4..8];
    let stored_sig = &bytes[8..16];
    
    // 2. Recompute HMAC
    let mut payload = session_bytes.to_vec();
    payload.extend_from_slice(salt);
    
    let mut mac = HmacSha256::new_from_slice(secret_key).ok()?;
    mac.update(&payload);
    let calculated_sig = mac.finalize().into_bytes();
    
    // 3. Compare Truncated HMAC (Constant time ideally, but slice comparison in Rust is optimized)
    if &calculated_sig[0..8] == stored_sig {
        Some(u32::from_be_bytes(session_bytes.try_into().ok()?))
    } else {
        None
    }
}

/// Checks whether any known canary tokens are present in the content.
///
/// Efficient approach (no new deps):
/// - Parse + index active canaries by prefix.
/// - For each unique prefix, scan content for `{prefix}-` and attempt to parse a UUID immediately after.
/// - Only count a hit if the exact `{prefix}-{uuid}` is in the active set.
///
/// Returns hits + stats. Use `check_for_exfiltration` for the simple legacy return type.
pub fn check_for_exfiltration_with_config(
    content: &str,
    active_canaries: &[impl AsRef<str>],
    cfg: &ExfiltrationScanConfig,
) -> Result<ExfiltrationOutcome, CanaryError> {
    if content.as_bytes().len() > cfg.max_content_bytes {
        // Don’t “helpfully” scan gigantic blobs in a security component.
        // Caller can chunk if they want.
        return Ok(ExfiltrationOutcome {
            hits: vec![],
            stats: ExfiltrationStats {
                scanned_bytes: cfg.max_content_bytes,
                ..Default::default()
            },
        });
    }

    let mut stats = ExfiltrationStats {
        scanned_bytes: content.as_bytes().len(),
        active_canaries_seen: 0,
        ..Default::default()
    };

    // Build active index: prefix -> set(tokens)
    let mut index: HashMap<String, HashSet<String>> = HashMap::new();

    for (i, canary) in active_canaries.iter().take(cfg.max_active_canaries).enumerate() {
        let raw = canary.as_ref();
        stats.active_canaries_seen = i + 1;

        match parse_and_canonicalize_token(raw) {
            Ok((prefix, uuid)) => {
                let token = format!("{prefix}-{uuid}");
                index.entry(prefix).or_default().insert(token);
            }
            Err(e) => {
                stats.active_canaries_invalid += 1;
                if cfg.strict_active_list {
                    return Err(e);
                }
            }
        }
    }

    if index.is_empty() {
        return Ok(ExfiltrationOutcome {
            hits: vec![],
            stats,
        });
    }

    // Scan content by prefix needles.
    let mut hits_map: HashMap<String, Vec<usize>> = HashMap::new();
    let mut total_positions = 0usize;

    // Stable-ish: longer prefixes first reduces accidental scanning work when prefixes overlap.
    let mut prefixes: Vec<String> = index.keys().cloned().collect();
    prefixes.sort_by(|a, b| b.len().cmp(&a.len()));

    for prefix in prefixes {
        let needle = format!("{prefix}-");
        let Some(active_set) = index.get(&prefix) else { continue };

        let mut search_from = 0usize;
        while let Some(rel) = content[search_from..].find(&needle) {
            let start = search_from + rel;

            // Candidate token must have UUID right after the needle.
            let uuid_start = start + needle.len();
            let uuid_end = uuid_start + 36; // UUID string length

            if uuid_end > content.len() {
                break; // no room for a UUID
            }

            // Safety: UUID is ASCII, slicing on byte boundary is fine here.
            let uuid_str = &content[uuid_start..uuid_end];
            let Ok(uuid) = Uuid::parse_str(uuid_str) else {
                search_from = start + 1;
                continue;
            };

            let candidate = format!("{prefix}-{uuid}");
            if active_set.contains(&candidate) {
                let positions = hits_map.entry(candidate).or_default();

                if positions.len() < cfg.max_hits_per_token && total_positions < cfg.max_total_hits {
                    positions.push(start);
                    total_positions += 1;
                } else {
                    stats.hits_truncated = true;
                }

                if total_positions >= cfg.max_total_hits {
                    stats.hits_truncated = true;
                    break;
                }
            }

            search_from = start + 1;
        }

        if total_positions >= cfg.max_total_hits {
            break;
        }
    }

    let mut hits: Vec<CanaryHit> = hits_map
        .into_iter()
        .filter_map(|(token, positions)| {
            if positions.is_empty() {
                None
            } else {
                Some(CanaryHit { token, positions })
            }
        })
        .collect();

    // Deterministic ordering helps tests + audit logs.
    hits.sort_by(|a, b| a.token.cmp(&b.token));

    stats.unique_tokens_hit = hits.len();
    stats.total_hits = hits.iter().map(|h| h.positions.len()).sum();

    Ok(ExfiltrationOutcome { hits, stats })
}

/// Legacy convenience: returns just the hits (no stats), never errors.
/// Invalid active canaries are ignored.
pub fn check_for_exfiltration(content: &str, active_canaries: &[impl AsRef<str>]) -> Vec<CanaryHit> {
    let cfg = ExfiltrationScanConfig::default();
    match check_for_exfiltration_with_config(content, active_canaries, &cfg) {
        Ok(out) => out.hits,
        Err(_) => vec![],
    }
}

// -----------------------------------------------------------------------------
// Parsing/validation helpers
// -----------------------------------------------------------------------------

fn normalize_and_validate_prefix(prefix: &str) -> Result<String, CanaryError> {
    let p = prefix.trim();
    if p.is_empty() {
        return Err(CanaryError::InvalidPrefix("empty prefix".to_string()));
    }
    if p.len() > 32 {
        return Err(CanaryError::InvalidPrefix("prefix too long (max 32)".to_string()));
    }

    // Allow uppercase/lowercase, digits, underscore, hyphen. No whitespace, no colon, no fun.
    if !p.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
    }) {
        return Err(CanaryError::InvalidPrefix(
            "prefix must be [A-Za-z0-9_-] only".to_string(),
        ));
    }

    Ok(p.to_string())
}

/// Parses `{prefix}-{uuid}` and returns canonical `(prefix, uuid)`.
fn parse_and_canonicalize_token(token: &str) -> Result<(String, Uuid), CanaryError> {
    let t = token.trim();
    if t.len() < 1 + 36 {
        return Err(CanaryError::InvalidTokenFormat("too short".to_string()));
    }

    // UUID is last 36 chars. Character before it must be '-'.
    if t.len() < 37 {
        return Err(CanaryError::InvalidTokenFormat("too short for uuid".to_string()));
    }
    let uuid_str = &t[t.len() - 36..];
    let dash_idx = t.len() - 37;
    if &t[dash_idx..dash_idx + 1] != "-" {
        return Err(CanaryError::InvalidTokenFormat(
            "missing '-' before uuid".to_string(),
        ));
    }

    let prefix = &t[..dash_idx];
    let prefix = normalize_and_validate_prefix(prefix)?;
    let uuid = Uuid::parse_str(uuid_str).map_err(|_| {
        CanaryError::InvalidTokenFormat("invalid uuid".to_string())
    })?;

    Ok((prefix, uuid))
}

/// Canonicalizes token into `{prefix}-{uuid}` with validated prefix.
fn parse_and_canonicalize_token_string(token: &str) -> Result<String, CanaryError> {
    let (p, u) = parse_and_canonicalize_token(token)?;
    Ok(format!("{p}-{u}"))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_default_prefix() {
        let t = generate_canary();
        assert!(t.starts_with("ZT-CANARY-"));
        let canon = parse_and_canonicalize_token_string(&t).unwrap();
        assert_eq!(canon, t);
    }

    #[test]
    fn generation_custom_prefix_valid() {
        let t = try_generate_canary_with_prefix("SECRET_OPS").unwrap();
        assert!(t.starts_with("SECRET_OPS-"));
        assert!(Uuid::parse_str(&t[t.len() - 36..]).is_ok());
    }

    #[test]
    fn generation_custom_prefix_invalid_falls_back_in_non_strict() {
        let t = generate_canary_with_prefix("bad prefix with spaces");
        assert!(t.starts_with("ZT-CANARY-"));
    }

    #[test]
    fn generation_custom_prefix_invalid_strict_errors() {
        let err = try_generate_canary_with_prefix("bad prefix with spaces").unwrap_err();
        assert!(matches!(err, CanaryError::InvalidPrefix(_)));
    }

    #[test]
    fn parse_token_rejects_missing_dash_before_uuid() {
        let bogus = format!("ZT-CANARY{}{}", "-", "not-a-uuid");
        let err = parse_and_canonicalize_token(&bogus).unwrap_err();
        assert!(matches!(err, CanaryError::InvalidTokenFormat(_)));
    }

    #[test]
    fn detects_canaries_and_positions_multiple_hits() {
        let c1 = "ZT-CANARY-550e8400-e29b-41d4-a716-446655440000";
        let c2 = "ZT-CANARY-123e4567-e89b-12d3-a456-426614174000";
        let content = format!("ok {c1} nope {c2} again {c1}.");

        let tokens = vec![c1.to_string(), c2.to_string()];
        let out = check_for_exfiltration_with_config(&content, &tokens, &Default::default()).unwrap();
        assert_eq!(out.hits.len(), 2);
        assert_eq!(out.stats.unique_tokens_hit, 2);

        let hit1 = out.hits.iter().find(|h| h.token == c1).unwrap();
        assert_eq!(hit1.positions.len(), 2);

        let hit2 = out.hits.iter().find(|h| h.token == c2).unwrap();
        assert_eq!(hit2.positions.len(), 1);
    }

    #[test]
    fn no_hits_returns_empty() {
        let content = "nothing to see here";
        let hits = check_for_exfiltration(content, &["ZT-CANARY-550e8400-e29b-41d4-a716-446655440000"]);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_invalid_active_canaries_by_default() {
        let content = "hello ZT-CANARY-550e8400-e29b-41d4-a716-446655440000";
        let active = vec![
            "not-a-token".to_string(),
            "ZT-CANARY-550e8400-e29b-41d4-a716-446655440000".to_string(),
        ];

        let out = check_for_exfiltration_with_config(content, &active, &Default::default()).unwrap();
        assert_eq!(out.stats.active_canaries_invalid, 1);
        assert_eq!(out.hits.len(), 1);
    }

    #[test]
    fn strict_active_list_errors_on_invalid_canary() {
        let content = "hello";
        let active = vec!["not-a-token".to_string()];

        let mut cfg = ExfiltrationScanConfig::default();
        cfg.strict_active_list = true;

        let err = check_for_exfiltration_with_config(content, &active, &cfg).unwrap_err();
        assert!(matches!(err, CanaryError::InvalidTokenFormat(_) | CanaryError::InvalidPrefix(_)));
    }

    #[test]
    fn supports_multiple_prefixes() {
        let c1 = "ZT-CANARY-550e8400-e29b-41d4-a716-446655440000";
        let c2 = "SECRET-OPS-123e4567-e89b-12d3-a456-426614174000";
        let content = format!("X {c1} Y {c2} Z");

        let active = vec![c1.to_string(), c2.to_string()];
        let out = check_for_exfiltration_with_config(&content, &active, &Default::default()).unwrap();
        assert_eq!(out.hits.len(), 2);
    }

    #[test]
    fn does_not_false_positive_on_almost_token() {
        let real = "ZT-CANARY-550e8400-e29b-41d4-a716-446655440000";
        let almost = "ZT-CANARY-550e8400-e29b-41d4-a716-44665544000X"; // one char off
        let content = format!("real:{real} almost:{almost}");

        let active = vec![real.to_string()];
        let out = check_for_exfiltration_with_config(&content, &active, &Default::default()).unwrap();
        assert_eq!(out.hits.len(), 1);
        assert_eq!(out.hits[0].token, real);
    }

    #[test]
    fn hit_limits_truncate() {
        let c1 = "ZT-CANARY-550e8400-e29b-41d4-a716-446655440000";
        let content = format!("{c1} {c1} {c1} {c1} {c1}");

        let active = vec![c1.to_string()];
        let mut cfg = ExfiltrationScanConfig::default();
        cfg.max_hits_per_token = 2;
        cfg.max_total_hits = 2;

        let out = check_for_exfiltration_with_config(&content, &active, &cfg).unwrap();
        assert_eq!(out.hits.len(), 1);
        assert_eq!(out.hits[0].positions.len(), 2);
        assert!(out.stats.hits_truncated);
    }

    #[test]
    fn preserves_byte_offsets_with_unicode_around() {
        // Unicode before token shifts byte offsets; we want byte offsets, not char indices.
        let c1 = "ZT-CANARY-550e8400-e29b-41d4-a716-446655440000";
        let content = format!("☃☃ {c1} end");
        let active = vec![c1.to_string()];

        let out = check_for_exfiltration_with_config(&content, &active, &Default::default()).unwrap();
        let hit = &out.hits[0];

        // Verify by slicing at byte offset.
        let pos = hit.positions[0];
        assert_eq!(&content[pos..pos + c1.len()], c1);
    }
    
    #[test]
    fn test_signed_canary_round_trip() {
        let key = b"super-secret-key-123";
        let session_id = 1337_u32;
        let prefix = "ZT-SESS";
        
        let token = generate_signed_canary(prefix, session_id, key).unwrap();
        println!("Signed Token: {}", token);
        
        // Ensure it looks like a normal canary
        assert!(token.starts_with("ZT-SESS-"));
        
        // Extract
        let extracted = extract_session_from_canary(&token, key);
        assert_eq!(extracted, Some(session_id));
    }
    
    #[test]
    fn test_tampered_canary_fails() {
        let key = b"super-secret-key-123";
        let session_id = 999_u32;
        let token = generate_signed_canary("ZT-TEST", session_id, key).unwrap();
        
        // Tamper with the session ID part of the UUID string
        // UUID format: 8-4-4-4-12 hex chars
        // ZT-TEST-000003e7-.... (0x3e7 = 999)
        // Let's change 3e7 to 3e8
        // Need to be careful. session_id is first 4 bytes.
        // 999 = 0x000003E7
        // UUID str starts with 000003e7-
        
        let tampered = token.replace("000003e7", "000003e8");
        
        let extracted = extract_session_from_canary(&tampered, key);
        assert_eq!(extracted, None);
    }
}
