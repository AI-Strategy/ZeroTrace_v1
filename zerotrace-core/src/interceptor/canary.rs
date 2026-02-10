use uuid::Uuid;

/// Default prefix used for generated canary tokens.
pub const DEFAULT_CANARY_PREFIX: &str = "ZT-CANARY";

/// Generates a new canary token using the default prefix.
pub fn generate_canary() -> String {
    generate_canary_with_prefix(DEFAULT_CANARY_PREFIX)
}

/// Generates a new canary token using a custom prefix.
///
/// Example output: `ZT-CANARY-550e8400-e29b-41d4-a716-446655440000`
pub fn generate_canary_with_prefix(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

/// A detected canary token and the byte offsets where it appeared in `content`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryHit<'a> {
    pub token: &'a str,
    pub positions: Vec<usize>,
}

/// Checks whether any known canary tokens are present in the output.
///
/// In a real system, you'd typically validate against a datastore of active canaries and
/// record an audit event when a hit occurs.
///
/// Returns a list of `CanaryHit` entries (token + all positions where it appeared).
pub fn check_for_exfiltration<'a, T>(
    content: &str,
    active_canaries: &'a [T],
) -> Vec<CanaryHit<'a>>
where
    T: AsRef<str> + 'a, // Removed the lifetime bound on T itself, bound refer to reference
{
    let mut hits = Vec::new();

    for canary in active_canaries {
        let token = canary.as_ref();
        let positions: Vec<usize> = content
            .match_indices(token)
            .map(|(idx, _)| idx)
            .collect();

        if !positions.is_empty() {
            hits.push(CanaryHit { token, positions });
        }
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn detects_canary_and_positions() {
        let c1 = "ZT-CANARY-1111";
        let c2 = "ZT-CANARY-2222";
        let content = format!("ok {c1} nope {c2} again {c1}");

        let tokens = vec![c1.to_string(), c2.to_string()];
        let hits = check_for_exfiltration(&content, &tokens);
        assert_eq!(hits.len(), 2);

        let hit1 = hits.iter().find(|h| h.token == c1).unwrap();
        assert_eq!(hit1.positions.len(), 2);

        let hit2 = hits.iter().find(|h| h.token == c2).unwrap();
        assert_eq!(hit2.positions.len(), 1);
    }

    #[test]
    fn test_generation_formats() {
        let default_token = generate_canary();
        assert!(default_token.starts_with("ZT-CANARY-"));
        
        let custom_token = generate_canary_with_prefix("SECRET-OPS");
        assert!(custom_token.starts_with("SECRET-OPS-"));
    }

    #[test]
    fn test_no_hits() {
        let content = "nothing to see here";
        let hits = check_for_exfiltration(&content, &["ZT-CANARY-123"]);
        assert!(hits.is_empty());
    }
}
