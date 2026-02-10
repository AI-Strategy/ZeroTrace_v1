// src/interceptor/v30_context_stitch.rs
// Vector 30: Context-Stitch / Soft Leak
// Defense: Tracks "Information Gain" across multiple turns to detect metadata reconstruction.

use std::collections::HashSet;

pub struct ContextStitchGuard {
    // Tracks unique "high-entropy" tokens revealed across the session
    revealed_tokens: HashSet<String>,
    max_tokens: usize,
}

impl ContextStitchGuard {
    pub fn new(max_tokens: usize) -> Self {
        Self {
            revealed_tokens: HashSet::new(),
            max_tokens,
        }
    }

    /// Inspects a response for new metadata tokens.
    /// Returns true if the cumulative exposure exceeds the safety threshold.
    pub fn check_exposure(&mut self, response_tokens: Vec<&str>) -> bool {
        for token in response_tokens {
            self.revealed_tokens.insert(token.to_string());
        }

        self.revealed_tokens.len() > self.max_tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stitch_detection() {
        let mut guard = ContextStitchGuard::new(5); // Increased to 5 to allow Turn 2

        // Turn 1: "The file is..."
        assert!(!guard.check_exposure(vec!["file", "is"]));

        // Turn 2: "...located in..."
        assert!(!guard.check_exposure(vec!["located", "in"]));

        // Turn 3: ".../private/keys" (Cumulative count > 3)
        // Set info: {"file", "is", "located", "in", "private", "keys"} -> Size 6
        assert!(guard.check_exposure(vec!["private", "keys"]));
    }
}
