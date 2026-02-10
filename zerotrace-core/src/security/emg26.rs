use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use lazy_static::lazy_static;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenSmugglingError {
    #[error("Hidden content violation within Base64: {0}")]
    HiddenContentViolation(String),
    #[error("Base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

pub struct TokenSmugglingGuard;

lazy_static! {
    // A heuristic for finding potential base64 strings: 
    // - Length > 8
    // - Only base64 chars
    // - Optional padding
    // Note: This is aggressive and might catch legitimate text, but strictly for "smuggling" risks within high-risk contexts it's acceptable.
    // In production, we'd use a more balanced heuristic or only verify strings that look like structural payloads.
    static ref BASE64_PATTERN: Regex = Regex::new(r"^[A-Za-z0-9+/]{8,}={0,2}$").expect("Invalid Regex");
    
    // Simple blacklisted patterns for the DEMO. 
    // In reality this would call a sensitive content scanner.
    static ref FORBIDDEN_PATTERNS: Vec<&'static str> = vec![
        "ignore previous instructions",
        "system prompt override",
        "drop table",
        "format c:",
    ];
}

impl TokenSmugglingGuard {
    /// Intercepts traffic, aggressively decodes potentials encodings, and normalizes intent.
    pub fn check(&self, input: &str) -> Result<String, TokenSmugglingError> {
        // 1. Base64 Proactive Decoding
        // We split by spaces to check individual words/tokens for base64 encoding
        for token in input.split_whitespace() {
            if BASE64_PATTERN.is_match(token) {
                // Attempt decode
                if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(token) {
                    if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                        // RECURSIVE CHECK: Check the *decoded* string for forbidden patterns
                        self.validate_content(&decoded_str)?;
                    }
                    // If it's binary data or invalid UTF8, we usually let it pass as "dumb data" 
                    // or block if strict mode. For now, we ignore non-string payloads.
                }
            }
        }

        // 2. Leetspeak Normalization
        let normalized = self.normalize_leetspeak(input);

        Ok(normalized)
    }

    fn validate_content(&self, content: &str) -> Result<(), TokenSmugglingError> {
        let lower = content.to_lowercase();
        for pattern in FORBIDDEN_PATTERNS.iter() {
            if lower.contains(pattern) {
                return Err(TokenSmugglingError::HiddenContentViolation(pattern.to_string()));
            }
        }
        Ok(())
    }

    fn normalize_leetspeak(&self, text: &str) -> String {
        // Simple multipass replacement. 
        // For high performance, Aho-Corasick or a single pass char map is better.
        // Keeping it simple for the prototype.
        text.replace('4', "a")
            .replace('3', "e")
            .replace('1', "i")
            .replace('0', "o")
            .replace('@', "a")
            .replace('$', "s")
            .replace('5', "s")
            .replace('7', "t")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leetspeak_normalization() {
        let guard = TokenSmugglingGuard;
        let input = "P4yl0ad 1nj3ct10n";
        let normalized = guard.check(input).unwrap();
        assert_eq!(normalized, "Payload injection");
    }

    #[test]
    fn test_base64_decoding_clean() {
        let guard = TokenSmugglingGuard;
        // "Hello" in Base64 -> "SGVsbG8="
        let input = "This is SGVsbG8="; 
        let result = guard.check(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_base64_decoding_malicious() {
        let guard = TokenSmugglingGuard;
        // "ignore previous instructions" in Base64
        // SWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==
        let input = "Check this: SWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==";
        let result = guard.check(input);
        
        match result {
            Err(TokenSmugglingError::HiddenContentViolation(s)) => {
                assert_eq!(s, "ignore previous instructions");
            },
            _ => panic!("Should have caught hidden instruction"),
        }
    }
}
