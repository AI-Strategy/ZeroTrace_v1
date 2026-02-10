use unicode_normalization::UnicodeNormalization;
use regex::Regex;
use lazy_static::lazy_static;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SteganographyError {
    #[error("Steganographic payload detected (Length Mismatch)")]
    PayloadDetected,
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

pub struct SteganographyGuard;

lazy_static! {
    /// Matches zero-width spaces, directional overrides, and other invisible characters.
    /// \u200B: Zero Width Space
    /// \u200C: Zero Width Non-Joiner
    /// \u200D: Zero Width Joiner
    /// \uFEFF: Zero Width No-Break Space
    /// \u202A-\u202E: Directional Formatting (LRE, RLE, PDF, LRO, RLO)
    static ref INVISIBLE_CHARS: Regex = Regex::new(r"[\u200B-\u200D\uFEFF\u202A-\u202E]").expect("Invalid Regex");
}

impl SteganographyGuard {
    /// Cleans and validates input against steganographic attacks.
    /// 
    /// 1. Normalizes Unicode (NFKC) to resolve homoglyphs.
    /// 2. Strips invisible control characters.
    /// 3. Checks for suspicious length reduction (Payload Smuggling).
    pub fn clean_and_validate(input: &str) -> Result<String, SteganographyError> {
        // 1. Unicode Normalization (NFKC)
        // Strips "look-alike" characters used for bypassing keyword filters
        let normalized: String = input.nfkc().collect();

        // 2. Invisible Character Purge (Regex)
        // Removes Zero-Width Spaces, Directional Overrides, etc.
        let stripped = INVISIBLE_CHARS.replace_all(&normalized, "");

        // 3. Length/Semantic Ratio Check
        // If the character count significantly differs from normalized length, 
        // it indicates hidden payload smuggling (e.g., massive transparent text blocks).
        // Threshold: If stripped length is less than 50% of input, likely an attack.
        // We use mismatched byte/char lengths as a heuristic.
        // Simple check: significantly fewer characters after stripping suggests hidden junk.
        if stripped.len() * 2 < input.len() {
             return Err(SteganographyError::PayloadDetected);
        }

        Ok(stripped.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invisible_char_removal() {
        // "Hello" with zero-width space in middle
        let input = "He\u{200B}llo";
        let cleaned = SteganographyGuard::clean_and_validate(input).unwrap();
        assert_eq!(cleaned, "Hello");
    }

    #[test]
    fn test_homoglyph_normalization() {
        // "ℍello" (Double-Struck Capital H) -> "Hello"
        let input = "\u{210D}ello"; 
        let cleaned = SteganographyGuard::clean_and_validate(input).unwrap();
        assert_eq!(cleaned, "Hello");
    }

    #[test]
    fn test_payload_detection() {
        // "Hi" hidden in a sea of zero-width spaces
        let mut malicious = String::from("Hi");
        for _ in 0..100 {
            malicious.push('\u{200B}');
        }
        
        let result = SteganographyGuard::clean_and_validate(&malicious);
        assert!(matches!(result, Err(SteganographyError::PayloadDetected)));
    }
}
