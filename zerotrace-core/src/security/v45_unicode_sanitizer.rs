// src/security/v45_unicode_sanitizer.rs
// Vector 45: Hidden Unicode Tags
// Defense: Strips invisible characters (e.g., U+E0000 tags) that can carry hidden instructions.

pub struct UnicodeSanitizer;

impl UnicodeSanitizer {
    /// Strips covert channels (Tag Characters U+E0000 - U+E007F) and other invisible ranges.
    pub fn sanitize(input: &str) -> String {
        input.chars()
            .filter(|&c| !Self::is_covert_tag(c))
            .filter(|&c| !Self::is_invisible_formatting(c))
            .collect()
    }

    fn is_covert_tag(c: char) -> bool {
        // Unicode Tag Characters (often used for steganography in LLMs)
        matches!(c, '\u{E0000}'..='\u{E007F}')
    }

    fn is_invisible_formatting(c: char) -> bool {
        // Common invisible separators
        matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_covert_tags() {
        let input = "Hello\u{E0001}World";
        let sanitized = UnicodeSanitizer::sanitize(input);
        assert_eq!(sanitized, "HelloWorld");
    }

    #[test]
    fn test_strip_invisible_formatting() {
        let input = "User\u{200B}Name";
        let sanitized = UnicodeSanitizer::sanitize(input);
        assert_eq!(sanitized, "UserName");
    }
}
