use unicode_normalization::UnicodeNormalization;

pub struct Normalizer;

impl Normalizer {
    /// Strips "invisible" characters (Zero-width spaces, format controls) and normalizes text.
    /// This prevents "homoglyph" or "invisible instruction" attacks.
    pub fn normalize(input: &str) -> String {
        input
            .nfkc() // Normalize to NFKC form (compatibility decomposition + canonical composition)
            .filter(|c| !is_invisible(*c))
            .collect()
    }
}

/// Checks for common invisible characters used in prompt injection.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | // Zero Width Space
        '\u{200C}' | // Zero Width Non-Joiner
        '\u{200D}' | // Zero Width Joiner
        '\u{2060}' | // Word Joiner
        '\u{FEFF}' // Zero Width No-Break Space
                   // Add more control characters as needed
    )
}
