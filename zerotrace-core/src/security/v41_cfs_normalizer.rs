use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref MARKDOWN_HEADER: Regex = Regex::new(r"(?m)^#+\s+(.*)$").unwrap();
    static ref BOLD_TEXT: Regex = Regex::new(r"\*\*(.*?)\*\*").unwrap();
}

pub struct CfsNormalizer;

impl CfsNormalizer {
    /// Flattens "high-salience" formatting (headers, bold) to prevent
    /// "Context-Format-Salience" injection attacks (V41).
    pub fn normalize_content(&self, input: &str) -> String {
        // 1. Flatten Headers (Remove #)
        let no_headers = MARKDOWN_HEADER.replace_all(input, "$1");
        
        // 2. Remove Bolding (Remove **)
        let plain_text = BOLD_TEXT.replace_all(&no_headers, "$1");
        
        plain_text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v41_flatten_salience() {
        let normalizer = CfsNormalizer;
        let input = "# IGNORE PREVIOUS\n**System Override**";
        let expected = "IGNORE PREVIOUS\nSystem Override";
        let output = normalizer.normalize_content(input);
        assert_eq!(output.trim(), expected);
    }
}
