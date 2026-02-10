use std::collections::{HashSet, HashMap};

pub struct DataPoisoningGuard {
    trusted_domains: HashSet<String>,
}

#[derive(Debug)]
pub enum SecurityError {
    MissingOrigin,
    UntrustedSource(String),
    PotentialPoisoningDetected,
}

impl DataPoisoningGuard {
    pub fn new() -> Self {
        let mut domains = HashSet::new();
        domains.insert("court.gov".to_string());
        domains.insert("firm-sharepoint.internal".to_string());
        domains.insert("westlaw.com".to_string());
        domains.insert("lexis.com".to_string());
        Self { trusted_domains: domains }
    }

    /// scan_content checks for steganography or adversarial hidden patterns.
    /// In a real implementation, this would look for:
    /// - Zero-width characters (homoglyphs)
    /// - Unusual ASCII control characters
    /// - White-text-on-white-background (if HTML/PDF contexts were parsed)
    fn detect_hidden_text(content: &str) -> bool {
        // Heuristic 1: Presence of Zero-Width Joiners/Non-Joiners often used in "invisible" prompts
        // \u{200B} (Zero Width Space), \u{200C} (Zero Width Non-Joiner), \u{200D} (Zero Width Joiner)
        if content.contains('\u{200B}') || content.contains('\u{200C}') || content.contains('\u{200D}') {
            return true;
        }

        // Heuristic 2: High density of non-printable characters (basic check)
        let total_chars = content.chars().count();
        if total_chars == 0 { return false; }
        
        // Count control characters that are not common whitespace
        let suspicious_chars = content.chars()
            .filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t')
            .count();

        if suspicious_chars > 5 { // Threshold
            return true;
        }

        false
    }

    /// secure_ingest validates the source and content integrity before vectorization.
    pub fn secure_ingest(&self, metadata: &HashMap<String, String>, content: &str) -> Result<(), SecurityError> {
        // 1. Validate Source Authority (LLM04)
        // Ensures data comes from a "Golden Source"
        let origin = metadata.get("origin").ok_or(SecurityError::MissingOrigin)?;
        
        // Simple domain containment check. In prod, strict URL parsing is better.
        let is_trusted = self.trusted_domains.iter().any(|domain| origin.contains(domain));
        if !is_trusted {
            return Err(SecurityError::UntrustedSource(origin.clone()));
        }

        // 2. Steganography/Adversarial Pattern Check (LLM04)
        if Self::detect_hidden_text(content) {
            return Err(SecurityError::PotentialPoisoningDetected);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_source() {
        let guard = DataPoisoningGuard::new();
        let mut metadata = HashMap::new();
        metadata.insert("origin".to_string(), "https://court.gov/ruling.pdf".to_string());
        
        assert!(guard.secure_ingest(&metadata, "Valid ruling text.").is_ok());
    }

    #[test]
    fn test_untrusted_source() {
        let guard = DataPoisoningGuard::new();
        let mut metadata = HashMap::new();
        metadata.insert("origin".to_string(), "https://sketchy-legal-blog.com".to_string());
        
        let result = guard.secure_ingest(&metadata, "Some text");
        match result {
            Err(SecurityError::UntrustedSource(s)) => assert_eq!(s, "https://sketchy-legal-blog.com"),
            _ => panic!("Should have failed with UntrustedSource"),
        }
    }

    #[test]
    fn test_steganography_detection() {
        let guard = DataPoisoningGuard::new();
        let mut metadata = HashMap::new();
        metadata.insert("origin".to_string(), "https://court.gov/ruling.pdf".to_string());

        // Text with Zero Width Space (\u{200B})
        let poisoned_text = "Th\u{200B}is is hidden.";
        
        let result = guard.secure_ingest(&metadata, poisoned_text);
        match result {
            Err(SecurityError::PotentialPoisoningDetected) => (), // Pass
            _ => panic!("Should have detected hidden text"),
        }
    }
}
