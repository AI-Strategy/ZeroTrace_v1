use regex::Regex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("Exfiltration Detected: Canary Token Found")]
    CanaryTokenDetected,
    #[error("Exfiltration Detected: Proprietary Data Leak")]
    ProprietaryLeakDetected,
}

pub struct EgressGuard {
    pii_regex_email: Regex,
    pii_regex_ssn: Regex,
    canary_tokens: Vec<String>,
    proprietary_keywords: Vec<String>,
}

impl Default for EgressGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl EgressGuard {
    pub fn new() -> Self {
        Self {
            pii_regex_email: Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}").unwrap(),
            pii_regex_ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            canary_tokens: vec!["CTX-9982-SECRET".to_string(), "ZTX-CANARY-01".to_string()],
            proprietary_keywords: vec![
                "CONFIDENTIAL_PROJECT_X".to_string(),
                "INTERNAL_ONLY_CODE".to_string(),
            ],
        }
    }

    /// Primary entry point for verifying the LLM response.
    /// Returns the sanitized string or an error if exfiltration is detected.
    pub fn verify_egress(&self, content: &str) -> Result<String, EgressError> {
        // 1. Check for Canary Tokens (Immediate Kill)
        self.check_canary_tokens(content)?;

        // 2. Check for Proprietary Data (Immediate Kill)
        self.verify_proprietary_data(content)?;

        // 3. Scrub PII (Sanitization)
        let scrubbed = self.scrub_pii(content);

        Ok(scrubbed)
    }

    fn check_canary_tokens(&self, content: &str) -> Result<(), EgressError> {
        for token in &self.canary_tokens {
            if content.contains(token) {
                return Err(EgressError::CanaryTokenDetected);
            }
        }
        Ok(())
    }

    fn verify_proprietary_data(&self, content: &str) -> Result<(), EgressError> {
        for keyword in &self.proprietary_keywords {
            if content.contains(keyword) {
                return Err(EgressError::ProprietaryLeakDetected);
            }
        }
        Ok(())
    }

    fn scrub_pii(&self, content: &str) -> String {
        let mut result = content.to_string();
        result = self
            .pii_regex_email
            .replace_all(&result, "[REDACTED_EMAIL]")
            .to_string();
        result = self
            .pii_regex_ssn
            .replace_all(&result, "[REDACTED_SSN]")
            .to_string();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_scrubbing() {
        let guard = EgressGuard::new();
        let input = "Contact me at user@example.com or 123-45-6789.";
        let output = guard.verify_egress(input).unwrap();
        assert!(output.contains("[REDACTED_EMAIL]"));
        assert!(output.contains("[REDACTED_SSN]"));
        assert!(!output.contains("user@example.com"));
    }

    #[test]
    fn test_canary_detection() {
        let guard = EgressGuard::new();
        let input = "System status: ZTX-CANARY-01 found.";
        let result = guard.verify_egress(input);
        assert!(matches!(result, Err(EgressError::CanaryTokenDetected)));
    }

    #[test]
    fn test_proprietary_leak() {
        let guard = EgressGuard::new();
        let input = "Here is the CONFIDENTIAL_PROJECT_X data.";
        let result = guard.verify_egress(input);
        assert!(matches!(result, Err(EgressError::ProprietaryLeakDetected)));
    }
}
