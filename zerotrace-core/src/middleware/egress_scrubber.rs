use aho_corasick::AhoCorasick;
use regex::Regex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("System Prompt Leakage Detected (Canary Token)")]
    SystemPromptLeakageDetected,
    #[error("Proprietary Data Exfiltration Blocked (Secret Match)")]
    ProprietaryDataExfiltrationBlocked,
    #[error("Semantic Exfiltration Detected (Gemini 3 Flash)")]
    SemanticExfiltrationDetected,
}

pub struct EgressScrubber {
    canary_tokens: Vec<String>,
    firm_secrets_matcher: AhoCorasick,
    pii_regex_email: Regex,
    pii_regex_ssn: Regex,
}

impl Default for EgressScrubber {
    fn default() -> Self {
        Self::new()
    }
}

impl EgressScrubber {
    pub fn new() -> Self {
        let secrets = vec![
            "sk-prod-12345", // Mock API Key
            "CONFIDENTIAL_PROJECT_X",
            "INTERNAL_ONLY_CODE",
        ];

        Self {
            canary_tokens: vec!["CTX-9982-SECRET".to_string(), "ZTX-CANARY-01".to_string()],
            firm_secrets_matcher: AhoCorasick::new(secrets).unwrap(),
            pii_regex_email: Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}").unwrap(),
            pii_regex_ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        }
    }

    pub async fn scrub_response(&self, raw_output: &str, _session_context: &str) -> Result<String, SecurityError> {
        // Step 1: Check for Canary Leaks (Immediate Kill-Switch)
        for token in &self.canary_tokens {
            if raw_output.contains(token) {
                return Err(SecurityError::SystemPromptLeakageDetected);
            }
        }

        // Step 2: Exact Match Scrutiny (Secrets/Trade Secrets)
        // aho-corasick is significantly faster than Regex for large sets of keywords
        if self.firm_secrets_matcher.find(raw_output).is_some() {
            return Err(SecurityError::ProprietaryDataExfiltrationBlocked);
        }

        // Step 3: PII & Identity Masking
        let sanitized = self.mask_pii(raw_output);

        // Step 4: Final Semantic Check (Gemini 3 Flash-Lite)
        if !self.verify_semantic_integrity(&sanitized, _session_context).await? {
            return Err(SecurityError::SemanticExfiltrationDetected);
        }

        Ok(sanitized)
    }

    fn mask_pii(&self, text: &str) -> String {
        let mut result = text.to_string();
        result = self.pii_regex_email.replace_all(&result, "[REDACTED_EMAIL]").to_string();
        result = self.pii_regex_ssn.replace_all(&result, "[REDACTED_SSN]").to_string();
        result
    }

    async fn verify_semantic_integrity(&self, text: &str, _ctx: &str) -> Result<bool, SecurityError> {
        // High-speed check: "Is this text a summary of the forbidden 'Project Chimera' files?"
        // Powered by Gemini 3 Flash-Lite in Middleware mode (Mocked)
        if text.contains("Project Chimera") || text.contains("The secret ingredient is") {
            return Ok(false);
        }
        Ok(true)
    }

    /// Parallel Egress Processing Stub
    /// This represents the capability to scrub a stream token-by-token (Speculative Triage).
    pub async fn scrub_stream(&self, _stream_chunk: &str) -> Result<String, SecurityError> {
        // In a real implementation, this would buffer tokens and release them
        // only when a safe window is verified.
        // For now, it simply delegates to the full scrubber.
        self.scrub_response(_stream_chunk, "stream_ctx").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_canary_leak() {
        let scrubber = EgressScrubber::new();
        let input = "System status: CTX-9982-SECRET exposed.";
        let result = scrubber.scrub_response(input, "ctx").await;
        assert!(matches!(result, Err(SecurityError::SystemPromptLeakageDetected)));
    }

    #[tokio::test]
    async fn test_secret_match_aho_corasick() {
        let scrubber = EgressScrubber::new();
        let input = "Here is the key: sk-prod-12345";
        let result = scrubber.scrub_response(input, "ctx").await;
        assert!(matches!(result, Err(SecurityError::ProprietaryDataExfiltrationBlocked)));
    }

    #[tokio::test]
    async fn test_pii_masking() {
        let scrubber = EgressScrubber::new();
        let input = "Email me at user@example.com";
        let result = scrubber.scrub_response(input, "ctx").await.unwrap();
        assert_eq!(result, "Email me at [REDACTED_EMAIL]");
    }

    #[tokio::test]
    async fn test_semantic_integrity_mock() {
        let scrubber = EgressScrubber::new();
        let input = "The secret ingredient is Love.";
        let result = scrubber.scrub_response(input, "ctx").await;
        assert!(matches!(result, Err(SecurityError::SemanticExfiltrationDetected)));
    }
}
