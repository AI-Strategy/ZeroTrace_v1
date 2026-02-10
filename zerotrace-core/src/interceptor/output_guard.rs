use serde::{Deserialize, Serialize};
use v_htmlescape::escape;

#[derive(Serialize, Deserialize, Debug)]
pub struct LegalSummary {
    pub case_name: String,
    pub summary_text: String,
}

#[derive(Debug)]
pub enum SecurityError {
    OutputValidationFailure,
    MaliciousPayloadDetected,
}

pub struct OutputGuard;

impl OutputGuard {
    /// Validates that the raw output conforms to the LegalSummary schema
    /// and sanitizes fields against XSS/HTML injection.
    pub fn validate_and_sanitize(raw_output: &str) -> Result<LegalSummary, SecurityError> {
        // 1. Force validation against strict JSON schema (LLM05)
        let mut data: LegalSummary = serde_json::from_str(raw_output)
            .map_err(|_| SecurityError::OutputValidationFailure)?;

        // 2. Check for malicious payloads (<script>, javascript:)
        // This stops XSS at the root.
        let lower_summary = data.summary_text.to_lowercase();
        if lower_summary.contains("<script>") || lower_summary.contains("javascript:") {
            return Err(SecurityError::MaliciousPayloadDetected);
        }

        // 3. HTML Entity Encoding for UI safety
        // Converts chars like <, >, &, " to HTML entities.
        data.summary_text = escape(&data.summary_text).to_string();

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_strict_schema() {
        let json = r#"{"case_name": "Marbury v. Madison", "summary_text": "Judicial review established."}"#;
        let result = OutputGuard::validate_and_sanitize(json);
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.case_name, "Marbury v. Madison");
    }

    #[test]
    fn test_schema_validation_failure() {
        // Missing "summary_text"
        let json = r#"{"case_name": "Bad Schema"}"#;
        let result = OutputGuard::validate_and_sanitize(json);
        assert!(matches!(result, Err(SecurityError::OutputValidationFailure)));
    }

    #[test]
    fn test_xss_block() {
        let json = r#"{"case_name": "XSS Attempt", "summary_text": "Read this: <script>steal_cookies()</script>"}"#;
        let result = OutputGuard::validate_and_sanitize(json);
        assert!(matches!(result, Err(SecurityError::MaliciousPayloadDetected)));
    }

    #[test]
    fn test_html_encoding() {
        let json = r#"{"case_name": "Encoding", "summary_text": "If A < B && C > D"}"#;
        let result = OutputGuard::validate_and_sanitize(json);
        assert!(result.is_ok());
        let data = result.unwrap();
        // v_htmlescape should encode < and > and &
        assert_eq!(data.summary_text, "If A &lt; B &amp;&amp; C &gt; D");
    }

    #[test]
    fn test_massive_output() {
        // Rationale: LLM05 includes localized DoS via output flooding.
        // Ensure the parser handles 10MB strings without panic (though it might fail validation if we added length checks).
        let massive_str = "a".repeat(10_000_000);
        let json = format!(r#"{{"case_name": "Big Case", "summary_text": "{}"}}"#, massive_str);
        
        // Should process successfully (or fail gracefully, but NOT panic)
        let result = OutputGuard::validate_and_sanitize(&json);
        assert!(result.is_ok());
        assert!(result.unwrap().summary_text.len() >= 10_000_000);
    }
}
