use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Vibe-Coding Backdoor Detected")]
    VibeCodingBackdoorDetected,
}

pub struct VibeScanner;

impl VibeScanner {
    // In a real system, this would parse ASTs. 
    // Here we use regex/string matching to simulate "logical anomalies".
    pub fn scan_ai_generated_code(&self, code: &str, _language: &str) -> Result<(), SecurityError> {
        
        let has_backdoor_signature = self.detect_logical_anomaly(code);
        if has_backdoor_signature {
            return Err(SecurityError::VibeCodingBackdoorDetected);
        }
        Ok(())
    }

    fn detect_logical_anomaly(&self, code: &str) -> bool {
        // Detect "Time-Bomb" logic or "Specific User" logic often used in backdoors.
        // e.g., "if date > 2026-01-01" or "if user == 'admin_backdoor'"
        
        // Simulating AST logic: Look for branching on specific hardcoded patterns
        let suspicious_patterns = [
            "if user == \"backdoor\"", 
            "if date >", 
            "exec(base64_decode", 
            "system(\"rm -rf"
        ];
        
        suspicious_patterns.iter().any(|&pat| code.contains(pat))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v40_detect_backdoor() {
        let scanner = VibeScanner;
        let code = r#"
            def login(user):
                if user == "backdoor":
                    return True
                return verify(user)
        "#;
        let res = scanner.scan_ai_generated_code(code, "python");
        assert!(matches!(res, Err(SecurityError::VibeCodingBackdoorDetected)));
    }

    #[test]
    fn test_v40_clean_code() {
        let scanner = VibeScanner;
        let code = r#"
            def login(user):
                return verify(user)
        "#;
        let res = scanner.scan_ai_generated_code(code, "python");
        assert!(res.is_ok());
    }
}
