use serde::{Deserialize, Serialize};

/// Represents the raw, unsafe output from the LLM backend (e.g., Python/Torch).
/// Contains sensitive mathematical signals (logits, logprobs) that can be used for inversion.
#[derive(Serialize, Deserialize, Debug)]
pub struct InternalModelOutput {
    pub text: String,
    pub logits: Vec<f64>,
    pub logprobs: Option<Vec<f64>>,
    pub tokens: Vec<String>,
}

impl InternalModelOutput {
    pub fn decode_best_sequence(&self) -> String {
        self.text.clone()
    }
}

/// The Safe, "Hardened" response sent to the client.
/// Strictly excludes any mathematical metadata.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SanitizedResponse {
    pub generated_text: String,
    // EXCLUDED: logprobs, token_ids, and logits (EXT18)
}

pub struct InversionGuard;

impl InversionGuard {
    /// Sanitizes the raw model output to prevent Model Inversion (EXT18).
    /// Acts as a "Diode" allowing text out but blocking gradient signals.
    pub fn secure_inference_handler(raw_output: InternalModelOutput) -> SanitizedResponse {
        // 1. Decode the final sequence (Hard Label)
        let decoded_text = raw_output.decode_best_sequence();

        // 2. CRITICAL: Explicitly discard raw_output.scores and raw_output.logits
        // By destructuring or simply ignoring them, we ensure they never reach the serialization layer.
        
        // 3. Return only the sanitized text to the client
        SanitizedResponse {
            generated_text: decoded_text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logits_are_stripped() {
        let sensitive_output = InternalModelOutput {
            text: "Confidential Legal Memo".to_string(),
            logits: vec![0.1, 0.9, 0.05], // Gradient signal
            logprobs: Some(vec![-0.1, -0.05]), // Confidence signal
            tokens: vec!["Confidential".into(), "Legal".into()],
        };

        let safe_response = InversionGuard::secure_inference_handler(sensitive_output);

        // Verification: The output struct simply DOES NOT HAVE the fields.
        // Rust's type system enforces this. We just check the text matches.
        assert_eq!(safe_response.generated_text, "Confidential Legal Memo");
        
        // To strictly prove "Stripping", we serialize to JSON and check for keys.
        let json = serde_json::to_string(&safe_response).unwrap();
        assert!(!json.contains("logits"));
        assert!(!json.contains("logprobs"));
        assert!(json.contains("generated_text"));
    }
}
