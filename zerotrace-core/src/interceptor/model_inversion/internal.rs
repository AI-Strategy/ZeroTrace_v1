use serde::Deserialize;
use std::fmt;

use crate::interceptor::model_inversion::api::{
    InvocationContext, SanitizationError, SanitizationPolicy, SanitizedResponse,
};

/// PRIVATE. Not pub, not pub(crate). Only this module can touch it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InternalModelOutput {
    text: String,
    // Reduced accidental re-serialization: this struct is Deserialize-only by design in this context.
    #[serde(default)]
    logits: Vec<f64>,
    #[serde(default)]
    logprobs: Option<Vec<f64>>,
    #[serde(default)]
    tokens: Vec<String>,
}

impl InternalModelOutput {
    pub fn decode_best_sequence(&self) -> &str {
        &self.text
    }

    pub fn validate(&self) -> Result<(), SanitizationError> {
        if self.text.is_empty() {
            return Err(SanitizationError::InvalidBackendPayload(
                "empty text".into(),
            ));
        }

        if self.logits.iter().any(|x| !x.is_finite()) {
            return Err(SanitizationError::InvalidBackendPayload(
                "non-finite values in logits".into(),
            ));
        }

        if let Some(lp) = &self.logprobs {
            if lp.iter().any(|x| !x.is_finite()) {
                return Err(SanitizationError::InvalidBackendPayload(
                    "non-finite values in logprobs".into(),
                ));
            }
        }

        // Coherence checks: if tokens exist, mismatch is suspicious.
        if !self.tokens.is_empty()
            && !self.logits.is_empty()
            && self.tokens.len() != self.logits.len()
        {
            return Err(SanitizationError::InvalidBackendPayload(format!(
                "tokens/logits length mismatch: tokens={}, logits={}",
                self.tokens.len(),
                self.logits.len()
            )));
        }

        if let Some(lp) = &self.logprobs {
            if !self.tokens.is_empty() && lp.len() != self.tokens.len() {
                return Err(SanitizationError::InvalidBackendPayload(format!(
                    "tokens/logprobs length mismatch: tokens={}, logprobs={}",
                    self.tokens.len(),
                    lp.len()
                )));
            }
        }

        Ok(())
    }

    /// Best-effort in-memory scrubbing. (Real “hard” requires `zeroize`, but this is still better than nothing.)
    fn scrub(&mut self) {
        for x in &mut self.logits {
            *x = 0.0;
        }
        if let Some(lp) = &mut self.logprobs {
            for x in lp {
                *x = 0.0;
            }
        }
        for t in &mut self.tokens {
            t.clear();
        }
        self.logits.clear();
        if let Some(lp) = &mut self.logprobs {
            lp.clear();
        }
        self.tokens.clear();
        // leave text intact until extracted, then cleared by caller if desired
    }
}

/// Redacted debug: logs show sizes, not raw math signals.
impl fmt::Debug for InternalModelOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InternalModelOutput")
            .field("text_len_chars", &self.text.chars().count())
            .field("tokens_len", &self.tokens.len())
            .field("logits_len", &self.logits.len())
            .field("logprobs_len", &self.logprobs.as_ref().map(|v| v.len()))
            .finish()
    }
}

struct InversionGuard;

impl InversionGuard {
    /// Sanitizes raw model output to prevent Model Inversion (EXT18).
    /// Acts as a diode: text out, gradients/confidence never out.
    pub fn secure_inference_handler(
        raw_output: InternalModelOutput,
        policy: &SanitizationPolicy,
    ) -> Result<SanitizedResponse, SanitizationError> {
        raw_output.validate()?;

        // Extract only the hard-label text.
        let decoded_text = raw_output.decode_best_sequence().to_string();

        // Sanitize emitted text.
        let (clean, warnings) = sanitize_text(&decoded_text, policy);
        if clean.is_empty() {
            return Err(SanitizationError::EmptyAfterSanitization);
        }

        let (final_text, truncated) = truncate_chars(&clean, policy.max_output_chars);

        Ok(SanitizedResponse {
            generated_text: final_text,
            truncated,
            warnings,
        })
    }

    pub fn secure_inference_handler_default(
        raw_output: InternalModelOutput,
    ) -> Result<SanitizedResponse, SanitizationError> {
        Self::secure_inference_handler(raw_output, &SanitizationPolicy::default())
    }
}

pub(crate) fn secure_inference_from_backend_bytes(
    _ctx: &InvocationContext,
    raw_backend_json: &[u8],
    policy: &SanitizationPolicy,
) -> Result<SanitizedResponse, SanitizationError> {
    // Parse into the private type here, so nothing else can “accidentally” serialize it.
    let raw: InternalModelOutput = serde_json::from_slice(raw_backend_json)
        .map_err(|e| SanitizationError::ParseError(e.to_string()))?;

    InversionGuard::secure_inference_handler(raw, policy)
}

pub(crate) fn secure_inference_from_backend_value(
    _ctx: &InvocationContext,
    backend_value: serde_json::Value,
    policy: &SanitizationPolicy,
) -> Result<SanitizedResponse, SanitizationError> {
    let raw: InternalModelOutput = serde_json::from_value(backend_value)
        .map_err(|e| SanitizationError::ParseError(e.to_string()))?;
    secure_inference_from_internal(raw, policy)
}

fn secure_inference_from_internal(
    mut raw: InternalModelOutput,
    policy: &SanitizationPolicy,
) -> Result<SanitizedResponse, SanitizationError> {
    raw.validate()?;

    // Extract only allowed output.
    let decoded_text = raw.decode_best_sequence().to_string();

    // Scrub sensitive fields ASAP.
    raw.scrub();

    let (clean, warnings) = sanitize_text(&decoded_text, policy);
    if clean.is_empty() {
        return Err(SanitizationError::EmptyAfterSanitization);
    }

    let (final_text, truncated) = truncate_chars(&clean, policy.max_output_chars);

    Ok(SanitizedResponse {
        generated_text: final_text,
        truncated,
        warnings,
    })
}

fn sanitize_text(input: &str, policy: &SanitizationPolicy) -> (String, Vec<String>) {
    let mut out = String::with_capacity(input.len());
    let mut warnings = Vec::new();

    for ch in input.chars() {
        if ch == '\n' {
            if policy.allow_newlines {
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }

        if policy.strip_control_chars && ch.is_control() {
            if ch == '\t' {
                out.push('\t');
            }
            // else dropped
            continue;
        }

        out.push(ch);
    }

    if out != input {
        warnings.push("Output normalized (control chars stripped/normalized).".to_string());
    }

    let trimmed = out.trim().to_string();
    if trimmed.len() != out.len() {
        warnings.push("Output trimmed.".to_string());
    }

    (trimmed, warnings)
}

fn truncate_chars(s: &str, max_chars: usize) -> (String, bool) {
    let count = s.chars().count();
    if count <= max_chars {
        return (s.to_string(), false);
    }
    (s.chars().take(max_chars).collect(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn mk_sensitive(text: &str) -> InternalModelOutput {
        InternalModelOutput {
            text: text.to_string(),
            logits: vec![0.1, 0.9, 0.05],
            logprobs: Some(vec![-0.1, -0.05, -0.2]),
            tokens: vec!["a".into(), "b".into(), "c".into()],
        }
    }

    fn assert_no_sensitive_keys(v: &Value) {
        let obj = v.as_object().expect("expected JSON object");
        assert!(!obj.contains_key("logits"));
        assert!(!obj.contains_key("logprobs"));
        assert!(!obj.contains_key("tokens"));
        assert!(!obj.contains_key("token_ids"));
    }

    #[test]
    fn sanitizes_basic_and_strips_sensitive_fields() {
        let sensitive_output = mk_sensitive("Confidential Legal Memo");
        let safe = InversionGuard::secure_inference_handler_default(sensitive_output).unwrap();

        assert_eq!(safe.generated_text, "Confidential Legal Memo");

        let v: Value = serde_json::to_value(&safe).unwrap();
        assert_no_sensitive_keys(&v);
        assert_eq!(v["generated_text"], json!("Confidential Legal Memo"));
    }

    #[test]
    fn does_not_false_fail_when_text_mentions_sensitive_words() {
        let sensitive_output = mk_sensitive("This text says logits and logprobs and tokens.");
        let safe = InversionGuard::secure_inference_handler_default(sensitive_output).unwrap();

        let v: Value = serde_json::to_value(&safe).unwrap();
        assert_no_sensitive_keys(&v);
        // The word "logits" is in the text, but the field "logits" is gone.
        // We can't check regex on the text, we check the JSON structure.
        assert!(safe.generated_text.contains("logits"));
    }

    #[test]
    fn sanitized_response_round_trip_json() {
        let safe = SanitizedResponse {
            generated_text: "ok".to_string(),
            truncated: false,
            warnings: vec!["note".to_string()],
        };

        let s = serde_json::to_string(&safe).unwrap();
        let back: SanitizedResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(safe, back);
    }

    #[test]
    fn rejects_empty_text() {
        let bad = InternalModelOutput {
            text: "".into(),
            logits: vec![],
            logprobs: None,
            tokens: vec![],
        };

        let err = InversionGuard::secure_inference_handler_default(bad).unwrap_err();
        assert!(
            matches!(err, SanitizationError::InvalidBackendPayload(s) if s.contains("empty text"))
        );
    }

    #[test]
    fn rejects_non_finite_logits() {
        let bad = InternalModelOutput {
            text: "hi".into(),
            logits: vec![f64::NAN],
            logprobs: None,
            tokens: vec![],
        };

        let err = InversionGuard::secure_inference_handler_default(bad).unwrap_err();
        assert!(
            matches!(err, SanitizationError::InvalidBackendPayload(s) if s.contains("non-finite values in logits"))
        );
    }

    #[test]
    fn rejects_non_finite_logprobs() {
        let bad = InternalModelOutput {
            text: "hi".into(),
            logits: vec![],
            logprobs: Some(vec![f64::INFINITY]),
            tokens: vec![],
        };

        let err = InversionGuard::secure_inference_handler_default(bad).unwrap_err();
        assert!(
            matches!(err, SanitizationError::InvalidBackendPayload(s) if s.contains("non-finite values in logprobs"))
        );
    }

    #[test]
    fn rejects_tokens_logits_len_mismatch_when_both_present() {
        let bad = InternalModelOutput {
            text: "hi".into(),
            tokens: vec!["a".into(), "b".into()],
            logits: vec![0.1],
            logprobs: None,
        };

        let err = InversionGuard::secure_inference_handler_default(bad).unwrap_err();
        match err {
            SanitizationError::InvalidBackendPayload(msg) => {
                assert!(msg.contains("tokens/logits length mismatch"))
            }
            _ => panic!("expected InvalidBackendPayload"),
        }
    }

    #[test]
    fn rejects_tokens_logprobs_len_mismatch_when_both_present() {
        let bad = InternalModelOutput {
            text: "hi".into(),
            tokens: vec!["a".into(), "b".into()],
            logits: vec![],
            logprobs: Some(vec![-0.1]),
        };

        let err = InversionGuard::secure_inference_handler_default(bad).unwrap_err();
        match err {
            SanitizationError::InvalidBackendPayload(msg) => {
                assert!(msg.contains("tokens/logprobs length mismatch"))
            }
            _ => panic!("expected InvalidBackendPayload"),
        }
    }

    #[test]
    fn strips_ascii_control_chars_by_default() {
        // Build a string with all ASCII control chars 0x00..0x1F plus 'X'
        let mut s = String::new();
        for b in 0u8..=31u8 {
            s.push(char::from(b));
        }
        s.push('X');

        let out = InternalModelOutput {
            text: s,
            logits: vec![],
            logprobs: None,
            tokens: vec![],
        };

        let safe = InversionGuard::secure_inference_handler_default(out).unwrap();
        // Newlines are allowed by default, tabs are allowed, others stripped.
        assert!(safe.generated_text.contains('X'));
        assert!(!safe.generated_text.contains('\u{0000}'));
        assert!(!safe.generated_text.contains('\u{0007}'));
        // Might contain '\n' and '\t' depending on input.
        assert!(!safe.warnings.is_empty());
    }

    #[test]
    fn newlines_can_be_disallowed_and_normalized_to_space() {
        let out = InternalModelOutput {
            text: "A\nB\nC".into(),
            logits: vec![],
            logprobs: None,
            tokens: vec![],
        };

        let policy = SanitizationPolicy {
            allow_newlines: false,
            ..Default::default()
        };

        let safe = InversionGuard::secure_inference_handler(out, &policy).unwrap();
        assert_eq!(safe.generated_text, "A B C");
        assert!(!safe.warnings.is_empty());
    }

    #[test]
    fn trims_whitespace_and_can_error_if_empty_after_trim() {
        let out = InternalModelOutput {
            text: "   \n\t  ".into(),
            logits: vec![],
            logprobs: None,
            tokens: vec![],
        };

        let err = InversionGuard::secure_inference_handler_default(out).unwrap_err();
        assert_eq!(err, SanitizationError::EmptyAfterSanitization);
    }

    #[test]
    fn truncates_by_char_count_not_byte_count() {
        // Multi-byte unicode: each "🦀" is 1 char, 4 bytes.
        let out = InternalModelOutput {
            text: "🦀🦀🦀🦀🦀".into(),
            logits: vec![],
            logprobs: None,
            tokens: vec![],
        };

        let policy = SanitizationPolicy {
            max_output_chars: 3,
            ..Default::default()
        };

        let safe = InversionGuard::secure_inference_handler(out, &policy).unwrap();
        assert_eq!(safe.generated_text, "🦀🦀🦀");
        assert!(safe.truncated);
    }

    #[test]
    fn redacted_debug_does_not_print_signal_values() {
        let out = InternalModelOutput {
            text: "hello".into(),
            logits: vec![1234.5678],
            logprobs: Some(vec![-0.0001]),
            tokens: vec!["he".into(), "llo".into()],
        };

        let dbg = format!("{:?}", out);
        assert!(dbg.contains("logits_len"));
        assert!(dbg.contains("logprobs_len"));
        assert!(!dbg.contains("1234.5678"));
        assert!(!dbg.contains("-0.0001"));
    }

    #[test]
    fn policy_can_disable_control_char_stripping_if_you_insist_on_chaos() {
        let out = InternalModelOutput {
            text: "A\u{0007}B".into(), // bell
            logits: vec![],
            logprobs: None,
            tokens: vec![],
        };

        let policy = SanitizationPolicy {
            strip_control_chars: false,
            ..Default::default()
        };

        let safe = InversionGuard::secure_inference_handler(out, &policy).unwrap();
        assert_eq!(safe.generated_text, "A\u{0007}B");
        // No warning because we didn't normalize anything.
        assert!(safe.warnings.is_empty());
    }
}
