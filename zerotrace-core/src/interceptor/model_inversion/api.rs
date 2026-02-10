use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct InvocationContext {
    pub actor: String,
    pub request_id: String,
}

impl InvocationContext {
    pub fn new(actor: impl Into<String>, request_id: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            request_id: request_id.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SanitizationPolicy {
    pub max_output_chars: usize,
    pub strip_control_chars: bool,
    pub allow_newlines: bool,
}

impl Default for SanitizationPolicy {
    fn default() -> Self {
        Self {
            max_output_chars: 8_000,
            strip_control_chars: true,
            allow_newlines: true,
        }
    }
}

/// Safe response returned to clients.
/// EXT18: strictly excludes logits/logprobs/tokens.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SanitizedResponse {
    pub generated_text: String,

    #[serde(default)]
    pub truncated: bool,

    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SanitizationError {
    #[error("Backend JSON parse error: {0}")]
    ParseError(String),

    #[error("Backend payload invalid: {0}")]
    InvalidBackendPayload(String),

    #[error("Sanitized output empty after processing")]
    EmptyAfterSanitization,
}
