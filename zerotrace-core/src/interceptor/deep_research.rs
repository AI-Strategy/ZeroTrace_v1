//! Deep Research submission client (production-grade).
//!
//! WHY THIS EXISTS:
//! - You want an async “deep analysis” path that can be backed by a queue or API,
//!   while keeping your core security logic deterministic and testable.
//! - Inputs are hostile. Outputs are untrusted. The network is unreliable.
//! - This module validates, redacts, logs, and normalizes everything at the boundary.
//!
//! Observability:
//! - Uses `tracing` for structured logging (JSON recommended via tracing-subscriber in your binary).
//! - Does NOT log raw signatures or context data by default.
//!
//! Suggested deps (Cargo.toml):
//! ```toml
//! [dependencies]
//! serde = { version = "1", features = ["derive"] }
//! thiserror = "1"
//! tracing = "0.1"
//! async-trait = "0.1"
//!
//! [dev-dependencies]
//! tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
//! ```
//!
//! Optional (in your binary) for JSON logs:
//! ```toml
//! tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

static REQ_ID: AtomicU64 = AtomicU64::new(1);

const DEFAULT_MAX_SIGNATURE_BYTES: usize = 512;
const DEFAULT_MAX_CONTEXT_BYTES: usize = 32 * 1024; // 32 KiB
const DEFAULT_MAX_ANALYSIS_CHARS: usize = 8 * 1024;
const DEFAULT_MAX_RULE_PATTERN_CHARS: usize = 512;

/// Controls behavior when the backend fails or returns malformed/untrusted output.
#[derive(Debug, Clone, Copy)]
pub enum FailureMode {
    /// Return a conservative fallback result indicating manual review is needed.
    FailClosed,
    /// Propagate errors to the caller.
    FailOpen,
}

impl Default for FailureMode {
    fn default() -> Self {
        FailureMode::FailClosed
    }
}

/// Configuration for deep research submissions.
///
/// WHY:
/// - Makes policy explicit and testable.
/// - Avoids magic numbers scattered across call sites.
#[derive(Debug, Clone)]
pub struct DeepResearchConfig {
    pub failure_mode: FailureMode,
    pub max_signature_bytes: usize,
    pub max_context_bytes: usize,
    pub max_analysis_chars: usize,
    pub max_rule_pattern_chars: usize,
    /// If true, include a redacted signature token in logs.
    pub log_signature_ref: bool,
}

impl Default for DeepResearchConfig {
    fn default() -> Self {
        Self {
            failure_mode: FailureMode::default(),
            max_signature_bytes: DEFAULT_MAX_SIGNATURE_BYTES,
            max_context_bytes: DEFAULT_MAX_CONTEXT_BYTES,
            max_analysis_chars: DEFAULT_MAX_ANALYSIS_CHARS,
            max_rule_pattern_chars: DEFAULT_MAX_RULE_PATTERN_CHARS,
            log_signature_ref: false,
        }
    }
}

impl DeepResearchConfig {
    pub fn validate(&self) -> Result<(), DeepResearchError> {
        if self.max_signature_bytes == 0 || self.max_signature_bytes > 16 * 1024 {
            return Err(DeepResearchError::InvalidConfig(
                "max_signature_bytes must be within 1..=16384".to_string(),
            ));
        }
        if self.max_context_bytes == 0 || self.max_context_bytes > 512 * 1024 {
            return Err(DeepResearchError::InvalidConfig(
                "max_context_bytes must be within 1..=524288".to_string(),
            ));
        }
        if self.max_analysis_chars == 0 || self.max_analysis_chars > 200_000 {
            return Err(DeepResearchError::InvalidConfig(
                "max_analysis_chars out of bounds".to_string(),
            ));
        }
        if self.max_rule_pattern_chars == 0 || self.max_rule_pattern_chars > 16 * 1024 {
            return Err(DeepResearchError::InvalidConfig(
                "max_rule_pattern_chars out of bounds".to_string(),
            ));
        }
        Ok(())
    }
}

/// Request payload. Serialize-ready for a queue or HTTP API.
#[derive(Serialize, Debug, Clone)]
pub struct DeepResearchRequest {
    pub threat_signature: String,
    pub context_data: String,
}

impl DeepResearchRequest {
    /// Validates inputs and constructs a request.
    ///
    /// WHY:
    /// - Centralizes input validation at the boundary.
    /// - Prevents unbounded payloads and control-character abuse.
    pub fn new(
        signature: &str,
        context: &str,
        cfg: &DeepResearchConfig,
    ) -> Result<Self, DeepResearchError> {
        validate_signature(signature, cfg.max_signature_bytes)?;
        validate_context(context, cfg.max_context_bytes)?;

        Ok(Self {
            threat_signature: signature.to_string(),
            context_data: context.to_string(),
        })
    }
}

/// Result payload. Deserializable from backend and also safe to return upstream.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct DeepResearchResult {
    pub is_novel_threat: bool,
    pub technical_analysis: String,
    pub recommended_rule_pattern: Option<String>,
    pub confidence_score: f32,
    pub false_positive_risk: f32, // 0.0..=1.0
}

impl DeepResearchResult {
    /// Conservative fallback when deep research fails or output is malformed.
    ///
    /// Interpretation:
    /// - Treat as “needs review”: high FP risk and no rule emitted.
    pub fn fallback(reason: impl Into<String>) -> Self {
        Self {
            is_novel_threat: true,
            technical_analysis: truncate_chars(reason.into(), DEFAULT_MAX_ANALYSIS_CHARS),
            recommended_rule_pattern: None,
            confidence_score: 0.0,
            false_positive_risk: 1.0,
        }
    }

    /// Validates and normalizes backend output (untrusted).
    ///
    /// WHY:
    /// - Backends can drift, be compromised, or return garbage.
    /// - Floats can be NaN/Inf; strings can be huge; patterns can be malicious.
    pub fn validate_and_normalize(
        mut self,
        cfg: &DeepResearchConfig,
    ) -> Result<Self, OutputValidationError> {
        // floats must be finite and clamped
        if !self.confidence_score.is_finite() {
            return Err(OutputValidationError::InvalidFloat("confidence_score".to_string()));
        }
        if !self.false_positive_risk.is_finite() {
            return Err(OutputValidationError::InvalidFloat(
                "false_positive_risk".to_string(),
            ));
        }

        self.confidence_score = self.confidence_score.clamp(0.0, 1.0);
        self.false_positive_risk = self.false_positive_risk.clamp(0.0, 1.0);

        // analysis must be non-empty and bounded
        self.technical_analysis =
            sanitize_text(&self.technical_analysis, cfg.max_analysis_chars).ok_or_else(|| {
                OutputValidationError::InvalidText("technical_analysis empty/invalid".to_string())
            })?;

        // rule pattern optional, but if present must be bounded and printable
        if let Some(p) = &self.recommended_rule_pattern {
            let cleaned = sanitize_text(p, cfg.max_rule_pattern_chars).ok_or_else(|| {
                OutputValidationError::InvalidText("recommended_rule_pattern invalid".to_string())
            })?;
            // Safety: prevent “rule injection” through absurd patterns.
            // (You should still compile/test patterns in a gated pipeline before deploying rules.)
            if cleaned.len() > cfg.max_rule_pattern_chars {
                return Err(OutputValidationError::InvalidText(
                    "recommended_rule_pattern too long".to_string(),
                ));
            }
            self.recommended_rule_pattern = Some(cleaned);
        }

        Ok(self)
    }
}

/// Backend abstraction (queue, HTTP API, whatever).
///
/// WHY:
/// - Keeps business logic independent from transport.
/// - Enables deterministic unit tests and multiple backends.
#[async_trait]
pub trait DeepResearchBackend: Send + Sync + 'static {
    async fn submit(&self, req: DeepResearchRequest) -> Result<DeepResearchResult, BackendError>;
}

/// Backend failures are intentionally opaque at the domain boundary.
#[derive(Debug, Error)]
#[error("deep research backend error")]
pub struct BackendError {
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl BackendError {
    pub fn new<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Some(Box::new(e)),
        }
    }

    pub fn without_source() -> Self {
        Self { source: None }
    }
}

/// Domain errors: specific, bounded, caller-safe.
#[derive(Debug, Error)]
pub enum DeepResearchError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("backend failure")]
    Backend(#[from] BackendError),

    #[error("backend output invalid")]
    InvalidOutput(#[from] OutputValidationError),
}

#[derive(Debug, Error)]
pub enum OutputValidationError {
    #[error("invalid float field: {0}")]
    InvalidFloat(String),

    #[error("invalid text: {0}")]
    InvalidText(String),
}

/// Orchestrator that validates input, calls backend, validates output, and logs.
#[derive(Clone)]
pub struct DeepResearchService<B: DeepResearchBackend> {
    backend: Arc<B>,
    cfg: DeepResearchConfig,
}

impl<B: DeepResearchBackend> DeepResearchService<B> {
    pub fn new(backend: Arc<B>, cfg: DeepResearchConfig) -> Result<Self, DeepResearchError> {
        cfg.validate()?;
        Ok(Self { backend, cfg })
    }

    /// Submit for analysis with strict validation and safe logging.
    ///
    /// Complexity:
    /// - Validation: O(n) time, O(1) extra space (scans input)
    /// - Backend call: dominates runtime (I/O)
    /// - Output validation: O(m) time, O(1) extra space (bounded scans)
    pub async fn submit_for_analysis(
        &self,
        signature: &str,
        context: &str,
    ) -> Result<DeepResearchResult, DeepResearchError> {
        let req_id = next_req_id();
        let sig_ref = SignatureRef(signature);

        // Validate and build request (pure)
        let req = DeepResearchRequest::new(signature, context, &self.cfg)?;

        // Log without leaking sensitive payloads.
        if self.cfg.log_signature_ref {
            info!(
                req_id,
                signature_ref = %sig_ref,
                context_len = context.len(),
                "deep research submission started"
            );
        } else {
            info!(
                req_id,
                context_len = context.len(),
                "deep research submission started"
            );
        }

        // Backend I/O
        let backend_res = self.backend.submit(req).await;

        let raw = match backend_res {
            Ok(r) => r,
            Err(e) => {
                warn!(req_id, err = %e, "deep research backend failure");
                return match self.cfg.failure_mode {
                    FailureMode::FailClosed => Ok(DeepResearchResult::fallback(
                        "Deep research backend failure; requires manual review.",
                    )),
                    FailureMode::FailOpen => Err(DeepResearchError::Backend(e)),
                };
            }
        };

        // Validate backend output (untrusted)
        let validated = match raw.validate_and_normalize(&self.cfg) {
            Ok(v) => v,
            Err(e) => {
                warn!(req_id, err = %e, "deep research output validation failed");
                return match self.cfg.failure_mode {
                    FailureMode::FailClosed => Ok(DeepResearchResult::fallback(
                        "Deep research output malformed; requires manual review.",
                    )),
                    FailureMode::FailOpen => Err(DeepResearchError::InvalidOutput(e)),
                };
            }
        };

        info!(
            req_id,
            is_novel_threat = validated.is_novel_threat,
            confidence = validated.confidence_score,
            fp_risk = validated.false_positive_risk,
            has_rule = validated.recommended_rule_pattern.is_some(),
            "deep research submission completed"
        );

        Ok(validated)
    }
}

/// A default simulated backend (your original stub), now behind a trait.
///
/// In production you’d implement a real backend (queue / HTTP) here.
#[derive(Debug, Default)]
pub struct SimulatedBackend;

#[async_trait]
impl DeepResearchBackend for SimulatedBackend {
    async fn submit(&self, req: DeepResearchRequest) -> Result<DeepResearchResult, BackendError> {
        // Stub logic maintained, but using request values.
        if req.threat_signature.contains("unknown_payload") {
            Ok(DeepResearchResult {
                is_novel_threat: true,
                technical_analysis: "Identified novel recursive-descent injection pattern."
                    .to_string(),
                recommended_rule_pattern: Some(r"(?i)recursive_descent_v2".to_string()),
                confidence_score: 0.998,
                false_positive_risk: 0.001,
            })
        } else {
            Ok(DeepResearchResult {
                is_novel_threat: false,
                technical_analysis: "Known pattern, already covered.".to_string(),
                recommended_rule_pattern: None,
                confidence_score: 1.0,
                false_positive_risk: 0.0,
            })
        }
    }
}

/// Optional convenience wrapper (kept similar to your original API).
/// Now returns `Result` so callers can decide fail-open vs fail-closed policy.
pub async fn submit_for_analysis(
    signature: &str,
    context: &str,
) -> Result<DeepResearchResult, DeepResearchError> {
    let backend = Arc::new(SimulatedBackend::default());
    let cfg = DeepResearchConfig::default();
    let svc = DeepResearchService::new(backend, cfg)?;
    svc.submit_for_analysis(signature, context).await
}

/// Input validation

fn validate_signature(signature: &str, max_bytes: usize) -> Result<(), DeepResearchError> {
    let s = signature.trim();
    if s.is_empty() {
        return Err(DeepResearchError::InvalidInput(
            "threat_signature must not be empty".to_string(),
        ));
    }
    if s.len() > max_bytes {
        return Err(DeepResearchError::InvalidInput(
            "threat_signature too large".to_string(),
        ));
    }
    // Keep it printable ASCII (no control chars, no weird whitespace).
    if !s.chars().all(|c| c.is_ascii_graphic()) {
        return Err(DeepResearchError::InvalidInput(
            "threat_signature contains disallowed characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_context(context: &str, max_bytes: usize) -> Result<(), DeepResearchError> {
    // Context can be empty in some pipelines, but huge context is a DoS vector.
    if context.len() > max_bytes {
        return Err(DeepResearchError::InvalidInput(
            "context_data too large".to_string(),
        ));
    }
    // Disallow dangerous control chars except common whitespace.
    if context.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(DeepResearchError::InvalidInput(
            "context_data contains disallowed control characters".to_string(),
        ));
    }
    Ok(())
}

/// Safe text sanitization: trims, strips dangerous control chars, bounds length.
fn sanitize_text(s: &str, max_chars: usize) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let cleaned: String = trimmed
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    Some(truncate_chars(cleaned, max_chars))
}

fn truncate_chars(mut s: String, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s;
    }
    s = s.chars().take(max_chars).collect();
    s
}

fn next_req_id() -> u64 {
    REQ_ID.fetch_add(1, Ordering::Relaxed)
}

/// Redacted signature token for logs (no raw signature leakage).
struct SignatureRef<'a>(&'a str);

impl<'a> std::fmt::Display for SignatureRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.trim();
        let prefix: String = s.chars().take(8).collect();
        write!(f, "{}…(len={})", prefix, s.len())
    }
}
