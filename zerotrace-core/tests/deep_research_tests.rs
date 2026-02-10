use std::sync::Arc;

use async_trait::async_trait;

use zerotrace_core::interceptor::deep_research::{
    BackendError, DeepResearchBackend, DeepResearchConfig, DeepResearchError, DeepResearchRequest,
    DeepResearchResult, DeepResearchService, FailureMode, SimulatedBackend,
};

#[tokio::test]
async fn happy_path_known_pattern() {
    let backend = Arc::new(SimulatedBackend::default());
    let cfg = DeepResearchConfig::default();
    let svc = DeepResearchService::new(backend, cfg).unwrap();

    let out = svc
        .submit_for_analysis("known_payload_v1", "context")
        .await
        .unwrap();

    assert!(!out.is_novel_threat);
    assert!(out.recommended_rule_pattern.is_none());
    assert_eq!(out.confidence_score, 1.0);
    assert_eq!(out.false_positive_risk, 0.0);
}

#[tokio::test]
async fn happy_path_novel_pattern() {
    let backend = Arc::new(SimulatedBackend::default());
    let cfg = DeepResearchConfig::default();
    let svc = DeepResearchService::new(backend, cfg).unwrap();

    let out = svc
        .submit_for_analysis("unknown_payload_v2", "context")
        .await
        .unwrap();

    assert!(out.is_novel_threat);
    assert!(out.recommended_rule_pattern.is_some());
    assert!(out.confidence_score > 0.9);
}

#[tokio::test]
async fn rejects_empty_signature() {
    let backend = Arc::new(SimulatedBackend::default());
    let cfg = DeepResearchConfig::default();
    let svc = DeepResearchService::new(backend, cfg).unwrap();

    let err = svc.submit_for_analysis("   ", "context").await.unwrap_err();
    match err {
        DeepResearchError::InvalidInput(_) => {}
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_context_over_limit() {
    let backend = Arc::new(SimulatedBackend::default());
    let mut cfg = DeepResearchConfig::default();
    cfg.max_context_bytes = 10;
    let svc = DeepResearchService::new(backend, cfg).unwrap();

    let err = svc
        .submit_for_analysis("sig_ok", "this is too long")
        .await
        .unwrap_err();

    match err {
        DeepResearchError::InvalidInput(_) => {}
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[derive(Default)]
struct MaliciousBackend;

#[async_trait]
impl DeepResearchBackend for MaliciousBackend {
    async fn submit(&self, _req: DeepResearchRequest) -> Result<DeepResearchResult, BackendError> {
        // NaN + empty analysis should fail output validation
        Ok(DeepResearchResult {
            is_novel_threat: true,
            technical_analysis: "   ".to_string(),
            recommended_rule_pattern: Some("\u{0000}bad".to_string()),
            confidence_score: f32::NAN,
            false_positive_risk: f32::INFINITY,
        })
    }
}

#[tokio::test]
async fn fail_closed_returns_fallback_on_malformed_output() {
    let backend = Arc::new(MaliciousBackend::default());
    let mut cfg = DeepResearchConfig::default();
    cfg.failure_mode = FailureMode::FailClosed;
    let svc = DeepResearchService::new(backend, cfg).unwrap();

    let out = svc
        .submit_for_analysis("sig_ok", "context_ok")
        .await
        .unwrap();

    assert!(out.is_novel_threat);
    assert_eq!(out.confidence_score, 0.0);
    assert_eq!(out.false_positive_risk, 1.0);
    assert!(out.recommended_rule_pattern.is_none());
    assert!(!out.technical_analysis.is_empty());
}
