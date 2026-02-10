use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("Classification Failed")]
    ClassificationError,
    #[error("Security Violation: {0}")]
    SecurityViolation(String),
    #[error("Drift Calculation Failed")]
    DriftCalculationError,
}

#[derive(Debug, PartialEq, Clone)]
pub enum SecurityWorkflow {
    WorkflowA_FastPath,     // Transactional: Static checks, <15ms
    WorkflowB_ShieldedPath, // Inquisitive: Neo4j Drift + Egress Scrub, ~120ms
    WorkflowC_AirlockPath,  // Agentic: Full 32-Vector Scan + Sandbox, >800ms
}

#[derive(Debug, PartialEq, Clone)]
pub enum Intent {
    Transactional,
    Inquisitive,
    Agentic,
}

/// Mock client for Gemini 3 Flash (The new standard)
pub struct Gemini3FlashRouter;

impl Gemini3FlashRouter {
    pub async fn classify_intent(&self, prompt: &str) -> Intent {
        // Mocking the "Intelligence-Weighted" triage
        let p = prompt.to_lowercase();
        if p.contains("hello") || p.contains("hey") || p.contains("weather") {
            Intent::Transactional
        } else if p.contains("legal")
            || p.contains("contract")
            || p.contains("finance")
            || p.contains("research")
        {
            Intent::Inquisitive
        } else if p.contains("code") || p.contains("deploy") || p.contains("agent") {
            Intent::Agentic
        } else {
            Intent::Inquisitive // Default safe fallback
        }
    }
}

/// Trait for calculating conversational drift (EMG29) via Neo4j
#[async_trait]
pub trait DriftCalculator: Send + Sync {
    async fn calculate_drift(&self, session_id: &str) -> Result<f64, BrokerError>;
}

pub struct MockNeo4jDriftCalculator;

#[async_trait]
impl DriftCalculator for MockNeo4jDriftCalculator {
    async fn calculate_drift(&self, session_id: &str) -> Result<f64, BrokerError> {
        // Mock logic: session_id "risky_session" has high drift
        if session_id == "risky_session" {
            Ok(0.85) // High drift > 0.7
        } else {
            Ok(0.1) // Low drift
        }
    }
}

pub struct SentryBroker {
    pub router: Gemini3FlashRouter,
    pub drift_calculator: Arc<dyn DriftCalculator>,
    pub drift_threshold: f64,
}

impl SentryBroker {
    pub fn new(drift_calculator: Arc<dyn DriftCalculator>) -> Self {
        Self {
            router: Gemini3FlashRouter,
            drift_calculator,
            drift_threshold: 0.7,
        }
    }

    /// Process the request through the Context-Aware Asynchronous Mesh.
    /// Implementation of Speculative Triage.
    pub async fn process_request(
        &self,
        user_prompt: &str,
        session_id: &str,
    ) -> Result<(String, SecurityWorkflow), BrokerError> {
        // 1. Triage the request to select the Workflow based on Intent
        let intent = self.router.classify_intent(user_prompt).await;

        match intent {
            Intent::Transactional => {
                // WORKFLOW A: Fast-Path
                // Bypass Drift Check for raw speed (Static Rust checks only)
                self.run_workflow_a(user_prompt).await
            }
            Intent::Inquisitive => {
                // WORKFLOW B: Shielded-Path
                // Check Drift + Egress Scrubbing
                let drift_score = self.drift_calculator.calculate_drift(session_id).await?;
                if drift_score > self.drift_threshold {
                    // Escalation: High drift forces Airlock
                    self.run_workflow_c(user_prompt, drift_score).await
                } else {
                    self.run_workflow_b(user_prompt, drift_score).await
                }
            }
            Intent::Agentic => {
                // WORKFLOW C: Airlock-Path
                // Full Scan regardless of drift
                let drift_score = self.drift_calculator.calculate_drift(session_id).await?;
                self.run_workflow_c(user_prompt, drift_score).await
            }
        }
    }

    async fn run_workflow_a(
        &self,
        _prompt: &str,
    ) -> Result<(String, SecurityWorkflow), BrokerError> {
        println!("[WORKFLOW A] Fast-Path: Transactional Intent. Running Static Rust Checks...");
        // In real impl: AhoCorasick::find(), RateLimiter::check()
        Ok((
            "Passed Workflow A".to_string(),
            SecurityWorkflow::WorkflowA_FastPath,
        ))
    }

    async fn run_workflow_b(
        &self,
        _prompt: &str,
        drift: f64,
    ) -> Result<(String, SecurityWorkflow), BrokerError> {
        println!("[WORKFLOW B] Shielded-Path: Inquisitive Intent. Drift: {:.2}. Running Neo4j + Egress Scrub...", drift);
        // In real impl: EgressScrubber::scrub()
        Ok((
            "Passed Workflow B".to_string(),
            SecurityWorkflow::WorkflowB_ShieldedPath,
        ))
    }

    async fn run_workflow_c(
        &self,
        _prompt: &str,
        drift: f64,
    ) -> Result<(String, SecurityWorkflow), BrokerError> {
        println!("[WORKFLOW C] Airlock-Path: Agentic/High-Risk Intent. Drift: {:.2}. Running Full 32-Vector Scan + Sandbox...", drift);
        println!("[NOTICE] High-Security Verification in Progress (Latency +800ms)...");
        // In real impl: Sandbox::exec(), Full Suite
        Ok((
            "Passed Workflow C".to_string(),
            SecurityWorkflow::WorkflowC_AirlockPath,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_workflow_a_transactional() {
        let calculator = Arc::new(MockNeo4jDriftCalculator);
        let broker = SentryBroker::new(calculator);

        let (res, workflow) = broker
            .process_request("Hello world", "any_session")
            .await
            .unwrap();
        assert_eq!(res, "Passed Workflow A");
        assert_eq!(workflow, SecurityWorkflow::WorkflowA_FastPath);
    }

    #[tokio::test]
    async fn test_workflow_b_inquisitive() {
        let calculator = Arc::new(MockNeo4jDriftCalculator);
        let broker = SentryBroker::new(calculator);

        let (res, workflow) = broker
            .process_request("Research legal contract", "safe_session")
            .await
            .unwrap();
        assert_eq!(res, "Passed Workflow B");
        assert_eq!(workflow, SecurityWorkflow::WorkflowB_ShieldedPath);
    }

    #[tokio::test]
    async fn test_workflow_c_agentic() {
        let calculator = Arc::new(MockNeo4jDriftCalculator);
        let broker = SentryBroker::new(calculator);

        let (res, workflow) = broker
            .process_request("Deploy code agent", "safe_session")
            .await
            .unwrap();
        assert_eq!(res, "Passed Workflow C");
        assert_eq!(workflow, SecurityWorkflow::WorkflowC_AirlockPath);
    }

    #[tokio::test]
    async fn test_workflow_b_escalation_to_c() {
        let calculator = Arc::new(MockNeo4jDriftCalculator);
        let broker = SentryBroker::new(calculator);

        // "Research" (Inquisitive) but "risky_session" (High Drift) -> Should escalate to C
        let (res, workflow) = broker
            .process_request("Research something", "risky_session")
            .await
            .unwrap();
        assert_eq!(res, "Passed Workflow C");
        assert_eq!(workflow, SecurityWorkflow::WorkflowC_AirlockPath);
    }
}
