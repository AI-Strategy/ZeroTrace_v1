use thiserror::Error;

#[derive(Debug, Error)]
pub enum DriftError {
    #[error("Memory Poisoning Detected: Logic Drift {drift_value:.2} > Threshold")]
    MemoryPoisoningDetected { drift_value: f64 },
}

pub struct LogicDriftAuditor {
    baseline_logic_score: f64,
    drift_threshold: f64,
}

impl LogicDriftAuditor {
    pub fn new(baseline: f64, threshold: f64) -> Self {
        Self {
            baseline_logic_score: baseline,
            drift_threshold: threshold,
        }
    }

    /// Simulates fetching current reasoning trajectory from Neo4j
    async fn fetch_current_logic_score(&self, session_id: &str) -> f64 {
        // Mocked Neo4j Lookup
        if session_id == "poisoned_session" {
            0.2 // Significant deviation from baseline (1.0)
        } else {
            0.95 // Close to baseline
        }
    }

    pub async fn audit_reasoning_trajectory(&self, session_id: &str) -> Result<(), DriftError> {
        // 1. Fetch historical reasoning vectors from Neo4j (Mimisbrunr scoring)
        let current_score = self.fetch_current_logic_score(session_id).await;

        // 2. Detect divergence from the established 'Golden Baseline'
        let drift = (self.baseline_logic_score - current_score).abs();

        if drift > self.drift_threshold {
            // Memory Poisoning identified: The system's logic has been 're-aligned'
            return Err(DriftError::MemoryPoisoningDetected { drift_value: drift });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_normal_trajectory() {
        let auditor = LogicDriftAuditor::new(1.0, 0.2);
        assert!(auditor
            .audit_reasoning_trajectory("safe_session")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_poisoned_memory_blocked() {
        let auditor = LogicDriftAuditor::new(1.0, 0.2);
        // "poisoned_session" returns 0.2 -> drift = 0.8 > 0.2
        let res = auditor.audit_reasoning_trajectory("poisoned_session").await;
        assert!(matches!(
            res,
            Err(DriftError::MemoryPoisoningDetected { .. })
        ));
    }
}
