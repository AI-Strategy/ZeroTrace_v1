use thiserror::Error;
use tokio::time::{sleep, Duration};

#[derive(Debug, Error)]
pub enum BehavioralError {
    #[error("Persistent Drift Detected (ASI: {asi}): {mitigation}")]
    PersistentDriftDetected { asi: f64, mitigation: String },
}

pub struct BehavioralGuard {
    pub stability_index_min: f64, // ASI (Agent Stability Index) threshold
}

impl Default for BehavioralGuard {
    fn default() -> Self {
        Self::new(0.85) // Minimal acceptable stability
    }
}

impl BehavioralGuard {
    pub fn new(min_stability: f64) -> Self {
        Self {
            stability_index_min: min_stability,
        }
    }

    /// Verifies Agent Stability Index (ASI) to detect Drift (V38) and Poisoning (V37).
    pub async fn verify_agent_stability(&self, agent_id: &str) -> Result<(), BehavioralError> {
        // Query Neo4j for the Agent Stability Index (ASI)
        // ASI measures consistency in tool usage, tone, and logic over time.
        // Mocked for V1 implementation.
        let current_asi = self.mock_get_asi_score(agent_id).await;

        if current_asi < self.stability_index_min {
            // Behavioral Drift detected: The agent has moved away from its safety alignment.
            // This is the mitigation for V37 (Memory Poisoning) and V38 (Coordination Drift).
            return Err(BehavioralError::PersistentDriftDetected {
                asi: current_asi,
                mitigation: "Force Episodic Memory Consolidation (Reset)".to_string(),
            });
        }
        Ok(())
    }

    async fn mock_get_asi_score(&self, agent_id: &str) -> f64 {
        // Simulate a DB lookup latency
        sleep(Duration::from_millis(20)).await;

        if agent_id.contains("poisoned") || agent_id.contains("start_travel_agent") {
            0.45 // Drifted/Poisoned
        } else {
            0.98 // Stable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_v37_poisoning_detection() {
        let guard = BehavioralGuard::new(0.8);
        let res = guard.verify_agent_stability("agent_poisoned_007").await;
        assert!(matches!(
            res,
            Err(BehavioralError::PersistentDriftDetected { .. })
        ));
    }

    #[tokio::test]
    async fn test_v38_coordination_drift_detection() {
        let guard = BehavioralGuard::new(0.9);
        // "Travel Agent" is a low-trust agent often targeted (as per threat model)
        let res = guard.verify_agent_stability("start_travel_agent_v1").await;
        assert!(matches!(
            res,
            Err(BehavioralError::PersistentDriftDetected { .. })
        ));
    }

    #[tokio::test]
    async fn test_clean_agent() {
        let guard = BehavioralGuard::new(0.8);
        let res = guard.verify_agent_stability("chief_of_staff_v1").await;
        assert!(res.is_ok());
    }
}
