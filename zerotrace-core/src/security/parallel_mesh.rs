use crate::security::speculative_router::{SecurityPath, SpeculativeError, SpeculativeRouter};
use thiserror::Error;
use tokio::time::{sleep, Duration};

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("Security Blocked: {0}")]
    SecurityBlock(String),
    #[error("Inference Failed: {0}")]
    InferenceError(String),
}

pub struct ParallelMesh {
    router: SpeculativeRouter,
}

impl Default for ParallelMesh {
    fn default() -> Self {
        Self::new()
    }
}

impl ParallelMesh {
    pub fn new() -> Self {
        Self {
            router: SpeculativeRouter::new(),
        }
    }

    /// The "Scatter-Gather" Intercept logic.
    /// Spawns parallel tasks and races them using `tokio::select!`.
    pub async fn secure_execute(&self, prompt: &str) -> Result<String, MeshError> {
        // Task A: Deterministic & Semantic Triage
        let security_task = self.router.triage_request(prompt);

        // Task C: Stateful Audit
        let drift_task = async {
            sleep(Duration::from_millis(30)).await;
            if prompt.contains("poison") {
                Err("Drift Detected")
            } else {
                Ok("Clean")
            }
        };

        // Task D: Speculative Inference
        // In a real app, this would be a JoinHandle we can abort.
        let inference_task = async {
            sleep(Duration::from_millis(100)).await;
            Ok::<String, String>(format!("Response to: {}", prompt))
        };

        // The Guard: Check Security and Drift concurrently
        let security_guard = async {
            let (sec_res, drift_res) = tokio::join!(security_task, drift_task);

            // Check Router
            if let Err(SpeculativeError::ImmediateBlock(msg)) = sec_res {
                return Err(MeshError::SecurityBlock(msg));
            }

            // Check Drift
            if let Err(msg) = drift_res {
                return Err(MeshError::SecurityBlock(format!(
                    "Stateful Audit Failed: {}",
                    msg
                )));
            }

            Ok(())
        };

        // Race: Guard vs Inference?
        // No, we want Guard to *complete* before we release Inference.
        // But we want Inference to *start* executing.
        // So we join them, but if Guard fails, we return Error (effectively dropping Inference Result).

        let (guard_res, inference_res) = tokio::join!(security_guard, inference_task);

        match guard_res {
            Ok(_) => match inference_res {
                Ok(response) => Ok(response),
                Err(e) => Err(MeshError::InferenceError(e)),
            },
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mesh_fast_block() {
        let mesh = ParallelMesh::new();
        let res = mesh.secure_execute("CANARY_TOKEN_123").await;
        // Should block immediately via Router (Task A)
        assert!(matches!(res, Err(MeshError::SecurityBlock(msg)) if msg.contains("Canary")));
    }

    #[tokio::test]
    async fn test_mesh_drift_block() {
        let mesh = ParallelMesh::new();
        let res = mesh.secure_execute("deployment poison logic").await;
        // Should block via Drift Check (Task C)
        assert!(
            matches!(res, Err(MeshError::SecurityBlock(msg)) if msg.contains("Stateful Audit"))
        );
    }

    #[tokio::test]
    async fn test_mesh_clean_execution() {
        let mesh = ParallelMesh::new();
        let res = mesh.secure_execute("Hello World").await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "Response to: Hello World");
    }
}
