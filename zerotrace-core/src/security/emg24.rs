use ndarray::Array1;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReasoningError {
    #[error("Max reasoning depth exceeded: {0}")]
    MaxDepthExceeded(usize),
    #[error("Infinite reasoning loop detected (Similarity: {0:.4})")]
    InfiniteLoopDetected(f32),
    #[error("Dimension mismatch in embeddings")]
    DimensionMismatch,
}

pub struct ReasoningGuard {
    max_recursion_depth: usize,
    similarity_threshold: f32,
}

impl ReasoningGuard {
    /// Create a new ReasoningGuard.
    /// * `max_recursion_depth`: Maximum allowed steps (e.g., 5-10).
    /// * `similarity_threshold`: threshold for loop detection (e.g., 0.98).
    pub fn new(max_recursion_depth: usize, similarity_threshold: f32) -> Self {
        Self {
            max_recursion_depth,
            similarity_threshold,
        }
    }

    /// Checks if reasoning should continue based on depth and history.
    ///
    /// * `current_depth`: Current step index (0-based).
    /// * `current_embedding`: Embedding of the current thought.
    /// * `history_embeddings`: Embeddings of previous thoughts.
    pub fn check_step(
        &self,
        current_depth: usize,
        current_embedding: &Array1<f32>,
        history_embeddings: &[Array1<f32>],
    ) -> Result<(), ReasoningError> {
        // 1. Check Hard Depth Limit
        if current_depth >= self.max_recursion_depth {
            return Err(ReasoningError::MaxDepthExceeded(self.max_recursion_depth));
        }

        // 2. Detect Logic Loops (Semantic Similarity)
        // Compare current step against all previous steps.
        // If it's too similar to *any* previous step, it's a loop.
        for prev_embedding in history_embeddings {
            let similarity = cosine_similarity(current_embedding, prev_embedding)?;

            if similarity > self.similarity_threshold {
                return Err(ReasoningError::InfiniteLoopDetected(similarity));
            }
        }

        Ok(())
    }
}

/// Calculates Cosine Similarity between two vectors.
fn cosine_similarity(a: &Array1<f32>, b: &Array1<f32>) -> Result<f32, ReasoningError> {
    if a.len() != b.len() {
        return Err(ReasoningError::DimensionMismatch);
    }

    let dot_product = a.dot(b);
    let norm_a = a.dot(a).sqrt();
    let norm_b = b.dot(b).sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return Ok(0.0); // Handle zero vectors safely
    }

    Ok(dot_product / (norm_a * norm_b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::array;

    #[test]
    fn test_max_depth_exceeded() {
        let guard = ReasoningGuard::new(5, 0.99);
        let emb = array![1.0, 0.0];
        // Depth 5 should fail (0-indexed 0..4 = 5 steps)
        assert!(guard.check_step(5, &emb, &[]).is_err());
        assert!(guard.check_step(4, &emb, &[]).is_ok());
    }

    #[test]
    fn test_loop_detection() {
        let guard = ReasoningGuard::new(10, 0.95);
        let history = vec![array![1.0, 0.0, 0.0]];

        let current = array![0.99, 0.05, 0.0]; // Very similar to history[0]

        let result = guard.check_step(1, &current, &history);
        match result {
            Err(ReasoningError::InfiniteLoopDetected(sim)) => assert!(sim > 0.95),
            _ => panic!("Should have detected loop"),
        }
    }

    #[test]
    fn test_no_loop_distinct_thoughts() {
        let guard = ReasoningGuard::new(10, 0.95);
        let history = vec![array![1.0, 0.0]];

        let current = array![0.0, 1.0]; // Orthogonal (Similarity 0.0)

        assert!(guard.check_step(1, &current, &history).is_ok());
    }
}
