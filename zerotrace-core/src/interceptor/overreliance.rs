use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Export Blocked: {0} citations pending human verification")]
    VerificationGateActive(usize),
    #[error("Confidence Lock: Model confidence {0:.1}% is below safety threshold {1:.1}%")]
    LowConfidenceLock(f64, f64),
}

#[derive(Serialize, Deserialize)]
pub struct VerificationState {
    pub total_citations: usize,
    // Using HashSet for unique ID verification
    pub verified_citation_ids: HashSet<String>, 
}

pub struct OverrelianceGuard {
    // Threshold below which UI must force "Yellow/Warning" state or lock
    confidence_threshold: f64,
}

impl OverrelianceGuard {
    pub fn new(confidence_threshold: f64) -> Self {
        Self { confidence_threshold }
    }

    /// Enforces "Engagement-Gated Workflow" (EXT15).
    /// Prevents export/copy-paste until all citations are verified.
    pub fn validate_export_readiness(&self, state: &VerificationState) -> Result<(), SecurityError> {
        // 1. Check if all citations have been physically 'unlocked' (clicked) by the user
        if state.verified_citation_ids.len() < state.total_citations {
            let missing = state.total_citations - state.verified_citation_ids.len();
            return Err(SecurityError::VerificationGateActive(missing));
        }

        // Log verification event would happen here in production (Auditor)
        
        Ok(())
    }

    /// Checks if the response requires "Mandatory Scrutiny" due to low confidence.
    pub fn check_confidence_lock(&self, model_confidence_score: f64) -> Result<(), SecurityError> {
        if model_confidence_score < self.confidence_threshold {
            return Err(SecurityError::LowConfidenceLock(model_confidence_score, self.confidence_threshold));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_blocked_when_unverified() {
        let guard = OverrelianceGuard::new(0.80);
        let mut verified_ids = HashSet::new();
        verified_ids.insert("cite_1".to_string());

        let state = VerificationState {
            total_citations: 3,
            verified_citation_ids: verified_ids,
        };

        // Should fail, 2 missing
        match guard.validate_export_readiness(&state) {
            Err(SecurityError::VerificationGateActive(2)) => (),
            _ => panic!("Should have blocked export with 2 missing"),
        }
    }

    #[test]
    fn test_export_allowed_when_fully_verified() {
        let guard = OverrelianceGuard::new(0.80);
        let mut verified_ids = HashSet::new();
        verified_ids.insert("cite_1".to_string());
        verified_ids.insert("cite_2".to_string());

        let state = VerificationState {
            total_citations: 2,
            verified_citation_ids: verified_ids,
        };

        assert!(guard.validate_export_readiness(&state).is_ok());
    }

    #[test]
    fn test_confidence_lock_triggers() {
        let guard = OverrelianceGuard::new(0.80); // 80% threshold
        
        // 75% confidence -> Block
        assert!(matches!(
            guard.check_confidence_lock(0.75),
            Err(SecurityError::LowConfidenceLock(0.75, 0.80))
        ));

        // 85% confidence -> Pass
        assert!(guard.check_confidence_lock(0.85).is_ok());
    }
}
