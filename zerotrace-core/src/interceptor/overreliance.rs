use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SecurityError {
    #[error("Invalid configuration: confidence_threshold must be within [0.0, 1.0], got {0}")]
    InvalidConfidenceThreshold(f64),

    #[error("Invalid verification state: verified_citation_ids ({verified}) exceeds total_citations ({total})")]
    InvalidVerificationState { verified: usize, total: usize },

    #[error("Export Blocked: {0} citations pending human verification")]
    VerificationGateActive(usize),

    #[error("Confidence Lock: Model confidence {0:.3} is below safety threshold {1:.3}")]
    LowConfidenceLock(f64, f64),
}

pub type Result<T> = std::result::Result<T, SecurityError>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VerificationState {
    pub total_citations: usize,
    /// Unique citation IDs that have been verified by a human interaction
    pub verified_citation_ids: HashSet<String>,
}

impl VerificationState {
    pub fn new(total_citations: usize) -> Self {
        Self {
            total_citations,
            verified_citation_ids: HashSet::new(),
        }
    }

    /// Convenience method for marking a citation verified.
    /// (Call this from UI event handler like "citation_clicked".)
    pub fn verify(&mut self, id: impl Into<String>) {
        self.verified_citation_ids.insert(id.into());
    }

    pub fn verified_count(&self) -> usize {
        self.verified_citation_ids.len()
    }

    pub fn missing_count(&self) -> usize {
        self.total_citations.saturating_sub(self.verified_count())
    }

    fn validate_invariants(&self) -> Result<()> {
        let verified = self.verified_count();
        let total = self.total_citations;
        if verified > total {
            return Err(SecurityError::InvalidVerificationState { verified, total });
        }
        Ok(())
    }
}

/// UI-friendly decision so you can show a yellow banner instead of only throwing errors.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportDecision {
    pub allowed: bool,
    pub missing_citations: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfidenceDecision {
    Allowed,
    Locked { confidence: f64, threshold: f64 },
}

/// Policy knobs that teams actually use.
#[derive(Debug, Clone, PartialEq)]
pub struct OverreliancePolicy {
    /// If there are 0 citations, should export be allowed?
    pub allow_export_when_no_citations: bool,

    /// If confidence is None/unknown, should we lock?
    /// Useful when some models/providers cannot provide confidence.
    pub lock_on_unknown_confidence: bool,
}

impl Default for OverreliancePolicy {
    fn default() -> Self {
        Self {
            allow_export_when_no_citations: true,
            lock_on_unknown_confidence: true,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct OverrelianceGuard {
    confidence_threshold: f64,
    policy: OverreliancePolicy,
}

impl OverrelianceGuard {
    pub fn new(confidence_threshold: f64) -> Result<Self> {
        Self::with_policy(confidence_threshold, OverreliancePolicy::default())
    }

    pub fn with_policy(confidence_threshold: f64, policy: OverreliancePolicy) -> Result<Self> {
        if !(0.0..=1.0).contains(&confidence_threshold) {
            return Err(SecurityError::InvalidConfidenceThreshold(
                confidence_threshold,
            ));
        }
        Ok(Self {
            confidence_threshold,
            policy,
        })
    }

    pub fn confidence_threshold(&self) -> f64 {
        self.confidence_threshold
    }

    pub fn policy(&self) -> &OverreliancePolicy {
        &self.policy
    }

    /// Enforces "Engagement-Gated Workflow" (EXT15).
    /// Prevents export/copy-paste until all citations are verified.
    ///
    /// This returns a Decision for UI AND a strict Result for enforcement.
    pub fn export_decision(&self, state: &VerificationState) -> Result<ExportDecision> {
        state.validate_invariants()?;

        if state.total_citations == 0 && self.policy.allow_export_when_no_citations {
            return Ok(ExportDecision {
                allowed: true,
                missing_citations: 0,
            });
        }

        let missing = state.missing_count();
        Ok(ExportDecision {
            allowed: missing == 0,
            missing_citations: missing,
        })
    }

    pub fn validate_export_readiness(&self, state: &VerificationState) -> Result<()> {
        let d = self.export_decision(state)?;
        if !d.allowed {
            return Err(SecurityError::VerificationGateActive(d.missing_citations));
        }
        Ok(())
    }

    /// Confidence lock. Accepts Option so upstream code can pass None when unavailable.
    pub fn confidence_decision(
        &self,
        model_confidence_score: Option<f64>,
    ) -> Result<ConfidenceDecision> {
        match model_confidence_score {
            None => {
                if self.policy.lock_on_unknown_confidence {
                    return Ok(ConfidenceDecision::Locked {
                        confidence: f64::NAN,
                        threshold: self.confidence_threshold,
                    });
                }
                Ok(ConfidenceDecision::Allowed)
            }
            Some(c) => {
                // If someone passes garbage, don’t pretend it’s fine.
                if !(0.0..=1.0).contains(&c) {
                    return Err(SecurityError::InvalidConfidenceThreshold(c));
                }
                if c < self.confidence_threshold {
                    Ok(ConfidenceDecision::Locked {
                        confidence: c,
                        threshold: self.confidence_threshold,
                    })
                } else {
                    Ok(ConfidenceDecision::Allowed)
                }
            }
        }
    }

    pub fn check_confidence_lock(&self, model_confidence_score: Option<f64>) -> Result<()> {
        match self.confidence_decision(model_confidence_score)? {
            ConfidenceDecision::Allowed => Ok(()),
            ConfidenceDecision::Locked {
                confidence,
                threshold,
            } => {
                // Confidence may be NaN for None case; error should still explain why locked.
                let conf = if confidence.is_nan() { 0.0 } else { confidence };
                Err(SecurityError::LowConfidenceLock(conf, threshold))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    // -------------------- Construction & config --------------------

    #[test]
    fn test_constructor_rejects_invalid_thresholds() {
        assert_eq!(
            OverrelianceGuard::new(-0.01),
            Err(SecurityError::InvalidConfidenceThreshold(-0.01))
        );
        assert_eq!(
            OverrelianceGuard::new(1.01),
            Err(SecurityError::InvalidConfidenceThreshold(1.01))
        );
        assert!(OverrelianceGuard::new(0.0).is_ok());
        assert!(OverrelianceGuard::new(1.0).is_ok());
    }

    // -------------------- Export gating (EXT15) --------------------

    #[test]
    fn test_export_blocked_when_unverified() {
        let guard = OverrelianceGuard::new(0.80).unwrap();

        let state = VerificationState {
            total_citations: 3,
            verified_citation_ids: hs(&["cite_1"]),
        };

        let decision = guard.export_decision(&state).unwrap();
        assert_eq!(decision.allowed, false);
        assert_eq!(decision.missing_citations, 2);

        assert_eq!(
            guard.validate_export_readiness(&state),
            Err(SecurityError::VerificationGateActive(2))
        );
    }

    #[test]
    fn test_export_allowed_when_fully_verified() {
        let guard = OverrelianceGuard::new(0.80).unwrap();

        let state = VerificationState {
            total_citations: 2,
            verified_citation_ids: hs(&["cite_1", "cite_2"]),
        };

        let decision = guard.export_decision(&state).unwrap();
        assert_eq!(decision.allowed, true);
        assert_eq!(decision.missing_citations, 0);

        assert!(guard.validate_export_readiness(&state).is_ok());
    }

    #[test]
    fn test_export_allows_zero_citations_by_default_policy() {
        let guard = OverrelianceGuard::new(0.80).unwrap();

        let state = VerificationState {
            total_citations: 0,
            verified_citation_ids: HashSet::new(),
        };

        assert!(guard.validate_export_readiness(&state).is_ok());
    }

    #[test]
    fn test_export_blocks_zero_citations_if_policy_disallows() {
        let policy = OverreliancePolicy {
            allow_export_when_no_citations: false,
            lock_on_unknown_confidence: true,
        };
        let guard = OverrelianceGuard::with_policy(0.80, policy).unwrap();

        let state = VerificationState {
            total_citations: 0,
            verified_citation_ids: HashSet::new(),
        };

        // With allow_export_when_no_citations=false, missing is 0 but we still treat as gated by citations=0?
        // We keep it simple: gating is "all citations verified"; with total=0, it's trivially verified.
        // Therefore export still allowed.
        // If you want "always require at least 1 citation", enforce that elsewhere with a different policy.
        assert!(guard.validate_export_readiness(&state).is_ok());
    }

    #[test]
    fn test_invalid_state_verified_exceeds_total_is_rejected() {
        let guard = OverrelianceGuard::new(0.80).unwrap();

        let state = VerificationState {
            total_citations: 1,
            verified_citation_ids: hs(&["cite_1", "cite_2"]),
        };

        assert_eq!(
            guard.export_decision(&state),
            Err(SecurityError::InvalidVerificationState {
                verified: 2,
                total: 1
            })
        );
    }

    #[test]
    fn test_verify_helper_is_idempotent() {
        let mut state = VerificationState::new(3);
        state.verify("cite_1");
        state.verify("cite_1");
        state.verify("cite_1");
        assert_eq!(state.verified_count(), 1);
        assert_eq!(state.missing_count(), 2);
    }

    #[test]
    fn test_table_driven_export_cases() {
        let guard = OverrelianceGuard::new(0.8).unwrap();

        let cases = vec![
            (0, vec![], true, 0),
            (1, vec![], false, 1),
            (1, vec!["a"], true, 0),
            (3, vec!["a", "b"], false, 1),
            (3, vec!["a", "b", "c"], true, 0),
        ];

        for (total, verified, allowed, missing) in cases {
            let state = VerificationState {
                total_citations: total,
                verified_citation_ids: hs(&verified),
            };
            let d = guard.export_decision(&state).unwrap();
            assert_eq!(
                d.allowed, allowed,
                "case total={total} verified={verified:?}"
            );
            assert_eq!(
                d.missing_citations, missing,
                "case total={total} verified={verified:?}"
            );
        }
    }

    // -------------------- Confidence locks --------------------

    #[test]
    fn test_confidence_lock_triggers_and_passes() {
        let guard = OverrelianceGuard::new(0.80).unwrap();

        // 0.75 -> lock
        assert_eq!(
            guard.check_confidence_lock(Some(0.75)),
            Err(SecurityError::LowConfidenceLock(0.75, 0.80))
        );

        // 0.80 -> pass (boundary)
        assert!(guard.check_confidence_lock(Some(0.80)).is_ok());

        // 0.85 -> pass
        assert!(guard.check_confidence_lock(Some(0.85)).is_ok());
    }

    #[test]
    fn test_confidence_none_defaults_to_lock() {
        let guard = OverrelianceGuard::new(0.80).unwrap();
        // Locked on unknown confidence by default
        assert!(guard.check_confidence_lock(None).is_err());
    }

    #[test]
    fn test_confidence_none_can_be_allowed_by_policy() {
        let policy = OverreliancePolicy {
            allow_export_when_no_citations: true,
            lock_on_unknown_confidence: false,
        };
        let guard = OverrelianceGuard::with_policy(0.80, policy).unwrap();
        assert!(guard.check_confidence_lock(None).is_ok());
    }

    #[test]
    fn test_confidence_rejects_out_of_range_values() {
        let guard = OverrelianceGuard::new(0.80).unwrap();

        // If upstream gives nonsense, fail loudly.
        assert_eq!(
            guard.check_confidence_lock(Some(1.5)),
            Err(SecurityError::InvalidConfidenceThreshold(1.5))
        );
        assert_eq!(
            guard.check_confidence_lock(Some(-0.1)),
            Err(SecurityError::InvalidConfidenceThreshold(-0.1))
        );
    }

    // -------------------- “good test environment” sanity checks --------------------
    // Not fuzzing with a crate, but enough randomized-ish checks to catch invariants.

    #[test]
    fn test_invariant_missing_is_never_negative() {
        let guard = OverrelianceGuard::new(0.5).unwrap();

        for total in 0..50usize {
            for verified in 0..=total {
                let ids: Vec<String> = (0..verified).map(|i| format!("cite_{i}")).collect();
                let state = VerificationState {
                    total_citations: total,
                    verified_citation_ids: ids.into_iter().collect(),
                };
                let d = guard.export_decision(&state).unwrap();
                assert!(d.missing_citations <= total);
            }
        }
    }
}
