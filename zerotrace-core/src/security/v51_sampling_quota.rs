// src/security/v51_sampling_quota.rs
// Vector 51: MCP Sampling Hijack
// Defense: Sampling Token Quotas. Limits the number of tokens a tool can request per session.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub enum SecurityError {
    QuotaExceeded { limit: usize, attempted: usize },
}

pub struct SamplingGuard {
    pub max_tokens_per_session: usize,
    pub current_usage: AtomicUsize,
}

impl SamplingGuard {
    pub fn new(limit: usize) -> Self {
        Self {
            max_tokens_per_session: limit,
            current_usage: AtomicUsize::new(0),
        }
    }

    pub fn check_and_record(&self, requested_tokens: usize) -> Result<(), SecurityError> {
        let prev = self
            .current_usage
            .fetch_add(requested_tokens, Ordering::SeqCst);
        let current = prev + requested_tokens;

        // V51 Defense: Check if the tool has exceeded its sampling quota
        if current > self.max_tokens_per_session {
            return Err(SecurityError::QuotaExceeded {
                limit: self.max_tokens_per_session,
                attempted: current,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_enforcement() {
        let guard = SamplingGuard::new(100);

        assert!(guard.check_and_record(50).is_ok());
        assert!(guard.check_and_record(40).is_ok()); // Total 90

        // Next request (20) brings total to 110 > 100
        match guard.check_and_record(20) {
            Err(SecurityError::QuotaExceeded { limit, attempted }) => {
                assert_eq!(limit, 100);
                assert_eq!(attempted, 110);
            }
            _ => panic!("Should have failed with QuotaExceeded"),
        }
    }
}
