use std::collections::HashMap;
use crate::security::emg21::SecurityError; // Reusing error type or we can extend it

// Extend SecurityError for EMG23
#[derive(Debug, thiserror::Error)]
pub enum IngestionError {
    #[error("Source not found in reputation ledger")]
    SourceNotFound,
    #[error("Low authority source blocked to prevent poisoning (Sybil Risk)")]
    LowAuthorityPoisoningRisk,
    #[error("Consensus check failed for partner source")]
    ConsensusFailed,
    #[error("Security error: {0}")]
    Security(#[from] SecurityError),
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum AuthorityLevel {
    VerifiedFirm,   // Bar-certified/Firm Key (Highest Trust)
    AuthorizedPartner, // Trusted Vendor (Needs Consensus)
    UnverifiedSource,  // Public Web/Community (Blocked/Sandboxed)
}

/// Trait for Consensus Engine (Proof-of-Authority).
/// In production, this would query Neo4j or a raft cluster.
#[async_trait::async_trait]
pub trait ConsensusEngine: Send + Sync {
    /// Returns true if the data payload is verified by a quorum of nodes.
    async fn verify_consensus(&self, data_payload: &str) -> bool;
}

pub struct IngestionGuard<C> 
where C: ConsensusEngine
{
    reputation_ledger: HashMap<String, AuthorityLevel>,
    consensus_engine: C,
}

impl<C> IngestionGuard<C>
where C: ConsensusEngine
{
    pub fn new(consensus_engine: C) -> Self {
        Self {
            reputation_ledger: HashMap::new(),
            consensus_engine,
        }
    }

    pub fn register_source(&mut self, source_id: String, level: AuthorityLevel) {
        self.reputation_ledger.insert(source_id, level);
    }

    /// Validates if a source is allowed to ingest data into the authoritative graph.
    /// 
    /// Policies:
    /// - **VerifiedFirm**: Allowed immediately.
    /// - **AuthorizedPartner**: Allowed ONLY if consensus passes.
    /// - **UnverifiedSource**: REJECTED.
    pub async fn validate_ingestion_source(&self, source_id: &str, data_payload: &str) -> Result<(), IngestionError> {
        let level = self.reputation_ledger.get(source_id)
            .ok_or(IngestionError::SourceNotFound)?;

        match level {
            AuthorityLevel::VerifiedFirm => {
                // Golden Source - Bypass consensus
                Ok(())
            },
            AuthorityLevel::AuthorizedPartner => {
                // Partner - Require Consensus
                if self.consensus_engine.verify_consensus(data_payload).await {
                    Ok(())
                } else {
                    Err(IngestionError::ConsensusFailed)
                }
            },
            AuthorityLevel::UnverifiedSource => {
                // Community/Public - Block to prevent Sybil/Poisoning
                Err(IngestionError::LowAuthorityPoisoningRisk)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockConsensus {
        should_pass: bool,
    }

    #[async_trait::async_trait]
    impl ConsensusEngine for MockConsensus {
        async fn verify_consensus(&self, _data: &str) -> bool {
            self.should_pass
        }
    }

    #[tokio::test]
    async fn test_verified_firm_bypass() {
        let consensus = MockConsensus { should_pass: false }; // Should ignore this
        let mut guard = IngestionGuard::new(consensus);
        guard.register_source("law_firm_a".to_string(), AuthorityLevel::VerifiedFirm);

        let result = guard.validate_ingestion_source("law_firm_a", "payload").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_partner_needs_consensus_pass() {
        let consensus = MockConsensus { should_pass: true };
        let mut guard = IngestionGuard::new(consensus);
        guard.register_source("vendor_b".to_string(), AuthorityLevel::AuthorizedPartner);

        let result = guard.validate_ingestion_source("vendor_b", "payload").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_partner_needs_consensus_fail() {
        let consensus = MockConsensus { should_pass: false };
        let mut guard = IngestionGuard::new(consensus);
        guard.register_source("vendor_b".to_string(), AuthorityLevel::AuthorizedPartner);

        let result = guard.validate_ingestion_source("vendor_b", "payload").await;
        assert!(matches!(result, Err(IngestionError::ConsensusFailed)));
    }

    #[tokio::test]
    async fn test_unverified_blocked() {
        let consensus = MockConsensus { should_pass: true }; // Irrelevant
        let mut guard = IngestionGuard::new(consensus);
        guard.register_source("anon_user".to_string(), AuthorityLevel::UnverifiedSource);

        let result = guard.validate_ingestion_source("anon_user", "payload").await;
        assert!(matches!(result, Err(IngestionError::LowAuthorityPoisoningRisk)));
    }
}
