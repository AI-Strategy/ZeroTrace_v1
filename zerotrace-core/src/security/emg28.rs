use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("Enclave attestation failed: {0}")]
    AttestationFailed(String),
    #[error("HSM Key Retrieval failed: {0}")]
    KeyRetrievalFailed(String),
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// Represents the in-memory, decrypted model weights.
/// In a real TEE, this memory would be encrypted at the hardware level.
pub struct ModelHandle {
    pub id: String,
    pub is_loaded: bool,
}

/// Trait to verify the environment (e.g., AWS Nitro, Intel SGX).
#[async_trait::async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Returns true if the environment is a verified secure enclave.
    async fn verify_enclave(&self) -> Result<bool, IntegrityError>;
}

/// Trait to interface with a Hardware Security Module (HSM).
#[async_trait::async_trait]
pub trait KeyManager: Send + Sync {
    /// Retrieves the decryption key for a specific model ID.
    /// In reality, this key would never leave the enclave's secure memory.
    async fn get_decryption_key(&self, model_id: &str) -> Result<Vec<u8>, IntegrityError>;
}

pub struct WeightIntegrityGuard<A, K>
where
    A: AttestationProvider,
    K: KeyManager,
{
    attestation_provider: A,
    key_manager: K,
}

impl<A, K> WeightIntegrityGuard<A, K>
where
    A: AttestationProvider,
    K: KeyManager,
{
    pub fn new(attestation_provider: A, key_manager: K) -> Self {
        Self {
            attestation_provider,
            key_manager,
        }
    }

    /// Verifies the environment and loads the model weights into volatile memory.
    /// This prevents "cold boot" attacks or disk harvesting by ensuring weights
    /// never touch the persistent disk and are only decrypted in a verified enclave.
    pub async fn verify_and_load(&self, model_id: &str) -> Result<ModelHandle, IntegrityError> {
        // 1. Verify Enclave Attestation
        match self.attestation_provider.verify_enclave().await {
            Ok(true) => {} // Proceed
            Ok(false) => {
                return Err(IntegrityError::AttestationFailed(
                    "Verification returned false".into(),
                ))
            }
            Err(e) => return Err(e),
        }

        // 2. Retrieve Key from HSM (simulated)
        // If we are not in an enclave, the HSM should refuse this connection,
        // but we double check attestation first.
        let _key = self.key_manager.get_decryption_key(model_id).await?;

        // 3. "Load" the model (Simulated)
        // In reality: decrypt_blob(encrypted_weights, key) -> RAM
        Ok(ModelHandle {
            id: model_id.to_string(),
            is_loaded: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAttestation {
        should_pass: bool,
    }

    #[async_trait::async_trait]
    impl AttestationProvider for MockAttestation {
        async fn verify_enclave(&self) -> Result<bool, IntegrityError> {
            Ok(self.should_pass)
        }
    }

    struct MockHSM {
        has_key: bool,
    }

    #[async_trait::async_trait]
    impl KeyManager for MockHSM {
        async fn get_decryption_key(&self, _model_id: &str) -> Result<Vec<u8>, IntegrityError> {
            if self.has_key {
                Ok(vec![0u8; 32]) // AES-256 key
            } else {
                Err(IntegrityError::KeyRetrievalFailed("Key not found".into()))
            }
        }
    }

    #[tokio::test]
    async fn test_load_success_in_enclave() {
        let attestation = MockAttestation { should_pass: true };
        let hsm = MockHSM { has_key: true };
        let guard = WeightIntegrityGuard::new(attestation, hsm);

        let result = guard.verify_and_load("legal-gpt-v4").await;
        assert!(result.is_ok());
        let handle = result.unwrap();
        assert_eq!(handle.id, "legal-gpt-v4");
        assert!(handle.is_loaded);
    }

    #[tokio::test]
    async fn test_load_fail_outside_enclave() {
        let attestation = MockAttestation { should_pass: false }; // Not in enclave
        let hsm = MockHSM { has_key: true };
        let guard = WeightIntegrityGuard::new(attestation, hsm);

        let result = guard.verify_and_load("legal-gpt-v4").await;
        assert!(matches!(result, Err(IntegrityError::AttestationFailed(_))));
    }

    #[tokio::test]
    async fn test_load_fail_missing_key() {
        let attestation = MockAttestation { should_pass: true };
        let hsm = MockHSM { has_key: false }; // Key missing/revoked
        let guard = WeightIntegrityGuard::new(attestation, hsm);

        let result = guard.verify_and_load("legal-gpt-v4").await;
        assert!(matches!(result, Err(IntegrityError::KeyRetrievalFailed(_))));
    }
}
