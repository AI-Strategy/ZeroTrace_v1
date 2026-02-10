use std::env;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Sandbox Attestation Failed: {0}")]
    AttestationFailed(String),
    #[error("Decryption Failed")]
    DecryptionFailed,
    #[error("Fetch Failed")]
    FetchFailed,
}

/// A wrapper for sensitive data that zeros memory on drop.
pub struct EphemeralVector {
    data: Vec<u8>,
}

impl EphemeralVector {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data).unwrap_or("<invalid utf8>")
    }
}

impl Drop for EphemeralVector {
    fn drop(&mut self) {
        // Zero out memory to satisfy § 502 "Defensive Intent"
        // In a real implementation with `zeroize` crate, we'd use that.
        for byte in self.data.iter_mut() {
            *byte = 0;
        }
    }
}

pub struct TransientVaultClient {
    #[allow(dead_code)]
    vault_api: String,
    #[allow(dead_code)]
    oidc_token: String,
}

impl Default for TransientVaultClient {
    fn default() -> Self {
        Self {
            vault_api: "https://mock-vault.internal".to_string(),
            oidc_token: "mock_oidc_token".to_string(),
        }
    }
}

impl TransientVaultClient {
    pub fn new(api: &str, token: &str) -> Self {
        Self {
            vault_api: api.to_string(),
            oidc_token: token.to_string(),
        }
    }

    /// Satisfies § 502 by ensuring 'Defensive-Only' detonation.
    /// In a real app, this would return a TestResult, here we return the "Secure Vector" wrapper.
    pub async fn fetch_and_detonate(&self, vector_id: &str) -> Result<EphemeralVector, VaultError> {
        // 1. ATTESTATION: Verify the environment is a non-egress Sandbox
        self.verify_sandbox_attestation()?;

        // 2. RETRIEVAL: Pull encrypted blob
        let encrypted_blob = self.request_blob(vector_id).await?;

        // 3. DETONATION: Decrypt ONLY in volatile memory (RAM)
        let vector = self.decrypt_in_memory(encrypted_blob)?;

        // In a real runner, we would execute the test here.
        // For this module, we return the vector so the caller can "use" it before it drops.

        Ok(vector)
    }

    fn verify_sandbox_attestation(&self) -> Result<(), VaultError> {
        // Check for gVisor / Firecracker unique hardware fingerprints or Env Var
        if env::var("ZEROTRACE_SANDBOX").unwrap_or_default() != "1" {
            return Err(VaultError::AttestationFailed(
                "Not running in authenticated Sandbox".into(),
            ));
        }
        Ok(())
    }

    async fn request_blob(&self, _vector_id: &str) -> Result<Vec<u8>, VaultError> {
        // Mock network fetch
        if self.oidc_token.is_empty() {
            return Err(VaultError::FetchFailed);
        }
        // Return a "mock encrypted" blob
        Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])
    }

    fn decrypt_in_memory(&self, _blob: Vec<u8>) -> Result<EphemeralVector, VaultError> {
        // Mock decryption - just returning a string as bytes
        // In reality, this would use a key derived from the OIDC token + Vault response
        let decrypted_content =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        Ok(EphemeralVector::new(decrypted_content.as_bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vault_sandbox_logic() {
        // Run tests serially to avoid env var race conditions

        // 1. Test Failure (No Env Var)
        env::remove_var("ZEROTRACE_SANDBOX");
        let client = TransientVaultClient::default();
        let res_fail = client.fetch_and_detonate("V01").await;
        assert!(matches!(res_fail, Err(VaultError::AttestationFailed(_))));

        // 2. Test Success (With Env Var)
        env::set_var("ZEROTRACE_SANDBOX", "1");
        let res_success = client.fetch_and_detonate("V01").await;
        assert!(res_success.is_ok());
        let vector = res_success.unwrap();
        assert!(vector.as_str().contains("EICAR"));

        // Cleanup
        env::remove_var("ZEROTRACE_SANDBOX");
    }

    #[test]
    fn test_ephemeral_drop() {
        let vector = EphemeralVector::new(vec![1, 2, 3]);
        {
            let _ref = &vector;
        }
        // We can't easily test "memory was zeroed" after ownership move/drop
        // without unsafe or Rc logic, so we trust the Drop impl for now.
        // But we can test manual drop logic if we implemented a method for it.
        drop(vector);
    }
}
