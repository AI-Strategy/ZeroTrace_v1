use sha2::{Sha256, Digest};
use std::collections::HashMap;

pub struct SupplyChainGuard {
    // Maps Artifact Name -> Trusted SHA256 Hash
    trusted_registry: HashMap<String, String>,
}

impl SupplyChainGuard {
    pub fn new() -> Self {
        // In reality, verify load this from a signed catalog file or env.
        let mut registry = HashMap::new();
        // Example: "golden-model-v1.bin" -> hash
        registry.insert(
            "model_v1".to_string(), 
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string() // Empty hash for demo
        );
        Self { trusted_registry: registry }
    }

    /// Verifies the integrity of a binary artifact against the Trusted Registry.
    /// Uses SHA-256 (compatible with OCI/Docker manifests).
    pub fn verify_artifact(&self, artifact_name: &str, data: &[u8]) -> Result<(), String> {
        // 1. Check if artifact is tracked
        let trusted_hash = match self.trusted_registry.get(artifact_name) {
            Some(h) => h,
            None => return Err(format!("LLM03: Unknown Artifact '{}' - Supply Chain Policy Violation", artifact_name)),
        };

        // 2. Calculate Hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let calculated_hash = hex::encode(result);

        // 3. Verify
        if calculated_hash != *trusted_hash {
            return Err(format!(
                "LLM03: Integrity Verification Failed for '{}'. Expected {}, got {}", 
                artifact_name, trusted_hash, calculated_hash
            ));
        }

        Ok(())
    }

    /// Updates the trusted registry (e.g. from a signed SBOM update).
    pub fn register_artifact(&mut self, name: &str, hash: &str) {
        self.trusted_registry.insert(name.to_string(), hash.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_artifact_verification() {
        let mut guard = SupplyChainGuard::new();
        let data = b"hello world";
        
        // Calculate hash of "hello world"
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());
        
        guard.register_artifact("hello_lib", &hash);

        assert!(guard.verify_artifact("hello_lib", data).is_ok());
    }

    #[test]
    fn test_tampered_artifact() {
        let mut guard = SupplyChainGuard::new();
        let data = b"hello world";
        let tampered_data = b"hello w0rld"; // Bit flip

        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        guard.register_artifact("core_model", &hash);

        let result = guard.verify_artifact("core_model", tampered_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Integrity Verification Failed"));
    }

    #[test]
    fn test_unknown_artifact() {
        let guard = SupplyChainGuard::new();
        let result = guard.verify_artifact("rogue_plugin", b"malware");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown Artifact"));
    }
}
