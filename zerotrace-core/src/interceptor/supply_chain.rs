use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

const MAX_ARTIFACT_NAME_LEN: usize = 128;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SupplyChainError {
    #[error("Invalid artifact name")]
    InvalidArtifactName,

    #[error("Unknown artifact '{0}'")]
    UnknownArtifact(String),

    #[error("Invalid trusted SHA-256 format for '{0}'")]
    InvalidTrustedHashFormat(String),

    #[error("Integrity verification failed for '{0}'")]
    HashMismatch(String),

    #[error("Registry lock poisoned")]
    RegistryPoisoned,
}

#[derive(Debug, Clone)]
pub struct ArtifactRecord {
    sha256: [u8; 32],
    // Optional metadata you may want later:
    // pub version: Option<String>,
    // pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactName(String);

impl ArtifactName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Tight but not annoying. Keep it simple for humans and agents.
    pub fn parse(input: &str) -> Result<Self, SupplyChainError> {
        let s = input.trim();
        if s.is_empty() || s.len() > MAX_ARTIFACT_NAME_LEN {
            return Err(SupplyChainError::InvalidArtifactName);
        }

        // Allow: alnum, ., _, -, / (for namespaces), :
        // Disallow whitespace and weirdness.
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
        {
            return Err(SupplyChainError::InvalidArtifactName);
        }

        Ok(Self(s.to_string()))
    }
}

/// Thread-safe guard so you can refresh catalogs without restarting.
pub struct SupplyChainGuard {
    registry: Arc<RwLock<HashMap<ArtifactName, ArtifactRecord>>>,
}

impl Default for SupplyChainGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyChainGuard {
    pub fn new() -> Self {
        let mut map = HashMap::new();

        // Example entry (empty content hash) for demo; in production, load from signed catalog.
        // sha256("") = e3b0c442...
        let demo_name = ArtifactName::parse("model_v1").expect("static name valid");
        let demo_hash =
            parse_sha256_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .expect("static hash valid");

        map.insert(demo_name, ArtifactRecord { sha256: demo_hash });

        Self {
            registry: Arc::new(RwLock::new(map)),
        }
    }

    pub fn with_registry(registry: HashMap<String, String>) -> Result<Self, SupplyChainError> {
        let mut map = HashMap::new();
        for (name, hex) in registry {
            let n = ArtifactName::parse(&name)?;
            let h = parse_sha256_hex(&hex)
                .map_err(|_| SupplyChainError::InvalidTrustedHashFormat(name))?;
            map.insert(n, ArtifactRecord { sha256: h });
        }
        Ok(Self {
            registry: Arc::new(RwLock::new(map)),
        })
    }

    /// Registers or updates an artifact hash in the trusted registry.
    /// This is where you would enforce "catalog must be signed" upstream.
    pub fn register_artifact_hex(
        &self,
        artifact_name: &str,
        sha256_hex: &str,
    ) -> Result<(), SupplyChainError> {
        let name = ArtifactName::parse(artifact_name)?;
        let digest = parse_sha256_hex(sha256_hex)
            .map_err(|_| SupplyChainError::InvalidTrustedHashFormat(artifact_name.to_string()))?;

        let mut reg = self
            .registry
            .write()
            .map_err(|_| SupplyChainError::RegistryPoisoned)?;
        reg.insert(name, ArtifactRecord { sha256: digest });
        Ok(())
    }

    /// Verifies the integrity of an artifact against the trusted registry.
    /// Uses SHA-256 (works with OCI/Docker digest workflows).
    pub fn verify_artifact(
        &self,
        artifact_name: &str,
        data: &[u8],
    ) -> Result<(), SupplyChainError> {
        let name = ArtifactName::parse(artifact_name)?;

        let expected = {
            let reg = self
                .registry
                .read()
                .map_err(|_| SupplyChainError::RegistryPoisoned)?;
            let rec = reg
                .get(&name)
                .ok_or_else(|| SupplyChainError::UnknownArtifact(name.as_str().to_string()))?;
            rec.sha256
        };

        let got = sha256_bytes(data);

        // Constant-time compare so failures don’t leak partial info.
        if !constant_time_eq(&expected, &got) {
            return Err(SupplyChainError::HashMismatch(name.as_str().to_string()));
        }

        Ok(())
    }

    /// Optional: returns how many artifacts are tracked.
    pub fn registry_len(&self) -> Result<usize, SupplyChainError> {
        let reg = self
            .registry
            .read()
            .map_err(|_| SupplyChainError::RegistryPoisoned)?;
        Ok(reg.len())
    }
}

// -------------------- Helpers --------------------

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Parses a 64-char hex SHA-256 digest into 32 bytes.
/// Accepts uppercase/lowercase.
fn parse_sha256_hex(s: &str) -> Result<[u8; 32], ()> {
    let t = s.trim();
    if t.len() != 64 {
        return Err(());
    }
    // hex::decode is case-insensitive but will fail on invalid chars.
    let bytes = hex::decode(t).map_err(|_| ())?;
    if bytes.len() != 32 {
        return Err(());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Constant-time byte comparison (no early return).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// -------------------- Tests --------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(sha256_bytes(data))
    }

    #[test]
    fn test_artifact_name_validation() {
        assert!(ArtifactName::parse("model_v1").is_ok());
        assert!(ArtifactName::parse("namespace/model:v1").is_ok());
        assert!(ArtifactName::parse("  model_v1  ").is_ok());

        assert!(ArtifactName::parse("").is_err());
        assert!(ArtifactName::parse("   ").is_err());
        assert!(ArtifactName::parse("bad name").is_err()); // space
        assert!(ArtifactName::parse("bad\tname").is_err());
        assert!(ArtifactName::parse("weird💥name").is_err());
        assert!(ArtifactName::parse(&"a".repeat(MAX_ARTIFACT_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn test_hash_parse_valid_lower_upper() {
        let empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(parse_sha256_hex(empty_hex).is_ok());

        let upper = empty_hex.to_ascii_uppercase();
        assert!(parse_sha256_hex(&upper).is_ok());
    }

    #[test]
    fn test_hash_parse_rejects_bad_length_or_chars() {
        assert!(parse_sha256_hex("abc").is_err());
        assert!(parse_sha256_hex(&"a".repeat(63)).is_err());
        assert!(parse_sha256_hex(&"a".repeat(65)).is_err());
        assert!(parse_sha256_hex(&format!("{}{}", "g", "0".repeat(63))).is_err());
        // invalid hex char
    }

    #[test]
    fn test_unknown_artifact() {
        let guard = SupplyChainGuard::new();
        let err = guard
            .verify_artifact("rogue_plugin", b"malware")
            .unwrap_err();
        assert!(matches!(err, SupplyChainError::UnknownArtifact(_)));
    }

    #[test]
    fn test_known_artifact_verification_ok() {
        let guard = SupplyChainGuard::new();
        let data = b"hello world";
        let digest = sha256_hex(data);

        guard.register_artifact_hex("hello_lib", &digest).unwrap();
        assert!(guard.verify_artifact("hello_lib", data).is_ok());
    }

    #[test]
    fn test_tampered_artifact_fails() {
        let guard = SupplyChainGuard::new();
        let data = b"hello world";
        let tampered = b"hello w0rld";
        let digest = sha256_hex(data);

        guard.register_artifact_hex("core_model", &digest).unwrap();
        let err = guard.verify_artifact("core_model", tampered).unwrap_err();
        assert!(matches!(err, SupplyChainError::HashMismatch(_)));
    }

    #[test]
    fn test_empty_artifact_hash() {
        let guard = SupplyChainGuard::new();
        let empty = b"";
        let digest = sha256_hex(empty);

        guard.register_artifact_hex("empty_blob", &digest).unwrap();
        assert!(guard.verify_artifact("empty_blob", empty).is_ok());
    }

    #[test]
    fn test_register_rejects_invalid_hash_format() {
        let guard = SupplyChainGuard::new();
        let err = guard
            .register_artifact_hex("bad_hash_artifact", "not-a-hash")
            .unwrap_err();
        assert!(matches!(err, SupplyChainError::InvalidTrustedHashFormat(_)));
    }

    #[test]
    fn test_register_rejects_invalid_artifact_name() {
        let guard = SupplyChainGuard::new();
        let digest = sha256_hex(b"abc");
        let err = guard
            .register_artifact_hex("bad name", &digest)
            .unwrap_err();
        assert_eq!(err, SupplyChainError::InvalidArtifactName);
    }

    #[test]
    fn test_registry_update_overwrites_previous_hash() {
        let guard = SupplyChainGuard::new();

        let v1 = b"version1";
        let v2 = b"version2";

        let h1 = sha256_hex(v1);
        let h2 = sha256_hex(v2);

        guard.register_artifact_hex("thing", &h1).unwrap();
        assert!(guard.verify_artifact("thing", v1).is_ok());
        assert!(guard.verify_artifact("thing", v2).is_err());

        guard.register_artifact_hex("thing", &h2).unwrap();
        assert!(guard.verify_artifact("thing", v2).is_ok());
        assert!(guard.verify_artifact("thing", v1).is_err());
    }

    #[test]
    fn test_constant_time_eq_correctness() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let mut c = [1u8; 32];
        c[31] = 2;

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1u8; 31]));
    }

    #[test]
    fn test_concurrent_reads_smoke() {
        let guard = SupplyChainGuard::new();
        let data = b"concurrency";
        let digest = sha256_hex(data);
        guard.register_artifact_hex("blob", &digest).unwrap();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let g = guard.registry.clone();
            handles.push(thread::spawn(move || {
                // Rebuild a lightweight view using the same registry Arc
                let guard = SupplyChainGuard { registry: g };
                for _ in 0..100 {
                    guard.verify_artifact("blob", data).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_with_registry_builder() {
        let mut reg = HashMap::new();
        reg.insert("libA".to_string(), sha256_hex(b"A"));
        reg.insert("libB".to_string(), sha256_hex(b"B"));

        let guard = SupplyChainGuard::with_registry(reg).unwrap();
        assert!(guard.verify_artifact("libA", b"A").is_ok());
        assert!(guard.verify_artifact("libB", b"B").is_ok());
        assert!(guard.verify_artifact("libB", b"A").is_err());
    }
}
