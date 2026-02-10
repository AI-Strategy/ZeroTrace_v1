use serde::Deserialize;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("Manifest file not found: {0}")]
    FileNotFound(String),
    #[error("Failed to parse manifest JSON: {0}")]
    ParseError(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Deserialize, Debug, Clone)]
pub struct SecurityVector {
    pub id: String,
    pub tier: u8, // 1: Fast, 2: Amber, 3: Airlock
    pub action: String,
}

pub fn load_manifest(path: &str) -> Result<Vec<SecurityVector>, ManifestError> {
    if !Path::new(path).exists() {
        return Err(ManifestError::FileNotFound(path.to_string()));
    }

    let raw_json = fs::read_to_string(path)?;

    // In a real scenario, we would verify the hash of raw_json here against a known good hash
    // before parsing to ensure integrity (Phase 3: OCI Registry Lock).

    let vectors: Vec<SecurityVector> =
        serde_json::from_str(&raw_json).map_err(|e| ManifestError::ParseError(e.to_string()))?;

    Ok(vectors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_valid_manifest() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let json_content = r#"[
            {"id": "LLM01", "tier": 1, "action": "Block"},
            {"id": "V39", "tier": 3, "action": "Freeze"}
        ]"#;
        write!(temp_file, "{}", json_content).unwrap();

        let path = temp_file.path().to_str().unwrap();
        let vectors = load_manifest(path).expect("Should load valid manifest");

        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].id, "LLM01");
        assert_eq!(vectors[1].tier, 3);
    }

    #[test]
    fn test_missing_file() {
        let result = load_manifest("non_existent_file.json");
        assert!(matches!(result, Err(ManifestError::FileNotFound(_))));
    }

    #[test]
    fn test_invalid_json() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "INVALID JSON").unwrap();

        let path = temp_file.path().to_str().unwrap();
        let result = load_manifest(path);

        assert!(matches!(result, Err(ManifestError::ParseError(_))));
    }
}
