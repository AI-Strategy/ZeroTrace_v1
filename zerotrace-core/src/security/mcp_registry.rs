use blake3::Hasher;
use std::collections::HashMap;
use thiserror::Error;
use hex;

#[derive(Debug, Error)]
pub enum McpError {
    #[error("Shadow Escape Detected: Unauthorized Tool '{0}'")]
    ShadowEscapeDetected(String),
}

pub struct McpRegistry {
    // Whitelist: Map of Tool Name -> Valid Manifest Hash
    authorized_tools: HashMap<String, String>,
}

impl Default for McpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl McpRegistry {
    pub fn new() -> Self {
        // Initialize with known safe tool hashes (Mocked for testing)
        let mut tools = HashMap::new();
        // Example: "safe-tool" -> "mock_safe_hash"
        tools.insert(
            "safe-tool".to_string(), 
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262".to_string() 
        );
        
        Self {
            authorized_tools: tools,
        }
    }

    pub fn verify_and_register(&self, tool_name: &str, manifest_content: &str) -> Result<(), McpError> {
        // 1. Generate hash of the incoming MCP tool manifest
        let mut hasher = Hasher::new();
        hasher.update(manifest_content.as_bytes());
        let manifest_hash = hasher.finalize().to_hex().to_string();

        // 2. Check against the cryptographic whitelist
        match self.authorized_tools.get(tool_name) {
            Some(valid_hash) if *valid_hash == manifest_hash => {
                // Verified
                Ok(())
            },
            _ => Err(McpError::ShadowEscapeDetected(tool_name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tool_registration() {
        let registry = McpRegistry::new();
        let tool_name = "safe-tool";
        let manifest = "content-that-hashes-to-af1349..."; // BLAKE3 hash of "safe-content" is actually needed here.
        
        // Let's re-calculate hash for "safe-content" to make test deterministic
        let mut hasher = Hasher::new();
        hasher.update(b"safe-content");
        let valid_hash = hasher.finalize().to_hex().to_string();
        
        // Re-inject into registry for test
        let mut test_registry = McpRegistry::new();
        test_registry.authorized_tools.insert(tool_name.to_string(), valid_hash);

        assert!(test_registry.verify_and_register(tool_name, "safe-content").is_ok());
    }

    #[test]
    fn test_shadow_tool_blocked() {
        let registry = McpRegistry::new();
        let res = registry.verify_and_register("malicious-tool", "eject-core");
        assert!(matches!(res, Err(McpError::ShadowEscapeDetected(_))));
    }
}
