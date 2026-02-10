// src/security/v52_namespace_pinning.rs
// Vector 52: Cross-Server Shadowing
// Defense: Namespace Pinning. Validates tool calls against Org_ID and Server_Hash.

use std::collections::HashMap;

pub struct NamespaceRegistry {
    // Map of "namespace.tool_name" -> "server_hash"
    pinned_tools: HashMap<String, String>,
}

impl NamespaceRegistry {
    pub fn new() -> Self {
        Self {
            pinned_tools: HashMap::new(),
        }
    }

    pub fn register_tool(&mut self, namespace: &str, tool: &str, expected_hash: &str) {
        let key = format!("{}.{}", namespace, tool);
        self.pinned_tools.insert(key, expected_hash.to_string());
    }

    pub fn validate_tool_call(&self, namespace: &str, tool: &str, provided_hash: &str) -> bool {
        let key = format!("{}.{}", namespace, tool);

        match self.pinned_tools.get(&key) {
            Some(expected) => expected == provided_hash,
            None => false, // Tool not pinned/registered
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_pinning() {
        let mut registry = NamespaceRegistry::new();
        registry.register_tool("acme_org", "delete_tmp", "hash_abc123");

        // Valid Call
        assert!(registry.validate_tool_call("acme_org", "delete_tmp", "hash_abc123"));

        // Invalid Hash (Shadowing Attempt)
        assert!(!registry.validate_tool_call("acme_org", "delete_tmp", "hash_malicious_999"));

        // Unknown Tool
        assert!(!registry.validate_tool_call("acme_org", "unknown_tool", "hash_abc123"));
    }
}
