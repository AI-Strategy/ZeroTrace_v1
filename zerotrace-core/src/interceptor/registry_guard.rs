use std::collections::HashMap;
use thiserror::Error;
use std::sync::RwLock;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("V66: MCP Registry Verification Failed")]
    V66UnverifiedTool,
    #[error("V75: Identity Collision/Hijack Detected")]
    V75IdentityCollision,
}

pub struct RegistryGuard {
    // V66: The 'Golden Registry' of verified MCP Tool Hashes (Tool ID -> SHA256)
    pub verified_tools: RwLock<HashMap<String, String>>,
    // V75: Active Session Tracker (NHI Token -> Origin IP)
    pub active_sessions: RwLock<HashMap<String, String>>,
}

impl RegistryGuard {
    pub fn new() -> Self {
        Self {
            verified_tools: RwLock::new(HashMap::new()),
            active_sessions: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_tool(&self, tool_id: &str, hash: &str) {
        let mut tools = self.verified_tools.write().unwrap();
        tools.insert(tool_id.to_string(), hash.to_string());
    }

    // V66/V69: MCP Tool Verification
    // Checks if the tool signature matches our 'Golden Registry'
    pub fn authorize_tool_invocation(&self, tool_id: &str, provided_hash: &str) -> std::result::Result<(), RegistryError> {
        let tools = self.verified_tools.read().unwrap();
        
        if let Some(valid_hash) = tools.get(tool_id) {
            if valid_hash == provided_hash {
                return Ok(());
            }
        }
        
        // If not found or mismatch -> Block unverified tools (V66)
        Err(RegistryError::V66UnverifiedTool)
    }

    // V74/V75: Attestation & Identity Collision
    pub fn check_identity_health(&self, token: &str, origin_ip: &str) -> std::result::Result<(), RegistryError> {
        // V75: Check if this NHI Token is appearing from multiple 
        // geographically distant IPs simultaneously (Session Hijacking)
        let mut sessions = self.active_sessions.write().unwrap();
        
        if let Some(existing_ip) = sessions.get(token) {
            if existing_ip != origin_ip {
                // Simplified Velocity Check: If IP changes, assume collision for this vector logic
                // Real system logic: check geo-velocity
                return Err(RegistryError::V75IdentityCollision);
            }
        } else {
            sessions.insert(token.to_string(), origin_ip.to_string());
        }
        
        Ok(())
    }
}
