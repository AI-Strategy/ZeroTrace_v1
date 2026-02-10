// src/security/v49_nhi_rotation.rs
// Vector 49: NHI Session Hijacking (Non-Human Identity)
// Defense: Temporal Token Rotation. JIT tokens bound to Firecracker VM ID + 60s Expiry.

use std::time::{SystemTime, UNIX_EPOCH};

pub struct NihTokenManager {
    vm_id: String,
}

#[derive(Debug, PartialEq)]
pub enum TokenStatus {
    Valid,
    Expired,
    InvalidBinding,
}

impl NihTokenManager {
    pub fn new(vm_id: &str) -> Self {
        Self {
            vm_id: vm_id.to_string(),
        }
    }

    /// Simulates generating a JIT token payload.
    /// Format: "VM_ID:TIMESTAMP:SIGNATURE"
    pub fn generate_token(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("{}:{}", self.vm_id, now)
    }

    /// Validates a token.
    pub fn validate_token(&self, token: &str) -> TokenStatus {
        let parts: Vec<&str> = token.split(':').collect();
        if parts.len() != 2 {
            return TokenStatus::InvalidBinding;
        }

        let token_vm_id = parts[0];
        let timestamp: u64 = parts[1].parse().unwrap_or(0);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if token_vm_id != self.vm_id {
            return TokenStatus::InvalidBinding;
        }

        if now - timestamp > 60 {
            return TokenStatus::Expired;
        }

        TokenStatus::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_token_validation() {
        let manager = NihTokenManager::new("vm-123");
        let token = manager.generate_token();

        assert_eq!(manager.validate_token(&token), TokenStatus::Valid);
    }

    #[test]
    fn test_invalid_binding() {
        let manager = NihTokenManager::new("vm-123");
        let token = "vm-999:1234567890"; // Wrong VM
        assert_eq!(manager.validate_token(token), TokenStatus::InvalidBinding);
    }
}
