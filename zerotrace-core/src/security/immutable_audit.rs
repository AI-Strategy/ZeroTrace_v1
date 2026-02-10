use chrono::Utc;
use sha2::{Sha256, Digest};
use std::fmt;

pub struct AuditEntry {
    pub timestamp: String,
    pub vector_id: String,
    pub payload_hash: String,
    pub result: String, // e.g., "BLOCKED", "CAUGHT_BY_V36"
}

impl fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] Vector: {} | Hash: {} | Result: {}", 
               self.timestamp, self.vector_id, self.payload_hash, self.result)
    }
}

pub struct WormLedger;

impl WormLedger {
    pub fn create_entry(vector_id: &str, payload: &[u8], result: &str) -> AuditEntry {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        
        AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            vector_id: vector_id.to_string(),
            payload_hash: format!("{:x}", hasher.finalize()),
            result: result.to_string(),
        }
    }

    /// Appends the entry to the WORM storage
    pub fn commit(entry: &AuditEntry) {
        // In production, this writes to a tamper-evident cloud log 
        // or a local file with an append-only attribute (chattr +a)
        // For V1, we log to stdout which is captured by the centralized logging driver
        println!("[AUDIT COMMIT] {}", entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_hashing() {
        let payload = b"malicious_payload";
        let entry = WormLedger::create_entry("V39", payload, "BLOCKED");
        
        // Known SHA256 of "malicious_payload"
        // echo -n "malicious_payload" | sha256sum
        // 8d1f...
        
        assert!(!entry.payload_hash.is_empty());
        assert_eq!(entry.vector_id, "V39");
        assert_eq!(entry.result, "BLOCKED");
    }

    #[test]
    fn test_audit_timestamp() {
        let entry = WormLedger::create_entry("V40", b"test", "OK");
        assert!(entry.timestamp.contains("T")); // ISO8601
        assert!(entry.timestamp.contains("Z") || entry.timestamp.contains("+"));
    }
}
