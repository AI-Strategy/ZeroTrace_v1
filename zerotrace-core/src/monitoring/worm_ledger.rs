use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct LedgerEntry {
    pub vector_id: String,
    pub result: String,
    pub timestamp: u64,
}

pub struct WormLedger {
    entries: Arc<Mutex<Vec<LedgerEntry>>>,
}

impl WormLedger {
    pub async fn init() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn record_entry(&self, vector_id: &str, result: &str) {
        let mut entries = self.entries.lock().await;
        entries.push(LedgerEntry {
            vector_id: vector_id.to_string(),
            result: result.to_string(),
            timestamp: 0, // Mock timestamp
        });
    }

    pub async fn get_last_entry(&self) -> LedgerEntry {
        let entries = self.entries.lock().await;
        entries.last().cloned().unwrap_or(LedgerEntry {
            vector_id: "NONE".to_string(),
            result: "NONE".to_string(),
            timestamp: 0,
        })
    }
}
