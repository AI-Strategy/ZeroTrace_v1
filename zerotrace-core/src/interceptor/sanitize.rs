use aho_corasick::AhoCorasick;
use dashmap::DashMap;
use uuid::Uuid;
use std::sync::Arc;
use lazy_static::lazy_static; // Assuming we add lazy_static or use OnceLock in real impl

pub struct PiiSanitizer {
    patterns: Vec<String>,
    ac: AhoCorasick,
    // Maps {REDACTED_UUID} -> "Original PII"
    // Using DashMap for high-concurrency access during streaming
    token_map: Arc<DashMap<String, String>>,
}

impl PiiSanitizer {
    pub fn new(patterns: Vec<String>) -> Self {
        let ac = AhoCorasick::new(&patterns).unwrap();
        Self {
            patterns,
            ac,
            token_map: Arc::new(DashMap::new()),
        }
    }

    /// Redacts PII found in the input using Aho-Corasick for multi-pattern matching.
    /// Replaces with a UUID token and stores the mapping.
    pub fn redact(&self, input: &str) -> String {
        let mut result = input.to_string();
        
        // Find all matches
        let matches: Vec<_> = self.ac.find_iter(input).collect();
        
        // Iterate in reverse to avoid index shifting issues
        for mat in matches.iter().rev() {
            let start = mat.start();
            let end = mat.end();
            let pii_value = &input[start..end];
            
            // Generate a secure token
            let token = format!("[PII-UUID-{}]", Uuid::new_v4());
            
            // Store mapping
            self.token_map.insert(token.clone(), pii_value.to_string());
            
            // Replace in string
            result.replace_range(start..end, &token);
        }
        
        result
    }

    /// Re-hydrates the response by replacing tokens with original PII.
    /// This is the "Double-Blind" return trip.
    pub fn rehydrate(&self, input: &str) -> String {
        let mut result = input.to_string();
        
        // In a real implementation, we would regex scan for [PII-UUID-...] tokens
        // and look them up. For this stub, we iterate the map (inefficient for large maps, 
        // but explicit for demonstration).
        for entry in self.token_map.iter() {
            let token = entry.key();
            let original = entry.value();
            result = result.replace(token, original);
        }
        
        result
    }
}
