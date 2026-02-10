use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

#[derive(Debug)]
pub enum SecurityError {
    ModelExtractionAttackDetected,
}

pub struct ModelTheftGuard {
    // Patterns indicative of Model Distillation / Dataset Synthesis
    distillation_patterns: Vec<Regex>,
    // State for extraction detection (In-Memory for this verified implementation)
    // In production, this would be Redis-backed.
    query_history: HashMap<String, Vec<(Instant, u64)>>,
    max_distinct_queries_per_hour: usize,
}

impl ModelTheftGuard {
    pub fn new(max_distinct_queries_per_hour: usize) -> Self {
        Self {
            distillation_patterns: vec![
                Regex::new(r"(?i)generate\s+(\d+|many|all)\s+(examples|samples|rows|records)").unwrap(),
                Regex::new(r"(?i)(print|reveal|show|dump)\s+(your|system)\s+(instructions|prompt|rules)").unwrap(),
                Regex::new(r"(?i)give\s+me\s+adversarial\s+examples").unwrap(),
            ],
            query_history: HashMap::new(),
            max_distinct_queries_per_hour,
        }
    }

    /// Checks if the prompt exhibits Model Theft / Distillation characteristics (Content-based).
    pub fn check_content(&self, user_input: &str) -> bool {
        for pattern in &self.distillation_patterns {
            if pattern.is_match(user_input) {
                return true;
            }
        }
        false
    }

    /// Stateful check for high-volume distinct query extraction (Behavior-based).
    /// Tracks query diversity per user to identify 'mapping' attacks.
    pub fn detect_extraction_attempt(&mut self, user_id: &str, query: &str) -> Result<(), SecurityError> {
        let now = Instant::now();
        let query_hash = self.calculate_hash(query);
        let hour = Duration::from_secs(3600);

        // 1. Retrieve and clean history for the user
        let history = self.query_history.entry(user_id.to_string()).or_insert(Vec::new());
        // Remove old entries (older than 1 hour)
        history.retain(|(timestamp, _)| now.duration_since(*timestamp) < hour);

        // 2. Add current query 
        history.push((now, query_hash));
        
        // 3. Count distinct entries
        // We track distinct hashes to detect "diverse" probing. 
        // Repeated identical queries might be a DoS (LLM10), but diverse queries are Extraction (EXT11).
        let distinct_count = history.iter().map(|(_, hash)| hash).collect::<HashSet<_>>().len();

        if distinct_count > self.max_distinct_queries_per_hour {
            return Err(SecurityError::ModelExtractionAttackDetected); // EXT11
        }

        Ok(())
    }

    fn calculate_hash(&self, t: &str) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_detection() {
        let guard = ModelTheftGuard::new(100);
        assert!(guard.check_content("Generate 1000 examples of medical records"));
        assert!(!guard.check_content("What is the weather?"));
    }

    #[test]
    fn test_extraction_rate_limiting() {
        let mut guard = ModelTheftGuard::new(3); // Allow 3 distinct queries per hour
        let user = "attacker_01";

        // 3 Distinct queries - OK
        assert!(guard.detect_extraction_attempt(user, "Query A").is_ok());
        assert!(guard.detect_extraction_attempt(user, "Query B").is_ok());
        assert!(guard.detect_extraction_attempt(user, "Query C").is_ok());

        // 4th Distinct query - Blocked
        assert!(matches!(
            guard.detect_extraction_attempt(user, "Query D"),
            Err(SecurityError::ModelExtractionAttackDetected)
        ));
    }

    #[test]
    fn test_duplicate_queries_ignored_for_extraction() {
        let mut guard = ModelTheftGuard::new(3);
        let user = "user_02";

        // Repeated queries should not trigger *Extraction* logic (though might trigger DoS logic elsewhere)
        // Here we verify they don't count towards *distinct* threshold.
        assert!(guard.detect_extraction_attempt(user, "Query A").is_ok());
        assert!(guard.detect_extraction_attempt(user, "Query A").is_ok());
        assert!(guard.detect_extraction_attempt(user, "Query A").is_ok());
        assert!(guard.detect_extraction_attempt(user, "Query A").is_ok());
        
        // Only 1 distinct query so far.
        // Add 2 more distinct
        assert!(guard.detect_extraction_attempt(user, "Query B").is_ok());
        assert!(guard.detect_extraction_attempt(user, "Query C").is_ok());

        // Now we are at 3 distinct. Next distinct fails.
        assert!(matches!(
            guard.detect_extraction_attempt(user, "Query D"),
            Err(SecurityError::ModelExtractionAttackDetected)
        ));
    }
}
