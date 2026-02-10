use strsim::levenshtein;
use std::collections::HashSet;

pub struct TyposquatEngine {
    protected_domains: HashSet<String>,
    threshold: usize,
}

impl TyposquatEngine {
    pub fn new(protected_domains: Vec<String>, threshold: usize) -> Self {
        let mut set = HashSet::new();
        for domain in protected_domains {
            set.insert(domain.to_lowercase());
        }
        Self {
            protected_domains: set,
            threshold,
        }
    }

    /// Checks if the input contains any typosquats of protected domains.
    /// Returns a list of (detected_word, target_domain) tuples.
    pub fn check(&self, input: &str) -> Vec<(String, String)> {
        let mut detections = Vec::new();
        
        // Simple tokenization by whitespace (in production, use a proper tokenizer)
        let tokens: Vec<&str> = input.split_whitespace().collect();

        for token in tokens {
            let token_lower = token.to_lowercase();
            
            // Skip exact matches (authorized use)
            if self.protected_domains.contains(&token_lower) {
                continue;
            }

            for target in &self.protected_domains {
                let distance = levenshtein(&token_lower, target);
                
                // Heuristic: If distance is small relative to length, flag it.
                // e.g. "g00gle" (len 6) vs "google" (len 6) -> dist 2 (o->0, o->0)
                // dist check: > 0 to avoid exact matches, <= threshold
                if distance > 0 && distance <= self.threshold {
                    // specific check for length to avoid short word false positives
                    if target.len() > 4 { 
                        detections.push((token.to_string(), target.clone()));
                    }
                }
            }
        }
        detections
    }

    pub fn is_typosquat(&self, input: &str) -> bool {
        !self.check(input).is_empty()
    }

    /// Placeholder for homoglyph detection (e.g. Cyrillic 'a' vs Latin 'a')
    pub fn check_homoglyphs(&self, input: &str) -> Vec<String> {
        // This requires a crate like `unicode-security` or a custom map.
        // For now, we stub it.
        Vec::new()
    }
}

pub fn scan_for_anomalies(input: &str) -> Vec<String> {
    let mut anomalies = Vec::new();
    
    // Initialize engine (in production, this would be a static or managed state)
    let engine = TyposquatEngine::new(
        vec!["google.com".to_string(), "zerotrace.ai".to_string(), "openai.com".to_string()],
        2
    );

    let squats = engine.check(input);
    for (bad, target) in squats {
        anomalies.push(format!("TYPOSQUAT_DETECTED: {} (targets {})", bad, target));
    }

    if input.contains("ignore previous instructions") {
        anomalies.push("JAILBREAK_ATTEMPT".to_string());
    }
    
    anomalies
}
