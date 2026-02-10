use crate::network::redis::UpstashClient;
use regex::Regex;
use uuid::Uuid;
use std::sync::Arc;
use lazy_static::lazy_static;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap();
    static ref SSN_REGEX: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    static ref IPV4_REGEX: Regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    static ref KEY_REGEX: Regex = Regex::new(r"(?i)(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,})").unwrap();
}

pub struct PiiSanitizer {
    redis: Arc<UpstashClient>,
}

impl PiiSanitizer {
    pub fn new(redis: Arc<UpstashClient>) -> Self {
        Self { redis }
    }

    /// Redacts PII found in the input using Regex and stores mappings in Redis with TTL.
    /// This makes the operation ASYNC.
    pub async fn redact(&self, input: &str) -> String {
        let mut result = input.to_string();
        
        // Note: Regex replacement in Rust is typically synchronous.
        // To support async Redis calls during replacement, we need a multi-pass or 
        // a collect-then-replace approach.
        
        // 1. Identify all matches first
        let mut replacements = Vec::new();
        
        self.collect_matches(&EMAIL_REGEX, &result, "EMAIL", &mut replacements);
        self.collect_matches(&SSN_REGEX, &result, "SSN", &mut replacements);
        self.collect_matches(&IPV4_REGEX, &result, "IP", &mut replacements);
        self.collect_matches(&KEY_REGEX, &result, "SECRET_KEY", &mut replacements);

        // 2. Async Store in Redis
        for (token, original) in &replacements {
            // TTL: 24 hours (86400 seconds) - Right to be Forgotten compliance
            if let Err(e) = self.redis.set_with_ttl(token, original, 86400).await {
                println!("Error storing PII token in Redis: {}", e);
                // Fail-Safe: We still return the redacted string, 
                // but re-hydration will fail. Privacy > Utility.
            }
        }

        // 3. Apply Replacements (in reverse order of occurrence would be ideal, 
        // but string replace is safer if tokens are unique)
        for (token, original) in replacements {
            result = result.replace(&original, &token);
        }

        result
    }

    fn collect_matches(&self, re: &Regex, text: &str, pii_type: &str, acc: &mut Vec<(String, String)>) {
        for caps in re.captures_iter(text) {
            let original = caps[0].to_string();
            // Deterministic token generation? No, random for security.
            let token = format!("[{}-UUID-{}]", pii_type, Uuid::new_v4());
            acc.push((token, original));
        }
    }

    /// Re-hydrates the response using Redis lookups.
    pub async fn rehydrate(&self, input: &str) -> String {
        let mut result = input.to_string();
        
        // Scan for tokens: [TYPE-UUID-...]
        let token_regex = Regex::new(r"\[[A-Z_]+-UUID-[a-f0-9-]{36}\]").unwrap();
        
        let mut tokens_found = Vec::new();
        for caps in token_regex.captures_iter(input) {
            tokens_found.push(caps[0].to_string());
        }

        for token in tokens_found {
            match self.redis.get(&token).await {
                Ok(Some(original)) => {
                    result = result.replace(&token, &original);
                },
                _ => {
                    // If Redis fails or token expired, keep redacted.
                }
            }
        }
        
        result
    }
}
