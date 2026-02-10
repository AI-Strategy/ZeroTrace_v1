use aho_corasick::AhoCorasick;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone)]
pub struct LLM01Sentinel {
    patterns: AhoCorasick,
}

impl LLM01Sentinel {
    pub fn new() -> Self {
        // High-severity injection signatures
        // These are distinct from DBS Deterministic Rules; these are "Block immediately" byte sequences.
        let signatures = &[
            "ignore all previous", 
            "disregard all above", 
            "system prompt:", 
            "you are now in developer mode",
            "ignroe all prevoius", // Typoglycemia variant
            "ignore previous instructions"
        ];
        Self {
            patterns: AhoCorasick::new(signatures).unwrap(),
        }
    }

    /// Validates and sanitizes input against LLM01 (Prompt Injection).
    /// Returns the sanitized string (normalized + wrapped) or an Error.
    pub fn sanitize(&self, raw_input: &str) -> Result<String, String> {
        // 1. Unicode Normalization (NFKC)
        // Eliminates lookalike characters and strips zero-width spaces/invisible chars.
        // This defeats "homograph" attacks where 'A' is actually a Cyrillic character.
        let normalized: String = raw_input.nfkc().collect();
        
        // 2. Scan for Malicious Signatures (Case-Insensitive check)
        if self.patterns.find(&normalized.to_lowercase()).is_some() {
             return Err("LLM01: Injection Signature Detected (Aho-Corasick)".to_string());
        }

        // 3. Structural Demarcation (XML Tagging)
        // We wrap the user input in <user_data> tags. 
        // The System Prompt must be instructed to ONLY process content within these tags.
        Ok(format!("<user_data>{}</user_data>", normalized))
    }
}
