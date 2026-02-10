use aho_corasick::AhoCorasick;
use regex::RegexSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpeculativeError {
    #[error("Immediate Block: {0}")]
    ImmediateBlock(String),
}

#[derive(Debug, PartialEq, Clone)]
pub enum SecurityPath {
    FastPath,     // Stage 1 Clean -> <5ms
    ShieldedPath, // Stage 1 Clean + Intent Complex -> ~50ms
    AirlockPath,  // Stage 1 Clean + Intent Risky -> ~800ms
}

#[derive(Debug, PartialEq)]
pub enum MinimalIntent {
    Safe,
    Complex,
    Risky,
}

/// Mock for the Gemini 3 Flash "Minimal Thinking" Mode
pub struct Gemini3Sentry;

impl Gemini3Sentry {
    pub async fn classify_intent_minimal(&self, prompt: &str) -> MinimalIntent {
        let p = prompt.to_lowercase();
        if p.contains("code") || p.contains("deploy") || p.contains("agent") {
            MinimalIntent::Risky
        } else if p.contains("legal") || p.contains("research") {
            MinimalIntent::Complex
        } else {
            MinimalIntent::Safe
        }
    }
}

pub struct SpeculativeRouter {
    // Stage 1: Fast Patterns (Deterministic)
    canary_matcher: AhoCorasick,
    malicious_regex: RegexSet,

    // Stage 2: Semantic Router (Gemini 3 Flash)
    sentry_broker: Gemini3Sentry,
}

impl Default for SpeculativeRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl SpeculativeRouter {
    pub fn new() -> Self {
        // Initialize Aho-Corasick for Canary Tokens
        let canaries = vec!["CANARY_TOKEN_123", "SECRET_KEY_XYZ"];
        let canary_matcher = AhoCorasick::new(canaries).unwrap();

        // Initialize RegexSet for basic exploits
        let malicious_regex = RegexSet::new(&[
            r"(?i)base64", // Simplified for demo
            r"(?i)eval\(",
        ])
        .unwrap();

        Self {
            canary_matcher,
            malicious_regex,
            sentry_broker: Gemini3Sentry,
        }
    }

    pub async fn triage_request(&self, prompt: &str) -> Result<SecurityPath, SpeculativeError> {
        // --- STAGE 1: DETERMINISTIC (Sub-5ms) ---
        // Immediate Block if Canary or Static Exploit found
        if self.canary_matcher.find_iter(prompt).next().is_some() {
            return Err(SpeculativeError::ImmediateBlock(
                "Canary Leak Detected".into(),
            ));
        }

        if self.malicious_regex.is_match(prompt) {
            return Err(SpeculativeError::ImmediateBlock(
                "Known Exploit Signature".into(),
            ));
        }

        // --- STAGE 2: SEMANTIC TRIAGE (Parallel/Speculative) ---
        // If Stage 1 is clean, we use Gemini 3 Flash in 'MINIMAL' thinking mode.
        let triage_intent = self.sentry_broker.classify_intent_minimal(prompt).await;

        match triage_intent {
            MinimalIntent::Safe => Ok(SecurityPath::FastPath), // Only run 2-3 vectors
            MinimalIntent::Complex => Ok(SecurityPath::ShieldedPath), // Run 12 vectors
            MinimalIntent::Risky => Ok(SecurityPath::AirlockPath), // Run all 35 vectors
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stage1_block_canary() {
        let router = SpeculativeRouter::new();
        // Prompt containing a canary token
        let res = router.triage_request("Here is the CANARY_TOKEN_123").await;
        assert!(matches!(res, Err(SpeculativeError::ImmediateBlock(_))));
    }

    #[tokio::test]
    async fn test_stage1_block_regex() {
        let router = SpeculativeRouter::new();
        // Prompt containing "eval("
        let res = router.triage_request("Please eval(code)").await;
        assert!(matches!(res, Err(SpeculativeError::ImmediateBlock(_))));
    }

    #[tokio::test]
    async fn test_stage2_fast_path() {
        let router = SpeculativeRouter::new();
        let res = router.triage_request("Hello world").await;
        assert_eq!(res.unwrap(), SecurityPath::FastPath);
    }

    #[tokio::test]
    async fn test_stage2_shielded_path() {
        let router = SpeculativeRouter::new();
        let res = router.triage_request("Research legal contract").await;
        assert_eq!(res.unwrap(), SecurityPath::ShieldedPath);
    }

    #[tokio::test]
    async fn test_stage2_airlock_path() {
        let router = SpeculativeRouter::new();
        let res = router.triage_request("Deploy agent code").await;
        assert_eq!(res.unwrap(), SecurityPath::AirlockPath);
    }
}
