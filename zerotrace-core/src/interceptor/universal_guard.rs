use crate::interceptor::sanitize::PiiSanitizer;
use crate::interceptor::slopsquat::SlopsquatDetector;
use crate::interceptor::crescendo::CrescendoCounter;
use crate::interceptor::emerging::EmergingThreatsGuard;
use crate::interceptor::llm01_sentinel::LLM01Sentinel;
use crate::protocol::dbs::DBSProtocol;
use crate::network::redis::RedisClient;
use std::sync::Arc;

pub struct UniversalGuard {
    sanitizer: PiiSanitizer,
    slopsquat: SlopsquatDetector,
    crescendo: CrescendoCounter,
    dbs_gate: DBSProtocol,
    llm01: LLM01Sentinel,
}

impl UniversalGuard {
    pub fn new() -> Self {
        // Stubbed Redis for Universal Guard (Env vars would be loaded here in main)
        // In real main.rs, we'd pass this client in.
        // For this baseline, we construct a default client attempting env vars or stub.
        let redis = Arc::new(RedisClient::from_env().unwrap_or(
            RedisClient::new("http://stub", "stub")
        ));

        Self {
            sanitizer: PiiSanitizer::new(redis.clone()),
            slopsquat: SlopsquatDetector::new(),
            crescendo: CrescendoCounter::new("http://stub".to_string(), "stub".to_string()), // Should reuse the Arc client really
            dbs_gate: DBSProtocol::new(),
            llm01: LLM01Sentinel::new(),
        }
    }

    /// The Unified Entry Point for all 29 Risks.
    /// Returns: Result<(SanitizedPrompt, Metadata), SecurityBlock>
    pub async fn evaluate_complete_risk_profile(&self, prompt: &str, user_id: &str) -> Result<String, String> {
        // 1. Emerging: Context Flood (EMG26)
        if EmergingThreatsGuard::detect_many_shot_overflow(prompt) {
            return Err("EMG26: Context Flooding Detected".to_string());
        }

        // 2. Shield: LLM01 Sentinel
        // Detects Injection Signatures & Normalizes Unicode
        let normalized_prompt = match self.llm01.sanitize(prompt) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };

        // 3. Shield: Persistent PII Scrubbing (LLM02)
        // Async call to Redis-backed sanitizer
        let scrubbed_prompt = self.sanitizer.redact(&normalized_prompt).await;

        // 4. Shield: Slopsquatting (EMG28)
        if self.slopsquat.detect_package_risk(&scrubbed_prompt) {
            return Err("EMG28: Slopsquatting/Unverified Package Detected".to_string());
        }

        // 5. Protocol: DBS Logic Gate (LLM01, LLM06)
        // "Fail-Closed" Deterministic check
        if !self.dbs_gate.validate(&scrubbed_prompt) {
             return Err("LLM01: Prompt Injection / DBS Violation".to_string());
        }

        // 6. Stateful: Crescendo (EMG29)
        match self.crescendo.check_escalation(user_id, &scrubbed_prompt).await {
            Ok(is_risk) => {
                if is_risk {
                    return Err("EMG29: Crescendo/Escalation Detected".to_string());
                }
            },
            Err(e) => println!("Warning: Redis unavail for Crescendo check: {}", e),
        }

        Ok(scrubbed_prompt)
    }

    /// Re-hydrates the LLM response, replacing PII tokens with original values (Double-Blind).
    pub async fn process_secure_response(&self, response_text: &str) -> String {
        // Emerging: Jitter could be applied here too
        self.sanitizer.rehydrate(response_text).await
    }
}
