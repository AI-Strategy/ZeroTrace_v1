use crate::interceptor::crescendo::CrescendoCounter;
use crate::interceptor::emerging::EmergingThreatsGuard;
use crate::interceptor::llm01_sentinel::LLM01Sentinel;
use crate::interceptor::sanitize::PiiSanitizer;
use crate::interceptor::slopsquat::SlopsquatDetector;
use crate::network::redis::RedisClient;
use crate::protocol::dbs::DBSProtocol;
use std::sync::Arc;

pub struct UniversalGuard {
    sanitizer: PiiSanitizer,
    slopsquat: SlopsquatDetector,
    crescendo: CrescendoCounter<RedisClient>,
    dbs_gate: DBSProtocol,
    llm01: LLM01Sentinel,
    emerging: EmergingThreatsGuard,
}

impl UniversalGuard {
    pub fn new() -> Self {
        // Stubbed Redis for Universal Guard (Env vars would be loaded here in main)
        // In real main.rs, we'd pass this client in.
        // For this baseline, we construct a default client attempting env vars or stub.
        let redis =
            Arc::new(RedisClient::from_env().unwrap_or(RedisClient::new("http://stub", "stub")));

        // Default Config for Crescendo
        let crescendo_cfg = crate::interceptor::crescendo::CrescendoConfig::default();

        Self {
            sanitizer: PiiSanitizer::new(redis.clone()),
            slopsquat: SlopsquatDetector::new(),
            crescendo: CrescendoCounter::with_client(redis.clone(), crescendo_cfg)
                .expect("Invalid Crescendo Config"),
            dbs_gate: DBSProtocol::new(),
            llm01: LLM01Sentinel::new(),
            emerging: EmergingThreatsGuard::new(Default::default())
                .expect("Invalid Default Emerging Threats Config"),
        }
    }

    /// The Unified Entry Point for all 29 Risks.
    /// Returns: Result<(SanitizedPrompt, Metadata), SecurityBlock>
    pub async fn evaluate_complete_risk_profile(
        &self,
        prompt: &str,
        user_id: &str,
    ) -> Result<String, String> {
        // 1. Emerging: Context Flood (EMG26)
        if let Ok(assessment) = self.emerging.assess_many_shot_overflow(prompt) {
            if assessment.tripped {
                return Err("EMG26: Context Flooding Detected".to_string());
            }
        }

        // 2. Shield: LLM01 Sentinel
        // Detects Injection Signatures & Normalizes Unicode
        let normalized_prompt = match self.llm01.sanitize(prompt) {
            Ok(p) => p,
            Err(e) => return Err(e.to_string()),
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
        match self
            .crescendo
            .check_escalation(user_id, &scrubbed_prompt)
            .await
        {
            Ok(is_risk) => {
                if is_risk {
                    return Err("EMG29: Crescendo/Escalation Detected".to_string());
                }
            }
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
