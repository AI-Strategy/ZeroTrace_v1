use crate::network::redis::RedisClient;
use anyhow::{Context, Result};
use std::sync::Arc;

pub struct CrescendoCounter {
    redis: Arc<RedisClient>,
    key_prefix: &'static str,
}

#[derive(Debug, Clone)]
pub struct EscalationDecision {
    pub tripped: bool,
    pub current_heat: i32,
    pub accumulated_heat: i32,
}

impl CrescendoCounter {
    // Tuning knobs. Make them config later if you must.
    const TTL_SECS: i64 = 60 * 60; // 1 hour “session”
    const HEAT_THRESHOLD: i32 = 10;

    // Per-turn decay: heat = floor(heat * DECAY_NUM / DECAY_DEN)
    const DECAY_NUM: i32 = 9;
    const DECAY_DEN: i32 = 10;

    // Additional cooldown when the prompt is “clean” (current_heat == 0)
    const CLEAN_COOLDOWN: i32 = 1;

    pub fn new(redis_url: impl Into<String>, redis_token: impl Into<String>) -> Self {
        CrescendoCounter {
            redis: Arc::new(RedisClient::new(&redis_url.into(), &redis_token.into())),
            key_prefix: "crescendo_heat",
        }
    }

    /// Backwards-compatible: returns `true` if risk threshold is exceeded.
    pub async fn check_escalation(&self, user_id: &str, current_prompt: &str) -> Result<bool> {
        Ok(self.check_escalation_detailed(user_id, current_prompt).await?.tripped)
    }

    /// Better API: returns the updated heat and the reason it tripped (if it did).
    pub async fn check_escalation_detailed(
        &self,
        user_id: &str,
        current_prompt: &str,
    ) -> Result<EscalationDecision> {
        let heat_key = format!("{}:{}", self.key_prefix, user_id);

        let current_heat = Self::calculate_heat(current_prompt);

        // Atomic update in Redis:
        // - applies decay
        // - adds current heat
        // - applies clean cooldown
        // - clamps >= 0
        // - sets TTL
        let new_heat = self
            .update_heat_atomic(&heat_key, current_heat)
            .await
            .context("failed to update crescendo heat")?;

        let tripped = new_heat >= Self::HEAT_THRESHOLD;

        if tripped {
            // Replace with tracing/logging in real code.
            println!(
                "Crescendo Detection: user={} heat={} threshold={}",
                user_id, new_heat, Self::HEAT_THRESHOLD
            );
        }

        Ok(EscalationDecision {
            tripped,
            current_heat,
            accumulated_heat: new_heat,
        })
    }

    async fn update_heat_atomic(&self, heat_key: &str, current_heat: i32) -> Result<i32> {
        // Single round-trip, no race conditions.
        // If your RedisClient doesn’t expose EVAL, it should.
        const LUA: &str = r#"
local key = KEYS[1]
local add = tonumber(ARGV[1]) or 0
local ttl = tonumber(ARGV[2]) or 3600
local decay_num = tonumber(ARGV[3]) or 9
local decay_den = tonumber(ARGV[4]) or 10
local clean_cooldown = tonumber(ARGV[5]) or 1

local heat = tonumber(redis.call("GET", key) or "0")

-- decay
heat = math.floor((heat * decay_num) / decay_den)

-- add
heat = heat + add

-- extra cooldown on clean turn
if add == 0 then
  heat = heat - clean_cooldown
end

-- clamp
if heat < 0 then heat = 0 end

-- store w/ TTL
redis.call("SET", key, heat, "EX", ttl)

return heat
"#;

        // You decide your RedisClient API. This is the shape you want:
        // eval_i64(script, keys, args) -> i64
        let args = vec![
            current_heat.to_string(),
            Self::TTL_SECS.to_string(),
            Self::DECAY_NUM.to_string(),
            Self::DECAY_DEN.to_string(),
            Self::CLEAN_COOLDOWN.to_string(),
        ];
        
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let out: i64 = self
            .redis
            .eval_i64(
                LUA,
                &[heat_key],
                &args_ref,
            )
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(out.clamp(0, i32::MAX as i64) as i32)
    }

    #[inline]
    pub fn calculate_heat(prompt: &str) -> i32 {
        // Faster than full Unicode lowercasing for typical attack strings (ASCII heavy).
        let s = prompt.to_ascii_lowercase();
        let mut score = 0;

        // Category triggers (boolean per category to avoid runaway repeats).
        let mut cats = 0;

        // Prompt injection / policy evasion
        if contains_any(&s, &["ignore", "bypass", "override", "jailbreak", "do anything now"]) {
            score += 3;
            cats += 1;
        }

        // Privilege escalation / system targeting
        if contains_any(&s, &["system", "admin", "root", "sudo", "developer message"]) {
            score += 3;
            cats += 1;
        }

        // Tool / execution intent
        if contains_any(&s, &["shell", "exec", "powershell", "cmd.exe", "bash", "terminal"]) {
            score += 4;
            cats += 1;
        }

        // Secrets / credentials targeting
        if contains_any(&s, &["credential", "api key", "token", "private key", "vault", "secret"]) {
            score += 3;
            cats += 1;
        }

        // Exfil indicators
        if contains_any(&s, &["exfil", "leak", "pastebin", "upload", "curl ", "wget ", "http://", "https://"]) {
            score += 2;
            cats += 1;
        }

        // Obfuscation / encoding often used to hide payloads
        if contains_any(&s, &["base64", "rot13", "obfusc", "encode", "decode"]) {
            score += 2;
            cats += 1;
        }

        // Synergy: multiple categories in one prompt is more suspicious than one keyword.
        if cats >= 3 {
            score += 2;
        }

        // Size-based pressure (cheap signal, not a verdict)
        if prompt.len() > 8_000 {
            score += 2;
        } else if prompt.len() > 2_000 {
            score += 1;
        }

        score
    }
}

#[inline]
fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heat_keywords_atomic() {
        assert_eq!(CrescendoCounter::calculate_heat("hello world"), 0);
        assert_eq!(CrescendoCounter::calculate_heat("ignore system"), 6); // 3 (ignore) + 3 (system)
        assert_eq!(CrescendoCounter::calculate_heat("sudo exec"), 7);    // 3 (sudo) + 4 (exec)
    }

    #[test]
    fn test_heat_synergy() {
        // "ignore" (3) + "system" (3) + "exec" (4) + Synergy (2) = 12
        let score = CrescendoCounter::calculate_heat("ignore system exec");
        assert_eq!(score, 12);
    }
    
    #[test]
    fn test_exfil_indicators() {
        assert_eq!(CrescendoCounter::calculate_heat("curl http://evil.com"), 2);
    }

    #[test]
    fn test_obfuscation() {
        assert_eq!(CrescendoCounter::calculate_heat("decode this base64 string"), 2);
    }

    #[test]
    fn test_length_heuristics() {
        let medium_prompt = "a".repeat(2500);
        assert_eq!(CrescendoCounter::calculate_heat(&medium_prompt), 1);

        let large_prompt = "a".repeat(8500);
        assert_eq!(CrescendoCounter::calculate_heat(&large_prompt), 2);
    }

    #[test]
    fn test_clean_prompt() {
        assert_eq!(CrescendoCounter::calculate_heat("what is the weather?"), 0);
    }
}
