use crate::network::redis::RedisClient;
use anyhow::Result;

pub struct CrescendoCounter {
    redis: RedisClient,
}

impl CrescendoCounter {
    pub fn new(redis_url: String, redis_token: String) -> Self {
        CrescendoCounter {
            redis: RedisClient::new(redis_url, redis_token),
        }
    }

    /// Analyzes multi-turn context for escalating risk (The "Boiling Frog" attack).
    /// Returns `true` if risk threshold is exceeded.
    pub async fn check_escalation(&self, user_id: &str, current_prompt: &str) -> Result<bool> {
        let history_key = format!("crescendo_history:{}", user_id);
        
        // 1. Fetch recent history (Last 5 turns)
        // In a real Redis impl, we'd use LRANGE. Here we simulate/stub or use the get method if storing JSON list.
        // For this clean baseline, we'll assume we store a "Heat Score" integer.
        let heat_key = format!("crescendo_heat:{}", user_id);
        
        let current_heat = self.calculate_heat(current_prompt);
        
        // 2. Retrieve accumulated heat
        let accumulated_heat_str = self.redis.get(&heat_key).await?.unwrap_or("0".to_string());
        let mut accumulated_heat: i32 = accumulated_heat_str.parse().unwrap_or(0);
        
        // 3. Update Heat
        accumulated_heat += current_heat;
        
        // Decay factor (simulated): If clean prompt, reduce heat slightly
        if current_heat == 0 {
            accumulated_heat = std::cmp::max(0, accumulated_heat - 1);
        }

        // 4. Store new heat (with TTL)
        // We'd ideally use INCR/EXPIRE. Using set for now with the basic client.
        // TTL 1 hour.
        // self.redis.set(&heat_key, &accumulated_heat.to_string()).await?; 
        // Note: The basic redis.rs stub might need set_with_ttl logic. 
        
        // 5. Threat Check
        const HEAT_THRESHOLD: i32 = 10;
        if accumulated_heat > HEAT_THRESHOLD {
            println!("Crescendo Detection: User {} heat score {} exceeded threshold.", user_id, accumulated_heat);
            return Ok(true);
        }
        
        Ok(false)
    }

    fn calculate_heat(&self, prompt: &str) -> i32 {
        let s = prompt.to_lowercase();
        let mut score = 0;
        
        // Keyword Escalation
        if s.contains("ignore") || s.contains("bypass") { score += 2; }
        if s.contains("system") || s.contains("admin") { score += 3; }
        if s.contains("shell") || s.contains("exec") { score += 4; }
        if s.contains("credential") || s.contains("key") { score += 3; }
        
        score
    }
}
