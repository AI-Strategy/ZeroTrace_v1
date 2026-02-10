//! Crescendo Counter: Redis-backed risk accumulation with decay.
//!
//! WHY THIS EXISTS (not “what it does”):
//! - You need a cheap, deterministic guardrail that *accumulates* suspicion over time,
//!   instead of overreacting to one spicy prompt.
//! - It must be race-free across distributed workers, hence the Redis Lua atomic update.
//! - It must treat **all inputs as hostile**: user IDs, prompts, and even Redis output.
//!
//! Observability:
//! - Uses `tracing` for structured logs (JSON recommended).
//! - Does NOT log raw prompts by default, because you like keeping secrets secret.
//!
//! Minimal deps (Cargo.toml):
//! ```toml
//! [dependencies]
//! thiserror = "1"
//! tracing = "0.1"
//! tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
//!
//! # optional but recommended for JSON logs in your binary
//! tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
//! ```
//!
//! NOTE: This module is library-friendly: it emits tracing events but does not initialize a subscriber.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use thiserror::Error;
use tracing::{info, warn};

/// Request correlation without relying on the caller doing the right thing.
static REQ_ID: AtomicU64 = AtomicU64::new(1);

/// Upper bounds: attackers love unbounded inputs; engineers love sleep.
const DEFAULT_PROMPT_SOFT_BYTES: usize = 8_000;
const DEFAULT_PROMPT_HARD_BYTES: usize = 64_000;
const DEFAULT_USER_ID_MAX_LEN: usize = 128;
const MAX_REDIS_KEY_BYTES: usize = 256;

/// Public decision returned to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationDecision {
    pub tripped: bool,
    pub current_heat: i32,
    pub accumulated_heat: i32,
}

/// Configuration for Crescendo.
///
/// WHY:
/// - Makes policy auditable and testable.
/// - Lets you tune behavior without touching core logic.
#[derive(Debug, Clone)]
pub struct CrescendoConfig {
    pub key_prefix: String,

    /// Session TTL in seconds (heat expires).
    pub ttl_secs: i64,

    /// Threshold where escalation trips.
    pub heat_threshold: i32,

    /// Decay applied per check: `heat = floor(heat * decay_num / decay_den)`.
    pub decay_num: i32,
    pub decay_den: i32,

    /// Extra cooldown applied when the prompt is “clean” (current_heat == 0).
    pub clean_cooldown: i32,

    /// Prompt size limits.
    pub prompt_soft_limit_bytes: usize,
    pub prompt_hard_limit_bytes: usize,

    /// User id validation.
    pub user_id_max_len: usize,

    /// If true, logs a redacted user id token. Default false.
    pub log_user_ref: bool,
}

impl Default for CrescendoConfig {
    fn default() -> Self {
        Self {
            key_prefix: "crescendo_heat".to_string(),
            ttl_secs: 60 * 60,
            heat_threshold: 10,
            decay_num: 9,
            decay_den: 10,
            clean_cooldown: 1,
            prompt_soft_limit_bytes: DEFAULT_PROMPT_SOFT_BYTES,
            prompt_hard_limit_bytes: DEFAULT_PROMPT_HARD_BYTES,
            user_id_max_len: DEFAULT_USER_ID_MAX_LEN,
            log_user_ref: false,
        }
    }
}

impl CrescendoConfig {
    /// Validate config at startup so you don’t discover a divide-by-zero in production.
    pub fn validate(&self) -> Result<(), CrescendoError> {
        if self.key_prefix.trim().is_empty() {
            return Err(CrescendoError::InvalidConfig(
                "key_prefix must not be empty".to_string(),
            ));
        }
        if self.ttl_secs <= 0 {
            return Err(CrescendoError::InvalidConfig(
                "ttl_secs must be > 0".to_string(),
            ));
        }
        if self.heat_threshold <= 0 {
            return Err(CrescendoError::InvalidConfig(
                "heat_threshold must be > 0".to_string(),
            ));
        }
        if self.decay_den <= 0 {
            return Err(CrescendoError::InvalidConfig(
                "decay_den must be > 0".to_string(),
            ));
        }
        if self.decay_num < 0 || self.decay_num > self.decay_den {
            return Err(CrescendoError::InvalidConfig(
                "decay_num must be within 0..=decay_den".to_string(),
            ));
        }
        if self.clean_cooldown < 0 {
            return Err(CrescendoError::InvalidConfig(
                "clean_cooldown must be >= 0".to_string(),
            ));
        }
        if self.prompt_soft_limit_bytes == 0 || self.prompt_hard_limit_bytes == 0 {
            return Err(CrescendoError::InvalidConfig(
                "prompt limits must be > 0".to_string(),
            ));
        }
        if self.prompt_soft_limit_bytes > self.prompt_hard_limit_bytes {
            return Err(CrescendoError::InvalidConfig(
                "prompt_soft_limit_bytes must be <= prompt_hard_limit_bytes".to_string(),
            ));
        }
        if self.user_id_max_len == 0 || self.user_id_max_len > 1024 {
            return Err(CrescendoError::InvalidConfig(
                "user_id_max_len must be within 1..=1024".to_string(),
            ));
        }
        Ok(())
    }
}

/// Redis evaluator abstraction.
///
/// WHY:
/// - Decouples your business logic from a specific Redis client implementation.
/// - Makes unit tests possible without a real Redis server.
/// - Keeps I/O at the edge.
pub trait RedisEval: Send + Sync + 'static {
    fn eval_i64<'a>(
        &'a self,
        script: &'a str,
        keys: &'a [&'a str],
        args: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<i64, RedisEvalError>> + Send + 'a>>;
}

/// Error returned by RedisEval implementers.
///
/// Intentionally opaque: callers shouldn’t get internal details that help attackers.
#[derive(Debug, Error)]
#[error("redis operation failed")]
pub struct RedisEvalError {
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl RedisEvalError {
    pub fn new<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Some(Box::new(e)),
        }
    }

    pub fn without_source() -> Self {
        Self { source: None }
    }
}

// bridge to the existing network client
use crate::network::redis::RedisClient;

impl RedisEval for RedisClient {
    fn eval_i64<'a>(
        &'a self,
        script: &'a str,
        keys: &'a [&'a str],
        args: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<i64, RedisEvalError>> + Send + 'a>> {
        let script = script.to_string();
        let keys = keys.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let args = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        
        // Clone self if needed, or just use reference if client supports it. 
        // RedisClient is Clone, but eval_i64 is async and takes &self.
        // The trait lifetime 'a matches self, so we can capture self. 
        // However, reqwest Client internals are Arc, so cloning RedisClient is cheap and often easier for 'static bounds if needed, 
        // but here we have 'a.
        
        Box::pin(async move {
            // We need to re-slice keys/args because RedisClient::eval_i64 takes slices, but we own Vecs now.
            let k: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
            let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            
            self.eval_i64(&script, &k, &a)
                .await
                .map_err(|e| RedisEvalError::new(std::io::Error::new(std::io::ErrorKind::Other, e)))
        })
    }
}

/// Crescendo counter.
///
/// Generic over RedisEval so it’s testable and not welded to one client.
pub struct CrescendoCounter<R: RedisEval> {
    redis: Arc<R>,
    cfg: CrescendoConfig,
}

/// Domain errors: specific, actionable, and not a stacktrace confetti cannon.
#[derive(Debug, Error)]
pub enum CrescendoError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("invalid user id: {0}")]
    InvalidUserId(String),

    #[error("invalid prompt: {0}")]
    InvalidPrompt(String),

    #[error("redis failure")]
    Redis(#[from] RedisEvalError),

    #[error("internal error: {0}")]
    Internal(String),
}

impl<R: RedisEval> CrescendoCounter<R> {
    /// Construct with injected Redis + config.
    pub fn with_client(redis: Arc<R>, cfg: CrescendoConfig) -> Result<Self, CrescendoError> {
        cfg.validate()?;
        Ok(Self { redis, cfg })
    }

    /// Backwards-compatible API: returns `true` if risk threshold is exceeded.
    pub async fn check_escalation(&self, user_id: &str, current_prompt: &str) -> Result<bool, CrescendoError> {
        Ok(self
            .check_escalation_detailed(user_id, current_prompt)
            .await?
            .tripped)
    }

    /// Better API: returns the updated heat + values used.
    ///
    /// Security posture:
    /// - Rejects invalid user_id early.
    /// - Rejects absurd prompts (hard limit).
    /// - Uses atomic Redis update (Lua) to prevent race conditions.
    pub async fn check_escalation_detailed(
        &self,
        user_id: &str,
        current_prompt: &str,
    ) -> Result<EscalationDecision, CrescendoError> {
        let req_id = next_req_id();

        let user = UserId::parse(user_id, self.cfg.user_id_max_len)?;
        validate_prompt(current_prompt, self.cfg.prompt_hard_limit_bytes)?;

        let heat_key = make_heat_key(&self.cfg.key_prefix, &user)?;
        let current_heat = self.calculate_heat(current_prompt);

        // Atomic update in Redis (single round trip).
        let new_heat = self
            .update_heat_atomic(&heat_key, current_heat)
            .await?;

        let tripped = new_heat >= self.cfg.heat_threshold;

        // Structured log event, no raw prompt.
        if tripped {
            if self.cfg.log_user_ref {
                warn!(
                    req_id,
                    user_ref = %user.safe_log(),
                    current_heat,
                    accumulated_heat = new_heat,
                    threshold = self.cfg.heat_threshold,
                    "crescendo escalation tripped"
                );
            } else {
                warn!(
                    req_id,
                    current_heat,
                    accumulated_heat = new_heat,
                    threshold = self.cfg.heat_threshold,
                    "crescendo escalation tripped"
                );
            }
        } else {
            if self.cfg.log_user_ref {
                info!(
                    req_id,
                    user_ref = %user.safe_log(),
                    current_heat,
                    accumulated_heat = new_heat,
                    threshold = self.cfg.heat_threshold,
                    "crescendo check ok"
                );
            } else {
                info!(
                    req_id,
                    current_heat,
                    accumulated_heat = new_heat,
                    threshold = self.cfg.heat_threshold,
                    "crescendo check ok"
                );
            }
        }

        Ok(EscalationDecision {
            tripped,
            current_heat,
            accumulated_heat: new_heat,
        })
    }

    /// Atomic Redis heat update.
    ///
    /// WHY:
    /// - Prevents race conditions across multiple workers.
    /// - Ensures consistent decay/add/clamp semantics.
    async fn update_heat_atomic(&self, heat_key: &str, current_heat: i32) -> Result<i32, CrescendoError> {
        const LUA: &str = r#"
local key = KEYS[1]
local add = tonumber(ARGV[1]) or 0
local ttl = tonumber(ARGV[2]) or 3600
local decay_num = tonumber(ARGV[3]) or 9
local decay_den = tonumber(ARGV[4]) or 10
local clean_cooldown = tonumber(ARGV[5]) or 1

local heat = tonumber(redis.call("GET", key) or "0")

heat = math.floor((heat * decay_num) / decay_den)
heat = heat + add

if add == 0 then
  heat = heat - clean_cooldown
end

if heat < 0 then heat = 0 end

redis.call("SET", key, heat, "EX", ttl)
return heat
"#;

        // Build args defensively.
        // Clamp inputs to sane ranges to avoid “creative” i32 overflows turning into Lua weirdness.
        let add = current_heat.max(0);
        let ttl = self.cfg.ttl_secs.max(1);

        let args_owned = [
            add.to_string(),
            ttl.to_string(),
            self.cfg.decay_num.to_string(),
            self.cfg.decay_den.to_string(),
            self.cfg.clean_cooldown.to_string(),
        ];
        let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();

        let out = self
            .redis
            .eval_i64(LUA, &[heat_key], &args)
            .await?;

        // Redis is untrusted too, because the world is a circus.
        let out = out.clamp(0, i32::MAX as i64) as i32;
        Ok(out)
    }

    /// Calculate heat from prompt heuristics (pure logic, no I/O).
    ///
    /// Complexity:
    /// - Time: O(n * k) where n = prompt length, k = number of keyword groups checked (small constant).
    /// - Space: O(n) due to ASCII lowercasing allocation (can be optimized later if you care).
    pub fn calculate_heat(&self, prompt: &str) -> i32 {
        calculate_heat_impl(prompt, self.cfg.prompt_soft_limit_bytes)
    }
}

/// Parse + validate user id into a safe, key-usable representation.
#[derive(Debug, Clone)]
struct UserId(String);

impl UserId {
    fn parse(raw: &str, max_len: usize) -> Result<Self, CrescendoError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(CrescendoError::InvalidUserId("empty".to_string()));
        }
        if s.len() > max_len {
            return Err(CrescendoError::InvalidUserId("too long".to_string()));
        }

        // Conservative allowlist: safe for Redis keys and logs.
        // If you need Unicode IDs, store a mapping elsewhere. Don’t jam it into your keyspace.
        if !s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.' | '@')
        }) {
            return Err(CrescendoError::InvalidUserId(
                "contains disallowed characters".to_string(),
            ));
        }

        Ok(Self(s.to_string()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn safe_log(&self) -> UserIdLog<'_> {
        UserIdLog(self.as_str())
    }
}

/// Redacted user id token for logs.
struct UserIdLog<'a>(&'a str);

impl<'a> std::fmt::Display for UserIdLog<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0;
        let prefix: String = s.chars().take(6).collect();
        write!(f, "{}…(len={})", prefix, s.len())
    }
}

fn validate_prompt(prompt: &str, hard_limit: usize) -> Result<(), CrescendoError> {
    if prompt.trim().is_empty() {
        return Err(CrescendoError::InvalidPrompt("empty".to_string()));
    }
    if prompt.len() > hard_limit {
        return Err(CrescendoError::InvalidPrompt("too large".to_string()));
    }
    if contains_disallowed_control_chars(prompt) {
        return Err(CrescendoError::InvalidPrompt(
            "contains disallowed control characters".to_string(),
        ));
    }
    Ok(())
}

fn contains_disallowed_control_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
}

fn make_heat_key(prefix: &str, user: &UserId) -> Result<String, CrescendoError> {
    let key = format!("{}:{}", prefix, user.as_str());
    if key.len() > MAX_REDIS_KEY_BYTES {
        return Err(CrescendoError::InvalidUserId(
            "derived redis key too long".to_string(),
        ));
    }
    Ok(key)
}

#[inline]
fn next_req_id() -> u64 {
    REQ_ID.fetch_add(1, Ordering::Relaxed)
}

/// Core scoring logic (pure).
fn calculate_heat_impl(prompt: &str, soft_limit: usize) -> i32 {
    // If it’s over the soft limit, we add heat anyway.
    // But we avoid allocating a massive lowercase copy if the prompt is huge.
    let len = prompt.len();

    // Size-based pressure (cheap signal, not a verdict).
    let mut score = 0;
    if len > soft_limit {
        score += 2;
    } else if len > 2_000 {
        score += 1;
    }

    // Lowercase for ASCII-heavy attack strings; fast and predictable.
    let s = prompt.to_ascii_lowercase();

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
    if contains_any(
        &s,
        &["exfil", "leak", "pastebin", "upload", "curl ", "wget ", "http://", "https://"],
    ) {
        score += 2;
        cats += 1;
    }

    // Obfuscation / encoding
    if contains_any(&s, &["base64", "rot13", "obfusc", "encode", "decode"]) {
        score += 2;
        cats += 1;
    }

    // Synergy: multiple categories in one prompt is more suspicious than one keyword.
    if cats >= 3 {
        score += 2;
    }

    score.clamp(0, i32::MAX)
}

#[inline]
fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}
