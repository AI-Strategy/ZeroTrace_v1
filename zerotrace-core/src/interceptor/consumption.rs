//! Production-grade Consumption Guard
//!
//! What this exists for (not just what it does):
//! - Prevents prompt-based DoS via oversized payloads (bytes + token limits).
//! - Enforces a daily spend ceiling with an atomic budget reservation step.
//! - Produces structured, low-leak logs for security operations and incident response.
//!
//! Notes:
//! - This module deliberately avoids logging raw user input.
//! - Budget enforcement is done via an abstract SpendStore trait to decouple Redis or any other backend.
//!
//! Suggested dependencies (Cargo.toml):
//! tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
//! tracing = "0.1"
//! tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
//! async-trait = "0.1"
//! thiserror = "1"
//! tiktoken-rs = "0.5"
//! blake3 = "1"

use async_trait::async_trait;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::OnceLock,
    time::Duration,
};
use thiserror::Error;
use tiktoken_rs::{cl100k_base, CoreBPE};
use tracing::{error, info, warn};

/// Initialize JSON logging (call once, early in main()).
///
/// Why it exists:
/// - Ensures logs are machine-readable (SIEM-friendly).
/// - Avoids accidental plaintext log formats drifting across binaries.
pub fn init_json_logging() {
    // Intentionally not returning Result: if logging can't initialize, continuing silently is worse.
    // If you want recoverable init, wrap this externally.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .with_current_span(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .try_init();
}

/// A request-scoped identifier intended for correlation (not security).
#[derive(Debug, Clone)]
pub struct RequestId(String);

impl RequestId {
    /// Strictly validate a request id so log fields can't be abused.
    ///
    /// Why:
    /// - Prevents log injection / parsing issues in structured pipelines.
    pub fn parse(s: &str) -> Result<Self, SecurityError> {
        if s.is_empty() || s.len() > 64 {
            return Err(SecurityError::InvalidRequestId);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        {
            return Err(SecurityError::InvalidRequestId);
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A subject identifier for budget tracking (user, tenant, api key id, etc).
#[derive(Debug, Clone)]
pub struct SubjectId(String);

impl SubjectId {
    /// Strictly validate a subject id that becomes part of a backend key.
    ///
    /// Why:
    /// - Prevents keyspace pollution and weird delimiter attacks.
    pub fn parse(s: &str) -> Result<Self, SecurityError> {
        if s.is_empty() || s.len() > 96 {
            return Err(SecurityError::InvalidSubjectId);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(SecurityError::InvalidSubjectId);
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Budget values stored as integer micro-dollars to avoid floating point surprises.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsdMicros(u64);

impl UsdMicros {
    pub const fn new(micros: u64) -> Self {
        Self(micros)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Convert USD per 1k tokens into micros safely.
    pub fn from_usd_per_1k_tokens_usd(usd: f64) -> Result<Self, SecurityError> {
        if !usd.is_finite() || usd <= 0.0 || usd > 1_000_000.0 {
            return Err(SecurityError::InvalidConfig);
        }
        // round to micros
        let micros = (usd * 1_000_000.0).round();
        if micros <= 0.0 {
            return Err(SecurityError::InvalidConfig);
        }
        Ok(Self(micros as u64))
    }
}

/// Configuration for the guard.
///
/// Why it exists:
/// - Centralizes policy knobs.
/// - Prevents “random magic numbers” scattered across services.
#[derive(Debug, Clone)]
pub struct ConsumptionGuardConfig {
    pub max_bytes_per_request: NonZeroUsize,
    pub max_tokens_per_request: NonZeroUsize,
    pub daily_budget_usd_micros: NonZeroU64,
    pub usd_per_1k_tokens_micros: NonZeroU64,
    pub tokenize_timeout: Duration,
    pub daily_key_ttl_secs: NonZeroU64,
}

impl ConsumptionGuardConfig {
    pub fn new(
        max_bytes_per_request: NonZeroUsize,
        max_tokens_per_request: NonZeroUsize,
        daily_budget_usd_micros: NonZeroU64,
        usd_per_1k_tokens_micros: NonZeroU64,
    ) -> Self {
        Self {
            max_bytes_per_request,
            max_tokens_per_request,
            daily_budget_usd_micros,
            usd_per_1k_tokens_micros,
            tokenize_timeout: Duration::from_millis(250),
            daily_key_ttl_secs: NonZeroU64::new(36 * 60 * 60).expect("non-zero const"),
        }
    }
}

/// Minimal request context to avoid leaking sensitive content.
#[derive(Debug)]
pub struct RequestContext<'a> {
    pub subject_id: SubjectId,
    pub request_id: Option<RequestId>,
    pub user_input: &'a str,
}

/// Decision returned by validation.
///
/// Why:
/// - Callers often need observability fields (token count, estimated cost) for metrics and audits.
#[derive(Debug, Clone)]
pub struct ValidationDecision {
    pub token_count: usize,
    pub estimated_cost_usd_micros: u64,
    pub new_daily_total_usd_micros: u64,
    pub daily_budget_usd_micros: u64,
}

/// Errors are intentionally user-safe in Display text (no internal stack traces, no secrets).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecurityError {
    #[error("Invalid server configuration")]
    InvalidConfig,

    #[error("Invalid subject id")]
    InvalidSubjectId,

    #[error("Invalid request id")]
    InvalidRequestId,

    #[error("Payload limit exceeded (bytes)")]
    PayloadTooLargeBytes,

    #[error("Payload limit exceeded (tokens)")]
    PayloadTooLargeTokens,

    #[error("Tokenizer initialization failed")]
    TokenizerUnavailable,

    #[error("Tokenization timed out")]
    TokenizationTimedOut,

    #[error("Daily budget exceeded")]
    BudgetExceeded,

    #[error("Budget backend unavailable")]
    BudgetStoreUnavailable,
}

/// The outcome of attempting to reserve budget atomically.
#[derive(Debug, Clone)]
pub struct ReserveOutcome {
    pub allowed: bool,
    pub new_total_usd_micros: u64,
}

/// Abstract store for spend tracking.
///
/// Why:
/// - Redis is an implementation detail.
/// - Keeps business logic testable and prevents I/O from infecting everything.
#[async_trait]
pub trait SpendStore: Send + Sync {
    async fn try_reserve_daily_budget(
        &self,
        key: &str,
        amount_usd_micros: u64,
        limit_usd_micros: u64,
        ttl_secs: u64,
    ) -> Result<ReserveOutcome, SpendStoreError>;
}

/// Store errors are internal; callers get mapped to SecurityError::BudgetStoreUnavailable.
#[derive(Debug, Error)]
pub enum SpendStoreError {
    #[error("backend error")]
    BackendError,
    #[error("invalid response")]
    InvalidResponse,
}

/// A clock abstraction for deterministic tests and sane production behavior.
pub trait Clock: Send + Sync {
    /// Returns a UTC date stamp used in keying (YYYY-MM-DD).
    fn utc_day_stamp(&self) -> String;
}

/// Production clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn utc_day_stamp(&self) -> String {
        // Avoid chrono dependency. This uses the system time and a small conversion via time crate would be nicer,
        // but we’re keeping dependencies minimal here. If you already use chrono, swap this out.
        //
        // Fallback: use YYYYMMDD via UNIX days; still stable for keying.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let days = now.as_secs() / 86_400;
        format!("unix-days-{}", days)
    }
}

/// The guard itself.
pub struct ConsumptionGuard {
    cfg: ConsumptionGuardConfig,
    clock: Box<dyn Clock>,
}

impl ConsumptionGuard {
    pub fn new(cfg: ConsumptionGuardConfig) -> Result<Self, SecurityError> {
        // Explicit config validation (defensive against “oops” and “oops but malicious”).
        if cfg.max_bytes_per_request.get() == 0
            || cfg.max_tokens_per_request.get() == 0
            || cfg.daily_budget_usd_micros.get() == 0
            || cfg.usd_per_1k_tokens_micros.get() == 0
            || cfg.tokenize_timeout.as_millis() == 0
            || cfg.daily_key_ttl_secs.get() == 0
        {
            return Err(SecurityError::InvalidConfig);
        }

        Ok(Self {
            cfg,
            clock: Box::new(SystemClock),
        })
    }

    /// Override clock (tests).
    pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Validates request against payload limits and enforces daily budget via atomic reservation.
    ///
    /// Why it exists:
    /// - Token counting + budget enforcement are the first line of defense against cost-exfiltration attacks.
    /// - The reservation step prevents race conditions in concurrent requests.
    ///
    /// Security posture:
    /// - Does not log raw input.
    /// - Logs a stable hash for correlation.
    ///
    /// Complexity:
    /// - Time: O(n) for tokenization where n = input length (bytes).
    /// - Space: O(1) additional space (tokenizer internal work aside).
    pub async fn validate_request<S: SpendStore>(
        &self,
        ctx: &RequestContext<'_>,
        store: &S,
    ) -> Result<ValidationDecision, SecurityError> {
        // 0) Byte preflight (cheap DoS guard).
        let byte_len = ctx.user_input.as_bytes().len();
        if byte_len > self.cfg.max_bytes_per_request.get() {
            warn!(
                event = "consumption_guard_reject",
                reason = "bytes_limit",
                bytes = byte_len,
                max_bytes = self.cfg.max_bytes_per_request.get(),
                subject = ctx.subject_id.as_str(),
                request_id = ctx.request_id.as_ref().map(|r| r.as_str()),
            );
            return Err(SecurityError::PayloadTooLargeBytes);
        }

        // 1) Tokenize with timeout and spawn_blocking to avoid stalling async executors.
        let input = ctx.user_input.to_owned();
        let token_count = self
            .tokenize_with_timeout(input)
            .await
            .map_err(|e| {
                warn!(
                    event = "consumption_guard_reject",
                    reason = "tokenize_failed",
                    error = %e,
                    subject = ctx.subject_id.as_str(),
                    request_id = ctx.request_id.as_ref().map(|r| r.as_str()),
                );
                e
            })?;

        // 2) Enforce token limits.
        if token_count > self.cfg.max_tokens_per_request.get() {
            warn!(
                event = "consumption_guard_reject",
                reason = "token_limit",
                tokens = token_count,
                max_tokens = self.cfg.max_tokens_per_request.get(),
                subject = ctx.subject_id.as_str(),
                request_id = ctx.request_id.as_ref().map(|r| r.as_str()),
            );
            return Err(SecurityError::PayloadTooLargeTokens);
        }

        // 3) Estimate cost (micros) with integer arithmetic.
        let estimated_cost = estimate_cost_usd_micros(
            token_count,
            self.cfg.usd_per_1k_tokens_micros.get(),
        );

        // 4) Reserve budget atomically in store.
        let key = self.daily_spend_key(&ctx.subject_id);
        let limit = self.cfg.daily_budget_usd_micros.get();
        let ttl = self.cfg.daily_key_ttl_secs.get();

        let outcome = store
            .try_reserve_daily_budget(&key, estimated_cost, limit, ttl)
            .await
            .map_err(|err| {
                // Don't leak backend details. Logs get a generic classification.
                error!(
                    event = "consumption_guard_backend_error",
                    reason = "budget_store_unavailable",
                    subject = ctx.subject_id.as_str(),
                    request_id = ctx.request_id.as_ref().map(|r| r.as_str()),
                    error = %err,
                );
                SecurityError::BudgetStoreUnavailable
            })?;

        if !outcome.allowed {
            warn!(
                event = "consumption_guard_reject",
                reason = "budget_exceeded",
                tokens = token_count,
                estimated_cost_usd_micros = estimated_cost,
                new_total_usd_micros = outcome.new_total_usd_micros,
                daily_budget_usd_micros = limit,
                subject = ctx.subject_id.as_str(),
                request_id = ctx.request_id.as_ref().map(|r| r.as_str()),
                input_hash = %hash_for_logs(ctx.user_input),
            );
            return Err(SecurityError::BudgetExceeded);
        }

        info!(
            event = "consumption_guard_allow",
            tokens = token_count,
            estimated_cost_usd_micros = estimated_cost,
            new_total_usd_micros = outcome.new_total_usd_micros,
            daily_budget_usd_micros = limit,
            subject = ctx.subject_id.as_str(),
            request_id = ctx.request_id.as_ref().map(|r| r.as_str()),
            input_hash = %hash_for_logs(ctx.user_input),
        );

        Ok(ValidationDecision {
            token_count,
            estimated_cost_usd_micros: estimated_cost,
            new_daily_total_usd_micros: outcome.new_total_usd_micros,
            daily_budget_usd_micros: limit,
        })
    }

    /// Count tokens directly (sync). Useful for non-async contexts and tests.
    pub fn count_tokens(&self, text: &str) -> Result<usize, SecurityError> {
        let bpe = get_bpe()?;
        Ok(bpe.encode_with_special_tokens(text).len())
    }

    fn daily_spend_key(&self, subject: &SubjectId) -> String {
        let day = self.clock.utc_day_stamp();
        // Key format is intentionally simple and constrained.
        format!("spend:{}:{}", subject.as_str(), day)
    }

    async fn tokenize_with_timeout(&self, input: String) -> Result<usize, SecurityError> {
        let timeout = self.cfg.tokenize_timeout;

        let task = tokio::task::spawn_blocking(move || {
            let bpe = get_bpe()?;
            Ok::<usize, SecurityError>(bpe.encode_with_special_tokens(&input).len())
        });

        match tokio::time::timeout(timeout, task).await {
            Err(_) => Err(SecurityError::TokenizationTimedOut),
            Ok(join_res) => match join_res {
                Err(_) => Err(SecurityError::TokenizerUnavailable), // join failure
                Ok(res) => res,
            },
        }
    }
}

/// Compute estimated cost (USD micros) from token count and USD micros per 1k tokens.
///
/// Pure function for testability.
///
/// Time: O(1), Space: O(1)
pub fn estimate_cost_usd_micros(token_count: usize, usd_per_1k_tokens_micros: u64) -> u64 {
    // Ceil division to avoid “free rounding down” abuse at scale.
    let tokens = token_count as u64;
    (tokens.saturating_mul(usd_per_1k_tokens_micros) + 999) / 1000
}

/// Do not log raw payloads. Hash gives correlation without leaking content.
fn hash_for_logs(input: &str) -> String {
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

// ---- Tokenizer cache (defensive init) ----

static BPE_CACHE: OnceLock<Result<CoreBPE, ()>> = OnceLock::new();

fn get_bpe() -> Result<&'static CoreBPE, SecurityError> {
    match BPE_CACHE.get_or_init(|| cl100k_base().map_err(|_| ())) {
        Ok(bpe) => Ok(bpe),
        Err(_) => Err(SecurityError::TokenizerUnavailable),
    }
}

// -------------------- Example SpendStore implementation --------------------
// This is an in-memory store useful for tests and local dev.
// Your Redis adapter should implement SpendStore using an atomic script (e.g., Lua) to avoid races.

use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory SpendStore for tests/dev.
///
/// Why:
/// - Lets you unit test policy logic without a real Redis.
pub struct InMemorySpendStore {
    inner: Mutex<HashMap<String, u64>>,
}

impl InMemorySpendStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Directly set spend for a key (tests).
    pub fn set(&self, key: &str, usd_micros: u64) {
        let mut guard = self.inner.lock().expect("mutex poisoned");
        guard.insert(key.to_owned(), usd_micros);
    }

    /// Read spend for a key (tests).
    pub fn get(&self, key: &str) -> u64 {
        let guard = self.inner.lock().expect("mutex poisoned");
        *guard.get(key).unwrap_or(&0)
    }
}

#[async_trait]
impl SpendStore for InMemorySpendStore {
    async fn try_reserve_daily_budget(
        &self,
        key: &str,
        amount_usd_micros: u64,
        limit_usd_micros: u64,
        _ttl_secs: u64,
    ) -> Result<ReserveOutcome, SpendStoreError> {
        let mut guard = self.inner.lock().map_err(|_| SpendStoreError::BackendError)?;
        let current = *guard.get(key).unwrap_or(&0);
        let new_total = current.saturating_add(amount_usd_micros);

        if new_total > limit_usd_micros {
            // Denied: keep current spend unchanged.
            return Ok(ReserveOutcome {
                allowed: false,
                new_total_usd_micros: current,
            });
        }

        guard.insert(key.to_owned(), new_total);

        Ok(ReserveOutcome {
            allowed: true,
            new_total_usd_micros: new_total,
        })
    }
}
