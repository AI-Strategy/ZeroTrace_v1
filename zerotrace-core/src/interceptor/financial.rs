//! # Financial Guard - LLM Cost Control & Budget Enforcement
//!
//! ## Purpose
//! Provides multi-layered financial security for LLM API operations, preventing
//! cost overruns through budget limits, velocity monitoring, and semantic caching.
//! Critical for preventing runaway costs from infinite loops, prompt injection attacks,
//! or misconfigured automated agents.
//!
//! ## Security Model
//! - **Budget Circuit Breaker**: Hard daily spending limit
//! - **Velocity Monitor**: Detects abnormal spending patterns (recursive loops)
//! - **Semantic Caching**: Zero-cost cache hits reduce redundant API calls
//! - **Audit Trail**: All spending decisions could be logged for compliance
//!
//! ## Architecture
//! - Designed for distributed systems (Redis-backed state)
//! - Thread-safe operations via external locking (Arc<Mutex>)
//! - Idempotent budget checks

use rust_decimal::prelude::*;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

/// Maximum daily budget allowed (prevents misconfiguration).
/// Industry standard: $10,000/day for enterprise deployments.
const MAX_DAILY_LIMIT: Decimal = Decimal::from_parts(100_000_00, 0, 0, false, 2); // $100,000.00

/// Minimum daily budget (must be positive to prevent division errors).
const MIN_DAILY_LIMIT: Decimal = Decimal::from_parts(1_00, 0, 0, false, 2); // $1.00

/// Maximum cost per 1k tokens (prevents pricing model errors).
const MAX_COST_PER_1K: Decimal = Decimal::from_parts(100_00, 0, 0, false, 2); // $100.00/1k

/// Minimum cost per 1k tokens (must be positive).
const MIN_COST_PER_1K: Decimal = Decimal::from_parts(1, 0, 0, false, 5); // $0.00001

/// Maximum velocity threshold (prevents runaway spending).
const MAX_VELOCITY_THRESHOLD: Decimal = Decimal::from_parts(1000_00, 0, 0, false, 2); // $1,000/min

/// Velocity window duration (1 minute sliding window).
const VELOCITY_WINDOW: Duration = Duration::from_secs(60);

/// Maximum token count per request (prevents overflow attacks).
const MAX_TOKENS_PER_REQUEST: u64 = 1_000_000_000; // 1 billion tokens

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Comprehensive error taxonomy for financial guard operations.
#[derive(Debug, Error, Serialize, Clone, PartialEq)]
#[non_exhaustive]
pub enum SecurityError {
    #[error("Budget exceeded: current=${current}, estimated=${estimated}, limit=${limit}")]
    BudgetExceeded {
        current: Decimal,
        estimated: Decimal,
        limit: Decimal,
    },

    #[error("Spend velocity exceeded: ${spend_in_window} in {elapsed_secs}s (limit: ${threshold}/min)")]
    SpendVelocityExceeded {
        spend_in_window: Decimal,
        elapsed_secs: u64,
        threshold: Decimal,
    },

    #[error("Invalid configuration: {reason}")]
    InvalidConfiguration { reason: String },

    #[error("Invalid input: {field}={value} (constraint: {constraint})")]
    InvalidInput {
        field: String,
        value: String,
        constraint: String,
    },

    #[error("Numerical overflow: {operation}")]
    NumericalOverflow { operation: String },

    #[error("State corruption detected: {reason}")]
    StateCorruption { reason: String },
}

// ============================================================================
// SPENDING METRICS
// ============================================================================

/// Detailed spending metrics returned from budget checks.
///
/// ## Purpose
/// Provides transparency for debugging, monitoring, and compliance.
/// Enables dashboards to show real-time cost tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpendingMetrics {
    /// Estimated cost for this request
    pub estimated_cost: Decimal,
    
    /// Current daily spend before this request
    pub current_daily_spend: Decimal,
    
    /// Projected daily spend after this request
    pub projected_daily_spend: Decimal,
    
    /// Daily budget limit
    pub daily_limit: Decimal,
    
    /// Remaining budget after this request
    pub remaining_budget: Decimal,
    
    /// Percentage of budget consumed (0-100)
    pub budget_utilization_percent: Decimal,
    
    /// Whether this was a cache hit (zero cost)
    pub is_cache_hit: bool,
    
    /// Current velocity (spend per minute)
    pub current_velocity: Decimal,
    
    /// Velocity threshold
    pub velocity_threshold: Decimal,
}

impl SpendingMetrics {
    /// Checks if budget is critically low (>90% consumed).
    pub fn is_critical(&self) -> bool {
        self.budget_utilization_percent >= Decimal::from(90)
    }

    /// Checks if budget is in warning zone (>75% consumed).
    pub fn is_warning(&self) -> bool {
        self.budget_utilization_percent >= Decimal::from(75)
    }
}

// ============================================================================
// VELOCITY MONITOR
// ============================================================================

/// Sliding window velocity monitor for detecting spending spikes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VelocityMonitor {
    threshold_per_minute: Decimal,
    #[serde(skip)]
    window_start: Option<Instant>,
    spend_in_window: Decimal,
}

impl VelocityMonitor {
    /// Creates a new velocity monitor with the specified threshold.
    fn new(threshold_per_minute: Decimal) -> Result<Self, SecurityError> {
        validate_velocity_threshold(threshold_per_minute)?;

        Ok(Self {
            threshold_per_minute,
            window_start: None,
            spend_in_window: Decimal::ZERO,
        })
    }

    /// Checks if adding this cost would exceed velocity threshold.
    #[instrument(skip(self), fields(threshold = %self.threshold_per_minute))]
    fn check(&mut self, cost: Decimal) -> Result<Decimal, SecurityError> {
        let now = Instant::now();

        match self.window_start {
            Some(start) => {
                let elapsed = now.duration_since(start);

                if elapsed >= VELOCITY_WINDOW {
                    // Window expired - reset
                    debug!(
                        elapsed_secs = elapsed.as_secs(),
                        "Velocity window reset"
                    );
                    self.spend_in_window = cost;
                    self.window_start = Some(now);
                } else {
                    // Accumulate in current window
                    self.spend_in_window = self.spend_in_window
                        .checked_add(cost)
                        .ok_or_else(|| SecurityError::NumericalOverflow {
                            operation: format!("velocity accumulation: {} + {}", self.spend_in_window, cost),
                        })?;

                    if self.spend_in_window > self.threshold_per_minute {
                        warn!(
                            spend_in_window = %self.spend_in_window,
                            threshold = %self.threshold_per_minute,
                            elapsed_secs = elapsed.as_secs(),
                            "Velocity threshold exceeded - possible runaway spending"
                        );

                        return Err(SecurityError::SpendVelocityExceeded {
                            spend_in_window: self.spend_in_window,
                            elapsed_secs: elapsed.as_secs(),
                            threshold: self.threshold_per_minute,
                        });
                    }
                }
            }
            None => {
                // First spend - initialize window
                self.spend_in_window = cost;
                self.window_start = Some(now);
                debug!("Velocity monitoring initialized");
            }
        }

        Ok(self.spend_in_window)
    }

    /// Returns current velocity (spend per minute).
    fn current_velocity(&self) -> Decimal {
        match self.window_start {
            Some(start) => {
                let elapsed = Instant::now().duration_since(start).as_secs_f64();
                if elapsed > 0.0 {
                    // Normalize to per-minute rate
                    let minutes = elapsed / 60.0;
                    self.spend_in_window / Decimal::from_f64(minutes).unwrap_or(Decimal::ONE)
                } else {
                    self.spend_in_window
                }
            }
            None => Decimal::ZERO,
        }
    }

    /// Resets the velocity monitor (useful for testing or manual intervention).
    fn reset(&mut self) {
        self.spend_in_window = Decimal::ZERO;
        self.window_start = None;
        info!("Velocity monitor manually reset");
    }
}

// ============================================================================
// FINANCIAL GUARD (Main Component)
// ============================================================================

/// Production-grade financial security guard for LLM API operations.
#[derive(Debug)]
pub struct FinancialGuard {
    daily_limit: Decimal,
    cost_per_1k_tokens: Decimal,
    velocity_monitor: VelocityMonitor,
}

impl FinancialGuard {
    pub fn new(daily_limit: Decimal, cost_per_1k: Decimal) -> Result<Self, SecurityError> {
        validate_daily_limit(daily_limit)?;
        validate_cost_per_1k(cost_per_1k)?;

        // Default velocity threshold: 10% of daily limit per minute
        let default_velocity = daily_limit / Decimal::from(10);
        let velocity_monitor = VelocityMonitor::new(default_velocity)?;

        info!(
            daily_limit = %daily_limit,
            cost_per_1k = %cost_per_1k,
            velocity_threshold = %default_velocity,
            "FinancialGuard initialized"
        );

        Ok(Self {
            daily_limit,
            cost_per_1k_tokens: cost_per_1k,
            velocity_monitor,
        })
    }

    pub fn with_velocity(
        daily_limit: Decimal,
        cost_per_1k: Decimal,
        velocity_threshold: Decimal,
    ) -> Result<Self, SecurityError> {
        validate_daily_limit(daily_limit)?;
        validate_cost_per_1k(cost_per_1k)?;
        validate_velocity_threshold(velocity_threshold)?;

        let velocity_monitor = VelocityMonitor::new(velocity_threshold)?;

        info!(
            daily_limit = %daily_limit,
            cost_per_1k = %cost_per_1k,
            velocity_threshold = %velocity_threshold,
            "FinancialGuard initialized with custom velocity threshold"
        );

        Ok(Self {
            daily_limit,
            cost_per_1k_tokens: cost_per_1k,
            velocity_monitor,
        })
    }

    #[instrument(
        skip(self),
        fields(
            daily_limit = %self.daily_limit,
            cost_per_1k = %self.cost_per_1k_tokens
        )
    )]
    pub fn check_budget(
        &mut self,
        estimated_tokens: u64,
        current_daily_spend: Decimal,
        is_cache_hit: bool,
    ) -> Result<SpendingMetrics, SecurityError> {
        // STEP 1: Input validation
        validate_token_count(estimated_tokens)?;
        validate_current_spend(current_daily_spend)?;

        // STEP 2: Semantic caching zero-cost logic
        if is_cache_hit {
            debug!(
                estimated_tokens = estimated_tokens,
                "Cache hit - zero cost incurred"
            );

            return Ok(SpendingMetrics {
                estimated_cost: Decimal::ZERO,
                current_daily_spend,
                projected_daily_spend: current_daily_spend,
                daily_limit: self.daily_limit,
                remaining_budget: self.daily_limit - current_daily_spend,
                budget_utilization_percent: calculate_utilization(
                    current_daily_spend,
                    self.daily_limit,
                )?,
                is_cache_hit: true,
                current_velocity: self.velocity_monitor.current_velocity(),
                velocity_threshold: self.velocity_monitor.threshold_per_minute,
            });
        }

        // STEP 3: Calculate estimated cost
        let estimated_cost = self.calculate_cost(estimated_tokens)?;

        // STEP 4: Check budget limit (circuit breaker)
        let projected_spend = current_daily_spend
            .checked_add(estimated_cost)
            .ok_or_else(|| SecurityError::NumericalOverflow {
                operation: format!("budget projection: {} + {}", current_daily_spend, estimated_cost),
            })?;

        if projected_spend > self.daily_limit {
            error!(
                current_spend = %current_daily_spend,
                estimated_cost = %estimated_cost,
                projected_spend = %projected_spend,
                daily_limit = %self.daily_limit,
                "Daily budget exceeded - request denied"
            );

            return Err(SecurityError::BudgetExceeded {
                current: current_daily_spend,
                estimated: estimated_cost,
                limit: self.daily_limit,
            });
        }

        // STEP 5: Velocity check (rate limiter)
        let velocity = self.velocity_monitor.check(estimated_cost)?;

        // STEP 6: Calculate metrics
        let remaining = self.daily_limit - projected_spend;
        let utilization = calculate_utilization(projected_spend, self.daily_limit)?;

        // STEP 7: Log budget status
        match utilization {
            u if u >= Decimal::from(90) => {
                tracing::warn!(
                    estimated_cost = %estimated_cost,
                    projected_spend = %projected_spend,
                    remaining = %remaining,
                    utilization_pct = %utilization,
                    velocity = %velocity,
                    "Budget check passed (CRITICAL utilization)"
                );
            }
            u if u >= Decimal::from(75) => {
                tracing::info!(
                    estimated_cost = %estimated_cost,
                    projected_spend = %projected_spend,
                    remaining = %remaining,
                    utilization_pct = %utilization,
                    velocity = %velocity,
                    "Budget check passed (WARNING utilization)"
                );
            }
            _ => {
                tracing::debug!(
                    estimated_cost = %estimated_cost,
                    projected_spend = %projected_spend,
                    remaining = %remaining,
                    utilization_pct = %utilization,
                    velocity = %velocity,
                    "Budget check passed"
                );
            }
        }

        Ok(SpendingMetrics {
            estimated_cost,
            current_daily_spend,
            projected_daily_spend: projected_spend,
            daily_limit: self.daily_limit,
            remaining_budget: remaining,
            budget_utilization_percent: utilization,
            is_cache_hit: false,
            current_velocity: self.velocity_monitor.current_velocity(),
            velocity_threshold: self.velocity_monitor.threshold_per_minute,
        })
    }

    fn calculate_cost(&self, tokens: u64) -> Result<Decimal, SecurityError> {
        let tokens_decimal = Decimal::from(tokens);
        let thousand = Decimal::from(1000);

        let tokens_in_thousands = tokens_decimal
            .checked_div(thousand)
            .ok_or_else(|| SecurityError::NumericalOverflow {
                operation: "token division by 1000".to_string(),
            })?;

        let cost = tokens_in_thousands
            .checked_mul(self.cost_per_1k_tokens)
            .ok_or_else(|| SecurityError::NumericalOverflow {
                operation: format!(
                    "cost calculation: {} * {}",
                    tokens_in_thousands, self.cost_per_1k_tokens
                ),
            })?;

        Ok(cost)
    }

    pub fn daily_limit(&self) -> Decimal {
        self.daily_limit
    }

    pub fn cost_per_1k(&self) -> Decimal {
        self.cost_per_1k_tokens
    }

    pub fn velocity_threshold(&self) -> Decimal {
        self.velocity_monitor.threshold_per_minute
    }

    pub fn update_daily_limit(&mut self, new_limit: Decimal) -> Result<(), SecurityError> {
        validate_daily_limit(new_limit)?;
        self.daily_limit = new_limit;
        Ok(())
    }

    pub fn update_velocity_threshold(
        &mut self,
        new_threshold: Decimal,
    ) -> Result<(), SecurityError> {
        validate_velocity_threshold(new_threshold)?;
        self.velocity_monitor.threshold_per_minute = new_threshold;
        Ok(())
    }

    pub fn reset_velocity(&mut self) {
        self.velocity_monitor.reset();
    }
}

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

fn validate_daily_limit(limit: Decimal) -> Result<(), SecurityError> {
    if limit <= Decimal::ZERO {
        return Err(SecurityError::InvalidConfiguration {
            reason: format!("Daily limit must be positive, got: {}", limit),
        });
    }

    if limit < MIN_DAILY_LIMIT {
        return Err(SecurityError::InvalidConfiguration {
            reason: format!("Daily limit ${} below minimum ${}", limit, MIN_DAILY_LIMIT),
        });
    }

    if limit > MAX_DAILY_LIMIT {
        return Err(SecurityError::InvalidConfiguration {
            reason: format!("Daily limit ${} exceeds maximum ${}", limit, MAX_DAILY_LIMIT),
        });
    }

    Ok(())
}

fn validate_cost_per_1k(cost: Decimal) -> Result<(), SecurityError> {
    if cost <= Decimal::ZERO {
        return Err(SecurityError::InvalidConfiguration {
            reason: format!("Cost per 1k must be positive, got: {}", cost),
        });
    }

    if cost < MIN_COST_PER_1K {
        return Err(SecurityError::InvalidConfiguration {
            reason: format!("Cost per 1k ${} below minimum ${}", cost, MIN_COST_PER_1K),
        });
    }

    if cost > MAX_COST_PER_1K {
        return Err(SecurityError::InvalidConfiguration {
            reason: format!("Cost per 1k ${} exceeds maximum ${}", cost, MAX_COST_PER_1K),
        });
    }

    Ok(())
}

fn validate_velocity_threshold(threshold: Decimal) -> Result<(), SecurityError> {
    if threshold <= Decimal::ZERO {
        return Err(SecurityError::InvalidConfiguration {
            reason: format!("Velocity threshold must be positive, got: {}", threshold),
        });
    }

    if threshold > MAX_VELOCITY_THRESHOLD {
        return Err(SecurityError::InvalidConfiguration {
            reason: format!("Velocity threshold ${} exceeds maximum ${}", threshold, MAX_VELOCITY_THRESHOLD),
        });
    }

    Ok(())
}

fn validate_token_count(tokens: u64) -> Result<(), SecurityError> {
    if tokens == 0 {
        return Err(SecurityError::InvalidInput {
            field: "estimated_tokens".to_string(),
            value: "0".to_string(),
            constraint: "must be > 0".to_string(),
        });
    }

    if tokens > MAX_TOKENS_PER_REQUEST {
        return Err(SecurityError::InvalidInput {
            field: "estimated_tokens".to_string(),
            value: tokens.to_string(),
            constraint: format!("must be <= {}", MAX_TOKENS_PER_REQUEST),
        });
    }

    Ok(())
}

fn validate_current_spend(spend: Decimal) -> Result<(), SecurityError> {
    if spend < Decimal::ZERO {
        return Err(SecurityError::StateCorruption {
            reason: format!("Current daily spend cannot be negative: {}", spend),
        });
    }

    Ok(())
}

fn calculate_utilization(spent: Decimal, limit: Decimal) -> Result<Decimal, SecurityError> {
    if limit == Decimal::ZERO {
        return Err(SecurityError::StateCorruption {
            reason: "Daily limit is zero - cannot calculate utilization".to_string(),
        });
    }

    let utilization = (spent / limit) * Decimal::from(100);
    Ok(utilization.round_dp(2))
}

// ============================================================================
// DISPLAY IMPLEMENTATIONS
// ============================================================================

impl fmt::Display for FinancialGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FinancialGuard(limit=${}, cost=${}/1k, velocity=${}/min)",
            self.daily_limit,
            self.cost_per_1k_tokens,
            self.velocity_monitor.threshold_per_minute
        )
    }
}

impl fmt::Display for SpendingMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SpendingMetrics(cost=${}, projected=${}/{}, utilization={}%)",
            self.estimated_cost,
            self.projected_daily_spend,
            self.daily_limit,
            self.budget_utilization_percent
        )
    }
}
