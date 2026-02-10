use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum SecurityError {
    BudgetExceeded,
    SpendVelocityExceeded,
}

pub struct FinancialGuard {
    daily_limit: Decimal,
    cost_per_1k_tokens: Decimal,
    // Enhancement: Velocity Check
    // In a real distributed system, these would be in Redis.
    // For the interceptor logic, we model the check.
    last_spend_check: Option<Instant>,
    spend_in_window: Decimal,
    velocity_threshold_per_minute: Decimal,
}

impl FinancialGuard {
    pub fn new(daily_limit: Decimal, cost_per_1k: Decimal) -> Self {
        Self {
            daily_limit,
            cost_per_1k_tokens: cost_per_1k,
            last_spend_check: None,
            spend_in_window: Decimal::ZERO,
            velocity_threshold_per_minute: Decimal::new(500, 2), // $5.00/min example
        }
    }

    /// Calculates cost and checks against budget and velocity.
    /// `current_daily_spend` should be retrieved from Redis.
    pub fn check_budget(&mut self, estimated_tokens: u64, current_daily_spend: Decimal, is_cache_hit: bool) -> Result<Decimal, SecurityError> {
        // 1. Semantic Caching Zero-Cost Logic
        if is_cache_hit {
            return Ok(Decimal::ZERO);
        }

        // 2. Calculate estimated cost
        let estimated_cost = (Decimal::from(estimated_tokens) / Decimal::from(1000)) * self.cost_per_1k_tokens;

        // 3. Circuit Breaker Logic (Budget)
        if (current_daily_spend + estimated_cost) > self.daily_limit {
            return Err(SecurityError::BudgetExceeded);
        }

        // 4. Velocity Monitor (Enhancement)
        // Checks if spend is happening too fast (e.g., recursive loop)
        self.check_velocity(estimated_cost)?;

        Ok(estimated_cost)
    }

    fn check_velocity(&mut self, cost: Decimal) -> Result<(), SecurityError> {
        let now = Instant::now();
        match self.last_spend_check {
            Some(last_time) => {
                let elapsed = now.duration_since(last_time);
                if elapsed > Duration::from_secs(60) {
                    // Reset window if > 1 minute
                    self.spend_in_window = cost;
                    self.last_spend_check = Some(now);
                } else {
                    // Accumulate
                    self.spend_in_window += cost;
                    if self.spend_in_window > self.velocity_threshold_per_minute {
                        return Err(SecurityError::SpendVelocityExceeded);
                    }
                }
            }
            None => {
                self.spend_in_window = cost;
                self.last_spend_check = Some(now);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::prelude::FromPrimitive;

    #[test]
    fn test_budget_enforcement() {
        let mut guard = FinancialGuard::new(Decimal::new(10, 0), Decimal::new(1, 3)); // $10 limit, $0.001 per 1k
        // 1M tokens = $1.00
        let cost = guard.check_budget(1_000_000, Decimal::new(5, 0), false).unwrap();
        assert_eq!(cost, Decimal::new(1, 0)); // $1.00

        // Exceed budget
        let result = guard.check_budget(6_000_000, Decimal::new(5, 0), false); // $6 + $5 = $11 > $10
        assert!(matches!(result, Err(SecurityError::BudgetExceeded)));
    }

    #[test]
    fn test_semantic_caching_zero_cost() {
        let mut guard = FinancialGuard::new(Decimal::new(10, 0), Decimal::new(1, 0));
        // Cache hit = 0 cost, ignores budget check effectively for the increment
        let cost = guard.check_budget(1_000, Decimal::new(999, 2), true).unwrap();
        assert_eq!(cost, Decimal::ZERO);
    }

    #[test]
    fn test_spend_velocity_spike() {
        let mut guard = FinancialGuard::new(Decimal::new(100, 0), Decimal::new(1, 0)); // High budget
        guard.velocity_threshold_per_minute = Decimal::new(2, 0); // $2.00 per min max

        // Spend $1.50
        assert!(guard.check_budget(1500, Decimal::ZERO, false).is_ok());

        // Spend $1.00 more (Total $2.50 in window) -> Should fail velocity
        assert!(matches!(guard.check_budget(1000, Decimal::ZERO, false), Err(SecurityError::SpendVelocityExceeded)));
    }
}
