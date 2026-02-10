use rust_decimal::Decimal;
use zerotrace_core::interceptor::financial::{FinancialGuard, SecurityError, SpendingMetrics};

#[test]
fn test_budget_enforcement_basic() {
    let mut guard = FinancialGuard::new(
        Decimal::new(1000, 2),  // $10.00 limit
        Decimal::new(1, 3),     // $0.001 per 1k. Note: 1 / 1000 = 0.001
    ).unwrap();

    // 1M tokens = 1000 * 1k-blocks. Cost = 1000 * 0.001 = 1.00
    let metrics = guard.check_budget(
        1_000_000,              // 1M tokens
        Decimal::new(500, 2),   // $5.00 already spent
        false,
    ).unwrap();

    assert_eq!(metrics.estimated_cost, Decimal::new(100, 2)); // $1.00
    assert_eq!(metrics.projected_daily_spend, Decimal::new(600, 2)); // $6.00
    assert_eq!(metrics.remaining_budget, Decimal::new(400, 2)); // $4.00
}

#[test]
fn test_budget_exceeded() {
    let mut guard = FinancialGuard::new(
        Decimal::new(1000, 2),  // $10.00 limit
        Decimal::new(1, 3),     // $0.001 per 1k
    ).unwrap();

    // Spend $6.00 more when $5.00 already spent = $11.00 total > $10.00
    let result = guard.check_budget(
        6_000_000,              // 6M tokens = $6.00
        Decimal::new(500, 2),   // $5.00 already spent
        false,
    );

    assert!(matches!(result, Err(SecurityError::BudgetExceeded { .. })));
}

#[test]
fn test_semantic_caching_zero_cost() {
    let mut guard = FinancialGuard::new(
        Decimal::new(1000, 2),
        Decimal::new(1, 0),
    ).unwrap();

    let metrics = guard.check_budget(
        1_000,                      // Irrelevant for cache hit
        Decimal::new(99999, 2),     // Near budget limit (999.99)
        true,                       // Cache hit
    ).unwrap();

    assert_eq!(metrics.estimated_cost, Decimal::ZERO);
    assert_eq!(metrics.is_cache_hit, true);
    assert_eq!(metrics.projected_daily_spend, Decimal::new(99999, 2)); // Unchanged
}

#[test]
fn test_spend_velocity_spike() {
    let mut guard = FinancialGuard::with_velocity(
        Decimal::new(10000, 2),  // $100.00 daily budget
        Decimal::new(1, 0),      // $1.00 per 1k
        Decimal::new(200, 2),    // $2.00 per minute max
    ).unwrap();

    // Spend $1.50
    assert!(guard.check_budget(1500, Decimal::ZERO, false).is_ok());

    // Spend $1.00 more (total $2.50 in window) -> should fail velocity
    let result = guard.check_budget(1000, Decimal::ZERO, false);

    assert!(matches!(result, Err(SecurityError::SpendVelocityExceeded { .. })));
}

#[test]
fn test_invalid_configuration() {
    assert!(FinancialGuard::new(Decimal::ZERO, Decimal::ONE).is_err()); // Zero budget
    assert!(FinancialGuard::new(Decimal::new(-100, 0), Decimal::ONE).is_err()); // Negative budget
    assert!(FinancialGuard::new(Decimal::ONE, Decimal::ZERO).is_err()); // Zero cost
}

#[test]
fn test_utilization_calculation() {
    let mut guard = FinancialGuard::new(
        Decimal::new(10000, 2), // $100.00
        Decimal::new(1, 0),
    ).unwrap();

    let metrics = guard.check_budget(
        75_000,                     // $75.00
        Decimal::ZERO,
        false,
    ).unwrap();

    assert_eq!(metrics.budget_utilization_percent, Decimal::new(75, 0)); // 75%
    assert!(metrics.is_warning());
    assert!(!metrics.is_critical());
}

#[test]
fn test_extreme_token_counts() {
    let mut guard = FinancialGuard::new(
        Decimal::new(1000000, 2), // $10,000
        Decimal::new(2, 3),       // $0.002/1k
    ).unwrap();

    // 100M tokens = $200
    // 100M / 1000 * 0.002 = 100,000 * 0.002 = 200
    let metrics = guard.check_budget(100_000_000, Decimal::ZERO, false).unwrap();

    assert_eq!(metrics.estimated_cost, Decimal::new(200, 0));
}
