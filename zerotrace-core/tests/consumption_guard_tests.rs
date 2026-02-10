use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Duration;
use tokio;
use zerotrace_core::interceptor::consumption::{
    estimate_cost_usd_micros, Clock, ConsumptionGuard, ConsumptionGuardConfig, InMemorySpendStore,
    RequestContext, RequestId, SecurityError, SubjectId,
};

struct FixedClock {
    stamp: String,
}

impl Clock for FixedClock {
    fn utc_day_stamp(&self) -> String {
        self.stamp.clone()
    }
}

fn guard_for_tests() -> ConsumptionGuard {
    let cfg = ConsumptionGuardConfig {
        max_bytes_per_request: NonZeroUsize::new(8 * 1024).unwrap(),
        max_tokens_per_request: NonZeroUsize::new(2000).unwrap(),
        daily_budget_usd_micros: NonZeroU64::new(5_000_000).unwrap(), // $5.00
        usd_per_1k_tokens_micros: NonZeroU64::new(2_000_000).unwrap(), // $2.00 / 1k tokens
        tokenize_timeout: Duration::from_millis(500),
        daily_key_ttl_secs: NonZeroU64::new(36 * 60 * 60).unwrap(),
    };

    ConsumptionGuard::new(cfg)
        .unwrap()
        .with_clock(Box::new(FixedClock {
            stamp: "2026-02-09".to_string(),
        }))
}

fn ctx<'a>(subject: &str, input: &'a str) -> RequestContext<'a> {
    RequestContext {
        subject_id: SubjectId::parse(subject).unwrap(),
        request_id: Some(RequestId::parse("req_123").unwrap()),
        user_input: input,
    }
}

#[tokio::test]
async fn happy_path_allows_and_reserves_budget() {
    let guard = guard_for_tests();
    let store = InMemorySpendStore::new();

    let input_str = "Hello world";
    let context = ctx("user_1", input_str);
    let decision = guard.validate_request(&context, &store).await.unwrap();

    assert!(decision.token_count > 0);
    assert!(decision.estimated_cost_usd_micros > 0);
    assert_eq!(
        decision.new_daily_total_usd_micros,
        decision.estimated_cost_usd_micros
    );
}

#[tokio::test]
async fn rejects_when_token_limit_exceeded() {
    let mut cfg = ConsumptionGuardConfig::new(
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(5).unwrap(), // tiny token limit
        NonZeroU64::new(10_000_000).unwrap(),
        NonZeroU64::new(1_000_000).unwrap(),
    );
    cfg.tokenize_timeout = Duration::from_millis(500);

    let guard = ConsumptionGuard::new(cfg).unwrap();
    let store = InMemorySpendStore::new();

    let input = "Hello world this is a test of token limits";
    let context = ctx("user_1", input);
    let err = guard.validate_request(&context, &store).await.unwrap_err();

    assert!(matches!(err, SecurityError::PayloadTooLargeTokens));
}

#[tokio::test]
async fn rejects_when_byte_limit_exceeded_preflight() {
    let cfg = ConsumptionGuardConfig::new(
        NonZeroUsize::new(8).unwrap(), // tiny byte limit
        NonZeroUsize::new(2000).unwrap(),
        NonZeroU64::new(10_000_000).unwrap(),
        NonZeroU64::new(1_000_000).unwrap(),
    );

    let guard = ConsumptionGuard::new(cfg).unwrap();
    let store = InMemorySpendStore::new();

    let context = ctx("user_1", "this is way too long");
    let err = guard.validate_request(&context, &store).await.unwrap_err();

    assert!(matches!(err, SecurityError::PayloadTooLargeBytes));
}

#[tokio::test]
async fn rejects_when_budget_would_be_exceeded() {
    let guard = guard_for_tests();
    let store = InMemorySpendStore::new();

    // Pre-seed spend close to budget.
    // Budget is $5.00 => 5_000_000 micros
    // Set current to $4.99
    let subject = SubjectId::parse("user_1").unwrap();
    let key = format!("spend:{}:{}", subject.as_str(), "2026-02-09");
    store.set(&key, 4_999_000); // $4.999

    let context = RequestContext {
        subject_id: subject,
        request_id: Some(RequestId::parse("req_123").unwrap()),
        user_input: "Hello world", // small but non-zero cost
    };

    let err = guard.validate_request(&context, &store).await.unwrap_err();

    assert!(matches!(err, SecurityError::BudgetExceeded));
}

#[test]
fn cost_estimation_is_ceiling_divided_by_1000() {
    // $2 / 1k tokens => 2_000_000 micros
    let usd_per_1k = 2_000_000;

    // 1 token => ceil(1 * 2_000_000 / 1000) = 2000 micros
    assert_eq!(estimate_cost_usd_micros(1, usd_per_1k), 2000);

    // 1000 tokens => 2_000_000 micros
    assert_eq!(estimate_cost_usd_micros(1000, usd_per_1k), 2_000_000);

    // 1001 tokens => 2_002_000 micros (ceiling)
    assert_eq!(estimate_cost_usd_micros(1001, usd_per_1k), 2_002_000);
}
