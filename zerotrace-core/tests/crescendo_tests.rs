use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use zerotrace_core::interceptor::crescendo::{
    CrescendoConfig, CrescendoCounter, CrescendoError, EscalationDecision, RedisEval,
    RedisEvalError,
};

struct MockRedis {
    // capture last call for assertions
    last: Mutex<Option<(String, Vec<String>, Vec<String>)>>,
    // predetermined response
    response: Mutex<Result<i64, RedisEvalError>>,
}

impl Default for MockRedis {
    fn default() -> Self {
        Self {
            last: Mutex::new(None),
            // Default to 0 success
            response: Mutex::new(Ok(0)),
        }
    }
}

impl MockRedis {
    fn returning(v: i64) -> Self {
        let m = MockRedis::default();
        *m.response.lock().unwrap() = Ok(v);
        m
    }
    fn failing() -> Self {
        let m = MockRedis::default();
        *m.response.lock().unwrap() = Err(RedisEvalError::without_source());
        m
    }
}

impl RedisEval for MockRedis {
    fn eval_i64<'a>(
        &'a self,
        script: &'a str,
        keys: &'a [&'a str],
        args: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<i64, RedisEvalError>> + Send + 'a>> {
        let script_s = script.to_string();
        let keys_v = keys.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let args_v = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        *self.last.lock().unwrap() = Some((script_s, keys_v, args_v));

        let out = match self.response.lock().unwrap().as_ref() {
            Ok(v) => Ok(*v),
            Err(_) => Err(RedisEvalError::without_source()),
        };
        Box::pin(async move { out })
    }
}

#[tokio::test]
async fn trips_threshold_when_redis_returns_high_heat() {
    let redis = Arc::new(MockRedis::returning(999));
    let mut cfg = CrescendoConfig::default();
    cfg.heat_threshold = 10;

    let counter = CrescendoCounter::with_client(redis, cfg).unwrap();
    let decision = counter
        .check_escalation_detailed("user_123", "hello world")
        .await
        .unwrap();

    assert!(decision.tripped);
    assert_eq!(decision.accumulated_heat, 999);
    assert_eq!(decision.current_heat, 0);
}

#[tokio::test]
async fn rejects_invalid_user_id_characters() {
    let redis = Arc::new(MockRedis::returning(0));
    let counter = CrescendoCounter::with_client(redis, CrescendoConfig::default()).unwrap();

    let err = counter
        .check_escalation_detailed("bad user id", "hello")
        .await
        .unwrap_err();

    match err {
        CrescendoError::InvalidUserId(_) => {}
        other => panic!("expected InvalidUserId, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_prompt_over_hard_limit() {
    let redis = Arc::new(MockRedis::returning(0));
    let mut cfg = CrescendoConfig::default();
    cfg.prompt_hard_limit_bytes = 100;
    cfg.prompt_soft_limit_bytes = 100; // Must be <= hard limit

    let counter = CrescendoCounter::with_client(redis, cfg).unwrap();
    let prompt = "a".repeat(101);

    let err = counter
        .check_escalation_detailed("user_123", &prompt)
        .await
        .unwrap_err();

    match err {
        CrescendoError::InvalidPrompt(_) => {}
        other => panic!("expected InvalidPrompt, got {other:?}"),
    }
}

#[tokio::test]
async fn redis_eval_called_with_expected_key_and_args_shape() {
    let redis = Arc::new(MockRedis::returning(5));
    let cfg = CrescendoConfig::default();
    let counter = CrescendoCounter::with_client(redis.clone(), cfg).unwrap();

    let _ = counter
        .check_escalation_detailed("user_123", "ignore system exec")
        .await
        .unwrap();

    let last = redis.last.lock().unwrap().clone().expect("expected call");
    let (_script, keys, args) = last;

    assert_eq!(keys.len(), 1);
    assert!(keys[0].starts_with("crescendo_heat:user_123"));

    // args: add, ttl, decay_num, decay_den, clean_cooldown
    assert_eq!(args.len(), 5);
    assert!(args[0].parse::<i32>().is_ok());
    assert!(args[1].parse::<i64>().is_ok());
}

#[tokio::test]
async fn redis_failure_propagates_as_domain_error() {
    let redis = Arc::new(MockRedis::failing());
    let counter = CrescendoCounter::with_client(redis, CrescendoConfig::default()).unwrap();

    let err = counter
        .check_escalation_detailed("user_123", "hello")
        .await
        .unwrap_err();

    match err {
        CrescendoError::Redis(_) => {}
        other => panic!("expected Redis error, got {other:?}"),
    }
}
