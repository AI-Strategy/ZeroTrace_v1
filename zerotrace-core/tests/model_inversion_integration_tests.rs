use serde_json::{json, Value};

use zerotrace_core::interceptor::model_inversion::{
    secure_inference_from_backend_bytes, secure_inference_from_backend_value, InvocationContext,
    SanitizationError, SanitizationPolicy,
};

fn assert_only_safe_keys(v: &Value) {
    let obj = v.as_object().expect("response must be JSON object");
    assert!(obj.contains_key("generated_text"));
    assert!(obj.contains_key("truncated"));
    assert!(obj.contains_key("warnings"));

    // Explicitly forbidden keys:
    for k in ["logits", "logprobs", "tokens", "token_ids", "scores"] {
        assert!(!obj.contains_key(k), "found forbidden key: {k}");
    }
}

#[test]
fn bytes_api_strips_sensitive_fields_structurally() {
    let ctx = InvocationContext::new("llm", "req-1");

    let backend = json!({
        "text": "Confidential Legal Memo",
        "logits": [0.1, 0.9, 0.5],
        "logprobs": [-0.1, -0.2, -0.5],
        "tokens": ["Confidential", "Legal", "Memo"]
    });

    let out =
        secure_inference_from_backend_bytes(&ctx, backend.to_string().as_bytes(), None).unwrap();
    assert_eq!(out.generated_text, "Confidential Legal Memo");

    let v = serde_json::to_value(&out).unwrap();
    assert_only_safe_keys(&v);
}

#[test]
fn value_api_strips_sensitive_fields_structurally() {
    let ctx = InvocationContext::new("llm", "req-2");

    let backend = json!({
        "text": "Hello",
        "logits": [0.1],
        "logprobs": [-0.1],
        "tokens": ["Hello"]
    });

    let out = secure_inference_from_backend_value(&ctx, backend, None).unwrap();
    let v = serde_json::to_value(&out).unwrap();
    assert_only_safe_keys(&v);
}

#[test]
fn does_not_false_fail_when_text_mentions_logits_words() {
    let ctx = InvocationContext::new("llm", "req-3");

    let backend = json!({
        "text": "This output literally says logits and logprobs and tokens.",
        "logits": [0.1],
        "logprobs": [-0.1],
        "tokens": ["x"]
    });

    let out = secure_inference_from_backend_value(&ctx, backend, None).unwrap();
    assert!(out.generated_text.contains("logits"));

    let v = serde_json::to_value(&out).unwrap();
    assert_only_safe_keys(&v);
}

#[test]
fn reject_unknown_fields_due_to_deny_unknown_fields() {
    let ctx = InvocationContext::new("llm", "req-4");

    let backend = json!({
        "text": "hi",
        "logits": [],
        "logprobs": null,
        "tokens": [],
        "extra": "nope"
    });

    let err = secure_inference_from_backend_value(&ctx, backend, None).unwrap_err();
    assert!(matches!(err, SanitizationError::ParseError(_)));
}

#[test]
fn reject_empty_text() {
    let ctx = InvocationContext::new("llm", "req-5");

    let backend = json!({
        "text": "",
        "logits": [],
        "logprobs": null,
        "tokens": []
    });

    let err = secure_inference_from_backend_value(&ctx, backend, None).unwrap_err();
    assert!(matches!(err, SanitizationError::InvalidBackendPayload(_)));
}

#[test]
fn policy_newlines_off_normalizes() {
    let ctx = InvocationContext::new("llm", "req-6");
    let policy = SanitizationPolicy {
        allow_newlines: false,
        ..Default::default()
    };

    let backend = json!({
        "text": "A\nB\nC",
        "logits": [],
        "logprobs": null,
        "tokens": []
    });

    let out = secure_inference_from_backend_value(&ctx, backend, Some(&policy)).unwrap();
    assert_eq!(out.generated_text, "A B C");
}

#[test]
fn policy_truncates_by_char_count() {
    let ctx = InvocationContext::new("llm", "req-7");
    let policy = SanitizationPolicy {
        max_output_chars: 3,
        ..Default::default()
    };

    let backend = json!({
        "text": "🦀🦀🦀🦀🦀",
        "logits": [],
        "logprobs": null,
        "tokens": []
    });

    let out = secure_inference_from_backend_value(&ctx, backend, Some(&policy)).unwrap();
    assert_eq!(out.generated_text, "🦀🦀🦀");
    assert!(out.truncated);
}

#[test]
fn bytes_api_rejects_malformed_json() {
    let ctx = InvocationContext::new("llm", "req-8");

    let bad = b"{ this is not json }";
    let err = secure_inference_from_backend_bytes(&ctx, bad, None).unwrap_err();
    assert!(matches!(err, SanitizationError::ParseError(_)));
}
