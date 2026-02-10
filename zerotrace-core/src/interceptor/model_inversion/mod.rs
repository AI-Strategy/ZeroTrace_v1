pub mod api;
mod internal;

// Re-export specific items from API
pub use api::{InvocationContext, SanitizationError, SanitizationPolicy, SanitizedResponse};

/// Public entrypoint: accept backend bytes (JSON) and return ONLY a sanitized response.
/// The raw model output type is private and cannot be referenced by callers.
pub fn secure_inference_from_backend_bytes(
    ctx: &InvocationContext,
    backend_json: &[u8],
    policy: Option<&SanitizationPolicy>,
) -> Result<SanitizedResponse, SanitizationError> {
    match policy {
        Some(p) => internal::secure_inference_from_backend_bytes(ctx, backend_json, p),
        None => {
            let p = SanitizationPolicy::default();
            internal::secure_inference_from_backend_bytes(ctx, backend_json, &p)
        }
    }
}

/// Convenience overload if you already parsed JSON elsewhere.
pub fn secure_inference_from_backend_value(
    ctx: &InvocationContext,
    backend_value: serde_json::Value,
    policy: Option<&SanitizationPolicy>,
) -> Result<SanitizedResponse, SanitizationError> {
    match policy {
        Some(p) => internal::secure_inference_from_backend_value(ctx, backend_value, p),
        None => {
            let p = SanitizationPolicy::default();
            internal::secure_inference_from_backend_value(ctx, backend_value, &p)
        }
    }
}
