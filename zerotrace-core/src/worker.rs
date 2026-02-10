use worker::*;
use crate::interceptor::sanitize::PiiSanitizer;
use crate::network::redis::UpstashClient;
use serde_json::json;

mod utils {
    pub fn set_panic_hook() {
        // When the `console_error_panic_hook` feature is enabled, we can call the
        // `set_panic_hook` function at least once during initialization, and then
        // we will get better error messages if our code ever panics.
        #[cfg(feature = "console_error_panic_hook")]
        console_error_panic_hook::set_once();
    }
}

#[event(fetch)]
pub async fn main(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    utils::set_panic_hook();

    // 1. Parse Request
    if req.method() != Method::Post {
        return Response::error("Method Not Allowed", 405);
    }
    
    let body_text = match req.text().await {
        Ok(text) => text,
        Err(_) => return Response::error("Bad Request", 400),
    };

    // 2. Initialize Infrastructure
    // In a real worker, PiiSanitizer would be initialized once or lazily
    let sanitizer = PiiSanitizer::new(vec!["password".to_string(), "credit_card".to_string(), "sk-live".to_string()]);
    
    // Initialize Upstash Client using the helper I added to redis.rs (need to update redis.rs to use worker::Env if generic, or just use env vars)
    // For this sample, we assume we can get vars from `env`
    let redis_url = env.var("UPSTASH_REDIS_REST_URL")?.to_string();
    let redis_token = env.secret("UPSTASH_REDIS_REST_TOKEN")?.to_string();
    let redis = UpstashClient::new(&redis_url, &redis_token);

    // 3. Security Logic: PII Scrubbing
    let sanitized_input = sanitizer.redact(&body_text);
    
    // 4. Redis Check: Semantic Cache or Blocklist
    // Hashing the input for cache lookup (simple checksum for demo)
    let input_hash = format!("{:x}", md5::compute(&sanitized_input)); 
    
    if let Some(cached_response) = redis.get_semantic_cache(&input_hash).await {
         return Response::from_json(&json!({
             "status": "cached",
             "content": cached_response
         }));
    }

    // 5. Audit Logging (Async - utilizing ctx.wait_until if needed, but here simple)
    // definition of "The Trace" would happen here.

    // 6. Return Sanitized Payload (mocking upstream forwarding)
    Response::from_json(&json!({
        "status": "cleared",
        "original_length": body_text.len(),
        "sanitized_content": sanitized_input,
        "processed_at": "Edge-Data-Center-01"
    }))
}
