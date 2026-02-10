use worker::*;
use crate::interceptor::universal_guard::UniversalGuard;
use serde_json::json;

mod utils {
    pub fn set_panic_hook() {
        #[cfg(feature = "console_error_panic_hook")]
        console_error_panic_hook::set_once();
    }
}

#[event(fetch)]
pub async fn main(mut req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    utils::set_panic_hook();
    
    // Performance Optimization: Use Lazy Static or OnceCell (simulated here)
    // to avoid re-initializing Aho-Corasick/Regex on every request.
    // In a real Worker, global state persists across invocations in the same Isolate.
    // Note: Since `UniversalGuard` creation is synchronous here, we can construct it.
    // However, if it needs async (Redis), we usually lazy-load the client.
    let guard = UniversalGuard::new(); 


    if req.method() != Method::Post {
        return Response::error("Method Not Allowed", 405);
    }
    
    let body_text = match req.text().await {
        Ok(text) => text,
        Err(_) => return Response::error("Bad Request", 400),
    };
    
    // 2. REQUEST PHASE: Inbound Inspection & Sanitization
    // "Fail-Closed" check against all 29 Risk Vectors.
    let user_id = "user_123"; // Logic would extract from Auth Header
    
    let secure_prompt = match guard.evaluate_complete_risk_profile(&body_text, user_id).await {
        Ok(prompt) => prompt,
        Err(block_reason) => {
            console_log!("Blocked Request: {}", block_reason);
            return Response::from_json(&json!({
                "status": "blocked",
                "reason": block_reason,
                "risk_code": "ZeroTrace-Guard-Block"
            }));
        }
    };

    // 3. UPSTREAM PHASE: Forward to LLM (Simulated)
    // In a real proxy, we would `reqwest::Client::new().post(llm_url)...`
    // Here we simulate the LLM responding, potentially using the PII tokens.
    // E.g. User: "My email is alice@example.com"
    // Secure Prompt: "My email is [EMAIL-UUID-123...]"
    // Simulated LLM Response: "Hello, I see your email is [EMAIL-UUID-123...]."
    
    // Simulating "Echo" behavior of an LLM preserving the tokens
    let llm_response_simulation = format!("Processed: {}", secure_prompt); 

    // 4. RESPONSE PHASE: Re-hydration (Double-Blind)
    // We swap the tokens back to the original values so the user sees their data,
    // but the LLM provider never saw it.
    let final_response = guard.process_secure_response(&llm_response_simulation).await;

    Response::from_json(&json!({
        "status": "authorized",
        "redacted_prompt_sent_to_llm": secure_prompt, // Debug only, remove in prod!
        "final_response_to_user": final_response,
        "trace_id": "uuid-gen-here"
    }))
}
