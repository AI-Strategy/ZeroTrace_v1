use axum::{
    routing::{get, post},
    Router, Json,
};
use serde::{Deserialize, Serialize};
use zerotrace_core::interceptor::{detect, sanitize};
use zerotrace_core::protocol::dbs::DBSProtocol;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/scan", post(scan_input));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("ZeroTrace Airlock listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> &'static str {
    "ZeroTrace Airlock: ONLINE"
}

#[derive(Deserialize)]
struct ScanRequest {
    request_id: String,
    content: String,
}

#[derive(Serialize)]
struct ScanResponse {
    request_id: String,
    authorized: bool,
    sanitized_content: String,
    warnings: Vec<String>,
}

async fn scan_input(Json(payload): Json<ScanRequest>) -> Json<ScanResponse> {
    // 0. Normalize Input (Invisible character stripping)
    let normalized_content = zerotrace_core::interceptor::normalization::Normalizer::normalize(&payload.content);

    // 1. Check DBS Protocol
    // For general text scan, we don't have a structured tool action yet, so passing None.
    // In a future /execute endpoint, we would pass Some((user_id, tool_name)).
    if !DBSProtocol::enforce(&normalized_content, None) {
        return Json(ScanResponse {
            request_id: payload.request_id,
            authorized: false,
            authorized: false,
            sanitized_content: "".to_string(),
            warnings: vec!["DBS_VIOLATION".to_string()],
        });
    }

    // 2. Scan for anomalies
    let mut anomalies = detect::scan_for_anomalies(&normalized_content);
    
    // 2.1 Scan for Secrets (Entropy)
    let secret_warnings = zerotrace_core::interceptor::entropy::scan_for_secrets(&normalized_content);
    anomalies.extend(secret_warnings);

    // 2.2 Scan for Canary Exfiltration
    let test_canaries = vec!["ZT-CANARY-TEST".to_string()]; 
    let canary_leaks = zerotrace_core::interceptor::canary::check_for_exfiltration(&normalized_content, &test_canaries);
    if !canary_leaks.is_empty() {
        anomalies.push("DATA_EXFILTRATION:CANARY_DETECTED".to_string());
    }
    
    // 3. Sanitize content (Advanced PII)
    // In a real app, the sanitizer would be a long-lived state in 'app', not recreated per request
    let sanitizer = sanitize::PiiSanitizer::new(vec!["password".to_string(), "credit_card".to_string()]);
    let sanitized = sanitizer.redact(&normalized_content);

    Json(ScanResponse {
        request_id: payload.request_id,
        authorized: anomalies.is_empty(),
        sanitized_content: if anomalies.is_empty() { sanitized } else { "".to_string() },
        warnings: anomalies,
    })
}
