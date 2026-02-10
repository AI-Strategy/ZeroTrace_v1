use axum::{
    extract::{State, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use zerotrace_core::interceptor::universal_guard::UniversalGuard;

struct AppState {
    guard: UniversalGuard,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Initialize UniversalGuard (Stubbed Redis by default in dev)
    let guard = UniversalGuard::new();
    let shared_state = Arc::new(AppState { guard });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/scan", post(scan_input))
        .with_state(shared_state);

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
    user_id: String,
    content: String,
}

#[derive(Serialize)]
struct ScanResponse {
    request_id: String,
    authorized: bool,
    sanitized_content: String,
    warnings: Vec<String>,
}

async fn scan_input(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ScanRequest>,
) -> Json<ScanResponse> {
    match state.guard.evaluate_complete_risk_profile(&payload.content, &payload.user_id).await {
        Ok(sanitized) => Json(ScanResponse {
            request_id: payload.request_id,
            authorized: true,
            sanitized_content: sanitized,
            warnings: vec![],
        }),
        Err(block_reason) => Json(ScanResponse {
            request_id: payload.request_id,
            authorized: false,
            sanitized_content: "".to_string(),
            warnings: vec![block_reason],
        }),
    }
}
