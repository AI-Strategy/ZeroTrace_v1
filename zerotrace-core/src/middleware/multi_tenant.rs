use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Mock Security Cell Structure
#[derive(Clone, Debug)]
pub struct SecurityCell {
    pub org_id: String,
    pub shard_endpoint: String,
    pub active: bool,
}

// Global Registry (In a real app, this would be Redis/Database backed)
lazy_static::lazy_static! {
    static ref CELL_REGISTRY: RwLock<HashMap<String, SecurityCell>> = RwLock::new(HashMap::new());
}

pub struct TenantRouter;

impl TenantRouter {
    pub fn register_cell(org_id: &str, shard: &str) {
        let mut registry = CELL_REGISTRY.write().unwrap();
        registry.insert(
            org_id.to_string(),
            SecurityCell {
                org_id: org_id.to_string(),
                shard_endpoint: shard.to_string(),
                active: true,
            },
        );
    }

    pub fn get_cell(org_id: &str) -> Option<SecurityCell> {
        let registry = CELL_REGISTRY.read().unwrap();
        registry.get(org_id).cloned()
    }
}

pub struct ValidatedTenant(pub SecurityCell);

#[async_trait]
impl<S> FromRequestParts<S> for ValidatedTenant
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let org_id_header = parts.headers.get("X-Organization-ID").ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Missing X-Organization-ID header" })),
            )
                .into_response()
        })?;

        let org_id = org_id_header.to_str().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid X-Organization-ID header encoding" })),
            )
                .into_response()
        })?;

        // Lookup Tenant Cell
        match TenantRouter::get_cell(org_id) {
            Some(cell) if cell.active => Ok(ValidatedTenant(cell)),
            Some(_) => Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Tenant account is suspended" })),
            )
                .into_response()),
            None => Err((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Tenant Security Cell not found" })),
            )
                .into_response()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::post, Router};
    use tower::util::ServiceExt; // Fixed path: tower::util::ServiceExt for oneshot

    async fn mock_handler(ValidatedTenant(cell): ValidatedTenant) -> Json<serde_json::Value> {
        Json(json!({ "status": "routed", "shard": cell.shard_endpoint }))
    }

    #[tokio::test]
    async fn test_tenant_routing_success() {
        // Register a mock tenant
        TenantRouter::register_cell("org_123", "neo4j://shard_01");

        let app = Router::new().route("/execute", post(mock_handler));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/execute")
                    .header("X-Organization-ID", "org_123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_tenant_missing_header() {
        let app = Router::new().route("/execute", post(mock_handler));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/execute")
                    // No Header
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_tenant_not_found() {
        let app = Router::new().route("/execute", post(mock_handler));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/execute")
                    .header("X-Organization-ID", "org_unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
