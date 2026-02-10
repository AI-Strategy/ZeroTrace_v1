use axum::{
    body::Body,
    http::{Request, Response, StatusCode, Uri},
    response::IntoResponse,
};
use reqwest::Client;
use std::str::FromStr;

#[derive(Clone)]
pub struct ProxyClient {
    client: Client,
    upstream_base_url: String, // e.g., "https://api.openai.com"
}

impl ProxyClient {
    pub fn new(upstream_url: &str) -> Self {
        Self {
            client: Client::new(),
            upstream_base_url: upstream_url.to_string(),
        }
    }

    /// Forwards the authorized request to the upstream provider.
    /// This is called only AFTER the Interceptor has cleared the request.
    pub async fn forward(&self, mut req: Request<Body>) -> Result<Response<Body>, StatusCode> {
        let path = req.uri().path();
        let path_query = req
            .uri()
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or(path);

        let uri = format!("{}{}", self.upstream_base_url, path_query);
        let uri = Uri::from_str(&uri).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        *req.uri_mut() = uri;

        // In a real implementation, we would convert axum::http::Request to reqwest::Request
        // This requires some boilerplate header copying.
        // For this stub, we return a mock success response from "Upstream".
        
        // Mock Upstream Response
        let mock_response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(r#"{"id":"chatcmpl-mock","choices":[{"message":{"content":"[ZeroTrace Proxy]: Safe Response from Upstream"}}]}"#))
            .unwrap();

        Ok(mock_response)
    }
}
