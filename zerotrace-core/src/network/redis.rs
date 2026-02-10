use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Clone)]
pub struct RedisClient {
    client: Client,
    base_url: String,
    token: String,
}

#[derive(Deserialize, Debug)]
struct RedisResponse<T> {
    result: Option<T>,
}

#[derive(Serialize)]
struct EvalRequest<'a> {
    script: &'a str,
    keys: &'a [&'a str],
    args: &'a [&'a str],
}

impl RedisClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
            token: token.to_string(),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        let base_url = env::var("UPSTASH_REDIS_REST_URL").map_err(|_| "Missing UPSTASH_REDIS_REST_URL")?;
        let token = env::var("UPSTASH_REDIS_REST_TOKEN").map_err(|_| "Missing UPSTASH_REDIS_REST_TOKEN")?;
        Ok(Self::new(&base_url, &token))
    }

    /// Evaluates a Lua script (for atomic operations).
    pub async fn eval_i64(&self, script: &str, keys: &[&str], args: &[&str]) -> Result<i64, String> {
        let url = format!("{}/eval", self.base_url);
        let req_body = EvalRequest { script, keys, args };

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&req_body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status() != StatusCode::OK {
            return Err(format!("Redis Error: {}", resp.status()));
        }

        let body: RedisResponse<i64> = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body.result.unwrap_or(0))
    }

    /// Checks if a domain is in the "Verified Registry" (Bloom Filter or Set check).
    pub async fn check_registry(&self, domain: &str) -> Result<bool, String> {
        // Redis Command: SISMEMBER verified_domains <domain>
        let url = format!("{}/sismember/verified_domains/{}", self.base_url, domain);
        
        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status() != StatusCode::OK {
            return Err(format!("Redis Error: {}", resp.status()));
        }

        let body: RedisResponse<u8> = resp.json().await.map_err(|e| e.to_string())?;
        
        // 1 means exists (Verified), 0 means not found (Unverified/Potential Malicious)
        Ok(body.result == Some(1))
    }

    /// Fetches a cached semantic response.
    pub async fn get_semantic_cache(&self, hash: &str) -> Option<String> {
        let url = format!("{}/get/cache:{}", self.base_url, hash);
        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .ok()?;
            
        let body: RedisResponse<String> = resp.json().await.ok()?;
        body.result
    }

    /// Sets a key with an expiration time (SETEX equivalent).
    pub async fn set_with_ttl(&self, key: &str, value: &str, seconds: u64) -> Result<(), String> {
        // Redis Command: SETEX key seconds value
        let url = format!("{}/setex/{}/{}/{}", self.base_url, key, seconds, value);
        
        let resp = self.client.get(&url) 
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status() != StatusCode::OK {
            return Err(format!("Redis Error: {}", resp.status()));
        }

        Ok(())
    }

    /// Gets a value by key.
    pub async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let url = format!("{}/get/{}", self.base_url, key);
        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status() != StatusCode::OK {
            return Err(format!("Redis Error: {}", resp.status()));
        }

        let body: RedisResponse<String> = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body.result)
    }
}
