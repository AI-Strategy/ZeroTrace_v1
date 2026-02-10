use neo4rs::{Graph, ConfigBuilder};
use dashmap::DashMap;
use std::sync::Arc;
use anyhow::{Result, anyhow};

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Configuration Error")]
    ConfigError,
    #[error("Connection Error")]
    ConnectionError,
}

pub struct TenantPooler {
    // DashMap for high-concurrency, lock-free access to tenant drivers
    drivers: DashMap<String, Arc<Graph>>,
}

impl TenantPooler {
    pub fn new() -> Self {
        Self { drivers: DashMap::new() }
    }

    pub async fn get_driver(&self, org_id: &str, uri: &str, user: &str, pass: &str) -> Result<Arc<Graph>, SecurityError> {
        // 1. Return existing driver if already cached
        if let Some(driver) = self.drivers.get(org_id) {
            return Ok(Arc::clone(&driver));
        }

        // 2. Provision new driver for the tenant if not in cache
        // Note: In 2026, neo4j+s:// is the standard for Aura
        let config = ConfigBuilder::default()
            .uri(uri)
            .user(user)
            .password(pass)
            .db("neo4j") // Aura default
            .fetch_size(500)
            .max_connections(5) // Avoid 'Connection Starvation' on Aura
            .build()
            .map_err(|_| SecurityError::ConfigError)?;

        let driver = Arc::new(Graph::connect(config).await.map_err(|_| SecurityError::ConnectionError)?);
        
        // Cache the driver for subsequent requests
        self.drivers.insert(org_id.to_string(), Arc::clone(&driver));
        
        Ok(driver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pooler_initialization() {
        let pool = TenantPooler::new();
        assert!(pool.drivers.is_empty());
    }

    // Note: We cannot easily test actual connection logic without a live Neo4j instance or mocking the Driver.
    // However, we can assert that the struct initializes correctly and handles the cache logic conceptually.
    // Integration tests would cover the actual connection.
}
