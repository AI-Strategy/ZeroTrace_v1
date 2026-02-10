use dashmap::DashMap;
use std::sync::Arc;
use tokio_postgres::{Client, NoTls, Error};
use thiserror::Error;
use std::str::FromStr;

#[derive(Debug, Error)]
pub enum PostgresError {
    #[error("Connection Error: {0}")]
    ConnectionError(#[from] tokio_postgres::Error),
    #[error("Configuration Error")]
    ConfigError,
}

pub struct PostgresTenantPooler {
    // DashMap for high-concurrency access to tenant clients
    // In production, we might want a real pool (deadpool/bb8), but for now we multiplex.
    clients: DashMap<String, Arc<Client>>,
}

impl PostgresTenantPooler {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
        }
    }

    /// Retrieves an existing client or establishes a new connection.
    /// Note: tokio-postgres Client handles multiplexing, so sharing one Arc<Client> is efficient.
    pub async fn get_client(&self, connection_string: &str) -> Result<Arc<Client>, PostgresError> {
        // 1. Check cache
        // We use the connection string as key for simplicity in multi-tenant setup
        if let Some(client) = self.clients.get(connection_string) {
            // Check if client is closed? tokio-postgres client doesn't expose is_closed easily without query.
            // For robustness, we might want to health check or let it fail and retry.
            // For this phase, we return the cached client.
            return Ok(Arc::clone(&client));
        }

        // 2. Connect
        let (client, connection) = tokio_postgres::connect(connection_string, NoTls).await?;

        // 3. Spawn the connection handler
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Postgres connection error: {}", e);
            }
        });

        let client = Arc::new(client);
        self.clients.insert(connection_string.to_string(), Arc::clone(&client));

        Ok(client)
    }
}
