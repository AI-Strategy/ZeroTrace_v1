use anyhow::{Result, Context};

/// Manages Row-Level Security (RLS) context for Postgres connections.
pub struct RlsManager;

impl RlsManager {
    /// Generates the SQL command to set the current client context.
    /// This must be executed at the start of every connection/transaction.
    pub fn set_context_sql(client_id: &str) -> String {
        // Sanitize? UUIDs are safe, but good to be careful.
        // In a real query builder (sqlx), we'd bind parameters. 
        // For raw string generation (sent to a driver), strict format is key.
        format!("SET app.current_client_id = '{}';", client_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_sql_generation() {
        let client_id = "123e4567-e89b-12d3-a456-426614174000";
        let sql = RlsManager::set_context_sql(client_id);
        assert_eq!(sql, "SET app.current_client_id = '123e4567-e89b-12d3-a456-426614174000';");
    }
}
