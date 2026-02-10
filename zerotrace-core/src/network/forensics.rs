use reqwest::Client;
use serde_json::json;
use std::env;

pub struct ForensicMonitor {
    client: Client,
    neo4j_url: String, // e.g., "http://localhost:7474/db/neo4j/tx/commit"
    auth_token: String,
}

impl ForensicMonitor {
    pub fn new() -> Self {
        let url = env::var("NEO4J_HTTP_URL").unwrap_or_else(|_| "http://localhost:7474/db/neo4j/tx/commit".to_string());
        let user = env::var("NEO4J_USER").unwrap_or_else(|_| "neo4j".to_string());
        let pass = env::var("NEO4J_PASS").unwrap_or_else(|_| "password".to_string());
        let auth = base64::encode(format!("{}:{}", user, pass));

        ForensicMonitor {
            client: Client::new(),
            neo4j_url: url,
            auth_token: auth,
        }
    }

    /// Triggers an immediate forensic investigation for High Severity events.
    /// This is a Fire-and-Forget async call.
    pub async fn trigger_investigation(&self, agent_id: &str, risk_code: &str) {
        println!("FORENSIC TRIGGER: Analyzing Agent {} for Risk {}", agent_id, risk_code);

        // Cypher Query to Detect Infection Path (Worm Check)
        let query = r#"
            MATCH path = (origin:Agent {id: $agent_id})-[:COMMUNICATED_WITH*1..3]->(target:Agent)
            WHERE ALL(a IN nodes(path) WHERE a.risk_score > 0.5)
            RETURN [n in nodes(path) | n.id] as infection_chain
            LIMIT 1
        "#;

        let payload = json!({
            "statements": [
                {
                    "statement": query,
                    "parameters": {
                        "agent_id": agent_id
                    }
                }
            ]
        });

        let _ = self.client.post(&self.neo4j_url)
            .header("Authorization", format!("Basic {}", self.auth_token))
            .json(&payload)
            .send()
            .await
            .map_err(|e| eprintln!("Neo4j Trigger Error: {}", e));
            
        // Note: In a real system, we would parse the result. 
        // If a chain is found, we would auto-block the 'origin' agent in Redis.
    }
}

use tokio_postgres::NoTls;
use futures::StreamExt;

pub struct ForensicSentinel {
    db_url: String,
    monitor: ForensicMonitor,
}

impl ForensicSentinel {
    pub fn new(db_url: String) -> Self {
        ForensicSentinel {
            db_url,
            monitor: ForensicMonitor::new(),
        }
    }

    /// Listens for Postgres high-severity alerts and triggers Neo4j analysis.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (client, mut connection) = tokio_postgres::connect(&self.db_url, NoTls).await?;

        // Spawn the connection to run in the background
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Postgres connection error: {}", e);
            }
        });

        // Listen for the specific channel
        client.execute("LISTEN high_severity_alerts", &[]).await?;
        println!("ForensicSentinel: Listening for high_severity_alerts...");

        let mut notifications = client.notifications();
        while let Some(notification) = notifications.next().await {
            let notification = notification?;
            let payload_str = notification.payload();
            
            // Parse JSON payload
            let payload: serde_json::Value = serde_json::from_str(payload_str)?;
            
            // Extract Agent ID and Risk Code
            if let (Some(agent_id), Some(risk_code)) = (
                payload.get("agent_id").and_then(|v| v.as_str()),
                payload.get("risk_code").and_then(|v| v.as_str())
            ) {
                println!("ForensicSentinel: Received Alert for Agent {}", agent_id);
                // Trigger Neo4j Investigation
                self.monitor.trigger_investigation(agent_id, risk_code).await;
            }
        }

        Ok(())
    }
}
