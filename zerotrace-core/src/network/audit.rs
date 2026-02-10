use tokio::sync::mpsc;
use tokio_postgres::{NoTls, Client};
use serde_json::Value;
use uuid::Uuid;
use std::sync::Arc;

#[derive(Debug)]
pub struct AuditEvent {
    pub risk_domain: String,
    pub risk_code: String,
    pub severity: i32,
    pub user_id: Option<Uuid>,
    pub agent_id: Option<String>,
    pub session_id: Uuid,
    pub input_prompt: Option<String>,
    pub intervention_type: String,
    pub rule_id: String,
    pub metadata: Value,
}

#[derive(Clone)]
pub struct AuditLogger {
    sender: mpsc::UnboundedSender<AuditEvent>,
}

impl AuditLogger {
    /// Spawns a background task to handle logging asynchronously.
    /// This ensures the critical path remains <5ms.
    pub fn new(connection_string: String) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            // In a real implementation, we'd handle connection retry/backoff here.
            let (client, connection) = tokio_postgres::connect(&connection_string, NoTls)
                .await
                .expect("Failed to connect to Postgres Audit DB");

            // The connection object performs the actual communication with the database,
            // so spawn it off to run on its own.
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("connection error: {}", e);
                }
            });

            while let Some(event) = rx.recv().await {
                // Batching could be implemented here for even higher throughput.
                let _ = client.execute(
                    "INSERT INTO zerotrace_audit.event_logs (
                        risk_domain, risk_code, severity, user_id, agent_id, session_id,
                        input_prompt, intervention_type, deterministic_rule_id, metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    &[
                        &event.risk_domain,
                        &event.risk_code,
                        &event.severity,
                        &event.user_id,
                        &event.agent_id,
                        &event.session_id,
                        &event.input_prompt,
                        &event.intervention_type,
                        &event.rule_id,
                        &event.metadata,
                    ],
                ).await.map_err(|e| eprintln!("Audit Log Error: {}", e));

                // TRIGGER FORENSICS for High Severity (4 or 5)
                if event.severity >= 4 {
                    if let Some(agent_id) = &event.agent_id {
                        let monitor = crate::network::forensics::ForensicMonitor::new();
                        monitor.trigger_investigation(agent_id, &event.risk_code).await;
                    }
                }
            }
        });

        AuditLogger { sender: tx }
    }

    /// O(1) fire-and-forget logging.
    pub fn log(&self, event: AuditEvent) {
        if let Err(e) = self.sender.send(event) {
            eprintln!("Failed to send audit event: {}", e);
        }
    }
}
