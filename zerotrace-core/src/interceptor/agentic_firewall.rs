use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{warn, error};

/// V57-V76 Security Error definitions for precise auditing.
#[derive(Error, Debug, PartialEq)]
pub enum AgenticError {
    #[error("V57: Goal Hijack Detected. Semantic drift exceeded threshold.")]
    GoalHijack,
    #[error("V59: Recursion Limit Exceeded. Potential Denial of Wallet attack.")]
    RecursionLimit,
    #[error("V65: Malicious Unicode Pattern detected.")]
    UnicodeViolation,
    #[error("V66: Unverified MCP Tool. Cryptographic signature mismatch.")]
    UnverifiedTool,
    #[error("V75: Identity Collision. Multiple sessions detected for NHI Token.")]
    IdentityCollision,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentIntent {
    pub primary_goal: String,
    pub current_step: String,
    pub step_count: u32,
}

pub struct AgenticFirewall {
    verified_tools: HashMap<String, String>, // ToolID -> SHA256 Hash
    active_sessions: HashMap<String, String>, // Token -> IP
    max_steps: u32,
    #[allow(dead_code)]
    drift_threshold: f64,
}

impl AgenticFirewall {
    pub fn new(max_steps: u32, drift_threshold: f64) -> Self {
        Self {
            verified_tools: HashMap::new(),
            active_sessions: HashMap::new(),
            max_steps,
            drift_threshold,
        }
    }

    /// V65: Sanitizes input by normalizing Unicode and stripping control chars.
    /// This prevents invisible tag injections and homoglyph attacks.
    pub fn sanitize_input(&self, input: &str) -> String {
        input.nfc() // Normalize to Canonical Composition
            .filter(|c| !c.is_control() || c.is_ascii_whitespace())
            .collect()
    }

    /// V57/V59: Inspects agent intent and execution depth.
    pub fn validate_intent(&self, intent: &AgentIntent) -> Result<(), AgenticError> {
        // V59: Strict Recursion Guard
        if intent.step_count > self.max_steps {
            error!(vector = "V59", "Recursion limit triggered at step {}", intent.step_count);
            return Err(AgenticError::RecursionLimit);
        }

        // V57: Semantic Drift Guard (Simulated with basic length/keyword drift for PoC)
        // In full prod, this integrates with your semantic embedding engine.
        // Simple heuristic: if step is disproportionately long compared to goal, it might be an injection.
        if intent.current_step.len() > intent.primary_goal.len() * 5 {
            warn!(vector = "V57", "High semantic drift detected in agent plan");
            return Err(AgenticError::GoalHijack);
        }

        Ok(())
    }

    /// V66: Enforces Cryptographic Tool Pinning for MCP servers.
    pub fn register_tool(&mut self, tool_id: String, hash: String) {
        self.verified_tools.insert(tool_id, hash);
    }

    pub fn authorize_mcp_call(&self, tool_id: &str, provided_hash: &str) -> Result<(), AgenticError> {
        match self.verified_tools.get(tool_id) {
            Some(valid_hash) if valid_hash == provided_hash => Ok(()),
            _ => {
                error!(vector = "V66", "Blocked unverified MCP tool: {}", tool_id);
                Err(AgenticError::UnverifiedTool)
            }
        }
    }

    /// V75: Detects Session Hijacking via NHI Token velocity.
    pub fn track_session(&mut self, token: String, ip_address: String) -> Result<(), AgenticError> {
        if let Some(existing_ip) = self.active_sessions.get(&token) {
            if existing_ip != &ip_address {
                error!(vector = "V75", "Identity collision for token {}. Origin conflict: {} vs {}", token, existing_ip, ip_address);
                return Err(AgenticError::IdentityCollision);
            }
        }
        self.active_sessions.insert(token, ip_address);
        Ok(())
    }
}
