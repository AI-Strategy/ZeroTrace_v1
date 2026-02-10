use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use thiserror::Error;
use uuid::Uuid;

// -----------------------------------------------------------------------------
// Data model
// -----------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ActionRisk {
    /// Pure read-only operations. Still can be proposed depending on your workflow.
    ReadOnly,
    /// State changes (writes, updates, side effects).
    Mutating,
    /// Unknown actions default to safest handling.
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ActionProposal {
    /// Unique ID for audit trails + signature binding.
    pub proposal_id: Uuid,
    /// Canonical normalized action name (UPPER_SNAKE).
    pub action: String,
    /// UI-friendly field that keeps your existing convention.
    pub action_type: String,
    /// Risk classification (used by UI/workflow).
    pub risk: ActionRisk,
    /// Opaque JSON payload (validated for type + size).
    pub payload: Value,
    /// Always true: by definition, proposals need a human approval step.
    pub requires_human_approval: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecurityError {
    #[error("Unauthorized agency attempt: {action}. Reason: {reason}")]
    UnauthorizedAgencyAttempt { action: String, reason: String },

    #[error("Invalid action format: {0}")]
    InvalidActionFormat(String),

    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(String),

    #[error("Payload too large: {len} > {max} bytes")]
    PayloadTooLarge { len: usize, max: usize },
}

// -----------------------------------------------------------------------------
// Policy + Guard
// -----------------------------------------------------------------------------

/// How strict you want to be about what actions even get proposed.
#[derive(Debug, Clone)]
pub enum PolicyMode {
    /// Allow anything *except* forbidden actions.
    AllowAllExceptForbidden,
    /// Only allow actions explicitly listed (everything else is blocked).
    AllowList(HashSet<String>),
}

#[derive(Debug, Clone)]
pub struct AgencyPolicy {
    pub mode: PolicyMode,

    /// Actions you will not even allow as proposals.
    pub forbidden_actions: HashSet<String>,

    /// Optional: basic risk mapping.
    pub read_only_actions: HashSet<String>,
    pub mutating_actions: HashSet<String>,

    /// Payload rules.
    pub max_payload_bytes: usize,
    pub require_object_payload: bool,

    /// Reserved prefix. Prevents “I proposed it myself bro” bypasses.
    pub reserved_prefix: &'static str,

    /// Max length for action names.
    pub max_action_len: usize,
}

impl Default for AgencyPolicy {
    fn default() -> Self {
        let forbidden_actions: HashSet<String> = [
            "SEND_EMAIL",
            "DELETE_FILE",
            "EXECUTE_SHELL",
            "COMMIT_CODE",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        // You can grow this over time. Keep it boring and explicit.
        let read_only_actions: HashSet<String> = [
            "SEARCH_KNOWLEDGE_GRAPH",
            "GET_CASE_STATUS",
            "FETCH_DOCUMENT",
            "LOOKUP_PRECEDENT",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        let mutating_actions: HashSet<String> = [
            "UPDATE_CASE",
            "CREATE_TICKET",
            "ADD_NOTE",
            "WRITE_SUMMARY",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            mode: PolicyMode::AllowAllExceptForbidden,
            forbidden_actions,
            read_only_actions,
            mutating_actions,
            max_payload_bytes: 64 * 1024, // 64KB
            require_object_payload: true,
            reserved_prefix: "PROPOSE_",
            max_action_len: 64,
        }
    }
}

pub struct AgencyGuard {
    policy: AgencyPolicy,
}

impl Default for AgencyGuard {
    fn default() -> Self {
        Self {
            policy: AgencyPolicy::default(),
        }
    }
}

impl AgencyGuard {
    pub fn new(policy: AgencyPolicy) -> Self {
        Self { policy }
    }

    /// Backwards-compatible convenience:
    /// uses default policy.
    pub fn propose_action(action: &str, params: Value) -> Result<ActionProposal, SecurityError> {
        Self::default().propose(action, params)
    }

    /// Enhanced entrypoint (policy-driven).
    pub fn propose(&self, action: &str, params: Value) -> Result<ActionProposal, SecurityError> {
        let normalized = normalize_action(action, self.policy.max_action_len)?;

        // Prevent bypass tricks like feeding "PROPOSE_SEND_EMAIL" back in.
        if normalized.starts_with(self.policy.reserved_prefix) {
            return Err(SecurityError::InvalidActionFormat(format!(
                "Action may not start with reserved prefix '{}'",
                self.policy.reserved_prefix
            )));
        }

        // Policy mode enforcement.
        match &self.policy.mode {
            PolicyMode::AllowAllExceptForbidden => {}
            PolicyMode::AllowList(allowed) => {
                if !allowed.contains(&normalized) {
                    return Err(SecurityError::UnauthorizedAgencyAttempt {
                        action: normalized,
                        reason: "not in allowlist".to_string(),
                    });
                }
            }
        }

        // Absolute forbidden actions.
        if self.policy.forbidden_actions.contains(&normalized) {
            return Err(SecurityError::UnauthorizedAgencyAttempt {
                action: normalized,
                reason: "forbidden action".to_string(),
            });
        }

        // Payload type rules (default: require JSON object).
        if self.policy.require_object_payload && !params.is_object() {
            return Err(SecurityError::InvalidPayloadType(
                "payload must be a JSON object".to_string(),
            ));
        }

        // Payload size rules (serialize to bytes to estimate actual transport weight).
        let payload_len = serde_json::to_vec(&params)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if payload_len > self.policy.max_payload_bytes {
            return Err(SecurityError::PayloadTooLarge {
                len: payload_len,
                max: self.policy.max_payload_bytes,
            });
        }

        let risk = classify_risk(
            &normalized,
            &self.policy.read_only_actions,
            &self.policy.mutating_actions,
        );

        Ok(ActionProposal {
            proposal_id: Uuid::new_v4(),
            action: normalized.clone(),
            action_type: format!("{}{}", self.policy.reserved_prefix, normalized),
            risk,
            payload: params,
            requires_human_approval: true,
        })
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn normalize_action(action: &str, max_len: usize) -> Result<String, SecurityError> {
    let a = action.trim();
    if a.is_empty() {
        return Err(SecurityError::InvalidActionFormat(
            "empty action".to_string(),
        ));
    }
    let upper = a.to_uppercase();

    if upper.len() > max_len {
        return Err(SecurityError::InvalidActionFormat(format!(
            "action length {} exceeds max {}",
            upper.len(),
            max_len
        )));
    }

    // Strict charset: A-Z, 0-9, underscore only. (Boring is good.)
    if !upper
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(SecurityError::InvalidActionFormat(
            "action must be UPPER_SNAKE using A-Z, 0-9, '_' only".to_string(),
        ));
    }

    Ok(upper)
}

fn classify_risk(
    action: &str,
    read_only: &HashSet<String>,
    mutating: &HashSet<String>,
) -> ActionRisk {
    if mutating.contains(action) {
        return ActionRisk::Mutating;
    }
    if read_only.contains(action) {
        return ActionRisk::ReadOnly;
    }
    ActionRisk::Unknown
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn safe_action_proposal_basic() {
        let params = json!({"query": "legal precedents"});
        let proposal = AgencyGuard::propose_action("SEARCH_KNOWLEDGE_GRAPH", params).unwrap();

        assert_eq!(proposal.action, "SEARCH_KNOWLEDGE_GRAPH");
        assert_eq!(proposal.action_type, "PROPOSE_SEARCH_KNOWLEDGE_GRAPH");
        assert_eq!(proposal.risk, ActionRisk::ReadOnly);
        assert!(proposal.requires_human_approval);
        assert_eq!(proposal.payload["query"], "legal precedents");
    }

    #[test]
    fn normalization_uppercase_and_trim() {
        let params = json!({"x": 1});
        let proposal = AgencyGuard::propose_action("  search_knowledge_graph  ", params).unwrap();
        assert_eq!(proposal.action, "SEARCH_KNOWLEDGE_GRAPH");
    }

    #[test]
    fn blocked_action_send_email() {
        let params = json!({"recipient": "ceo@competitor.com", "body": "secrets"});
        let result = AgencyGuard::propose_action("SEND_EMAIL", params);

        assert!(matches!(
            result,
            Err(SecurityError::UnauthorizedAgencyAttempt{ action, .. }) if action == "SEND_EMAIL"
        ));
    }

    #[test]
    fn blocked_action_is_case_insensitive() {
        let params = json!({"cmd": "rm -rf /"});
        let result = AgencyGuard::propose_action("execute_shell", params);
        assert!(matches!(
            result,
            Err(SecurityError::UnauthorizedAgencyAttempt{ action, .. }) if action == "EXECUTE_SHELL"
        ));
    }

    #[test]
    fn invalid_action_rejects_weird_chars() {
        let params = json!({"x": 1});
        let result = AgencyGuard::propose_action("SEARCH;DROP_TABLE", params);
        assert!(matches!(result, Err(SecurityError::InvalidActionFormat(_))));
    }

    #[test]
    fn reserved_prefix_rejected() {
        let params = json!({"x": 1});
        let result = AgencyGuard::propose_action("PROPOSE_SEND_EMAIL", params);
        assert!(matches!(result, Err(SecurityError::InvalidActionFormat(_))));
    }

    #[test]
    fn payload_type_must_be_object_by_default() {
        let result = AgencyGuard::propose_action("SEARCH_KNOWLEDGE_GRAPH", json!("not-an-object"));
        assert!(matches!(result, Err(SecurityError::InvalidPayloadType(_))));
    }

    #[test]
    fn payload_too_large_blocked() {
        let mut policy = AgencyPolicy::default();
        policy.max_payload_bytes = 100; // small for test
        let guard = AgencyGuard::new(policy);

        let big = "a".repeat(10_000);
        let result = guard.propose("SEARCH_KNOWLEDGE_GRAPH", json!({ "blob": big }));

        assert!(matches!(result, Err(SecurityError::PayloadTooLarge{ .. })));
    }

    #[test]
    fn allowlist_mode_blocks_unknown_actions() {
        let mut allowed = HashSet::new();
        allowed.insert("SEARCH_KNOWLEDGE_GRAPH".to_string());

        let mut policy = AgencyPolicy::default();
        policy.mode = PolicyMode::AllowList(allowed);

        let guard = AgencyGuard::new(policy);

        let ok = guard.propose("SEARCH_KNOWLEDGE_GRAPH", json!({"q": "x"}));
        assert!(ok.is_ok());

        let blocked = guard.propose("LOOKUP_PRECEDENT", json!({"q": "x"}));
        assert!(matches!(
            blocked,
            Err(SecurityError::UnauthorizedAgencyAttempt{ reason, .. }) if reason.contains("allowlist")
        ));
    }

    #[test]
    fn unknown_action_defaults_to_unknown_risk_but_is_proposed() {
        let proposal = AgencyGuard::propose_action("MYSTERY_ACTION", json!({"x": 1})).unwrap();
        assert_eq!(proposal.risk, ActionRisk::Unknown);
        assert_eq!(proposal.action_type, "PROPOSE_MYSTERY_ACTION");
    }

    #[test]
    fn mutating_action_is_classified() {
        let proposal = AgencyGuard::propose_action("UPDATE_CASE", json!({"case_id": "123"})).unwrap();
        assert_eq!(proposal.risk, ActionRisk::Mutating);
    }
}
