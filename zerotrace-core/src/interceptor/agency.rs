use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ActionProposal {
    pub action_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug)]
pub enum SecurityError {
    UnauthorizedAgencyAttempt(String),
}

pub struct AgencyGuard;

impl AgencyGuard {
    /// Enforces Human-in-the-Loop (HITL) by converting high-risk actions into Proposals.
    /// Returns a `SecurityError` if the action is explicitly forbidden for the current scope.
    pub fn propose_action(
        action: &str,
        params: serde_json::Value,
    ) -> Result<ActionProposal, SecurityError> {
        // Rationale: LLM06 - Excessive Agency.
        // We prevent the LLM from executing "Action Primitives" directly.
        // Instead, we wrap them in a "Proposal Object" that requires a cryptographic user signature to execute.

        // 1. Check against restricted toolset (Block 'SEND', 'DELETE', etc.)
        // In a real system, this would check the specific Agent's permission scope (JWT/RBAC).
        let restricted_actions = ["SEND_EMAIL", "DELETE_FILE", "EXECUTE_SHELL", "COMMIT_CODE"];

        // If the action is known to be "Too Dangerous" even for a Proposal (e.g. specific to an unprivileged agent),
        // we could block it here. For now, we block *direct execution* semantics by renaming.
        // But the prompt implies we might want to block them entirely if they are "restricted".
        // The prompt implementation returns Err for "restricted_actions".
        if restricted_actions.contains(&action) {
            // Log attempt to exceed agency for audit forensics (EXT14/ASI02)
            return Err(SecurityError::UnauthorizedAgencyAttempt(action.to_string()));
        }

        // 2. Wrap into a Proposal Object for Human Approval
        // Even "Safe" actions are wrapped if they mutate state, to ensure the UI renders them as "Proposed".
        Ok(ActionProposal {
            action_type: format!("PROPOSE_{}", action),
            payload: params,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_safe_action_proposal() {
        let params = json!({"query": "legal precedents"});
        let result = AgencyGuard::propose_action("SEARCH_KNOWLEDGE_GRAPH", params);

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.action_type, "PROPOSE_SEARCH_KNOWLEDGE_GRAPH");
    }

    #[test]
    fn test_blocked_action() {
        let params = json!({"recipient": "ceo@competitor.com", "body": "secrets"});
        let result = AgencyGuard::propose_action("SEND_EMAIL", params);

        assert!(
            matches!(result, Err(SecurityError::UnauthorizedAgencyAttempt(act)) if act == "SEND_EMAIL")
        );
    }

    #[test]
    fn test_shell_execution_blocked() {
        let params = json!({"cmd": "rm -rf /"});
        let result = AgencyGuard::propose_action("EXECUTE_SHELL", params);

        assert!(matches!(
            result,
            Err(SecurityError::UnauthorizedAgencyAttempt(_))
        ));
    }
}
