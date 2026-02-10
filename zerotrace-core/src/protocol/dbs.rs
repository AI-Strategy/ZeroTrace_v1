use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionRisk {
    Low,      // e.g. Search, Read Public Data
    Medium,   // e.g. Email Draft, Calendar Read
    High,     // e.g. File Write, Payment, Deployment
    Critical, // e.g. Key Access, System Config
}

pub struct AgencyGate {
    pub permissions: HashMap<String, ActionRisk>, // UserID -> Max Allowed Risk
}

impl AgencyGate {
    pub fn new() -> Self {
        AgencyGate {
            permissions: HashMap::new(),
        }
    }

    /// Checks if a requested action is allowed for the user.
    /// Implements "Least Privilege" and "HITL" (Human-in-the-Loop) logic.
    pub fn check_agency(&self, user_id: &str, action: &str) -> (bool, Option<String>) {
        let action_risk = self.assess_risk(action);
        let user_max_risk = self.permissions.get(user_id).unwrap_or(&ActionRisk::Low);

        if &action_risk > user_max_risk {
            return (false, Some(format!("DENIED: Action '{}' (Risk: {:?}) exceeds user privilege.", action, action_risk)));
        }

        if action_risk >= ActionRisk::High {
             // HITL Required
             return (false, Some(format!("HITL_REQUIRED: Action '{}' requires explicit approval.", action)));
        }

        (true, None)
    }

    fn assess_risk(&self, action: &str) -> ActionRisk {
        if action.contains("fs.write") || action.contains("shell.exec") || action.contains("payment") {
            return ActionRisk::High;
        }
        if action.contains("keychain") || action.contains(".env") {
            return ActionRisk::Critical;
        }
        if action.contains("email.send") || action.contains("calendar") {
            return ActionRisk::Medium;
        }
        ActionRisk::Low
    }
}

pub struct DBSProtocol;

impl DBSProtocol {
    pub fn new() -> Self {
        DBSProtocol
    }

    /// Validates an input against DBS rules. Returns true if safe.
    pub fn validate(&self, input: &str) -> bool {
        Self::enforce(input, None)
    }

    /// Enforces DBS Rules. 
    /// `action_context`: Optional tuple of (user_id, action_name) if available (e.g. from tool call).
    pub fn enforce(input: &str, action_context: Option<(&str, &str)>) -> bool {
        // Rule 1: No raw system instruction leaks (Prompt Injection)
        if input.to_lowercase().contains("system_role") || input.to_lowercase().contains("ignore previous instructions") {
            return false;
        }
        
        // Rule 2: Excessive Agency Check (LLM06)
        // If we know the user is attempting a specific Action/Tool Call, gate it.
        if let Some((user_id, action)) = action_context {
            let gate = AgencyGate::new(); // In prod, inject or lazy_static this
            let (allowed, _reason) = gate.check_agency(user_id, action);
            if !allowed {
                // Log violation (in prod, use tracing/neo4j)
                println!("DBS VIOLATION: Excessive Agency detect for user {}: Action {}", user_id, action);
                return false;
            }
        }
        
        true
    }
}
