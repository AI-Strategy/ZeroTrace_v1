use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Function '{0}' not found in registry")]
    FunctionNotFound(String),
    #[error("Validation failed for {0}: {1}")]
    ValidationFailed(String, String),
    #[error("Security policy violation: {0}")]
    PolicyViolation(String),
    #[error("Parameter extraction error: {0}")]
    ParameterError(String),
}

pub type Result<T> = std::result::Result<T, SecurityError>;

pub struct InvocationContext {
    pub params: serde_json::Value,
    pub user_roles: Vec<String>,
}

impl InvocationContext {
    pub fn new(params: serde_json::Value, user_roles: Vec<String>) -> Self {
        Self { params, user_roles }
    }

    pub fn param<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<T> {
        match &self.params {
            serde_json::Value::Object(map) => {
                if let Some(val) = map.get(key) {
                    serde_json::from_value(val.clone()).map_err(|e| {
                        SecurityError::ParameterError(format!("Invalid parameter '{}': {}", key, e))
                    })
                } else {
                    Err(SecurityError::ParameterError(format!(
                        "Missing parameter '{}'",
                        key
                    )))
                }
            }
            _ => Err(SecurityError::ParameterError(
                "Root params must be an object".into(),
            )),
        }
    }
}

pub trait AuditedFunction: Send + Sync {
    fn name(&self) -> &str;
    fn execute(&self, context: InvocationContext) -> Result<serde_json::Value>;
}

pub struct FunctionRegistry {
    functions: HashMap<String, Box<dyn AuditedFunction>>,
}

impl FunctionRegistry {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    pub fn register<F: AuditedFunction + 'static>(&mut self, f: F) {
        self.functions.insert(f.name().to_string(), Box::new(f));
    }

    pub fn execute(&self, name: &str, context: InvocationContext) -> Result<serde_json::Value> {
        if let Some(func) = self.functions.get(name) {
            func.execute(context)
        } else {
            Err(SecurityError::FunctionNotFound(name.to_string()))
        }
    }
}

// --- Example Functions ---

pub struct SafeCalculateInterest;
impl AuditedFunction for SafeCalculateInterest {
    fn name(&self) -> &str {
        "safe_calculate_interest"
    }
    fn execute(&self, context: InvocationContext) -> Result<serde_json::Value> {
        let amount: f64 = context.param("amount")?;
        let rate: f64 = context.param("rate")?;

        // Policy check (example)
        if amount > 1_000_000.0 && !context.user_roles.contains(&"admin".to_string()) {
            return Err(SecurityError::PolicyViolation(
                "Amount exceeds limit for non-admin".into(),
            ));
        }

        Ok(serde_json::json!({ "result": amount * rate }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_registry_execution() {
        let mut registry = FunctionRegistry::new();
        registry.register(SafeCalculateInterest);

        let ctx = InvocationContext::new(
            json!({ "amount": 1000.0, "rate": 0.05 }),
            vec!["user".to_string()],
        );

        let res = registry.execute("safe_calculate_interest", ctx).unwrap();
        assert_eq!(res["result"], 50.0);
    }

    #[test]
    fn test_policy_enforcement() {
        let mut registry = FunctionRegistry::new();
        registry.register(SafeCalculateInterest);

        let ctx = InvocationContext::new(
            json!({ "amount": 2_000_000.0, "rate": 0.05 }),
            vec!["user".to_string()], // Missing admin role
        );

        let err = registry
            .execute("safe_calculate_interest", ctx)
            .unwrap_err();
        match err {
            SecurityError::PolicyViolation(msg) => assert!(msg.contains("Amount exceeds limit")),
            _ => panic!("Expected PolicyViolation"),
        }
    }
}
