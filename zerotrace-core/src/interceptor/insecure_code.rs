use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Insecure Code Execution Attempt: Function '{0}' is not in the auditable registry.")]
    InsecureCodeExecutionAttempt(String),
    #[error("Runtime Error: {0}")]
    RuntimeError(String),
}

type SafeFunction = fn(Value) -> Result<String, String>;

pub struct FunctionRegistry {
    // A map of pre-vetted, audited function pointers.
    // The model selects a *name*, and we execute the *compiled Rust code*.
    audited_functions: HashMap<String, SafeFunction>,
}

impl FunctionRegistry {
    pub fn new() -> Self {
        let mut map: HashMap<String, SafeFunction> = HashMap::new();

        // Register safe, audited functions
        map.insert("calculate_interest".to_string(), safe_calculate_interest);
        map.insert("format_legal_date".to_string(), safe_format_date);

        Self {
            audited_functions: map,
        }
    }

    /// Invokes a function from the Clean-Room Registry (EXT20).
    /// Prevents "Insecure Code Generation" by disallowing the LLM from defining logic.
    pub fn invoke_function(
        &self,
        function_name: &str,
        params: Value,
    ) -> Result<String, SecurityError> {
        // 1. Prevent the model from writing its own code.
        // The LLM can ONLY call existing, signed functions.
        if let Some(func) = self.audited_functions.get(function_name) {
            func(params).map_err(SecurityError::RuntimeError)
        } else {
            // 2. Reject 'eval()', 'exec()', or unknown calls.
            // Any attempt to execute a function not in this HashMap is blocked.
            Err(SecurityError::InsecureCodeExecutionAttempt(
                function_name.to_string(),
            ))
        }
    }
}

// --- Safe Implementation Examples ---

fn safe_calculate_interest(params: Value) -> Result<String, String> {
    let principal = params
        .get("principal")
        .and_then(|v| v.as_f64())
        .ok_or("Missing principal")?;
    let rate = params
        .get("rate")
        .and_then(|v| v.as_f64())
        .ok_or("Missing rate")?;
    let interest = principal * rate;
    Ok(format!("{:.2}", interest))
}

fn safe_format_date(params: Value) -> Result<String, String> {
    let date_str = params
        .get("date")
        .and_then(|v| v.as_str())
        .ok_or("Missing date")?;
    // In a real app, parse and format. Here we just return "Formatted: ..."
    Ok(format!("Formatted: {}", date_str))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_function_call() {
        let registry = FunctionRegistry::new();
        let params = json!({ "principal": 1000.0, "rate": 0.05 });
        let result = registry.invoke_function("calculate_interest", params);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "50.00");
    }

    #[test]
    fn test_arbitrary_code_execution_blocked() {
        let registry = FunctionRegistry::new();
        let params = json!({});
        // 'os.system' or similar calls are simply strings that don't match any key.
        let result = registry.invoke_function("os.system('rm -rf /')", params);

        match result {
            Err(SecurityError::InsecureCodeExecutionAttempt(name)) => {
                assert_eq!(name, "os.system('rm -rf /')");
            }
            _ => panic!("Should have blocked arbitrary code"),
        }
    }

    #[test]
    fn test_unknown_function_blocked() {
        let registry = FunctionRegistry::new();
        let params = json!({});
        let result = registry.invoke_function("non_existent_function", params);
        assert!(result.is_err());
    }
}
