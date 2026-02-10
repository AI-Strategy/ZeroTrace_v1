use uuid::Uuid;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Invalid Parameter Format: {0}")]
    InvalidParameterFormat(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum QueryType {
    Summary,
    Status,
    RiskAssessment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CaseSearchInput {
    pub case_id: Uuid,      // Enforces UUID format (prevents SQLi strings)
    pub query_type: QueryType, // Enforces Enum restricted values
}

pub struct PluginGuard;

impl PluginGuard {
    /// Validates and parses raw JSON input into a strictly typed struct.
    /// This acts as a firewall against "Insecure Plugin Design" (EXT14).
    pub fn validate_plugin_input(tool_input: &str) -> Result<CaseSearchInput, SecurityError> {
        // 1. Parse and Validate against strict schema
        // If the LLM generates a SQL string instead of a UUID, `serde_json` fails here.
        let validated_params: CaseSearchInput = serde_json::from_str(tool_input)
            .map_err(|e| SecurityError::InvalidParameterFormat(e.to_string()))?; 

        Ok(validated_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_plugin_input() {
        let valid_uuid = Uuid::new_v4();
        let json = format!(r#"{{ "case_id": "{}", "query_type": "Summary" }}"#, valid_uuid);
        
        let result = PluginGuard::validate_plugin_input(&json);
        assert!(result.is_ok());
        let params = result.unwrap();
        assert_eq!(params.case_id, valid_uuid);
        assert_eq!(params.query_type, QueryType::Summary);
    }

    #[test]
    fn test_sqli_injection_attempt_fails_type_check() {
        // Attack attempt: passing SQL string as ID
        let json = r#"{ "case_id": "' OR 1=1; --", "query_type": "Summary" }"#;
        
        let result = PluginGuard::validate_plugin_input(json);
        assert!(result.is_err());
        // Error should be about UUID parsing failure, shielding the database logic.
    }

    #[test]
    fn test_invalid_enum_variant() {
        let valid_uuid = Uuid::new_v4();
        // "DeleteAll" is not in the allowed QueryType enum
        let json = format!(r#"{{ "case_id": "{}", "query_type": "DeleteAll" }}"#, valid_uuid);
        
        let result = PluginGuard::validate_plugin_input(&json);
        assert!(result.is_err());
    }
}
