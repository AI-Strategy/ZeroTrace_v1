use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SecurityError {
    #[error("Invalid JSON")]
    InvalidJson,

    #[error("Invalid parameter format: {0}")]
    InvalidParameterFormat(&'static str),

    #[error("Input too large: {bytes} bytes (limit {limit})")]
    InputTooLarge { bytes: usize, limit: usize },
}

pub type Result<T> = std::result::Result<T, SecurityError>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
pub enum QueryType {
    Summary,
    Status,
    RiskAssessment,
}

impl QueryType {
    /// Human/agent-friendly parsing while still being strict.
    /// Accepts: "Summary", "summary", "SUMMARY" (and same for others).
    fn parse_loose(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "summary" => Some(Self::Summary),
            "status" => Some(Self::Status),
            "riskassessment" | "risk_assessment" | "risk-assessment" => Some(Self::RiskAssessment),
            _ => None,
        }
    }
}

/// STRICT input. deny_unknown_fields prevents smuggling extra keys.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaseSearchInput {
    pub case_id: Uuid,
    pub query_type: QueryType,
}

/// A "loose" wire format that we accept from agents to reduce friction,
/// then normalize into strict CaseSearchInput.
/// This lets you accept query_type in more forgiving formats without allowing new fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseSearchWire {
    case_id: String,
    query_type: String,
}

pub struct PluginGuard;

impl PluginGuard {
    /// Maximum size of tool input JSON to prevent DoS.
    pub const MAX_INPUT_BYTES: usize = 8 * 1024; // 8KB is plenty for this tool

    /// Validates and parses raw JSON input into a strictly typed struct.
    /// Firewall against insecure plugin design (EXT14).
    pub fn validate_plugin_input(tool_input: &str) -> Result<CaseSearchInput> {
        if tool_input.len() > Self::MAX_INPUT_BYTES {
            return Err(SecurityError::InputTooLarge {
                bytes: tool_input.len(),
                limit: Self::MAX_INPUT_BYTES,
            });
        }

        // Enforce "must be JSON object" and deny unknown fields via CaseSearchWire
        let wire: CaseSearchWire =
            serde_json::from_str(tool_input).map_err(|_| SecurityError::InvalidJson)?;

        // Validate UUID strictly
        let case_id = Uuid::parse_str(wire.case_id.trim())
            .map_err(|_| SecurityError::InvalidParameterFormat("case_id must be a UUID"))?;

        // Validate QueryType with tolerant parsing (optional, but reduces agent failure rate)
        let query_type = QueryType::parse_loose(&wire.query_type).ok_or(
            SecurityError::InvalidParameterFormat(
                "query_type must be one of: Summary, Status, RiskAssessment",
            ),
        )?;

        Ok(CaseSearchInput {
            case_id,
            query_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk_valid_json(case_id: Uuid, query_type: &str) -> String {
        json!({
            "case_id": case_id.to_string(),
            "query_type": query_type
        })
        .to_string()
    }

    // -------------------- Happy path --------------------

    #[test]
    fn test_valid_plugin_input_pascal_case() {
        let id = Uuid::new_v4();
        let j = mk_valid_json(id, "Summary");

        let out = PluginGuard::validate_plugin_input(&j).unwrap();
        assert_eq!(out.case_id, id);
        assert_eq!(out.query_type, QueryType::Summary);
    }

    #[test]
    fn test_valid_query_type_case_insensitive() {
        let id = Uuid::new_v4();
        let j = mk_valid_json(id, "riskassessment");

        let out = PluginGuard::validate_plugin_input(&j).unwrap();
        assert_eq!(out.query_type, QueryType::RiskAssessment);
    }

    #[test]
    fn test_valid_query_type_with_underscores_or_dashes() {
        let id = Uuid::new_v4();
        let j1 = mk_valid_json(id, "risk_assessment");
        let j2 = mk_valid_json(id, "risk-assessment");

        assert_eq!(
            PluginGuard::validate_plugin_input(&j1).unwrap().query_type,
            QueryType::RiskAssessment
        );
        assert_eq!(
            PluginGuard::validate_plugin_input(&j2).unwrap().query_type,
            QueryType::RiskAssessment
        );
    }

    // -------------------- SQLi & format abuse --------------------

    #[test]
    fn test_sqli_injection_attempt_fails_uuid_check() {
        let j = r#"{ "case_id": "' OR 1=1; --", "query_type": "Summary" }"#;
        let err = PluginGuard::validate_plugin_input(j).unwrap_err();
        assert_eq!(
            err,
            SecurityError::InvalidParameterFormat("case_id must be a UUID")
        );
    }

    #[test]
    fn test_invalid_enum_variant_rejected() {
        let id = Uuid::new_v4();
        let j = mk_valid_json(id, "DeleteAll");
        let err = PluginGuard::validate_plugin_input(&j).unwrap_err();
        assert_eq!(
            err,
            SecurityError::InvalidParameterFormat(
                "query_type must be one of: Summary, Status, RiskAssessment"
            )
        );
    }

    // -------------------- Schema strictness --------------------

    #[test]
    fn test_unknown_field_is_rejected() {
        let id = Uuid::new_v4();
        let j = json!({
            "case_id": id.to_string(),
            "query_type": "Summary",
            "extra": "smuggle_me"
        })
        .to_string();

        let err = PluginGuard::validate_plugin_input(&j).unwrap_err();
        assert_eq!(err, SecurityError::InvalidJson); // deny_unknown_fields trips serde
    }

    #[test]
    fn test_missing_field_rejected() {
        let id = Uuid::new_v4();
        let j = json!({
            "case_id": id.to_string()
        })
        .to_string();

        let err = PluginGuard::validate_plugin_input(&j).unwrap_err();
        assert_eq!(err, SecurityError::InvalidJson);
    }

    #[test]
    fn test_wrong_type_rejected() {
        let id = Uuid::new_v4();
        let j = json!({
            "case_id": id.to_string(),
            "query_type": 123
        })
        .to_string();

        let err = PluginGuard::validate_plugin_input(&j).unwrap_err();
        assert_eq!(err, SecurityError::InvalidJson);
    }

    #[test]
    fn test_null_values_rejected() {
        let id = Uuid::new_v4();
        let j = json!({
            "case_id": id.to_string(),
            "query_type": null
        })
        .to_string();

        let err = PluginGuard::validate_plugin_input(&j).unwrap_err();
        assert_eq!(err, SecurityError::InvalidJson);
    }

    #[test]
    fn test_json_but_not_object_rejected() {
        let j = r#"["case_id", "not-an-object"]"#;
        let err = PluginGuard::validate_plugin_input(j).unwrap_err();
        assert_eq!(err, SecurityError::InvalidJson);

        let j2 = r#""just a string""#;
        let err2 = PluginGuard::validate_plugin_input(j2).unwrap_err();
        assert_eq!(err2, SecurityError::InvalidJson);
    }

    // -------------------- Input size hardening --------------------

    #[test]
    fn test_input_too_large_rejected() {
        let id = Uuid::new_v4();
        let base = mk_valid_json(id, "Summary");

        // Pad beyond limit with harmless whitespace (still a DoS vector).
        let padded = format!("{}{}", base, " ".repeat(PluginGuard::MAX_INPUT_BYTES + 1));
        let err = PluginGuard::validate_plugin_input(&padded).unwrap_err();

        assert_eq!(
            err,
            SecurityError::InputTooLarge {
                bytes: padded.len(),
                limit: PluginGuard::MAX_INPUT_BYTES
            }
        );
    }

    // -------------------- Whitespace normalization --------------------

    #[test]
    fn test_uuid_whitespace_trimmed() {
        let id = Uuid::new_v4();
        let j = json!({
            "case_id": format!("  {}  ", id),
            "query_type": "Summary"
        })
        .to_string();

        let out = PluginGuard::validate_plugin_input(&j).unwrap();
        assert_eq!(out.case_id, id);
    }

    #[test]
    fn test_query_type_whitespace_trimmed() {
        let id = Uuid::new_v4();
        let j = json!({
            "case_id": id.to_string(),
            "query_type": "  status  "
        })
        .to_string();

        let out = PluginGuard::validate_plugin_input(&j).unwrap();
        assert_eq!(out.query_type, QueryType::Status);
    }
}
