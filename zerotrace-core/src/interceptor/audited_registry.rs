use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Invalid function name '{name}'. Allowed: [A-Za-z0-9_.-], length 1..=64.")]
    InvalidFunctionName { name: String },

    #[error("Insecure Code Execution Attempt: Function '{name}' is not in the auditable registry.")]
    InsecureCodeExecutionAttempt { name: String },

    #[error("Input too large for '{function}': {bytes} bytes (max {max}).")]
    InputTooLarge {
        function: &'static str,
        bytes: usize,
        max: usize,
    },

    #[error("Output too large for '{function}': {bytes} bytes (max {max}).")]
    OutputTooLarge {
        function: &'static str,
        bytes: usize,
        max: usize,
    },

    #[error("Input too deep for '{function}': depth {depth} (max {max}).")]
    InputTooDeep {
        function: &'static str,
        depth: usize,
        max: usize,
    },

    #[error("Invalid parameters for '{function}': {reason}")]
    InvalidParams {
        function: &'static str,
        reason: String,
    },

    #[error("Runtime error in '{function}': {reason}")]
    RuntimeError {
        function: &'static str,
        reason: String,
    },
}

impl SecurityError {
    pub fn code(&self) -> &'static str {
        match self {
            SecurityError::InvalidFunctionName { .. } => "SEC_INVALID_FUNCTION_NAME",
            SecurityError::InsecureCodeExecutionAttempt { .. } => "SEC_UNKNOWN_FUNCTION",
            SecurityError::InputTooLarge { .. } => "SEC_INPUT_TOO_LARGE",
            SecurityError::OutputTooLarge { .. } => "SEC_OUTPUT_TOO_LARGE",
            SecurityError::InputTooDeep { .. } => "SEC_INPUT_TOO_DEEP",
            SecurityError::InvalidParams { .. } => "SEC_INVALID_PARAMS",
            SecurityError::RuntimeError { .. } => "SEC_RUNTIME_ERROR",
        }
    }
}

#[derive(Debug)]
pub enum FunctionError {
    InvalidParams(String),
    Runtime(String),
}

type SafeFunction = fn(&InvocationContext, Value) -> Result<Value, FunctionError>;

#[derive(Debug, Clone)]
pub struct InvocationContext {
    /// Who/what initiated the call (user id, agent id, “llm”, etc.)
    pub actor: String,
    /// Correlation id (request id, trace id, etc.)
    pub request_id: String,
}

impl InvocationContext {
    pub fn new(actor: impl Into<String>, request_id: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            request_id: request_id.into(),
        }
    }

    pub fn anonymous() -> Self {
        Self {
            actor: "unknown".to_string(),
            request_id: "unknown".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionPolicy {
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_json_depth: usize,
    /// Keys that should be redacted in audit logs
    pub redact_keys: &'static [&'static str],
}

impl Default for FunctionPolicy {
    fn default() -> Self {
        Self {
            max_input_bytes: 8 * 1024,
            max_output_bytes: 8 * 1024,
            max_json_depth: 32,
            redact_keys: &["password", "pass", "secret", "token", "api_key", "key", "authorization"],
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionDescriptor {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub handler: SafeFunction,
    pub policy: FunctionPolicy,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub actor: String,
    pub request_id: String,
    pub function: String,
    pub function_version: String,
    pub outcome: String, // "ok" | "error"
    pub error_code: Option<String>,
    pub params_redacted: Value,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
}

#[derive(Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _event: AuditEvent) {}
}

/// Example audit sink for tests or local dev.
#[derive(Default)]
pub struct InMemoryAuditSink {
    pub events: Mutex<Vec<AuditEvent>>,
}

impl AuditSink for InMemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}

pub struct FunctionRegistry {
    audited_functions: HashMap<&'static str, FunctionDescriptor>,
    audit_sink: Arc<dyn AuditSink>,
}

impl FunctionRegistry {
    pub fn new() -> Self {
        Self::with_audit_sink(Arc::new(NoopAuditSink::default()))
    }

    pub fn with_audit_sink(audit_sink: Arc<dyn AuditSink>) -> Self {
        let mut reg = Self {
            audited_functions: HashMap::new(),
            audit_sink,
        };

        // Register safe, audited functions (compile-time code only).
        reg.register(FunctionDescriptor {
            name: "calculate_interest",
            version: "1.0.0",
            description: "Compute simple or compound interest with strict input validation.",
            handler: safe_calculate_interest,
            policy: FunctionPolicy {
                max_input_bytes: 2 * 1024,
                max_output_bytes: 2 * 1024,
                max_json_depth: 16,
                redact_keys: FunctionPolicy::default().redact_keys,
            },
        });

        reg.register(FunctionDescriptor {
            name: "format_legal_date",
            version: "1.0.0",
            description: "Parse YYYY-MM-DD and format as a legal-friendly date string.",
            handler: safe_format_legal_date,
            policy: FunctionPolicy {
                max_input_bytes: 2 * 1024,
                max_output_bytes: 2 * 1024,
                max_json_depth: 8,
                redact_keys: FunctionPolicy::default().redact_keys,
            },
        });

        reg
    }

    pub fn register(&mut self, desc: FunctionDescriptor) {
        // Duplicate registration is a configuration bug, so fail hard in dev.
        if self.audited_functions.contains_key(desc.name) {
            panic!("Duplicate function registration: {}", desc.name);
        }
        self.audited_functions.insert(desc.name, desc);
    }

    /// Invokes a function from the Clean-Room Registry (EXT20).
    /// The caller selects a *name*, and you run *compiled Rust* only.
    pub fn invoke_function(
        &self,
        ctx: &InvocationContext,
        function_name: &str,
        params: Value,
    ) -> Result<Value, SecurityError> {
        validate_function_name(function_name)?;

        let desc = self
            .audited_functions
            .get(function_name)
            .ok_or_else(|| SecurityError::InsecureCodeExecutionAttempt {
                name: function_name.to_string(),
            })?;

        // Defensive limits: size + nesting depth.
        let in_bytes = serde_json::to_vec(&params).map(|v| v.len()).unwrap_or(usize::MAX);
        if in_bytes > desc.policy.max_input_bytes {
            self.audit(ctx, desc, "error", Some("SEC_INPUT_TOO_LARGE"), &params);
            return Err(SecurityError::InputTooLarge {
                function: desc.name,
                bytes: in_bytes,
                max: desc.policy.max_input_bytes,
            });
        }

        let depth = json_depth(&params);
        if depth > desc.policy.max_json_depth {
            self.audit(ctx, desc, "error", Some("SEC_INPUT_TOO_DEEP"), &params);
            return Err(SecurityError::InputTooDeep {
                function: desc.name,
                depth,
                max: desc.policy.max_json_depth,
            });
        }

        // Run the audited handler.
        let result = (desc.handler)(ctx, params.clone()).map_err(|e| match e {
            FunctionError::InvalidParams(reason) => SecurityError::InvalidParams {
                function: desc.name,
                reason,
            },
            FunctionError::Runtime(reason) => SecurityError::RuntimeError {
                function: desc.name,
                reason,
            },
        })?;

        // Output limit.
        let out_bytes = serde_json::to_vec(&result).map(|v| v.len()).unwrap_or(usize::MAX);
        if out_bytes > desc.policy.max_output_bytes {
            self.audit(ctx, desc, "error", Some("SEC_OUTPUT_TOO_LARGE"), &params);
            return Err(SecurityError::OutputTooLarge {
                function: desc.name,
                bytes: out_bytes,
                max: desc.policy.max_output_bytes,
            });
        }

        self.audit(ctx, desc, "ok", None, &params);
        Ok(result)
    }

    /// Convenience wrapper if your upstream wants a string (LLM-friendly).
    pub fn invoke_function_text(
        &self,
        ctx: &InvocationContext,
        function_name: &str,
        params: Value,
    ) -> Result<String, SecurityError> {
        let v = self.invoke_function(ctx, function_name, params)?;
        Ok(match v {
            Value::String(s) => s,
            other => other.to_string(),
        })
    }

    fn audit(
        &self,
        ctx: &InvocationContext,
        desc: &FunctionDescriptor,
        outcome: &str,
        error_code: Option<&str>,
        params: &Value,
    ) {
        let redacted = redact_json(params, desc.policy.redact_keys);

        self.audit_sink.record(AuditEvent {
            actor: ctx.actor.clone(),
            request_id: ctx.request_id.clone(),
            function: desc.name.to_string(),
            function_version: desc.version.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|s| s.to_string()),
            params_redacted: redacted,
        });
    }
}

fn validate_function_name(name: &str) -> Result<(), SecurityError> {
    if name.is_empty() || name.len() > 64 {
        return Err(SecurityError::InvalidFunctionName {
            name: name.to_string(),
        });
    }
    // Strict allowlist: avoids log injection and “creative” names.
    // Allowed: ASCII alnum + '_' + '-' + '.' only.
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
    {
        return Err(SecurityError::InvalidFunctionName {
            name: name.to_string(),
        });
    }
    Ok(())
}

fn json_depth(v: &Value) -> usize {
    // Iterative walk to avoid recursion blowups.
    let mut max_depth = 1usize;
    let mut stack: Vec<(&Value, usize)> = vec![(v, 1)];

    while let Some((cur, depth)) = stack.pop() {
        max_depth = max_depth.max(depth);

        match cur {
            Value::Array(a) => {
                for item in a {
                    stack.push((item, depth + 1));
                }
            }
            Value::Object(m) => {
                for (_k, val) in m {
                    stack.push((val, depth + 1));
                }
            }
            _ => {}
        }
    }

    max_depth
}

fn redact_json(v: &Value, keys: &[&str]) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                if keys.iter().any(|rk| rk.eq_ignore_ascii_case(k)) {
                    out.insert(k.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    out.insert(k.clone(), redact_json(val, keys));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|x| redact_json(x, keys)).collect()),
        other => other.clone(),
    }
}

// -------------------------
// Safe Implementation Examples
// -------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterestParams {
    principal: f64,
    /// Decimal rate, e.g. 0.05 for 5%
    rate: f64,
    /// Number of periods (defaults to 1)
    periods: Option<u32>,
    /// If true, compound interest: principal * (1 + rate)^periods
    compound: Option<bool>,
}

fn safe_calculate_interest(_ctx: &InvocationContext, params: Value) -> Result<Value, FunctionError> {
    let p: InterestParams =
        serde_json::from_value(params).map_err(|e| FunctionError::InvalidParams(e.to_string()))?;

    if !p.principal.is_finite() || !p.rate.is_finite() {
        return Err(FunctionError::InvalidParams(
            "principal and rate must be finite numbers".to_string(),
        ));
    }
    if p.principal < 0.0 {
        return Err(FunctionError::InvalidParams(
            "principal must be >= 0".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&p.rate) {
        return Err(FunctionError::InvalidParams(
            "rate must be between 0.0 and 1.0 (decimal, e.g. 0.05)".to_string(),
        ));
    }

    let periods = p.periods.unwrap_or(1);
    if periods == 0 || periods > 10_000 {
        return Err(FunctionError::InvalidParams(
            "periods must be between 1 and 10_000".to_string(),
        ));
    }

    let compound = p.compound.unwrap_or(false);

    let total = if compound {
        p.principal * (1.0 + p.rate).powi(periods as i32)
    } else {
        p.principal + (p.principal * p.rate * periods as f64)
    };
    let interest = total - p.principal;

    // Keep output stable and explicit.
    Ok(json!({
        "principal": round2(p.principal),
        "rate": round6(p.rate),
        "periods": periods,
        "compound": compound,
        "interest": round2(interest),
        "total": round2(total),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DateParams {
    /// Must be YYYY-MM-DD
    date: String,
    /// "long_us" | "short_us" | "iso"
    style: Option<String>,
}

fn safe_format_legal_date(_ctx: &InvocationContext, params: Value) -> Result<Value, FunctionError> {
    let p: DateParams =
        serde_json::from_value(params).map_err(|e| FunctionError::InvalidParams(e.to_string()))?;

    let (y, m, d) = parse_iso_date(&p.date)
        .map_err(|e| FunctionError::InvalidParams(format!("date must be YYYY-MM-DD: {e}")))?;

    let style = p.style.unwrap_or_else(|| "long_us".to_string());
    let out = match style.as_str() {
        "iso" => format!("{:04}-{:02}-{:02}", y, m, d),
        "short_us" => format!("{:02}/{:02}/{:04}", m, d, y),
        "long_us" => format!("{} {}, {}", month_name(m), d, y),
        _ => {
            return Err(FunctionError::InvalidParams(
                "style must be one of: long_us, short_us, iso".to_string(),
            ))
        }
    };

    Ok(json!({ "formatted": out, "style": style }))
}

fn parse_iso_date(s: &str) -> Result<(u32, u32, u32), String> {
    // Strict: YYYY-MM-DD
    if s.len() != 10 {
        return Err("wrong length".to_string());
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return Err("missing '-' separators".to_string());
    }
    let year = s[0..4].parse::<u32>().map_err(|_| "invalid year")?;
    let month = s[5..7].parse::<u32>().map_err(|_| "invalid month")?;
    let day = s[8..10].parse::<u32>().map_err(|_| "invalid day")?;

    if year < 1600 || year > 9999 {
        return Err("year out of supported range".to_string());
    }
    if month < 1 || month > 12 {
        return Err("month out of range".to_string());
    }
    let dim = days_in_month(year, month);
    if day < 1 || day > dim {
        return Err(format!("day out of range for month (max {dim})"));
    }

    Ok((year, month, day))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) { 29 } else { 28 }
        }
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn month_name(month: u32) -> &'static str {
    match month {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => "Unknown",
    }
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

fn round6(x: f64) -> f64 {
    (x * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_interest_call() {
        let audit = Arc::new(InMemoryAuditSink::default());
        let registry = FunctionRegistry::with_audit_sink(audit.clone());
        let ctx = InvocationContext::new("llm", "req-1");

        let params = json!({ "principal": 1000.0, "rate": 0.05, "periods": 1, "compound": false });
        let result = registry.invoke_function(&ctx, "calculate_interest", params).unwrap();

        assert_eq!(result["interest"], json!(50.0));
        assert_eq!(result["total"], json!(1050.0));

        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "ok");
        assert_eq!(events[0].function, "calculate_interest");
    }

    #[test]
    fn blocks_arbitrary_code_string_by_name_validation() {
        let registry = FunctionRegistry::new();
        let ctx = InvocationContext::anonymous();
        let params = json!({});
        let err = registry
            .invoke_function(&ctx, "os.system('rm -rf /')", params)
            .unwrap_err();

        matches!(err, SecurityError::InvalidFunctionName { .. });
    }

    #[test]
    fn blocks_unknown_function() {
        let registry = FunctionRegistry::new();
        let ctx = InvocationContext::anonymous();
        let params = json!({});
        let err = registry
            .invoke_function(&ctx, "non_existent_function", params)
            .unwrap_err();

        matches!(err, SecurityError::InsecureCodeExecutionAttempt { .. });
    }

    #[test]
    fn denies_unknown_fields_in_params() {
        let registry = FunctionRegistry::new();
        let ctx = InvocationContext::anonymous();

        // "bonus" is not allowed due to deny_unknown_fields
        let params = json!({ "principal": 1000.0, "rate": 0.05, "bonus": 999 });
        let err = registry
            .invoke_function(&ctx, "calculate_interest", params)
            .unwrap_err();

        matches!(err, SecurityError::InvalidParams { .. });
    }

    #[test]
    fn valid_legal_date_formatting() {
        let registry = FunctionRegistry::new();
        let ctx = InvocationContext::anonymous();

        let params = json!({ "date": "2026-02-10", "style": "long_us" });
        let result = registry
            .invoke_function(&ctx, "format_legal_date", params)
            .unwrap();

        assert_eq!(result["formatted"], json!("February 10, 2026"));
    }

    #[test]
    fn rejects_invalid_date() {
        let registry = FunctionRegistry::new();
        let ctx = InvocationContext::anonymous();

        let params = json!({ "date": "2026-02-31" });
        let err = registry
            .invoke_function(&ctx, "format_legal_date", params)
            .unwrap_err();

        matches!(err, SecurityError::InvalidParams { .. });
    }
}
