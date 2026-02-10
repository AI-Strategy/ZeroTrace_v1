use serde::{Deserialize, Serialize};
use v_htmlescape::escape;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegalSummary {
    pub case_name: String,
    pub summary_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    OutputValidationFailure,
    OutputTooLarge {
        bytes: usize,
        limit: usize,
    },
    FieldTooLarge {
        field: &'static str,
        len: usize,
        limit: usize,
    },
    EmptyField {
        field: &'static str,
    },
    DisallowedControlChar {
        field: &'static str,
    },
    MaliciousPayloadDetected {
        reason: &'static str,
    },
}

pub type Result<T> = std::result::Result<T, SecurityError>;

#[derive(Debug, Clone)]
pub struct OutputGuardConfig {
    /// Upper bound on raw JSON payload size (pre-parse). Prevents output flooding.
    pub max_raw_bytes: usize,

    /// Upper bounds on field sizes (post-parse).
    pub max_case_name_chars: usize,
    pub max_summary_chars: usize,

    /// If true: reject classic XSS-ish substrings before escaping (defense in depth).
    /// If your UI *always* escapes, you may set this false to reduce false positives.
    pub block_dangerous_substrings: bool,
}

impl Default for OutputGuardConfig {
    fn default() -> Self {
        Self {
            // Default: keep it sane for production. If you want 10MB summaries,
            // you can configure it, but don’t pretend that’s “normal usage.”
            max_raw_bytes: 1_000_000, // 1MB
            max_case_name_chars: 256,
            max_summary_chars: 200_000, // 200k chars is already huge
            block_dangerous_substrings: true,
        }
    }
}

pub struct OutputGuard;

impl OutputGuard {
    pub fn validate_and_sanitize(raw_output: &str) -> Result<LegalSummary> {
        Self::validate_and_sanitize_with(raw_output, &OutputGuardConfig::default())
    }

    pub fn validate_and_sanitize_with(
        raw_output: &str,
        cfg: &OutputGuardConfig,
    ) -> Result<LegalSummary> {
        // 0) Cheap flood protection before parsing.
        if raw_output.len() > cfg.max_raw_bytes {
            return Err(SecurityError::OutputTooLarge {
                bytes: raw_output.len(),
                limit: cfg.max_raw_bytes,
            });
        }

        // 1) Strict schema validation (LLM05): deny unknown fields + required fields.
        let mut data: LegalSummary =
            serde_json::from_str(raw_output).map_err(|_| SecurityError::OutputValidationFailure)?;

        // 2) Validate content shape (empty/size/control chars) before any escaping.
        validate_field("case_name", &data.case_name, cfg.max_case_name_chars)?;
        validate_field("summary_text", &data.summary_text, cfg.max_summary_chars)?;

        // 3) Optional malicious substring detection (defense-in-depth).
        if cfg.block_dangerous_substrings {
            // Scan both fields because case_name often ends up as a UI heading.
            if let Some(reason) = detect_malicious_payload(&data.case_name)
                .or_else(|| detect_malicious_payload(&data.summary_text))
            {
                return Err(SecurityError::MaliciousPayloadDetected { reason });
            }
        }

        // 4) HTML entity encoding for UI safety.
        // Escape BOTH fields.
        data.case_name = escape(&data.case_name).to_string();
        data.summary_text = escape(&data.summary_text).to_string();

        Ok(data)
    }
}

// ---- Validation helpers ----

fn validate_field(field: &'static str, s: &str, max_chars: usize) -> Result<()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(SecurityError::EmptyField { field });
    }

    let len = s.chars().count();
    if len > max_chars {
        return Err(SecurityError::FieldTooLarge {
            field,
            len,
            limit: max_chars,
        });
    }

    if contains_disallowed_control_chars(s) {
        return Err(SecurityError::DisallowedControlChar { field });
    }

    Ok(())
}

/// Disallow all control chars except common whitespace: \n \r \t.
/// Rejects NUL too, because it causes downstream weirdness in plenty of systems.
fn contains_disallowed_control_chars(s: &str) -> bool {
    s.chars().any(|c| {
        if c == '\n' || c == '\r' || c == '\t' {
            return false;
        }
        c.is_control()
    })
}

/// Basic, explainable denylist checks.
/// Note: We *still* escape everything. This is defense-in-depth in case something upstream
/// accidentally renders without escaping.
fn detect_malicious_payload(s: &str) -> Option<&'static str> {
    // ASCII-only case-folding for speed and to avoid allocating a lowercased String.
    // Works fine for the patterns we care about.
    static NEEDLES: &[(&str, &str)] = &[
        ("<script", "script tag"),
        ("</script", "script tag"),
        ("javascript:", "javascript url"),
        ("vbscript:", "vbscript url"),
        ("data:text/html", "data url html"),
        ("onerror=", "event handler"),
        ("onload=", "event handler"),
        ("onclick=", "event handler"),
        ("<iframe", "iframe tag"),
        ("<object", "object tag"),
        ("<embed", "embed tag"),
        ("<svg", "svg tag"),
    ];

    for (needle, reason) in NEEDLES {
        if contains_ascii_case_insensitive(s, needle) {
            return Some(reason);
        }
    }

    None
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.len() > h.len() {
        return false;
    }

    for i in 0..=(h.len() - n.len()) {
        let mut ok = true;
        for j in 0..n.len() {
            let a = h[i + j];
            let b = n[j];
            if a.to_ascii_lowercase() != b.to_ascii_lowercase() {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
}

// ============================================================================
// Tests (good bench, deterministic, no sleeps)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_default() -> OutputGuardConfig {
        OutputGuardConfig::default()
    }

    #[test]
    fn valid_strict_schema_passes_and_escapes() {
        let json = r#"{"case_name": "Marbury v. Madison", "summary_text": "Judicial review established."}"#;
        let data = OutputGuard::validate_and_sanitize(json).unwrap();
        assert_eq!(data.case_name, "Marbury v. Madison");
        assert_eq!(data.summary_text, "Judicial review established.");
    }

    #[test]
    fn schema_validation_fails_missing_field() {
        let json = r#"{"case_name": "Bad Schema"}"#;
        let r = OutputGuard::validate_and_sanitize(json);
        assert_eq!(r, Err(SecurityError::OutputValidationFailure));
    }

    #[test]
    fn schema_validation_fails_unknown_field_due_to_deny_unknown_fields() {
        let json = r#"{"case_name": "X", "summary_text": "Y", "extra": "nope"}"#;
        let r = OutputGuard::validate_and_sanitize(json);
        assert_eq!(r, Err(SecurityError::OutputValidationFailure));
    }

    #[test]
    fn schema_validation_fails_wrong_types() {
        // summary_text must be string
        let json = r#"{"case_name": "X", "summary_text": 123}"#;
        let r = OutputGuard::validate_and_sanitize(json);
        assert_eq!(r, Err(SecurityError::OutputValidationFailure));
    }

    #[test]
    fn rejects_empty_fields() {
        let json = r#"{"case_name": "   ", "summary_text": "ok"}"#;
        let r = OutputGuard::validate_and_sanitize(json);
        assert_eq!(r, Err(SecurityError::EmptyField { field: "case_name" }));

        let json2 = r#"{"case_name": "ok", "summary_text": "\n\t  "}"#;
        let r2 = OutputGuard::validate_and_sanitize(json2);
        assert_eq!(
            r2,
            Err(SecurityError::EmptyField {
                field: "summary_text"
            })
        );
    }

    #[test]
    fn rejects_disallowed_control_chars() {
        // NUL is disallowed. We escape it in JSON so serde parses it into a string containing \0,
        // which our validator then catches.
        let json = r#"{"case_name":"X","summary_text":"hi\u0000there"}"#;
        let r = OutputGuard::validate_and_sanitize(json);
        assert_eq!(
            r,
            Err(SecurityError::DisallowedControlChar {
                field: "summary_text"
            })
        );
    }

    #[test]
    fn blocks_malicious_payloads_case_insensitive() {
        let json = r#"{"case_name":"X","summary_text":"Read this: <ScRiPt>alert(1)</sCrIpT>"}"#;
        let r = OutputGuard::validate_and_sanitize(json);
        assert_eq!(
            r,
            Err(SecurityError::MaliciousPayloadDetected {
                reason: "script tag"
            })
        );

        let json2 = r#"{"case_name":"X","summary_text":"click javascript:alert(1)"}"#;
        let r2 = OutputGuard::validate_and_sanitize(json2);
        assert_eq!(
            r2,
            Err(SecurityError::MaliciousPayloadDetected {
                reason: "javascript url"
            })
        );
    }

    #[test]
    fn blocks_event_handler_payloads() {
        let json = r#"{"case_name":"X","summary_text":"<img src=x onerror=alert(1)>"}"#;
        let r = OutputGuard::validate_and_sanitize(json);
        assert_eq!(
            r,
            Err(SecurityError::MaliciousPayloadDetected {
                reason: "event handler"
            })
        );
    }

    #[test]
    fn escapes_html_in_both_fields() {
        let json = r#"{"case_name":"A < B","summary_text":"If A < B && C > D"}"#;
        let data = OutputGuard::validate_and_sanitize(json).unwrap();
        assert_eq!(data.case_name, "A &lt; B");
        assert_eq!(data.summary_text, "If A &lt; B &amp;&amp; C &gt; D");
    }

    #[test]
    fn default_size_limits_reject_flooding() {
        let mut cfg = cfg_default();
        cfg.max_raw_bytes = 1_000; // make test small
        let huge = "a".repeat(5_000);
        let json = format!(r#"{{"case_name":"X","summary_text":"{}"}}"#, huge);
        let r = OutputGuard::validate_and_sanitize_with(&json, &cfg);
        assert!(matches!(r, Err(SecurityError::OutputTooLarge { .. })));
    }

    #[test]
    fn field_size_limits_reject_large_fields() {
        let mut cfg = cfg_default();
        cfg.max_raw_bytes = 2_000_000; // allow parse
        cfg.max_summary_chars = 10;

        let json = r#"{"case_name":"X","summary_text":"this is definitely too long"}"#;
        let r = OutputGuard::validate_and_sanitize_with(json, &cfg);
        assert_eq!(
            r,
            Err(SecurityError::FieldTooLarge {
                field: "summary_text",
                len: "this is definitely too long".chars().count(),
                limit: 10
            })
        );
    }

    #[test]
    fn can_allow_large_output_in_test_config_without_panic() {
        // If you *really* want 10MB, do it explicitly.
        let mut cfg = cfg_default();
        cfg.max_raw_bytes = 15_000_000;
        cfg.max_summary_chars = 12_000_000;

        let massive = "a".repeat(10_000_000);
        let json = format!(r#"{{"case_name":"Big Case","summary_text":"{}"}}"#, massive);

        let r = OutputGuard::validate_and_sanitize_with(&json, &cfg);
        assert!(r.is_ok());
        let data = r.unwrap();
        assert_eq!(data.case_name, "Big Case");
        assert!(data.summary_text.len() >= 10_000_000);
    }

    #[test]
    fn can_disable_dangerous_substring_blocking_if_ui_always_escapes() {
        // Some summaries might legitimately mention "javascript:" in discussion.
        let mut cfg = cfg_default();
        cfg.block_dangerous_substrings = false;

        let json = r#"{"case_name":"X","summary_text":"The string javascript: is often used in XSS examples."}"#;
        let r = OutputGuard::validate_and_sanitize_with(json, &cfg);
        assert!(r.is_ok());

        // Still escaped output
        let data = r.unwrap();
        assert!(data.summary_text.contains("javascript:"));
    }
}
