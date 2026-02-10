use std::sync::Arc;
use std::thread;
use zerotrace_core::interceptor::cprf::{
    ContextSentinel, ExecutionContext, SecurityError, SecurityPolicy, ToolRiskLevel,
};

#[test]
fn test_standard_context_allows_high_risk() {
    // Scenario: Internal user-initiated prompt
    let sentinel = ContextSentinel::new(ExecutionContext::Standard);

    assert!(
        sentinel.execute_tool_call("File_Export").is_ok(),
        "Standard context should allow high-risk tools (HITL enforcement is upstream)"
    );
    assert!(sentinel.execute_tool_call("Email_Send").is_ok());
    assert!(sentinel.execute_tool_call("SQL_Write").is_ok());
}

#[test]
fn test_tainted_context_blocks_high_risk() {
    // Scenario: Processing untrusted email content
    let sentinel = ContextSentinel::new(ExecutionContext::ExternalDataProcessing);

    let result = sentinel.execute_tool_call("Email_Send");

    assert!(
        result.is_err(),
        "Should block Email_Send in tainted context"
    );

    match result.unwrap_err() {
        SecurityError::CPRFBlocked {
            tool,
            context,
            risk,
        } => {
            assert_eq!(tool, "Email_Send");
            assert_eq!(context, ExecutionContext::ExternalDataProcessing);
            assert_eq!(risk, ToolRiskLevel::HighRisk);
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_tainted_context_allows_safe_tools() {
    // Scenario: Safe read operations should work even in tainted context
    let sentinel = ContextSentinel::new(ExecutionContext::ExternalDataProcessing);

    assert!(
        sentinel.execute_tool_call("Search_CaseLaw").is_ok(),
        "Tainted context should allow safe read-only tools"
    );
    assert!(sentinel.execute_tool_call("Database_Query").is_ok());
}

#[test]
fn test_invalid_tool_names_rejected() {
    // Scenario: Malformed input handling
    let sentinel = ContextSentinel::new(ExecutionContext::Standard);

    // Empty string
    assert!(matches!(
        sentinel.execute_tool_call(""),
        Err(SecurityError::InvalidToolName(_))
    ));

    // Special characters (potential injection)
    assert!(matches!(
        sentinel.execute_tool_call("Email; DROP TABLE"),
        Err(SecurityError::InvalidToolName(_))
    ));

    // Path traversal attempt
    assert!(matches!(
        sentinel.execute_tool_call("../../../etc/passwd"),
        Err(SecurityError::InvalidToolName(_))
    ));
}

#[test]
fn test_critical_tools_blocked_in_tainted_context() {
    // Scenario: System execution must never run from external data
    let sentinel = ContextSentinel::new(ExecutionContext::ExternalDataProcessing);

    let result = sentinel.execute_tool_call("System_Execute");

    assert!(result.is_err());
    match result.unwrap_err() {
        SecurityError::CPRFBlocked { risk, .. } => {
            assert_eq!(risk, ToolRiskLevel::Critical);
        }
        _ => panic!("Expected CPRF block"),
    }
}

#[test]
fn test_context_transition() {
    // Scenario: Dynamic context changes during execution
    let mut sentinel = ContextSentinel::new(ExecutionContext::Standard);

    // Initially allows high-risk
    assert!(sentinel.execute_tool_call("Email_Send").is_ok());

    // Transition to tainted
    sentinel.transition_context(ExecutionContext::ExternalDataProcessing);

    // Now blocks high-risk
    assert!(sentinel.execute_tool_call("Email_Send").is_err());
}

#[test]
fn test_custom_policy() {
    // Scenario: Organization-specific tool restrictions
    let mut policy = SecurityPolicy::default_production();
    Arc::get_mut(&mut policy.high_risk_tools) // Accessing internal field Requires pub access or constructor support
        // Wait, the fields `high_risk_tools` are private in `cprf.rs`.
        // I should check if I can modify the policy. The provided code has public fields?
        // Checking previous step...
        // `pub struct SecurityPolicy { high_risk_tools: Arc<HashSet<String>>, ... }` -> No, they are private by default if not pub.
        // The previous step shows:
        // pub struct SecurityPolicy {
        //    high_risk_tools: Arc<HashSet<String>>,
        //    critical_tools: Arc<HashSet<String>>,
        // }
        // Rust struct fields are private by default.
        // I need to ensure `SecurityPolicy` exposes fields or methods to modify them for this test to work OR use `with_policy` correctly.
        // The provided coderequest had:
        // pub struct SecurityPolicy {
        //     high_risk_tools: Arc<HashSet<String>>,
        //     critical_tools: Arc<HashSet<String>>,
        // }
        // If I paste that verbatim, functionality outside the module won't be able to access those fields.
        // However, the test code provided by the user accesses them:
        // Arc::get_mut(&mut policy.high_risk_tools).unwrap().insert(...)
        // This implies the user *expects* them to be public or accessible.
        // In `cprf.rs`, I should probably make them public or provide a constructor/mutator.
        // Let's assume for now I should generate the code as requested, but if `high_risk_tools` is private, this test will fail to compile.
        // The `cprf.rs` I just wrote:
        // pub struct SecurityPolicy {
        //     high_risk_tools: Arc<HashSet<String>>,
        //     critical_tools: Arc<HashSet<String>>,
        // }
        // This makes them private to the module. `tests/cprf_tests.rs` is a separate crate (integration test).
        // I should fix `cprf.rs` to make fields public OR add a method to mutate.
        // But since I already wrote `cprf.rs`, I have to "fix" it or the test.
        // Actually, integration tests treat the crate as a library. Private fields are inaccessible.
        // I will modify `cprf.rs` to make the fields public, as that seems to be the intent of the user's test case.
        // Wait, the user provided the code as:
        // ```rust
        // pub struct SecurityPolicy {
        //    high_risk_tools: Arc<HashSet<String>>,
        //    critical_tools: Arc<HashSet<String>>,
        // }
        // ```
        // In Rust, if I don't say `pub high_risk_tools`, it's private.
        // The user's test code:
        // `Arc::get_mut(&mut policy.high_risk_tools)`
        // This confirms they need to be public.
        // I will update `cprf.rs` to make fields public.
        // For now, let's write the test file assuming they WILL be public, and then immediately fix `cprf.rs`.
        // actually, I can do it in the "fix" step if it fails compilation, but better to do it now.
        .unwrap()
        .insert("Custom_PaymentAPI".to_string());

    let sentinel = ContextSentinel::with_policy(ExecutionContext::ExternalDataProcessing, policy);

    assert!(sentinel.execute_tool_call("Custom_PaymentAPI").is_err());
}
