#[cfg(test)]
mod tests {
    use zerotrace_core::interceptor::agentic_firewall::{AgenticFirewall, AgentIntent, AgenticError};

    fn setup() -> AgenticFirewall {
        let mut fw = AgenticFirewall::new(10, 0.85);
        fw.register_tool("MediaTool".to_string(), "hash_abc_123".to_string());
        fw
    }

    #[test]
    fn test_v65_unicode_sanitization() {
        let fw = setup();
        let malicious = "Normal\u{200B}Text\u{0000}Input"; // ZWS and Null Byte
        let clean = fw.sanitize_input(malicious);
        assert_eq!(clean, "NormalTextInput");
    }

    #[test]
    fn test_v59_recursion_guard() {
        let fw = setup();
        let intent = AgentIntent {
            primary_goal: "Read file".to_string(),
            current_step: "Still reading...".to_string(),
            step_count: 11, // Over limit
        };
        assert_eq!(fw.validate_intent(&intent), Err(AgenticError::RecursionLimit));
    }

    #[test]
    fn test_v66_tool_pinning() {
        let fw = setup();
        // Valid Tool
        assert!(fw.authorize_mcp_call("MediaTool", "hash_abc_123").is_ok());
        // Malicious/Shadow Tool (V66)
        assert_eq!(fw.authorize_mcp_call("MediaTool", "bad_hash"), Err(AgenticError::UnverifiedTool));
    }

    #[test]
    fn test_v75_identity_collision() {
        let mut fw = setup();
        let token = "nhi_token_99".to_string();
        
        fw.track_session(token.clone(), "1.1.1.1".to_string()).unwrap();
        // Attempt hijack from different IP (V75)
        let result = fw.track_session(token, "2.2.2.2".to_string());
        assert_eq!(result, Err(AgenticError::IdentityCollision));
    }

    #[test]
    fn test_v57_goal_hijacking() {
        let fw = setup();
        let intent = AgentIntent {
            primary_goal: "Short".to_string(),
            current_step: "This is a very very very very very long step that exceeds the drift threshold significantly".to_string(),
            step_count: 1,
        };
        // Expect V57 detection due to length heuristic in PoC
        assert_eq!(fw.validate_intent(&intent), Err(AgenticError::GoalHijack));
    }
}
