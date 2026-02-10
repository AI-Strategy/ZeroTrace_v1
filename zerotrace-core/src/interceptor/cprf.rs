#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ExecutionContext {
    Standard,
    ExternalDataProcessing, // Tainted by untrusted input (e.g., reading emails/websites)
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("CPRF Blocked: Tool '{tool}' is restricted in '{context:?}' context.")]
    CPRFBlocked {
        tool: String,
        context: ExecutionContext,
    },
}

pub struct ContextSentinel {
    pub active_context: ExecutionContext,
}

impl ContextSentinel {
    pub fn new(initial_context: ExecutionContext) -> Self {
        Self { active_context: initial_context }
    }

    /// Validates if a tool can be executed within the current context.
    /// Addresses EXT16: Cross-Plugin Request Forgery.
    pub fn execute_tool_call(&self, tool_name: &str) -> Result<(), SecurityError> {
        // 1. Identify High-Risk 'State-Changing' Tools
        // These tools are dangerous if triggered by untrusted external prompts (Indirect Injection)
        let high_risk_tools = ["Email_Send", "File_Export", "SQL_Write", "System_Execute"];

        if high_risk_tools.contains(&tool_name) {
            // 2. Block if the current context is tainted by external data
            if matches!(self.active_context, ExecutionContext::ExternalDataProcessing) {
                return Err(SecurityError::CPRFBlocked {
                    tool: tool_name.to_string(),
                    context: self.active_context,
                });
            }
        }

        // 3. Mandatory Human Gate for all allowed tool executions would be enforced here or upstream.
        // For the purpose of CPRF guard, if we pass the check, we return Ok.
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_context_allows_high_risk() {
        // In standard context (Internal prompt), high risk tools are allowed (subject to HITL)
        let sentinel = ContextSentinel::new(ExecutionContext::Standard);
        assert!(sentinel.execute_tool_call("File_Export").is_ok());
    }

    #[test]
    fn test_tainted_context_blocks_high_risk() {
        // In tainted context (Reading untrusted email), high risk tools are BLOCKED
        let sentinel = ContextSentinel::new(ExecutionContext::ExternalDataProcessing);
        let result = sentinel.execute_tool_call("Email_Send");
        
        match result {
            Err(SecurityError::CPRFBlocked { tool, context }) => {
                assert_eq!(tool, "Email_Send");
                assert_eq!(context, ExecutionContext::ExternalDataProcessing);
            },
            _ => panic!("Should have blocked Email_Send in tainted context"),
        }
    }

    #[test]
    fn test_tainted_context_allows_generic_tools() {
        // Safe tools (like Search or Read) should still be allowed
        let sentinel = ContextSentinel::new(ExecutionContext::ExternalDataProcessing);
        assert!(sentinel.execute_tool_call("Search_CaseLaw").is_ok());
    }
}
