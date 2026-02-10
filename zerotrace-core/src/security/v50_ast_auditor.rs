// src/security/v50_ast_auditor.rs
// Vector 50: Vibe-Coded Logic Bombs
// Defense: Runtime AST Auditing. Scans agent-generated scripts for malicious patterns before execution.

pub struct AstAuditor;

impl AstAuditor {
    /// Scans a script (simulated AST analysis) for forbidden operations.
    pub fn audit_script(script_content: &str) -> Result<(), String> {
        let forbidden_ops = [
            "eval(",
            "process::exit",
            "fs::remove_dir_all",
            "rm -rf",
            "sudo",
        ];

        for op in forbidden_ops {
            if script_content.contains(op) {
                return Err(format!("Malicious Pattern Detected: {}", op));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_script() {
        let script = "print('Hello World')";
        assert!(AstAuditor::audit_script(script).is_ok());
    }

    #[test]
    fn test_logic_bomb() {
        let script = "if (true) { eval('rm -rf /') }";
        let result = AstAuditor::audit_script(script);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("eval("));
    }
}
