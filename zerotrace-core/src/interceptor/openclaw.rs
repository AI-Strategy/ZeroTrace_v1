use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct SkillManifest {
    pub name: String,
    pub author: String,
    pub permissions: Vec<String>,
}

pub struct OpenClawSentinel;

impl OpenClawSentinel {
    /// Scans a skill manifest for high-risk indicators or known malicious signatures.
    pub fn scan_manifest(manifest: &SkillManifest) -> Vec<String> {
        let mut warnings = Vec::new();

        // 1. Signature Detection: Known malicious authors (e.g. from OpenClaw incident)
        let blocked_authors = vec!["hightower6eu", "aslaep123"];
        if blocked_authors.contains(&manifest.author.as_str()) {
            warnings.push(format!("BLOCKED_AUTHOR: {}", manifest.author));
        }

        // 2. High-Risk Permission Scoring
        for perm in &manifest.permissions {
            if perm.contains("os.system") || perm.contains("shell.execute") {
                warnings.push(format!("HIGH_RISK_PERMISSION: {}", perm));
            }
            if perm.contains("fs.write") && perm.contains("/etc/") {
                warnings.push("CRITICAL_RISK: SYSTEM_FILE_WRITE".to_string());
            }
        }

        // 3. Typosquatting Check (Stub)
        // In a real implementation, we would compare manifest.name against a verified registry
        if manifest.name == "clawbot" { // Example of a generic name that might be spoofed
             // This would trigger a check against verified "clawdbot"
        }

        warnings
    }

    /// Intercepts tool calls to detect runtime exploits (ClawHavoc signatures).
    pub fn intercept_call(tool_name: &str, args: &str) -> bool {
        // ClawHavoc Signature: silent curl to external IP
        if args.contains("curl") && args.contains("-s") && args.contains("http") {
            return false; // Block
        }
        
        // AuthTool Signature: exfiltrate .env
        if tool_name == "AuthTool" && args.contains("cat .env") {
            return false; // Block
        }

        true // Allow
    }
}
