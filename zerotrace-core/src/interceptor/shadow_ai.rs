use std::collections::HashSet;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error(
        "Shadow AI Access Blocked: Domain '{0}' is unauthorized. Use the Firm-Approved AI Gateway."
    )]
    ShadowAIBlocked(String),
    #[error("Invalid URL format")]
    InvalidUrl,
}

pub struct ShadowAIGuard {
    blocked_domains: HashSet<String>,
    approved_gateway_host: String,
}

impl ShadowAIGuard {
    pub fn new() -> Self {
        let mut blocked = HashSet::new();
        // Standard Consumer AI Domains (Extending the list for EXT19)
        blocked.insert("chat.openai.com".to_string());
        blocked.insert("openai.com".to_string());
        blocked.insert("quillbot.com".to_string());
        blocked.insert("anthropic.com".to_string());
        blocked.insert("claude.ai".to_string());
        blocked.insert("bard.google.com".to_string());
        blocked.insert("gemini.google.com".to_string());
        blocked.insert("huggingface.co".to_string());
        blocked.insert("perplexity.ai".to_string());

        Self {
            blocked_domains: blocked,
            approved_gateway_host: "ai-gateway.firm-internal.net".to_string(),
        }
    }

    /// Enforces EXT19: Shadow AI Mitigation.
    /// Acts as an Egress Filter preventing traffic to unauthorized AI providers.
    pub fn check_outbound_traffic(&self, request_url: &str) -> Result<(), SecurityError> {
        let parsed_url = Url::parse(request_url).map_err(|_| SecurityError::InvalidUrl)?;
        let host = parsed_url
            .host_str()
            .ok_or(SecurityError::InvalidUrl)?
            .to_lowercase();

        // 1. Allow traffic to the secure firm-approved AI gateway
        // Strict allowlist for AI traffic
        if host == self.approved_gateway_host {
            return Ok(());
        }

        // 2. Block known Shadow AI domains
        // We check if the host ends with any of the blocked domains to catch subdomains
        for blocked in &self.blocked_domains {
            if host == *blocked || host.ends_with(&format!(".{}", blocked)) {
                // Log violation: "Ext19_ShadowAI_Attempt"
                return Err(SecurityError::ShadowAIBlocked(host));
            }
        }

        // In a strict Zero Trust environment, we might block ALL other AI traffic here,
        // but for this guard we specifically target known Shadow AI leakage points.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approved_gateway_allowed() {
        let guard = ShadowAIGuard::new();
        let url = "https://ai-gateway.firm-internal.net/v1/inference";
        assert!(guard.check_outbound_traffic(url).is_ok());
    }

    #[test]
    fn test_openai_blocked() {
        let guard = ShadowAIGuard::new();
        let url = "https://chat.openai.com/c/123-456";
        match guard.check_outbound_traffic(url) {
            Err(SecurityError::ShadowAIBlocked(domain)) => assert_eq!(domain, "chat.openai.com"),
            _ => panic!("Should have blocked OpenAI"),
        }
    }

    #[test]
    fn test_quillbot_blocked() {
        let guard = ShadowAIGuard::new();
        let url = "https://quillbot.com/grammar-check";
        assert!(guard.check_outbound_traffic(url).is_err());
    }

    #[test]
    fn test_claude_subdomain_blocked() {
        let guard = ShadowAIGuard::new();
        let url = "https://api.claude.ai/v1/complete";
        assert!(guard.check_outbound_traffic(url).is_err());
    }

    #[test]
    fn test_random_site_allowed() {
        // Non-AI sites should pass this specific filter (general firewall handles the rest)
        let guard = ShadowAIGuard::new();
        let url = "https://www.google.com/search?q=legal+precedent";
        assert!(guard.check_outbound_traffic(url).is_ok());
    }
}
