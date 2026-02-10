use std::collections::HashSet;
use url::Url;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecurityError {
    #[error("Shadow AI Access Blocked: Domain '{host}' matched blocked rule '{matched}'. Use the Firm-Approved AI Gateway.")]
    ShadowAIBlocked { host: String, matched: String },

    #[error("Invalid URL format")]
    InvalidUrl,

    #[error("Unsupported URL scheme '{0}'")]
    UnsupportedScheme(String),

    #[error("URL missing host")]
    MissingHost,
}

/// Configuration for Shadow AI egress control.
#[derive(Debug, Clone)]
pub struct ShadowAIGuardConfig {
    /// Exact hosts allowed for AI traffic (firm gateway, proxy, etc).
    pub approved_gateway_hosts: HashSet<String>,

    /// Domains to block (exact domain + all subdomains).
    /// Example: "openai.com" blocks "openai.com" and "*.openai.com".
    pub blocked_domains: HashSet<String>,
}

impl Default for ShadowAIGuardConfig {
    fn default() -> Self {
        let mut blocked = HashSet::new();

        // Standard Consumer AI Domains (EXT19 baseline)
        for d in [
            "chat.openai.com",
            "openai.com",
            "quillbot.com",
            "anthropic.com",
            "claude.ai",
            "bard.google.com",
            "gemini.google.com",
            "huggingface.co",
            "perplexity.ai",
        ] {
            blocked.insert(normalize_domain(d));
        }

        let mut approved = HashSet::new();
        approved.insert(normalize_domain("ai-gateway.firm-internal.net"));

        Self {
            approved_gateway_hosts: approved,
            blocked_domains: blocked,
        }
    }
}

pub struct ShadowAIGuard {
    cfg: ShadowAIGuardConfig,
}

impl ShadowAIGuard {
    pub fn new() -> Self {
        Self {
            cfg: ShadowAIGuardConfig::default(),
        }
    }

    pub fn with_config(cfg: ShadowAIGuardConfig) -> Self {
        // Normalize everything so policy checks don’t depend on caller hygiene.
        let cfg = ShadowAIGuardConfig {
            approved_gateway_hosts: cfg
                .approved_gateway_hosts
                .into_iter()
                .map(|h| normalize_domain(&h))
                .collect(),
            blocked_domains: cfg
                .blocked_domains
                .into_iter()
                .map(|d| normalize_domain(&d))
                .collect(),
        };
        Self { cfg }
    }

    /// Enforces EXT19: Shadow AI Mitigation.
    /// Egress filter that blocks known consumer AI providers and allows firm gateway hosts.
    pub fn check_outbound_traffic(&self, request_url: &str) -> Result<(), SecurityError> {
        let parsed_url = Url::parse(request_url).map_err(|_| SecurityError::InvalidUrl)?;

        match parsed_url.scheme() {
            "http" | "https" => {}
            other => return Err(SecurityError::UnsupportedScheme(other.to_string())),
        }

        let host = parsed_url
            .host_str()
            .ok_or(SecurityError::MissingHost)
            .map(normalize_domain)?;

        // 1) Allow firm gateway
        if self.cfg.approved_gateway_hosts.contains(&host) {
            return Ok(());
        }

        // 2) Block known Shadow AI domains (exact + subdomains)
        if let Some(matched) = match_blocked_domain(&host, &self.cfg.blocked_domains) {
            return Err(SecurityError::ShadowAIBlocked {
                host,
                matched: matched.to_string(),
            });
        }

        Ok(())
    }
}

fn normalize_domain(s: &str) -> String {
    s.trim()
        .trim_end_matches('.') // "example.com." is valid DNS, but we treat it consistently
        .to_ascii_lowercase()
}

/// Returns the blocked domain that matched (for audit logs), if any.
fn match_blocked_domain<'a>(host: &str, blocked: &'a HashSet<String>) -> Option<&'a str> {
    // Exact match
    if let Some(matched) = blocked.get(host) {
        return Some(matched.as_str());
    }

    // Suffix match for subdomains: host ends with ".blocked"
    for d in blocked.iter() {
        let suffix = format!(".{d}");
        if host.ends_with(&suffix) {
            return Some(d.as_str());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> ShadowAIGuard {
        ShadowAIGuard::new()
    }

    #[test]
    fn approved_gateway_allowed() {
        let g = guard();
        let url = "https://ai-gateway.firm-internal.net/v1/inference";
        assert_eq!(g.check_outbound_traffic(url), Ok(()));
    }

    #[test]
    fn approved_gateway_allowed_case_and_trailing_dot() {
        let g = guard();
        let url = "HTTPS://AI-GATEWAY.FIRM-INTERNAL.NET./v1/inference";
        assert_eq!(g.check_outbound_traffic(url), Ok(()));
    }

    #[test]
    fn openai_blocked_exact_host() {
        let g = guard();
        let url = "https://chat.openai.com/c/123-456";
        let err = g.check_outbound_traffic(url).unwrap_err();
        assert!(matches!(err, SecurityError::ShadowAIBlocked { .. }));
        if let SecurityError::ShadowAIBlocked { host, matched } = err {
            assert_eq!(host, "chat.openai.com");
            assert_eq!(matched, "chat.openai.com");
        }
    }

    #[test]
    fn openai_blocked_with_port_and_case() {
        let g = guard();
        let url = "https://CHAT.OPENAI.COM:443/c/123";
        let err = g.check_outbound_traffic(url).unwrap_err();
        if let SecurityError::ShadowAIBlocked { host, matched } = err {
            assert_eq!(host, "chat.openai.com");
            assert_eq!(matched, "chat.openai.com");
        } else {
            panic!("Expected ShadowAIBlocked");
        }
    }

    #[test]
    fn openai_blocked_trailing_dot() {
        let g = guard();
        let url = "https://chat.openai.com./c/123";
        let err = g.check_outbound_traffic(url).unwrap_err();
        if let SecurityError::ShadowAIBlocked { host, matched } = err {
            assert_eq!(host, "chat.openai.com");
            assert_eq!(matched, "chat.openai.com");
        } else {
            panic!("Expected ShadowAIBlocked");
        }
    }

    #[test]
    fn claude_subdomain_blocked() {
        let g = guard();
        let url = "https://api.claude.ai/v1/complete";
        let err = g.check_outbound_traffic(url).unwrap_err();
        if let SecurityError::ShadowAIBlocked { host, matched } = err {
            assert_eq!(host, "api.claude.ai");
            assert_eq!(matched, "claude.ai"); // matched rule (parent domain)
        } else {
            panic!("Expected ShadowAIBlocked");
        }
    }

    #[test]
    fn does_not_false_positive_on_suffix_like_evil_com() {
        let g = guard();
        // Should NOT match "claude.ai" because host ends with ".evil.com"
        let url = "https://claude.ai.evil.com";
        assert_eq!(g.check_outbound_traffic(url), Ok(()));
    }

    #[test]
    fn random_site_allowed() {
        let g = guard();
        let url = "https://www.google.com/search?q=legal+precedent";
        assert_eq!(g.check_outbound_traffic(url), Ok(()));
    }

    #[test]
    fn invalid_url_rejected() {
        let g = guard();
        let url = "this is not a url";
        assert_eq!(
            g.check_outbound_traffic(url),
            Err(SecurityError::InvalidUrl)
        );
    }

    #[test]
    fn unsupported_scheme_rejected() {
        let g = guard();
        let url = "ftp://chat.openai.com/resource";
        assert_eq!(
            g.check_outbound_traffic(url),
            Err(SecurityError::UnsupportedScheme("ftp".to_string()))
        );
    }

    #[test]
    fn missing_host_rejected() {
        let g = guard();
        // Url::parse accepts this, but host_str() returns None.
        let url = "https:///path/only";
        assert_eq!(
            g.check_outbound_traffic(url),
            Err(SecurityError::MissingHost)
        );
    }

    #[test]
    fn configurable_policy_works() {
        let mut cfg = ShadowAIGuardConfig::default();
        // Add another approved host
        cfg.approved_gateway_hosts
            .insert("ai-gateway-backup.firm-internal.net".to_string());

        // Add a blocked domain
        cfg.blocked_domains.insert("example-ai.com".to_string());

        let g = ShadowAIGuard::with_config(cfg);

        assert_eq!(
            g.check_outbound_traffic("https://ai-gateway-backup.firm-internal.net/x"),
            Ok(())
        );

        let err = g
            .check_outbound_traffic("https://api.example-ai.com/v1")
            .unwrap_err();
        if let SecurityError::ShadowAIBlocked { host, matched } = err {
            assert_eq!(host, "api.example-ai.com");
            assert_eq!(matched, "example-ai.com");
        } else {
            panic!("Expected ShadowAIBlocked");
        }
    }
}
