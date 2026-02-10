use std::num::NonZeroUsize;
use zerotrace_core::interceptor::detect::{TyposquatEngine, TyposquatPolicy, FindingKind};

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> TyposquatEngine {
        let protected = vec![
            "google.com".to_string(),
            "zerotrace.ai".to_string(),
            "openai.com".to_string(),
        ];

        let mut policy = TyposquatPolicy::default();
        policy.max_edit_distance = 2;
        policy.max_candidates = NonZeroUsize::new(64).unwrap();

        TyposquatEngine::new(protected, policy).unwrap()
    }

    #[test]
    fn exact_match_is_not_flagged() {
        let e = engine();
        let input = "Please visit google.com for more info.";
        let findings = e.scan_text(input).unwrap();
        assert!(findings.is_empty(), "Exact protected domain should be authorized");
    }

    #[test]
    fn typosquat_is_flagged_for_close_edit_distance() {
        let e = engine();
        let input = "Totally legit: g00gle.com";
        let findings = e.scan_text(input).unwrap();

        assert!(
            findings.iter().any(|f| f.kind == FindingKind::TyposquatLikely),
            "Expected typosquat detection"
        );

        let match_google = findings.iter().any(|f| {
            f.kind == FindingKind::TyposquatLikely
                && f.target_domain.as_deref() == Some("google.com")
        });
        assert!(match_google, "Expected match targeting google.com");
    }

    #[test]
    fn embedded_url_host_is_extracted_and_scanned() {
        let e = engine();
        let input = "Click here: https://g00gle.com/login?x=1";
        let findings = e.scan_text(input).unwrap();

        assert!(
            findings.iter().any(|f| f.kind == FindingKind::TyposquatLikely),
            "Expected typosquat detection from URL host"
        );
    }

    #[test]
    fn short_domains_are_ignored_to_reduce_false_positives() {
        let protected = vec!["abcde.com".to_string()];
        let mut policy = TyposquatPolicy::default();
        policy.min_domain_len = NonZeroUsize::new(10).unwrap(); // make it strict

        let e = TyposquatEngine::new(protected, policy).unwrap();
        let findings = e.scan_text("abxde.com").unwrap();
        assert!(findings.is_empty(), "Should ignore too-short base domains");
    }

    #[test]
    fn mixed_script_domain_is_flagged() {
        let e = engine();

        // "gоogle.com" where the 'о' is Cyrillic small o (U+043E), not Latin 'o'
        let cyrillic_o = '\u{043E}';
        let input = format!("Suspicious: g{}ogle.com", cyrillic_o);

        let findings = e.scan_text(&input).unwrap();
        assert!(
            findings.iter().any(|f| f.kind == FindingKind::MixedScriptDomain),
            "Expected mixed-script homograph detection"
        );
    }
}
