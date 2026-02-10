use std::collections::HashSet;
use strsim::{jaro_winkler, levenshtein};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    /// Block/flag anything not in the verified allowlist.
    StrictAllowlist,
    /// Only flag likely typosquats; allow unknown packages (useful for dev boxes).
    WarnTyposquatsOnly,
}

#[derive(Debug, Clone)]
pub struct SlopsquatConfig {
    pub mode: PolicyMode,
    /// Base edit distance threshold used for longer names.
    pub max_edit_distance: usize,
    /// Similarity floor to reduce false positives (0.0..=1.0).
    pub jw_threshold: f64,
    /// Don’t try to typosquat-detect extremely short names.
    pub min_len_for_typosquat: usize,
}

impl Default for SlopsquatConfig {
    fn default() -> Self {
        Self {
            mode: PolicyMode::StrictAllowlist,
            max_edit_distance: 2,
            jw_threshold: 0.92,
            min_len_for_typosquat: 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Pip,
    Npm,
    Cargo,
    Yarn,
    Pnpm,
    Bun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    /// Package is not in allowlist (StrictAllowlist mode).
    Unverified,
    /// Package is close to a verified package (likely typo/hallucination).
    Typosquat {
        similar_to: String,
        edit_distance: usize,
        jw_score_x1000: u16,
    },
    /// Token looks like a direct URL/VCS reference rather than a package name.
    SuspiciousSpecifier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub ecosystem: Ecosystem,
    pub raw: String,
    pub normalized: String,
    pub kind: FindingKind,
}

pub struct SlopsquatDetector {
    verified_packages: HashSet<String>, // normalized
    cfg: SlopsquatConfig,
}

impl SlopsquatDetector {
    pub fn new() -> Self {
        Self::with_config(SlopsquatConfig::default())
    }

    pub fn with_config(cfg: SlopsquatConfig) -> Self {
        let mut verified = HashSet::new();
        for p in [
            "requests", "numpy", "pandas", "react", "express", "tokio", "serde",
        ] {
            verified.insert(normalize_pkg(p));
        }

        Self {
            verified_packages: verified,
            cfg,
        }
    }

    pub fn with_verified_packages(
        cfg: SlopsquatConfig,
        verified_packages: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        let mut verified = HashSet::new();
        for p in verified_packages {
            verified.insert(normalize_pkg(p.as_ref()));
        }
        Self {
            verified_packages: verified,
            cfg,
        }
    }

    /// Convenience: returns true if any risk is detected.
    pub fn detect_package_risk(&self, prompt: &str) -> bool {
        !self.scan_prompt(prompt).is_empty()
    }

    /// Full scan: returns findings for all detected package tokens.
    pub fn scan_prompt(&self, prompt: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for req in extract_install_requests(prompt) {
            for raw_token in req.packages {
                let raw = raw_token.clone();
                let normalized = normalize_pkg(&raw_token);

                if normalized.is_empty() {
                    continue;
                }

                // URL / VCS / path-style specifiers are risky in strict settings.
                if looks_like_url_or_vcs(&raw_token) {
                    findings.push(Finding {
                        ecosystem: req.ecosystem,
                        raw,
                        normalized,
                        kind: FindingKind::SuspiciousSpecifier,
                    });
                    continue;
                }

                if self.verified_packages.contains(&normalized) {
                    continue;
                }

                if let Some(typo) = self.detect_typosquat(&normalized) {
                    findings.push(Finding {
                        ecosystem: req.ecosystem,
                        raw,
                        normalized,
                        kind: typo,
                    });
                    continue;
                }

                if self.cfg.mode == PolicyMode::StrictAllowlist {
                    findings.push(Finding {
                        ecosystem: req.ecosystem,
                        raw,
                        normalized,
                        kind: FindingKind::Unverified,
                    });
                }
            }
        }

        findings
    }

    fn detect_typosquat(&self, pkg: &str) -> Option<FindingKind> {
        if pkg.len() < self.cfg.min_len_for_typosquat {
            return None;
        }

        let mut best: Option<(String, usize, f64)> = None;

        for v in &self.verified_packages {
            // Quick filters to reduce noisy comparisons
            if (v.len() as i32 - pkg.len() as i32).abs() > 3 {
                continue;
            }

            let dist = levenshtein(pkg, v);
            if dist == 0 {
                continue;
            }

            let jw = jaro_winkler(pkg, v);

            // Adaptive distance threshold: be stricter for short names
            let max_dist = max_dist_for_len(pkg.len(), self.cfg.max_edit_distance);

            if dist <= max_dist && jw >= self.cfg.jw_threshold {
                match &best {
                    None => best = Some((v.clone(), dist, jw)),
                    Some((_, best_dist, best_jw)) => {
                        // Prefer smaller edit distance, then higher similarity
                        if dist < *best_dist || (dist == *best_dist && jw > *best_jw) {
                            best = Some((v.clone(), dist, jw));
                        }
                    }
                }
            }
        }

        best.map(|(similar_to, dist, jw)| FindingKind::Typosquat {
            similar_to,
            edit_distance: dist,
            jw_score_x1000: (jw * 1000.0).round().clamp(0.0, 1000.0) as u16,
        })
    }
}

// ---------------------- Parsing / Normalization ----------------------

#[derive(Debug, Clone)]
struct InstallRequest {
    ecosystem: Ecosystem,
    packages: Vec<String>, // raw tokens
}

/// Extract install commands and the subsequent package tokens.
/// This is intentionally conservative and human-friendly.
fn extract_install_requests(prompt: &str) -> Vec<InstallRequest> {
    let tokens = tokenize_shellish(prompt);

    let mut out = Vec::new();
    let mut i = 0usize;

    while i < tokens.len() {
        // Support common “sudo …” prefix
        if tokens[i] == "sudo" {
            i += 1;
            continue;
        }

        // pip / python -m pip
        if is_pip_command(&tokens, i) {
            let (start, eco) = pip_command_len(&tokens, i);
            let (pkgs, next_i) = collect_package_tokens(&tokens, i + start, eco);
            out.push(InstallRequest {
                ecosystem: eco,
                packages: pkgs,
            });
            i = next_i;
            continue;
        }

        // npm / yarn / pnpm / bun
        if is_js_command(&tokens, i) {
            let (start, eco) = js_command_len(&tokens, i);
            let (pkgs, next_i) = collect_package_tokens(&tokens, i + start, eco);
            out.push(InstallRequest {
                ecosystem: eco,
                packages: pkgs,
            });
            i = next_i;
            continue;
        }

        // cargo add
        if i + 1 < tokens.len() && tokens[i] == "cargo" && tokens[i + 1] == "add" {
            let (pkgs, next_i) = collect_package_tokens(&tokens, i + 2, Ecosystem::Cargo);
            out.push(InstallRequest {
                ecosystem: Ecosystem::Cargo,
                packages: pkgs,
            });
            i = next_i;
            continue;
        }

        i += 1;
    }

    out
}

fn is_pip_command(tokens: &[String], i: usize) -> bool {
    if i >= tokens.len() {
        return false;
    }
    // pip install / pip3 install
    if (tokens[i] == "pip" || tokens[i] == "pip3")
        && i + 1 < tokens.len()
        && tokens[i + 1] == "install"
    {
        return true;
    }
    // python -m pip install
    if tokens[i] == "python" || tokens[i] == "python3" {
        if i + 3 < tokens.len()
            && tokens[i + 1] == "-m"
            && (tokens[i + 2] == "pip")
            && tokens[i + 3] == "install"
        {
            return true;
        }
    }
    false
}

fn pip_command_len(tokens: &[String], i: usize) -> (usize, Ecosystem) {
    if (tokens[i] == "pip" || tokens[i] == "pip3")
        && tokens.get(i + 1).map(|s| s.as_str()) == Some("install")
    {
        (2, Ecosystem::Pip)
    } else {
        // python -m pip install
        (4, Ecosystem::Pip)
    }
}

fn is_js_command(tokens: &[String], i: usize) -> bool {
    if i >= tokens.len() {
        return false;
    }
    // npm install / npm i
    if tokens[i] == "npm"
        && i + 1 < tokens.len()
        && (tokens[i + 1] == "install" || tokens[i + 1] == "i")
    {
        return true;
    }
    // yarn add
    if tokens[i] == "yarn" && i + 1 < tokens.len() && tokens[i + 1] == "add" {
        return true;
    }
    // pnpm add
    if tokens[i] == "pnpm" && i + 1 < tokens.len() && tokens[i + 1] == "add" {
        return true;
    }
    // bun add
    if tokens[i] == "bun" && i + 1 < tokens.len() && tokens[i + 1] == "add" {
        return true;
    }
    false
}

fn js_command_len(tokens: &[String], i: usize) -> (usize, Ecosystem) {
    match tokens[i].as_str() {
        "npm" => (2, Ecosystem::Npm),
        "yarn" => (2, Ecosystem::Yarn),
        "pnpm" => (2, Ecosystem::Pnpm),
        "bun" => (2, Ecosystem::Bun),
        _ => (0, Ecosystem::Npm),
    }
}

fn collect_package_tokens(tokens: &[String], mut i: usize, eco: Ecosystem) -> (Vec<String>, usize) {
    let mut pkgs = Vec::new();

    while i < tokens.len() {
        let t = tokens[i].as_str();

        // command separators and obvious shell glue
        if t == "&&" || t == ";" || t == "|" {
            break;
        }

        // options (skip, and sometimes skip option argument)
        if t.starts_with('-') {
            let skip_next = match eco {
                Ecosystem::Pip => matches!(
                    t,
                    "-r" | "--requirement"
                        | "-c"
                        | "--constraint"
                        | "--index-url"
                        | "--extra-index-url"
                        | "--trusted-host"
                        | "--find-links"
                        | "--platform"
                        | "--python-version"
                        | "--implementation"
                        | "--abi"
                ),
                Ecosystem::Npm | Ecosystem::Yarn | Ecosystem::Pnpm | Ecosystem::Bun => {
                    matches!(t, "--registry" | "--userconfig")
                }
                Ecosystem::Cargo => matches!(t, "--features" | "--git" | "--path"),
            };

            i += 1;
            if skip_next && i < tokens.len() {
                i += 1;
            }
            continue;
        }

        pkgs.push(tokens[i].clone());
        i += 1;
    }

    (pkgs, i)
}

fn tokenize_shellish(s: &str) -> Vec<String> {
    // Keep it simple and stable: split on whitespace and preserve separators as tokens.
    // This is enough for detection. We’re not writing a shell.
    s.split_whitespace().map(|t| t.trim().to_string()).collect()
}

fn looks_like_url_or_vcs(raw: &str) -> bool {
    let r = raw.to_ascii_lowercase();
    r.contains("://") || r.starts_with("git+") || r.starts_with("git@") || r.starts_with("ssh://")
}

fn normalize_pkg(raw: &str) -> String {
    // Trim quotes and common trailing punctuation.
    let mut s = raw
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'')
        .to_string();
    s = s
        .trim_matches(|c: char| matches!(c, ',' | ';' | ':' | ')' | ']' | '}' | '.'))
        .to_string();

    // Pip env markers: pkg; python_version < '3.10'
    if let Some((left, _)) = s.split_once(';') {
        s = left.trim().to_string();
    }

    // Pip extras: requests[socks]
    if let Some(idx) = s.find('[') {
        s.truncate(idx);
    }

    // Strip version constraints for pip/cargo: ==, >=, <=, ~=, !=, >, <, =
    for op in ["==", ">=", "<=", "~=", "!=", ">", "<", "="] {
        if let Some(idx) = s.find(op) {
            s.truncate(idx);
            break;
        }
    }

    // Strip npm/cargo @version:
    // - react@18.2.0 -> react
    // - @scope/pkg@1.2.3 -> @scope/pkg
    if s.starts_with('@') {
        // Find the last '@' after the scope portion if present.
        if let Some(last_at) = s[1..].rfind('@') {
            let pos = last_at + 1; // account for slicing
                                   // Only treat as version if the '@' is not the first char and not part of just "@scope/pkg"
            if pos > 1 && s[..pos].contains('/') {
                s.truncate(pos);
                // Now remove trailing '@' if we truncated at separator
                if s.ends_with('@') {
                    s.pop();
                }
            }
        }
    } else if let Some(idx) = s.rfind('@') {
        // treat as version for unscoped
        if idx > 0 {
            s.truncate(idx);
        }
    }

    s.trim().to_ascii_lowercase()
}

fn max_dist_for_len(len: usize, base: usize) -> usize {
    // Make short names harder to “almost match” by accident.
    match len {
        0..=4 => 1,
        5..=8 => base.min(2),
        _ => base,
    }
}

// ---------------------- Tests ----------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_detector() -> SlopsquatDetector {
        SlopsquatDetector::with_config(SlopsquatConfig {
            mode: PolicyMode::StrictAllowlist,
            ..Default::default()
        })
    }

    fn warn_only_detector() -> SlopsquatDetector {
        SlopsquatDetector::with_config(SlopsquatConfig {
            mode: PolicyMode::WarnTyposquatsOnly,
            ..Default::default()
        })
    }

    #[test]
    fn allows_verified_pip_packages() {
        let d = strict_detector();
        assert!(!d.detect_package_risk("pip install requests"));
        assert!(!d.detect_package_risk("python -m pip install numpy==1.26.4"));
        assert!(!d.detect_package_risk("pip3 install pandas[something]"));
    }

    #[test]
    fn allows_verified_js_packages() {
        let d = strict_detector();
        assert!(!d.detect_package_risk("npm install react@18.2.0"));
        assert!(!d.detect_package_risk("yarn add express"));
        assert!(!d.detect_package_risk("pnpm add react"));
        assert!(!d.detect_package_risk("bun add react"));
    }

    #[test]
    fn flags_typosquat_requests() {
        let d = strict_detector();
        let f = d.scan_prompt("pip install reqests");
        assert_eq!(f.len(), 1);
        assert!(matches!(f[0].kind, FindingKind::Typosquat { .. }));
        if let FindingKind::Typosquat {
            similar_to,
            edit_distance,
            ..
        } = &f[0].kind
        {
            assert_eq!(similar_to, "requests");
            assert!(*edit_distance <= 2);
        }
    }

    #[test]
    fn flags_typosquat_react() {
        let d = strict_detector();
        let f = d.scan_prompt("npm i reactt");
        assert_eq!(f.len(), 1);
        assert!(matches!(f[0].kind, FindingKind::Typosquat { .. }));
        assert_eq!(f[0].normalized, "reactt");
    }

    #[test]
    fn flags_unverified_in_strict_mode() {
        let d = strict_detector();
        let f = d.scan_prompt("cargo add super_suspicious_lib");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].normalized, "super_suspicious_lib");
        assert_eq!(f[0].kind, FindingKind::Unverified);
    }

    #[test]
    fn does_not_flag_unverified_in_warn_only_mode() {
        let d = warn_only_detector();
        let f = d.scan_prompt("cargo add super_suspicious_lib");
        assert!(f.is_empty());
    }

    #[test]
    fn flags_url_or_vcs_specifier() {
        let d = strict_detector();
        let f = d.scan_prompt("pip install git+https://github.com/org/repo.git");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::SuspiciousSpecifier);
    }

    #[test]
    fn handles_multiple_packages_and_options() {
        let d = strict_detector();

        // -U is an option, should still capture requests/numpy/pandas
        let f = d.scan_prompt("pip install -U requests numpy pandas");
        assert!(f.is_empty());

        // Mixed: one verified, one unverified
        let f2 = d.scan_prompt("pip install requests totallynotrealpkg");
        assert_eq!(f2.len(), 1);
        assert_eq!(f2[0].normalized, "totallynotrealpkg");
        assert_eq!(f2[0].kind, FindingKind::Unverified);
    }

    #[test]
    fn ignores_install_without_package_tokens() {
        let d = strict_detector();
        assert!(!d.detect_package_risk("pip install"));
        assert!(!d.detect_package_risk("npm install"));
        assert!(!d.detect_package_risk("cargo add"));
    }

    #[test]
    fn normalizes_quotes_punctuation_and_versions() {
        assert_eq!(normalize_pkg(r#""requests""#), "requests");
        assert_eq!(normalize_pkg("requests,"), "requests");
        assert_eq!(normalize_pkg("numpy==1.26.4"), "numpy");
        assert_eq!(normalize_pkg("pandas[socks]"), "pandas");
        assert_eq!(normalize_pkg("react@18.2.0"), "react");
    }

    #[test]
    fn scoped_npm_package_version_stripping_is_conservative() {
        // Not in verified list, but we ensure normalization doesn’t explode.
        assert_eq!(normalize_pkg("@scope/pkg@1.2.3"), "@scope/pkg");
        assert_eq!(normalize_pkg("@scope/pkg"), "@scope/pkg");
    }

    #[test]
    fn no_false_positive_on_suffix_like_evil_domain() {
        let d = strict_detector();
        // This is not an install command, so it should not flag.
        assert!(!d.detect_package_risk("Here is a URL: https://example.com/npm install react"));
    }

    #[test]
    fn table_driven_install_detection() {
        let d = strict_detector();

        let cases = [
            ("pip install requests", 0),
            ("python -m pip install reqests", 1),
            ("npm i reactt", 1),
            ("yarn add express", 0),
            ("pnpm add superlib", 1),
            ("bun add react", 0),
            ("cargo add serde", 0),
            ("cargo add srede", 1), // typo of serde
        ];

        for (prompt, expected_findings) in cases {
            let got = d.scan_prompt(prompt);
            assert_eq!(
                got.len(),
                expected_findings,
                "prompt={prompt} findings={got:?}"
            );
        }
    }
}
