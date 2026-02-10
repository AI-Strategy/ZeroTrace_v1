//! Production-grade Secret Scanner (patterns + entropy) with:
//! - span-based redaction helper
//! - pluggable / hot-reloadable pattern registry
//!
//! Why this exists:
//! - Detect leaked credentials in untrusted text without ever echoing secrets.
//! - Allow detector updates (new regexes/pattern IDs) without code redeploys.
//! - Provide stable, structured findings for enforcement + audit + metrics.
//!
//! Suggested dependencies (Cargo.toml):
//! regex = "1"
//! thiserror = "1"
//! tracing = "0.1"
//! tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
//! blake3 = "1"
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"

use regex::{Regex, RegexSet};
use serde::Deserialize;
use std::{
    fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::SystemTime,
};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Initialize JSON logging (call once early in your binary).
pub fn init_json_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .with_current_span(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .try_init();
}

/// Scanner config with explicit bounds.
#[derive(Debug, Clone)]
pub struct SecretScannerConfig {
    pub max_input_bytes: NonZeroUsize,
    pub max_candidates: NonZeroUsize,
    pub max_findings: NonZeroUsize,
    pub max_token_bytes: NonZeroUsize,
    pub min_token_len_for_entropy: NonZeroUsize,
    pub entropy_threshold_base64ish: f64,
    pub entropy_threshold_hexish: f64,
    pub enable_entropy_scanning: bool,
    pub enable_pattern_scanning: bool,
}

impl Default for SecretScannerConfig {
    fn default() -> Self {
        Self {
            max_input_bytes: NonZeroUsize::new(64 * 1024).expect("non-zero const"),
            max_candidates: NonZeroUsize::new(512).expect("non-zero const"),
            max_findings: NonZeroUsize::new(64).expect("non-zero const"),
            max_token_bytes: NonZeroUsize::new(512).expect("non-zero const"),
            min_token_len_for_entropy: NonZeroUsize::new(20).expect("non-zero const"),
            entropy_threshold_base64ish: 4.5,
            entropy_threshold_hexish: 3.2,
            enable_entropy_scanning: true,
            enable_pattern_scanning: true,
        }
    }
}

impl SecretScannerConfig {
    pub fn validate(&self) -> Result<(), ScanError> {
        if self.entropy_threshold_base64ish.is_nan()
            || self.entropy_threshold_hexish.is_nan()
            || self.entropy_threshold_base64ish <= 0.0
            || self.entropy_threshold_hexish <= 0.0
        {
            return Err(ScanError::InvalidConfig);
        }
        Ok(())
    }
}

/// Finding kind is now pluggable.
/// - Built-ins remain stable.
/// - Dynamic patterns come through as CustomPattern("<pattern_id>").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingKind {
    AwsAccessKeyId,
    OpenAiApiKey,
    HighEntropyToken,
    CustomPattern(String),
}

impl FindingKind {
    fn stable_id(&self) -> String {
        match self {
            FindingKind::AwsAccessKeyId => "AWS_ACCESS_KEY_ID".to_string(),
            FindingKind::OpenAiApiKey => "OPENAI_KEY".to_string(),
            FindingKind::HighEntropyToken => "HIGH_ENTROPY_TOKEN".to_string(),
            FindingKind::CustomPattern(id) => id.clone(),
        }
    }
}

/// Safe-to-return finding (does not include raw secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub span: (usize, usize), // byte offsets
    pub preview: String,      // redacted preview only
    pub entropy_x100: Option<u32>,
    pub input_hash: String,
}

/// Errors safe to propagate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScanError {
    #[error("Input too large")]
    InputTooLarge,
    #[error("Invalid scanner configuration")]
    InvalidConfig,
    #[error("Pattern registry error")]
    RegistryError,
}

/// Registry errors (internal).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RegistryError {
    #[error("Invalid registry JSON")]
    InvalidJson,
    #[error("Invalid pattern definition")]
    InvalidPattern,
    #[error("Regex compilation failed")]
    RegexCompileFailed,
    #[error("File read failed")]
    FileReadFailed,
}

/// A single regex detector definition.
/// This is what you ship/update dynamically.
#[derive(Debug, Clone, Deserialize)]
pub struct PatternSpec {
    /// Stable identifier for auditing and redaction tags (e.g. "GITHUB_PAT", "STRIPE_KEY").
    pub id: String,
    /// Regex pattern as a string.
    pub regex: String,
    /// Optional mapping to known built-in kinds. If omitted/unknown, becomes CustomPattern(id).
    #[serde(default)]
    pub kind: Option<String>,
}

/// Pluggable registry interface.
pub trait PatternRegistry: Send + Sync {
    fn snapshot(&self) -> Arc<CompiledPatterns>;
}

/// Compiled pattern set.
/// - RegexSet quickly checks if any pattern is present.
/// - Individual Regex finds spans.
#[derive(Debug)]
pub struct CompiledPatterns {
    set: RegexSet,
    entries: Vec<CompiledEntry>,
}

#[derive(Debug)]
struct CompiledEntry {
    id: String,
    kind: FindingKind,
    re: Regex,
}

fn kind_from_spec(spec: &PatternSpec) -> FindingKind {
    match spec.kind.as_deref() {
        Some("AWS_ACCESS_KEY_ID") => FindingKind::AwsAccessKeyId,
        Some("OPENAI_KEY") => FindingKind::OpenAiApiKey,
        Some(other) => FindingKind::CustomPattern(other.to_string()),
        None => FindingKind::CustomPattern(spec.id.clone()),
    }
}

fn validate_pattern_spec(spec: &PatternSpec) -> Result<(), RegistryError> {
    // Defensive: prevent absurd IDs (log injection, filesystem fun, etc).
    if spec.id.is_empty()
        || spec.id.len() > 64
        || !spec
            .id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(RegistryError::InvalidPattern);
    }
    if spec.regex.is_empty() || spec.regex.len() > 512 {
        return Err(RegistryError::InvalidPattern);
    }
    Ok(())
}

fn compile_patterns(specs: &[PatternSpec]) -> Result<CompiledPatterns, RegistryError> {
    for s in specs {
        validate_pattern_spec(s)?;
    }

    let set = RegexSet::new(specs.iter().map(|s| s.regex.as_str()))
        .map_err(|_| RegistryError::RegexCompileFailed)?;

    let mut entries = Vec::with_capacity(specs.len());
    for s in specs {
        let re = Regex::new(&s.regex).map_err(|_| RegistryError::RegexCompileFailed)?;
        entries.push(CompiledEntry {
            id: s.id.clone(),
            kind: kind_from_spec(s),
            re,
        });
    }

    Ok(CompiledPatterns { set, entries })
}

/// A registry you can update at runtime (admin API, config push, whatever).
///
/// Updates are atomic for readers:
/// - If update fails, old patterns remain in use.
/// - If update succeeds, new patterns are swapped in immediately.
///
/// That’s the whole “ship updated detectors without redeploy” bit.
pub struct HotReloadPatternRegistry {
    inner: RwLock<Arc<CompiledPatterns>>,
}

impl HotReloadPatternRegistry {
    pub fn new(initial_specs: Vec<PatternSpec>) -> Result<Self, RegistryError> {
        let compiled = compile_patterns(&initial_specs)?;
        Ok(Self {
            inner: RwLock::new(Arc::new(compiled)),
        })
    }

    /// Update the registry from JSON (e.g. fetched from S3, config service, admin endpoint).
    ///
    /// JSON format: `[{ "id": "GITHUB_PAT", "regex": "...", "kind": "..." }, ...]`
    pub fn update_from_json(&self, json: &str) -> Result<(), RegistryError> {
        let specs: Vec<PatternSpec> =
            serde_json::from_str(json).map_err(|_| RegistryError::InvalidJson)?;
        self.update_from_specs(specs)
    }

    pub fn update_from_specs(&self, specs: Vec<PatternSpec>) -> Result<(), RegistryError> {
        let compiled = compile_patterns(&specs)?;
        let mut guard = self.inner.write().map_err(|_| RegistryError::RegexCompileFailed)?;
        *guard = Arc::new(compiled);

        info!(
            event = "pattern_registry_updated",
            pattern_count = specs.len(),
        );
        Ok(())
    }
}

impl PatternRegistry for HotReloadPatternRegistry {
    fn snapshot(&self) -> Arc<CompiledPatterns> {
        self.inner
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| Arc::new(default_compiled_patterns()))
    }
}

/// File-backed hot reload (poll-style).
///
/// Call `refresh_if_changed()` periodically (cron, timer, admin endpoint).
pub struct FilePatternRegistry {
    path: PathBuf,
    last_modified: RwLock<Option<SystemTime>>,
    inner: HotReloadPatternRegistry,
}

impl FilePatternRegistry {
    pub fn new(path: impl Into<PathBuf>, fallback_specs: Vec<PatternSpec>) -> Result<Self, RegistryError> {
        let path = path.into();
        let inner = HotReloadPatternRegistry::new(fallback_specs)?;
        Ok(Self {
            path,
            last_modified: RwLock::new(None),
            inner,
        })
    }

    pub fn refresh_if_changed(&self) -> Result<bool, RegistryError> {
        let meta = fs::metadata(&self.path).map_err(|_| RegistryError::FileReadFailed)?;
        let mtime = meta.modified().map_err(|_| RegistryError::FileReadFailed)?;

        let mut lm = self.last_modified.write().map_err(|_| RegistryError::FileReadFailed)?;
        if lm.map(|t| t >= mtime).unwrap_or(false) {
            return Ok(false);
        }

        let content = fs::read_to_string(&self.path).map_err(|_| RegistryError::FileReadFailed)?;
        self.inner.update_from_json(&content)?;
        *lm = Some(mtime);

        info!(
            event = "pattern_registry_file_refreshed",
            path = %self.path.display(),
        );

        Ok(true)
    }
}

impl PatternRegistry for FilePatternRegistry {
    fn snapshot(&self) -> Arc<CompiledPatterns> {
        self.inner.snapshot()
    }
}

// ------------------------------ Scanner ------------------------------

/// Secret scanner engine.
///
/// Complexity:
/// - Pattern scan: O(n) average for set check + regex iter (bounded by max_findings).
/// - Entropy scan: O(C * L) where C is candidate tokens (bounded), L token length (bounded).
/// - Space: O(F) findings (bounded).
pub struct SecretScanner<R: PatternRegistry> {
    cfg: SecretScannerConfig,
    registry: Arc<R>,
}

impl<R: PatternRegistry> SecretScanner<R> {
    pub fn new(cfg: SecretScannerConfig, registry: Arc<R>) -> Result<Self, ScanError> {
        cfg.validate()?;
        Ok(Self { cfg, registry })
    }

    pub fn scan(&self, input: &str) -> Result<Vec<Finding>, ScanError> {
        if input.as_bytes().len() > self.cfg.max_input_bytes.get() {
            return Err(ScanError::InputTooLarge);
        }

        let input_hash = hash_for_logs(input);

        debug!(
            event = "secret_scan_start",
            input_hash = %input_hash,
            bytes = input.as_bytes().len(),
            pattern_scan = self.cfg.enable_pattern_scanning,
            entropy_scan = self.cfg.enable_entropy_scanning,
        );

        let mut findings: Vec<Finding> = Vec::new();

        if self.cfg.enable_pattern_scanning {
            let compiled = self.registry.snapshot();
            scan_patterns_with_registry(input, &input_hash, &self.cfg, &compiled, &mut findings)
                .map_err(|_| ScanError::RegistryError)?;
        }

        if self.cfg.enable_entropy_scanning && findings.len() < self.cfg.max_findings.get() {
            scan_entropy(input, &input_hash, &self.cfg, &mut findings);
        }

        dedup_findings(&mut findings);

        info!(
            event = "secret_scan_complete",
            input_hash = %input_hash,
            findings = findings.len(),
        );

        Ok(findings)
    }

    /// Convenience for caller workflows:
    /// - produces a sanitized copy of the input with findings redacted.
    pub fn scan_and_redact(
        &self,
        input: &str,
        style: RedactionStyle,
    ) -> Result<(Vec<Finding>, String), ScanError> {
        let findings = self.scan(input)?;
        let redacted = redact_by_findings(input, &findings, style);
        Ok((findings, redacted))
    }
}

fn scan_patterns_with_registry(
    input: &str,
    input_hash: &str,
    cfg: &SecretScannerConfig,
    compiled: &CompiledPatterns,
    out: &mut Vec<Finding>,
) -> Result<(), RegistryError> {
    if !compiled.set.is_match(input) {
        return Ok(());
    }

    for entry in &compiled.entries {
        if out.len() >= cfg.max_findings.get() {
            break;
        }

        for m in entry.re.find_iter(input) {
            if out.len() >= cfg.max_findings.get() {
                break;
            }

            let span = (m.start(), m.end());
            let preview = redact_preview(m.as_str());

            warn!(
                event = "secret_pattern_detected",
                input_hash = %input_hash,
                pattern_id = %entry.id,
                kind = %entry.kind.stable_id(),
                start = span.0,
                end = span.1,
            );

            out.push(Finding {
                kind: entry.kind.clone(),
                span,
                preview,
                entropy_x100: None,
                input_hash: input_hash.to_string(),
            });
        }
    }

    Ok(())
}

// ---------------------------- Entropy scanning ----------------------------

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum TokenClass {
    Base64ish,
    Hexish,
    Other,
}

fn scan_entropy(input: &str, input_hash: &str, cfg: &SecretScannerConfig, out: &mut Vec<Finding>) {
    let mut candidates_checked: usize = 0;

    for (start, token) in token_iter(input) {
        if out.len() >= cfg.max_findings.get() || candidates_checked >= cfg.max_candidates.get() {
            break;
        }
        candidates_checked += 1;

        if token.as_bytes().len() > cfg.max_token_bytes.get() {
            continue;
        }
        if !token.is_ascii() {
            continue;
        }
        if looks_like_urlish(token) || looks_like_emailish(token) {
            continue;
        }
        if token.len() < cfg.min_token_len_for_entropy.get() {
            continue;
        }

        let class = classify_token(token);
        let entropy = calculate_shannon_entropy_bytes(token.as_bytes());

        let threshold = match class {
            TokenClass::Base64ish => cfg.entropy_threshold_base64ish,
            TokenClass::Hexish => cfg.entropy_threshold_hexish,
            TokenClass::Other => cfg.entropy_threshold_base64ish,
        };

        if entropy >= threshold {
            let end = start + token.len();
            let preview = redact_preview(token);
            let entropy_x100 = (entropy * 100.0).round().clamp(0.0, u32::MAX as f64) as u32;

            debug!(
                event = "high_entropy_token_detected",
                input_hash = %input_hash,
                entropy = entropy,
                token_class = ?class,
                start = start,
                end = end,
            );

            out.push(Finding {
                kind: FindingKind::HighEntropyToken,
                span: (start, end),
                preview,
                entropy_x100: Some(entropy_x100),
                input_hash: input_hash.to_string(),
            });
        }
    }
}

/// Shannon entropy over bytes (0..=255).
///
/// Complexity: O(n) time, O(1) space.
pub fn calculate_shannon_entropy_bytes(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn classify_token(token: &str) -> TokenClass {
    let b = token.as_bytes();
    if b.iter().all(|c| c.is_ascii_hexdigit()) {
        return TokenClass::Hexish;
    }
    let base64ish = b.iter().all(|c| {
        c.is_ascii_alphanumeric()
            || *c == b'+'
            || *c == b'/'
            || *c == b'='
            || *c == b'_'
            || *c == b'-'
    });
    if base64ish {
        return TokenClass::Base64ish;
    }
    TokenClass::Other
}

// ---------------------------- Redaction ----------------------------

/// Redaction style options.
///
/// Why:
/// - You’ll want different output formats for logs vs UI vs downstream storage.
#[derive(Debug, Clone)]
pub struct RedactionStyle {
    pub replacement: String,
    pub include_kind_tag: bool,
    pub include_count_if_merged: bool,
    pub max_tag_len: usize,
}

impl Default for RedactionStyle {
    fn default() -> Self {
        Self {
            replacement: "[REDACTED]".to_string(),
            include_kind_tag: true,
            include_count_if_merged: true,
            max_tag_len: 40,
        }
    }
}

/// Redact input using `Finding.span`.
///
/// Guarantees:
/// - Never panics on malformed spans.
/// - Handles overlaps by merging.
/// - Attempts to respect UTF-8 boundaries (clamps to nearest safe boundary).
///
/// Complexity:
/// - Sorting spans: O(F log F), F bounded by max_findings
/// - Building output: O(n)
pub fn redact_by_findings(input: &str, findings: &[Finding], style: RedactionStyle) -> String {
    let mut spans: Vec<RedactSpan> = findings
        .iter()
        .map(|f| RedactSpan {
            start: f.span.0,
            end: f.span.1,
            tag: f.kind.stable_id(),
        })
        .collect();

    if spans.is_empty() {
        return input.to_string();
    }

    // Clamp, sanitize, sort.
    let len = input.len();
    for s in &mut spans {
        s.start = s.start.min(len);
        s.end = s.end.min(len);
        if s.end < s.start {
            std::mem::swap(&mut s.start, &mut s.end);
        }
        s.start = clamp_down_to_char_boundary(input, s.start);
        s.end = clamp_up_to_char_boundary(input, s.end);
    }

    spans.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));

    // Merge overlaps.
    let mut merged: Vec<MergedSpan> = Vec::new();
    for s in spans {
        if let Some(last) = merged.last_mut() {
            if s.start <= last.end {
                last.end = last.end.max(s.end);
                last.tags.push(s.tag);
                continue;
            }
        }
        merged.push(MergedSpan {
            start: s.start,
            end: s.end,
            tags: vec![s.tag],
        });
    }

    // Build redacted output.
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;

    for m in merged {
        if m.start > cursor {
            out.push_str(&input[cursor..m.start]);
        }

        out.push_str(&build_placeholder(&m, &style));

        cursor = m.end;
    }

    if cursor < input.len() {
        out.push_str(&input[cursor..]);
    }

    out
}

#[derive(Debug)]
struct RedactSpan {
    start: usize,
    end: usize,
    tag: String,
}

#[derive(Debug)]
struct MergedSpan {
    start: usize,
    end: usize,
    tags: Vec<String>,
}

fn build_placeholder(m: &MergedSpan, style: &RedactionStyle) -> String {
    if !style.include_kind_tag {
        return style.replacement.clone();
    }

    let mut uniq = m.tags.clone();
    uniq.sort();
    uniq.dedup();

    let mut tag = if uniq.len() == 1 {
        uniq[0].clone()
    } else if style.include_count_if_merged {
        format!("MULTI:{}", uniq.len())
    } else {
        "MULTI".to_string()
    };

    if tag.len() > style.max_tag_len {
        tag.truncate(style.max_tag_len);
    }

    format!("{}:{}", style.replacement, tag)
}

fn clamp_down_to_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn clamp_up_to_char_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

// ---------------------------- Tokenization & hygiene ----------------------------

fn token_iter<'a>(input: &'a str) -> impl Iterator<Item = (usize, &'a str)> + 'a {
    input.split_whitespace().filter_map(move |raw| {
        let start = raw.as_ptr() as usize - input.as_ptr() as usize;
        let trimmed = trim_wrapping_punct(raw);
        if trimmed.is_empty() {
            None
        } else {
            let left_trim = raw.len() - raw.trim_start_matches(is_wrap_punct).len();
            Some((start + left_trim, trimmed))
        }
    })
}

fn trim_wrapping_punct(s: &str) -> &str {
    s.trim_matches(is_wrap_punct)
}

fn is_wrap_punct(c: char) -> bool {
    matches!(
        c,
        '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '"' | '\'' | ',' | ';' | ':' | '!' | '?' | '.'
    )
}

fn looks_like_urlish(s: &str) -> bool {
    s.starts_with("http://") 
        || s.starts_with("https://") 
        || s.starts_with("www.")
        || s.contains("://")
        // Don't just check for '/' because Base64 uses it.
        // Maybe check for file paths?
        || s.starts_with('/') 
}

fn looks_like_emailish(s: &str) -> bool {
    if let Some(at) = s.find('@') {
        return s[at + 1..].contains('.');
    }
    false
}

fn hash_for_logs(input: &str) -> String {
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

fn redact_preview(s: &str) -> String {
    const MIN: usize = 8;
    if s.len() < MIN {
        return "[redacted]".to_string();
    }
    let prefix = &s[..3];
    let suffix = &s[s.len() - 2..];
    format!("{prefix}…{suffix}")
}

fn dedup_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        (a.kind.stable_id(), a.span.0, a.span.1).cmp(&(b.kind.stable_id(), b.span.0, b.span.1))
    });
    findings.dedup_by(|a, b| a.kind == b.kind && a.span == b.span);
}

// ---------------------------- Defaults ----------------------------

/// Default baseline patterns (you can replace/update at runtime).
pub fn default_pattern_specs() -> Vec<PatternSpec> {
    vec![
        PatternSpec {
            id: "AWS_ACCESS_KEY_ID".to_string(),
            kind: Some("AWS_ACCESS_KEY_ID".to_string()),
            regex: r"\bAKIA[0-9A-Z]{16}\b".to_string(),
        },
        PatternSpec {
            id: "OPENAI_KEY".to_string(),
            kind: Some("OPENAI_KEY".to_string()),
            regex: r"\bsk-[A-Za-z0-9]{20,}\b".to_string(),
        },
    ]
}

fn default_compiled_patterns() -> CompiledPatterns {
    compile_patterns(&default_pattern_specs()).expect("default patterns must compile")
}

/// Example: load specs from JSON file (one-liner helper).
pub fn load_specs_from_file(path: &Path) -> Result<Vec<PatternSpec>, RegistryError> {
    let content = fs::read_to_string(path).map_err(|_| RegistryError::FileReadFailed)?;
    serde_json::from_str(&content).map_err(|_| RegistryError::InvalidJson)
}
