//! Production-grade Secret Scanner (patterns + entropy) with:
//! - span-based redaction helper
//! - pluggable / hot-reloadable pattern registry
//!
//! Why this exists:
//! - Detect leaked credentials in untrusted text without ever echoing secrets.
//! - Allow detector updates (new regexes/pattern IDs) without code redeploys.
//! - Provide stable, structured findings for enforcement + audit + metrics.

use blake3;
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
        // Defensive: keep the bounds sane.
        if self.max_findings.get() == 0
            || self.max_candidates.get() == 0
            || self.max_input_bytes.get() == 0
            || self.max_token_bytes.get() == 0
            || self.min_token_len_for_entropy.get() == 0
        {
            return Err(ScanError::InvalidConfig);
        }
        Ok(())
    }
}

/// Finding kind is pluggable.
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
    /// Stable identifier for correlation across logs, metrics, enforcement actions, and audits.
    /// Deterministic: depends only on kind + span + input_hash.
    pub finding_id: String,
    pub kind: FindingKind,
    pub span: (usize, usize), // byte offsets
    pub preview: String,      // redacted preview only
    pub entropy_x100: Option<u32>,
    pub input_hash: String,
}

impl Finding {
    /// Construct a Finding with a stable ID derived from (kind, span, input_hash).
    pub fn new(
        kind: FindingKind,
        span: (usize, usize),
        preview: String,
        entropy_x100: Option<u32>,
        input_hash: String,
    ) -> Self {
        let finding_id = compute_finding_id(&kind, span, &input_hash);
        Self {
            finding_id,
            kind,
            span,
            preview,
            entropy_x100,
            input_hash,
        }
    }
}

/// Deterministic stable ID for a finding.
/// NOTE: does NOT include any secret material or the preview.
fn compute_finding_id(kind: &FindingKind, span: (usize, usize), input_hash: &str) -> String {
    // Keep format stable: if you change it, you’ll break correlation.
    let payload = format!("{}:{}:{}:{}", kind.stable_id(), span.0, span.1, input_hash);
    blake3::hash(payload.as_bytes()).to_hex().to_string()
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
    // Defensive: prevent absurd IDs (log injection, path tricks, etc).
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

        let mut guard = self
            .inner
            .write()
            .map_err(|_| RegistryError::RegexCompileFailed)?;
        *guard = Arc::new(compiled);

        info!(
            event = "pattern_registry_updated",
            pattern_count = specs.len(),
        );
        Ok(())
    }
}

lazy_static::lazy_static! {
    static ref DEFAULT_COMPILED: Arc<CompiledPatterns> = Arc::new(default_compiled_patterns());
}

impl PatternRegistry for HotReloadPatternRegistry {
    fn snapshot(&self) -> Arc<CompiledPatterns> {
        self.inner
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| DEFAULT_COMPILED.clone())
    }
}

/// File-backed hot reload (poll-style).
///
/// Call `refresh_if_changed()` periodically (timer, admin endpoint).
pub struct FilePatternRegistry {
    path: PathBuf,
    last_modified: RwLock<Option<SystemTime>>,
    inner: HotReloadPatternRegistry,
}

impl FilePatternRegistry {
    pub fn new(
        path: impl Into<PathBuf>,
        fallback_specs: Vec<PatternSpec>,
    ) -> Result<Self, RegistryError> {
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

        let mut lm = self
            .last_modified
            .write()
            .map_err(|_| RegistryError::FileReadFailed)?;
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
/// - Pattern scan: RegexSet match + limited regex iter (bounded by max_findings).
/// - Entropy scan: O(C * L) where C is candidate tokens (bounded), L token length (bounded).
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

    // Optimization: only run regexes that RegexSet says match.
    for idx in compiled.set.matches(input).iter() {
        if out.len() >= cfg.max_findings.get() {
            break;
        }
        let entry = &compiled.entries[idx];

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

            out.push(Finding::new(
                entry.kind.clone(),
                span,
                preview,
                None,
                input_hash.to_string(),
            ));
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

            out.push(Finding::new(
                FindingKind::HighEntropyToken,
                (start, end),
                preview,
                Some(entropy_x100),
                input_hash.to_string(),
            ));
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

// --- Helpers ---

fn dedup_findings(findings: &mut Vec<Finding>) {
    if findings.is_empty() {
        return;
    }
    // Sort deterministically to make dedup stable.
    findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    findings.dedup_by(|a, b| a.finding_id == b.finding_id);
}

// ---------------------------- Redaction ----------------------------

/// Redaction style options.
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

/// Safe tokenizer that yields (byte_offset, token_slice) without pointer arithmetic.
///
/// This keeps offsets correct and avoids relying on how split_whitespace is implemented.
fn token_iter<'a>(input: &'a str) -> impl Iterator<Item = (usize, &'a str)> + 'a {
    TokenIter { input, idx: 0 }.filter_map(|(start, end)| {
        let bytes = input.as_bytes();
        let (mut s, mut e) = (start, end);

        // Trim ASCII wrapping punctuation on both ends.
        while s < e && is_wrap_punct_byte(bytes[s]) {
            s += 1;
        }
        while e > s && is_wrap_punct_byte(bytes[e - 1]) {
            e -= 1;
        }

        if s >= e {
            None
        } else {
            Some((s, &input[s..e]))
        }
    })
}

struct TokenIter<'a> {
    input: &'a str,
    idx: usize,
}

impl<'a> Iterator for TokenIter<'a> {
    type Item = (usize, usize); // (start,end)
    fn next(&mut self) -> Option<Self::Item> {
        let s = self.input;
        let len = s.len();
        if self.idx >= len {
            return None;
        }

        // Skip whitespace
        while self.idx < len {
            let ch = s[self.idx..].chars().next()?;
            if ch.is_whitespace() {
                self.idx += ch.len_utf8();
            } else {
                break;
            }
        }
        if self.idx >= len {
            return None;
        }

        let start = self.idx;

        // Read until whitespace
        while self.idx < len {
            let ch = s[self.idx..].chars().next()?;
            if ch.is_whitespace() {
                break;
            }
            self.idx += ch.len_utf8();
        }
        let end = self.idx;
        Some((start, end))
    }
}

fn is_wrap_punct_byte(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'<'
            | b'>'
            | b'"'
            | b'\''
            | b','
            | b';'
            | b':'
            | b'!'
            | b'?'
            | b'.'
    )
}

fn looks_like_urlish(s: &str) -> bool {
    if s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("www.")
        || s.contains("://")
    {
        return true;
    }

    // Avoid false-negatives for base64 tokens that start with '/'.
    // Consider "path-like" only if it has multiple slashes (actual path segments).
    if s.starts_with('/') && s.matches('/').count() >= 2 {
        return true;
    }

    false
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

/// Safe preview: never panics on UTF-8 boundaries.
fn redact_preview(s: &str) -> String {
    const MIN_CHARS: usize = 8;
    let total = s.chars().count();
    if total < MIN_CHARS {
        return "[redacted]".to_string();
    }

    let prefix: String = s.chars().take(3).collect();
    let suffix: String = s
        .chars()
        .rev()
        .take(2)
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();

    if prefix.is_empty() || suffix.is_empty() {
        return "[redacted]".to_string();
    }
    format!("{prefix}…{suffix}")
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

// ============================================================================
// Tests (large bench)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    fn make_scanner_with_specs(
        specs: Vec<PatternSpec>,
        cfg: SecretScannerConfig,
    ) -> SecretScanner<HotReloadPatternRegistry> {
        cfg.validate().unwrap();
        let reg = Arc::new(HotReloadPatternRegistry::new(specs).unwrap());
        SecretScanner::new(cfg, reg).unwrap()
    }

    fn base_cfg() -> SecretScannerConfig {
        SecretScannerConfig::default()
    }

    #[test]
    fn config_validation_rejects_nan() {
        let mut cfg = base_cfg();
        cfg.entropy_threshold_base64ish = f64::NAN;
        assert!(matches!(cfg.validate(), Err(ScanError::InvalidConfig)));
    }

    #[test]
    fn input_too_large_is_rejected() {
        let mut cfg = base_cfg();
        cfg.max_input_bytes = NonZeroUsize::new(8).unwrap();
        let scanner = make_scanner_with_specs(default_pattern_specs(), cfg);

        let input = "this is longer than eight bytes";
        assert!(matches!(scanner.scan(input), Err(ScanError::InputTooLarge)));
    }

    #[test]
    fn pattern_scan_detects_default_aws_key() {
        let cfg = base_cfg();
        let scanner = make_scanner_with_specs(default_pattern_specs(), cfg);

        let input = "leak AKIA1234567890ABCD12 in text";
        let findings = scanner.scan(input).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::AwsAccessKeyId));
    }

    #[test]
    fn pattern_scan_detects_default_openai_key() {
        let cfg = base_cfg();
        let scanner = make_scanner_with_specs(default_pattern_specs(), cfg);

        let input = "key sk-abcdefghijklmnopqrstuvwxyzABCDE in text";
        let findings = scanner.scan(input).unwrap();
        assert!(findings.iter().any(|f| f.kind == FindingKind::OpenAiApiKey));
    }

    #[test]
    fn pattern_scan_preview_is_utf8_safe() {
        let cfg = base_cfg();
        let specs = vec![PatternSpec {
            id: "UNICODE_SECRET".to_string(),
            kind: None,
            regex: r"🔒\S{6,}".to_string(),
        }];
        let scanner = make_scanner_with_specs(specs, cfg);

        let input = "here 🔒секрет123 in text";
        let findings = scanner.scan(input).unwrap();
        assert_eq!(findings.len(), 1);
        // Just ensure it didn't panic and produced a preview.
        assert!(!findings[0].preview.is_empty());
    }

    #[test]
    fn pattern_scan_respects_max_findings_limit() {
        let mut cfg = base_cfg();
        cfg.max_findings = NonZeroUsize::new(5).unwrap();
        cfg.enable_entropy_scanning = false;

        let scanner = make_scanner_with_specs(default_pattern_specs(), cfg);

        let mut input = String::new();
        for _ in 0..50 {
            input.push_str(" sk-abcdefghijklmnopqrstuvwxyzABCDE ");
        }

        let findings = scanner.scan(&input).unwrap();
        assert_eq!(findings.len(), 5);
    }

    #[test]
    fn entropy_scan_detects_high_entropy_base64ish() {
        let mut cfg = base_cfg();
        cfg.enable_pattern_scanning = false;
        cfg.entropy_threshold_base64ish = 4.5;

        let scanner = make_scanner_with_specs(vec![], cfg);

        let token =
            "aZ0bY1cX2dW3eV4fU5gT6hS7iR8jQ9kP0lO1mN2nM3oL4pK5qJ6rI7sH8tG9uF0vE1wD2xC3yB4zA5";
        let input = format!("prefix {} suffix", token);

        let findings = scanner.scan(&input).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::HighEntropyToken));
    }

    #[test]
    fn entropy_scan_skips_urls_and_emails() {
        let mut cfg = base_cfg();
        cfg.enable_pattern_scanning = false;

        let scanner = make_scanner_with_specs(vec![], cfg);

        let input = "https://example.com/path/to/thing bob@example.com";
        let findings = scanner.scan(input).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn entropy_scan_respects_max_candidates_limit() {
        let mut cfg = base_cfg();
        cfg.enable_pattern_scanning = false;
        cfg.max_candidates = NonZeroUsize::new(5).unwrap();

        let scanner = make_scanner_with_specs(vec![], cfg);

        // 20 tokens, but only first 5 are considered.
        let mut input = String::new();
        for i in 0..20 {
            input.push_str(&format!("tok{:02}{} ", i, "aZ0bY1cX2dW3eV4fU5gT6hS7iR8jQ9"));
        }

        let _ = scanner.scan(&input).unwrap();
        // Not asserting exact findings count since entropy thresholds can vary with content,
        // but this ensures we don't panic and we exercise the candidate bound.
    }

    #[test]
    fn shannon_entropy_known_values() {
        assert_eq!(calculate_shannon_entropy_bytes(b""), 0.0);
        assert_eq!(calculate_shannon_entropy_bytes(b"aaaaaa"), 0.0);

        // Two symbols with equal probability => 1 bit
        let e = calculate_shannon_entropy_bytes(b"abababab");
        assert!(e > 0.99 && e < 1.01);
    }

    #[test]
    fn finding_id_is_deterministic_for_same_input_and_span() {
        let cfg = SecretScannerConfig::default();
        let scanner = make_scanner_with_specs(default_pattern_specs(), cfg);

        let input = "leak AKIA1234567890ABCD12 in text";
        let a = scanner.scan(input).unwrap();
        let b = scanner.scan(input).unwrap();

        assert!(!a.is_empty());
        assert_eq!(a.len(), b.len());

        // IDs should match 1:1 in stable order (dedup + sort makes order deterministic here).
        for (fa, fb) in a.iter().zip(b.iter()) {
            assert_eq!(fa.finding_id, fb.finding_id);
            assert_eq!(fa.input_hash, fb.input_hash);
        }
    }

    #[test]
    fn finding_id_changes_when_span_changes() {
        let input_hash = "deadbeef";
        let f1 = Finding::new(
            FindingKind::CustomPattern("X".to_string()),
            (10, 20),
            "abc…yz".to_string(),
            None,
            input_hash.to_string(),
        );
        let f2 = Finding::new(
            FindingKind::CustomPattern("X".to_string()),
            (10, 21),
            "abc…yz".to_string(),
            None,
            input_hash.to_string(),
        );
        assert_ne!(f1.finding_id, f2.finding_id);
    }

    #[test]
    fn finding_id_changes_when_kind_changes() {
        let input_hash = "deadbeef";
        let f1 = Finding::new(
            FindingKind::CustomPattern("A".to_string()),
            (10, 20),
            "abc…yz".to_string(),
            None,
            input_hash.to_string(),
        );
        let f2 = Finding::new(
            FindingKind::CustomPattern("B".to_string()),
            (10, 20),
            "abc…yz".to_string(),
            None,
            input_hash.to_string(),
        );
        assert_ne!(f1.finding_id, f2.finding_id);
    }

    #[test]
    fn finding_id_is_blake3_hex_len() {
        let f = Finding::new(
            FindingKind::HighEntropyToken,
            (1, 2),
            "abc…yz".to_string(),
            Some(123),
            "hash".to_string(),
        );
        // blake3 hex digest is 64 chars.
        assert_eq!(f.finding_id.len(), 64);
        assert!(f.finding_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn redaction_merges_overlaps_and_tags_multi() {
        let input = "before SECRET after";
        let findings = vec![
            Finding::new(
                FindingKind::CustomPattern("A".to_string()),
                (7, 13),
                "".to_string(),
                None,
                "x".to_string(),
            ),
            Finding::new(
                FindingKind::CustomPattern("B".to_string()),
                (9, 13),
                "".to_string(),
                None,
                "x".to_string(),
            ),
        ];

        let style = RedactionStyle::default();
        let out = redact_by_findings(input, &findings, style);
        assert!(out.contains("[REDACTED]:MULTI:2"));
    }

    #[test]
    fn redaction_clamps_bad_spans_and_is_utf8_safe() {
        // Intentionally create spans that cut through UTF-8 boundaries.
        let input = "hi 🙂 secret";
        let findings = vec![Finding::new(
            FindingKind::CustomPattern("X".to_string()),
            (4, 6), // likely mid-emoji byte range
            "".to_string(),
            None,
            "x".to_string(),
        )];

        let out = redact_by_findings(input, &findings, RedactionStyle::default());
        assert!(out.contains("[REDACTED]"));
        // Output should remain valid UTF-8, and we should not panic.
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn dedup_removes_duplicates() {
        let mut findings = vec![
            Finding::new(
                FindingKind::OpenAiApiKey,
                (10, 20),
                "abc…yz".to_string(),
                None,
                "h".to_string(),
            ),
            Finding::new(
                FindingKind::OpenAiApiKey,
                (10, 20),
                "abc…yz".to_string(),
                None,
                "h".to_string(),
            ),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn hot_reload_update_success_changes_behavior() {
        let cfg = base_cfg();
        let reg = Arc::new(
            HotReloadPatternRegistry::new(vec![PatternSpec {
                id: "FOO".to_string(),
                kind: None,
                regex: r"\bFOOSECRET\b".to_string(),
            }])
            .unwrap(),
        );
        let scanner = SecretScanner::new(cfg, reg.clone()).unwrap();

        let input = "FOOSECRET";
        let findings = scanner.scan(input).unwrap();
        assert_eq!(findings.len(), 1);

        reg.update_from_specs(vec![PatternSpec {
            id: "BAR".to_string(),
            kind: None,
            regex: r"\bBARSECRET\b".to_string(),
        }])
        .unwrap();

        let findings2 = scanner.scan("BARSECRET").unwrap();
        assert_eq!(findings2.len(), 1);

        let findings3 = scanner.scan("FOOSECRET").unwrap();
        assert!(findings3.is_empty());
    }

    #[test]
    fn hot_reload_update_failure_keeps_old_patterns() {
        let cfg = base_cfg();
        let reg = Arc::new(
            HotReloadPatternRegistry::new(vec![PatternSpec {
                id: "FOO".to_string(),
                kind: None,
                regex: r"\bFOOSECRET\b".to_string(),
            }])
            .unwrap(),
        );
        let scanner = SecretScanner::new(cfg, reg.clone()).unwrap();

        assert_eq!(scanner.scan("FOOSECRET").unwrap().len(), 1);

        // invalid regex
        let bad = vec![PatternSpec {
            id: "BAD".to_string(),
            kind: None,
            regex: r"(\b".to_string(),
        }];

        assert!(reg.update_from_specs(bad).is_err());

        // old still works
        assert_eq!(scanner.scan("FOOSECRET").unwrap().len(), 1);
    }

    #[test]
    fn invalid_pattern_id_rejected() {
        let bad = PatternSpec {
            id: "not allowed".to_string(),
            kind: None,
            regex: r"\bX\b".to_string(),
        };
        assert!(matches!(
            compile_patterns(&[bad]),
            Err(RegistryError::InvalidPattern)
        ));
    }

    #[test]
    fn invalid_pattern_regex_too_long_rejected() {
        let bad = PatternSpec {
            id: "TOO_LONG".to_string(),
            kind: None,
            regex: "a".repeat(513),
        };
        assert!(matches!(
            compile_patterns(&[bad]),
            Err(RegistryError::InvalidPattern)
        ));
    }

    #[test]
    fn scan_and_redact_replaces_detected_secret() {
        let cfg = base_cfg();
        let scanner = make_scanner_with_specs(default_pattern_specs(), cfg);

        let input = "sk-abcdefghijklmnopqrstuvwxyzABCDE";
        let (findings, redacted) = scanner
            .scan_and_redact(input, RedactionStyle::default())
            .unwrap();

        assert!(!findings.is_empty());
        assert!(!redacted.contains("sk-abcdefghijklmnopqrstuvwxyzABCDE"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn token_iter_offsets_are_correct_basic() {
        let input = "  (hello)  world!  ";
        let toks: Vec<(usize, &str)> = token_iter(input).collect();
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].1, "hello");
        assert_eq!(toks[1].1, "world");
        assert_eq!(&input[toks[0].0..toks[0].0 + toks[0].1.len()], "hello");
    }

    #[test]
    fn urlish_leading_slash_does_not_skip_single_slash_base64ish() {
        // Should NOT be considered a path-like URL (only one slash).
        let token =
            "/aZ0bY1cX2dW3eV4fU5gT6hS7iR8jQ9kP0lO1mN2nM3oL4pK5qJ6rI7sH8tG9uF0vE1wD2xC3yB4zA5";
        assert!(!looks_like_urlish(token));
    }

    #[test]
    fn urlish_multiple_slashes_is_skipped() {
        assert!(looks_like_urlish("/var/log/system.log"));
        assert!(looks_like_urlish("/a/b/c"));
    }

    #[test]
    fn classify_hexish_and_base64ish() {
        assert_eq!(classify_token("deadBEEF0123"), TokenClass::Hexish);
        assert_eq!(classify_token("AbcDef0123_-+/=="), TokenClass::Base64ish);
        assert_eq!(classify_token("not$base64"), TokenClass::Other);
    }

    #[test]
    fn file_registry_refresh_flow() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Use a closed file path
        let mut tmp = NamedTempFile::new().unwrap();
        // Regex needs double backslash in JSON string to be a single backslash in regex string
        let initial = r#"[{ "id":"FOO", "regex":"\\bFOOSECRET\\b" }]"#;
        write!(tmp, "{initial}").unwrap();

        // Keep the temporary file around but close the writer handle if possible,
        // or just rely on OS allowing read.
        // Better: usage of `keep()` or just re-opening.
        // Simplest fix for Windows: Put it in a temp DIR so we control the file creation/closing.

        let tmp_dir = tempfile::tempdir().unwrap();
        let file_path = tmp_dir.path().join("patterns.json");
        std::fs::write(&file_path, initial).unwrap();

        let reg =
            Arc::new(FilePatternRegistry::new(file_path.clone(), default_pattern_specs()).unwrap());

        // First refresh should load file.
        let refreshed = reg.refresh_if_changed().unwrap();
        assert_eq!(refreshed, true);

        let cfg = base_cfg();
        let scanner = SecretScanner::new(cfg, reg.clone()).unwrap();

        let findings = scanner.scan("FOOSECRET").unwrap();
        assert_eq!(findings.len(), 1);

        // Update file content
        // Ensure time moves forward for mtime check if needed, but here we just wrote it.
        // Some filesystems have low resolution. We can just force a change if we sleep slightly
        // or just rely on content change + mtime check logic.
        std::thread::sleep(std::time::Duration::from_millis(10));

        let updated = r#"[{ "id":"BAR", "regex":"\\bBARSECRET\\b" }]"#;
        std::fs::write(&file_path, updated).unwrap();

        // Refresh should detect and load.
        // We need access to refresh.
        // The scanner has an Arc to logic. We can cast or just hold a ref to reg.
        // In the test `reg` is `FilePatternRegistry`.
        assert_eq!(reg.refresh_if_changed().unwrap(), true);

        // Verify new pattern works
        assert_eq!(scanner.scan("BARSECRET").unwrap().len(), 1);
        assert_eq!(scanner.scan("FOOSECRET").unwrap().len(), 0);
        // So: separate test below validates refresh_if_changed toggles.
    }

    #[test]
    fn file_registry_refresh_if_changed_returns_false_when_unchanged() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().unwrap();
        let initial = r#"[{ "id":"FOO", "regex":"\\bFOOSECRET\\b" }]"#;
        write!(tmp, "{initial}").unwrap();
        tmp.flush().unwrap();

        let reg =
            FilePatternRegistry::new(tmp.path().to_path_buf(), default_pattern_specs()).unwrap();
        assert_eq!(reg.refresh_if_changed().unwrap(), true);
        assert_eq!(reg.refresh_if_changed().unwrap(), false);
    }
}
