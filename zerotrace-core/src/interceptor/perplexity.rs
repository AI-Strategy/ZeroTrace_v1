use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityError {
    InvalidConfig(&'static str),

    // Hard blocks
    ControlOrZeroWidthDetected {
        count: usize,
    },
    SuspiciousEncodedBlobDetected {
        kind: EncodedBlobKind,
        len: usize,
    },

    // Suffix / noise detections
    AdversarialEntropySpikeDetected {
        tail_bpc: f64,
        head_bpc: f64,
        delta: f64,
    },
    AdversarialHighEntropyTailDetected {
        tail_bpc: f64,
        threshold: f64,
    },
    AdversarialRepetitionDetected {
        repetition_score: f64,
        threshold: f64,
    },
    ExcessiveSymbolRatioDetected {
        symbol_ratio: f64,
        threshold: f64,
    },

    // New: multi-band rolling window
    AdversarialMultiBandDetected {
        suspicious_windows: usize,
        longest_run: usize,
        lookback_chars: usize,
    },
}

pub type Result<T> = std::result::Result<T, SecurityError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodedBlobKind {
    Base64Like,
    HexLike,
}

#[derive(Debug, Clone)]
pub struct PerplexityConfig {
    /// Minimum length (chars) before enforcing blocks.
    pub min_len: usize,

    /// Tail window length for primary suffix detection (chars).
    pub tail_len: usize,

    /// If tail entropy is above this, it's suspicious.
    pub tail_entropy_threshold_bpc: f64,

    /// If tail entropy minus head entropy exceeds this, strong suffix signal.
    pub entropy_spike_delta_bpc: f64,

    /// Repetition threshold in [0,1].
    pub repetition_threshold: f64,

    /// Symbol ratio threshold for natural-language-shaped prompts.
    pub symbol_ratio_threshold: f64,

    /// If true, include whitespace in entropy/repetition.
    pub include_whitespace_in_metrics: bool,

    /// Detect suspicious encoded blobs (base64/hex).
    pub detect_encoded_blobs: bool,
    pub min_blob_token_len: usize,

    /// Rolling multi-band scan config (last N chars of metrics text)
    pub rolling_scan_enabled: bool,
    pub rolling_lookback_chars: usize,
    pub rolling_window_chars: usize,
    pub rolling_step_chars: usize,

    /// Block if suspicious windows >= this count
    pub rolling_min_suspicious_windows: usize,

    /// Block if longest consecutive suspicious windows >= this
    pub rolling_min_consecutive_windows: usize,
}

impl Default for PerplexityConfig {
    fn default() -> Self {
        Self {
            min_len: 64,
            tail_len: 160,
            tail_entropy_threshold_bpc: 5.05,
            entropy_spike_delta_bpc: 1.10,
            repetition_threshold: 0.82,
            symbol_ratio_threshold: 0.38,
            include_whitespace_in_metrics: false,
            detect_encoded_blobs: true,
            min_blob_token_len: 80,

            rolling_scan_enabled: true,
            rolling_lookback_chars: 640,
            rolling_window_chars: 96,
            rolling_step_chars: 24,
            rolling_min_suspicious_windows: 3,
            rolling_min_consecutive_windows: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SuspiciousWindow {
    /// Start index in chars relative to the *metrics string* (not bytes).
    pub start_char: usize,
    pub end_char: usize,
    pub entropy_bpc: f64,
    pub repetition_score: f64,
    pub suspicious: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RollingBandReport {
    pub lookback_chars: usize,
    pub window_chars: usize,
    pub step_chars: usize,
    pub total_windows: usize,
    pub suspicious_windows: usize,
    pub longest_consecutive_suspicious: usize,
    pub windows: Vec<SuspiciousWindow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntegrityReport {
    pub len_chars: usize,
    pub head_bpc: f64,
    pub tail_bpc: f64,
    pub delta_bpc: f64,
    pub repetition_score_tail: f64,
    pub symbol_ratio: f64,
    pub looks_like_natural_language: bool,
    pub control_or_zw_count: usize,
    pub encoded_blob: Option<(EncodedBlobKind, usize)>,
    pub rolling: Option<RollingBandReport>,
    pub passed: bool,
}

pub struct PerplexityGuard {
    cfg: PerplexityConfig,
}

impl PerplexityGuard {
    pub fn new(cfg: PerplexityConfig) -> Result<Self> {
        if cfg.min_len == 0 {
            return Err(SecurityError::InvalidConfig("min_len must be >= 1"));
        }
        if cfg.tail_len == 0 {
            return Err(SecurityError::InvalidConfig("tail_len must be >= 1"));
        }
        if !(0.0..=8.0).contains(&cfg.tail_entropy_threshold_bpc) {
            return Err(SecurityError::InvalidConfig(
                "tail_entropy_threshold_bpc must be in [0,8]",
            ));
        }
        if !(0.0..=8.0).contains(&cfg.entropy_spike_delta_bpc) {
            return Err(SecurityError::InvalidConfig(
                "entropy_spike_delta_bpc must be in [0,8]",
            ));
        }
        if !(0.0..=1.0).contains(&cfg.repetition_threshold) {
            return Err(SecurityError::InvalidConfig(
                "repetition_threshold must be in [0,1]",
            ));
        }
        if !(0.0..=1.0).contains(&cfg.symbol_ratio_threshold) {
            return Err(SecurityError::InvalidConfig(
                "symbol_ratio_threshold must be in [0,1]",
            ));
        }
        if cfg.detect_encoded_blobs && cfg.min_blob_token_len < 16 {
            return Err(SecurityError::InvalidConfig(
                "min_blob_token_len should be >= 16 or disable blob detection",
            ));
        }

        if cfg.rolling_scan_enabled {
            if cfg.rolling_lookback_chars == 0 {
                return Err(SecurityError::InvalidConfig(
                    "rolling_lookback_chars must be >= 1",
                ));
            }
            if cfg.rolling_window_chars == 0 {
                return Err(SecurityError::InvalidConfig(
                    "rolling_window_chars must be >= 1",
                ));
            }
            if cfg.rolling_step_chars == 0 {
                return Err(SecurityError::InvalidConfig(
                    "rolling_step_chars must be >= 1",
                ));
            }
            if cfg.rolling_window_chars > cfg.rolling_lookback_chars {
                return Err(SecurityError::InvalidConfig(
                    "rolling_window_chars must be <= rolling_lookback_chars",
                ));
            }
            if cfg.rolling_min_suspicious_windows == 0 {
                return Err(SecurityError::InvalidConfig(
                    "rolling_min_suspicious_windows must be >= 1",
                ));
            }
            if cfg.rolling_min_consecutive_windows == 0 {
                return Err(SecurityError::InvalidConfig(
                    "rolling_min_consecutive_windows must be >= 1",
                ));
            }
        }

        Ok(Self { cfg })
    }

    pub fn config(&self) -> &PerplexityConfig {
        &self.cfg
    }

    pub fn report(&self, prompt: &str) -> IntegrityReport {
        let control_or_zw_count = count_control_or_zero_width(prompt);
        let shape = TextShape::from(prompt);
        let looks_like_natural_language = shape.looks_like_natural_language();
        let encoded_blob = if self.cfg.detect_encoded_blobs {
            detect_encoded_blob(prompt, self.cfg.min_blob_token_len)
        } else {
            None
        };

        let metrics_text: String = if self.cfg.include_whitespace_in_metrics {
            prompt.to_string()
        } else {
            prompt.chars().filter(|c| !c.is_whitespace()).collect()
        };

        let len_chars = metrics_text.chars().count();

        // Head/tail split (metrics string)
        let (head, tail) = split_head_tail(&metrics_text, self.cfg.tail_len);
        let head_bpc = shannon_entropy_bits_per_char(head);
        let tail_bpc = shannon_entropy_bits_per_char(tail);
        let delta_bpc = (tail_bpc - head_bpc).max(0.0);
        let repetition_score_tail = repetition_score(tail);

        let symbol_ratio = shape.symbol_ratio();

        // Rolling scan (only if enabled and long enough)
        let rolling = if self.cfg.rolling_scan_enabled && len_chars >= self.cfg.min_len {
            Some(self.rolling_scan(&metrics_text))
        } else {
            None
        };

        // Below min_len => never block
        if len_chars < self.cfg.min_len {
            return IntegrityReport {
                len_chars,
                head_bpc,
                tail_bpc,
                delta_bpc,
                repetition_score_tail,
                symbol_ratio,
                looks_like_natural_language,
                control_or_zw_count,
                encoded_blob,
                rolling,
                passed: true,
            };
        }

        let mut passed = true;

        if control_or_zw_count > 0 {
            passed = false;
        }
        if encoded_blob.is_some() {
            passed = false;
        }
        if tail_bpc > self.cfg.tail_entropy_threshold_bpc {
            passed = false;
        }
        if delta_bpc >= self.cfg.entropy_spike_delta_bpc
            && tail_bpc > self.cfg.tail_entropy_threshold_bpc
        {
            passed = false;
        }
        if repetition_score_tail >= self.cfg.repetition_threshold {
            passed = false;
        }
        if looks_like_natural_language && symbol_ratio > self.cfg.symbol_ratio_threshold {
            passed = false;
        }

        if let Some(r) = &rolling {
            if r.suspicious_windows >= self.cfg.rolling_min_suspicious_windows
                || r.longest_consecutive_suspicious >= self.cfg.rolling_min_consecutive_windows
            {
                passed = false;
            }
        }

        IntegrityReport {
            len_chars,
            head_bpc,
            tail_bpc,
            delta_bpc,
            repetition_score_tail,
            symbol_ratio,
            looks_like_natural_language,
            control_or_zw_count,
            encoded_blob,
            rolling,
            passed,
        }
    }

    pub fn validate_input_integrity(&self, prompt: &str) -> Result<()> {
        let r = self.report(prompt);

        if r.len_chars < self.cfg.min_len {
            return Ok(());
        }

        if r.control_or_zw_count > 0 {
            return Err(SecurityError::ControlOrZeroWidthDetected {
                count: r.control_or_zw_count,
            });
        }

        if let Some((kind, len)) = r.encoded_blob {
            return Err(SecurityError::SuspiciousEncodedBlobDetected { kind, len });
        }

        // Rolling scan check (first, because it’s the “multiple bands” proof)
        if let Some(roll) = r.rolling {
            if roll.suspicious_windows >= self.cfg.rolling_min_suspicious_windows
                || roll.longest_consecutive_suspicious >= self.cfg.rolling_min_consecutive_windows
            {
                return Err(SecurityError::AdversarialMultiBandDetected {
                    suspicious_windows: roll.suspicious_windows,
                    longest_run: roll.longest_consecutive_suspicious,
                    lookback_chars: roll.lookback_chars,
                });
            }
        }

        if r.tail_bpc > self.cfg.tail_entropy_threshold_bpc
            && r.delta_bpc >= self.cfg.entropy_spike_delta_bpc
        {
            return Err(SecurityError::AdversarialEntropySpikeDetected {
                tail_bpc: r.tail_bpc,
                head_bpc: r.head_bpc,
                delta: r.delta_bpc,
            });
        }

        if r.tail_bpc > self.cfg.tail_entropy_threshold_bpc {
            return Err(SecurityError::AdversarialHighEntropyTailDetected {
                tail_bpc: r.tail_bpc,
                threshold: self.cfg.tail_entropy_threshold_bpc,
            });
        }

        if r.repetition_score_tail >= self.cfg.repetition_threshold {
            return Err(SecurityError::AdversarialRepetitionDetected {
                repetition_score: r.repetition_score_tail,
                threshold: self.cfg.repetition_threshold,
            });
        }

        if r.looks_like_natural_language && r.symbol_ratio > self.cfg.symbol_ratio_threshold {
            return Err(SecurityError::ExcessiveSymbolRatioDetected {
                symbol_ratio: r.symbol_ratio,
                threshold: self.cfg.symbol_ratio_threshold,
            });
        }

        Ok(())
    }

    fn rolling_scan(&self, metrics_text: &str) -> RollingBandReport {
        let total_chars = metrics_text.chars().count();
        let lookback = self.cfg.rolling_lookback_chars.min(total_chars);

        // Analyze only the last `lookback` chars of metrics_text
        let start_char = total_chars - lookback;
        let region = slice_by_char_range(metrics_text, start_char, total_chars);

        let region_chars = region.chars().count();
        let win = self.cfg.rolling_window_chars.min(region_chars);
        let step = self.cfg.rolling_step_chars;

        let mut windows = Vec::new();
        let mut suspicious_windows = 0usize;
        let mut longest_run = 0usize;
        let mut current_run = 0usize;

        // sliding windows over region, in char indices relative to region (then offset by start_char)
        let mut pos = 0usize;
        while pos + win <= region_chars {
            let w = slice_by_char_range(region, pos, pos + win);
            let bpc = shannon_entropy_bits_per_char(w);
            let rep = repetition_score(w);

            // Suspicious window if:
            // - High entropy (noise), OR
            // - High repetition (trigger tail)
            let suspicious =
                bpc > self.cfg.tail_entropy_threshold_bpc || rep >= self.cfg.repetition_threshold;

            if suspicious {
                suspicious_windows += 1;
                current_run += 1;
                longest_run = longest_run.max(current_run);
            } else {
                current_run = 0;
            }

            windows.push(SuspiciousWindow {
                start_char: start_char + pos,
                end_char: start_char + pos + win,
                entropy_bpc: bpc,
                repetition_score: rep,
                suspicious,
            });

            pos = pos.saturating_add(step);
            if step == 0 {
                break; // defensive (should never happen; config checked)
            }
        }

        RollingBandReport {
            lookback_chars: lookback,
            window_chars: win,
            step_chars: step,
            total_windows: windows.len(),
            suspicious_windows,
            longest_consecutive_suspicious: longest_run,
            windows,
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn split_head_tail(s: &str, tail_len: usize) -> (&str, &str) {
    let idxs: Vec<usize> = s.char_indices().map(|(i, _)| i).collect();
    if idxs.is_empty() {
        return ("", "");
    }
    let total_chars = idxs.len();
    if total_chars <= tail_len {
        return ("", s);
    }
    let split_at_char = total_chars - tail_len;
    let split_byte_idx = idxs[split_at_char];
    s.split_at(split_byte_idx)
}

fn slice_by_char_range(s: &str, start_char: usize, end_char: usize) -> &str {
    // Safe substring slicing by char indices.
    if start_char >= end_char {
        return "";
    }
    let mut start_byte = None;
    let mut end_byte = None;
    let mut char_pos = 0usize;

    for (byte_idx, _ch) in s.char_indices() {
        if char_pos == start_char {
            start_byte = Some(byte_idx);
        }
        if char_pos == end_char {
            end_byte = Some(byte_idx);
            break;
        }
        char_pos += 1;
    }

    let sb = start_byte.unwrap_or_else(|| if start_char == char_pos { s.len() } else { 0 });
    let eb = end_byte.unwrap_or_else(|| s.len());
    &s[sb..eb]
}

fn shannon_entropy_bits_per_char(text: &str) -> f64 {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    for &c in &chars {
        *freq.entry(c).or_insert(0) += 1;
    }

    let n_f = n as f64;
    let mut entropy_bits = 0.0;
    for &count in freq.values() {
        let p = count as f64 / n_f;
        entropy_bits -= p * p.log2();
    }
    entropy_bits
}

fn repetition_score(text: &str) -> f64 {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n < 4 {
        return 0.0;
    }

    // Run-length
    let mut max_run = 1usize;
    let mut cur_run = 1usize;
    for i in 1..n {
        if chars[i] == chars[i - 1] {
            cur_run += 1;
            max_run = max_run.max(cur_run);
        } else {
            cur_run = 1;
        }
    }
    let run_score = max_run as f64 / n as f64;

    // Periodic repetition
    let max_period = (n / 2).min(64);
    let mut best_periodic: f64 = 0.0;
    for p in 1..=max_period {
        let mut matches = 0usize;
        let mut compared = 0usize;
        for i in p..n {
            compared += 1;
            if chars[i] == chars[i - p] {
                matches += 1;
            }
        }
        if compared > 0 {
            let ratio = matches as f64 / compared as f64;
            let weighted = ratio * (1.0 + 1.0 / p as f64);
            best_periodic = best_periodic.max(weighted.min(1.0));
        }
    }

    (0.55 * best_periodic + 0.45 * run_score).min(1.0)
}

fn count_control_or_zero_width(s: &str) -> usize {
    s.chars()
        .filter(|&c| {
            if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                return true;
            }
            matches!(
                c,
                '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
                    | '\u{2060}'
                    | '\u{FEFF}'
                    | '\u{202A}'
                    | '\u{202B}'
                    | '\u{202D}'
                    | '\u{202E}'
                    | '\u{202C}'
            )
        })
        .count()
}

fn detect_encoded_blob(s: &str, min_len: usize) -> Option<(EncodedBlobKind, usize)> {
    for tok in s.split_whitespace() {
        let t = tok.trim_matches(|c: char| {
            c == '"' || c == '\'' || c == ',' || c == ';' || c == ')' || c == '('
        });
        if t.len() < min_len {
            continue;
        }
        if is_hex_like(t) {
            return Some((EncodedBlobKind::HexLike, t.len()));
        }
        if is_base64_like(t) {
            return Some((EncodedBlobKind::Base64Like, t.len()));
        }
    }
    None
}

fn is_hex_like(t: &str) -> bool {
    let bytes = t.as_bytes();
    let mut hex = 0usize;
    for &b in bytes {
        if (b as char).is_ascii_hexdigit() {
            hex += 1;
        }
    }
    (hex as f64) / (bytes.len() as f64) >= 0.95
}

fn is_base64_like(t: &str) -> bool {
    let bytes = t.as_bytes();
    let mut ok = 0usize;
    for &b in bytes {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_' {
            ok += 1;
        }
    }
    (ok as f64) / (bytes.len() as f64) >= 0.97
}

#[derive(Debug, Clone)]
struct TextShape {
    total: usize,
    alpha: usize,
    digit: usize,
    whitespace: usize,
    symbol: usize,
    words: usize,
}

impl TextShape {
    fn from(s: &str) -> Self {
        let mut total = 0;
        let mut alpha = 0;
        let mut digit = 0;
        let mut whitespace = 0;
        let mut symbol = 0;

        for c in s.chars() {
            total += 1;
            if c.is_ascii_alphabetic() {
                alpha += 1;
            } else if c.is_ascii_digit() {
                digit += 1;
            } else if c.is_whitespace() {
                whitespace += 1;
            } else {
                symbol += 1;
            }
        }

        let words = s.split_whitespace().count();

        Self {
            total,
            alpha,
            digit,
            whitespace,
            symbol,
            words,
        }
    }

    fn symbol_ratio(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.symbol as f64 / self.total as f64
    }

    fn looks_like_natural_language(&self) -> bool {
        if self.total == 0 {
            return false;
        }
        let alpha_ratio = self.alpha as f64 / self.total as f64;
        let ws_ratio = self.whitespace as f64 / self.total as f64;

        self.words >= 4 && alpha_ratio >= 0.35 && ws_ratio >= 0.08 && self.symbol_ratio() <= 0.45
    }
}

// ============================================================================
// Tests (deterministic, broad coverage, no flaky entropy guessing)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_for_tests() -> PerplexityConfig {
        PerplexityConfig {
            min_len: 40,
            tail_len: 80,
            tail_entropy_threshold_bpc: 4.90,
            entropy_spike_delta_bpc: 0.85,
            repetition_threshold: 0.80,
            symbol_ratio_threshold: 0.45,
            include_whitespace_in_metrics: false,
            detect_encoded_blobs: false,
            min_blob_token_len: 60,
            rolling_scan_enabled: true,
            rolling_lookback_chars: 240,
            rolling_window_chars: 60,
            rolling_step_chars: 20,
            rolling_min_suspicious_windows: 3,
            rolling_min_consecutive_windows: 2,
        }
    }

    fn guard() -> PerplexityGuard {
        PerplexityGuard::new(cfg_for_tests()).unwrap()
    }

    // ---------- Config validation ----------

    #[test]
    fn rejects_bad_rolling_config() {
        let mut cfg = cfg_for_tests();
        cfg.rolling_step_chars = 0;
        assert!(PerplexityGuard::new(cfg).is_err());

        let mut cfg = cfg_for_tests();
        cfg.rolling_window_chars = 0;
        assert!(PerplexityGuard::new(cfg).is_err());

        let mut cfg = cfg_for_tests();
        cfg.rolling_window_chars = 300;
        cfg.rolling_lookback_chars = 200;
        assert!(PerplexityGuard::new(cfg).is_err());
    }

    // ---------- Char slicing correctness ----------

    #[test]
    fn slice_by_char_range_handles_unicode() {
        let s = "αβγδεζη"; // 7 chars, multi-byte
        assert_eq!(slice_by_char_range(s, 0, 2), "αβ");
        assert_eq!(slice_by_char_range(s, 2, 5), "γδε");
        assert_eq!(slice_by_char_range(s, 5, 7), "ζη");
    }

    // ---------- Rolling scan behavior ----------

    #[test]
    fn clean_text_has_low_suspicious_bands() {
        let g = guard();
        let prompt = "Please summarize the case and highlight key holdings, dissent, and procedural posture. "
            .repeat(5);

        let r = g.report(&prompt);
        assert!(r.passed);
        let roll = r.rolling.unwrap();
        assert!(roll.suspicious_windows < g.config().rolling_min_suspicious_windows);
        assert!(roll.longest_consecutive_suspicious < g.config().rolling_min_consecutive_windows);
        assert!(g.validate_input_integrity(&prompt).is_ok());
    }

    #[test]
    fn single_noisy_tail_may_not_trigger_multi_band_if_thresholds_high() {
        let mut cfg = cfg_for_tests();
        cfg.rolling_min_suspicious_windows = 5; // make multi-band harder to trip
        cfg.rolling_min_consecutive_windows = 4;
        let g = PerplexityGuard::new(cfg).unwrap();

        let prompt = format!(
            "{}{}",
            "Summarize the legal issue and outcome. ".repeat(12),
            deterministic_junk(80)
        );

        let rep = g.report(&prompt);
        // It may still block for tail entropy, but multi-band should be harder.
        if let Some(roll) = rep.rolling {
            assert!(roll.suspicious_windows < 5 || roll.longest_consecutive_suspicious < 4);
        }
    }

    #[test]
    fn two_separated_noisy_bands_trigger_multi_band() {
        let g = guard();
        let normal = "Provide a short risk assessment focused on evidentiary weaknesses and likely defenses. "
            .repeat(6);

        // Two distinct noisy segments in the last lookback region
        let noise1 = deterministic_junk(70);
        let noise2 = deterministic_junk(70);

        let prompt = format!("{}{}{}{}{}", normal, noise1, " ".repeat(10), normal, noise2);

        let rep = g.report(&prompt);
        assert!(rep.len_chars >= g.config().min_len);

        let roll = rep.rolling.clone().unwrap();
        assert!(
            roll.suspicious_windows >= 2,
            "Expected multiple suspicious windows, got {}",
            roll.suspicious_windows
        );

        let res = g.validate_input_integrity(&prompt);
        assert!(matches!(
            res,
            Err(SecurityError::AdversarialMultiBandDetected { .. })
        ));
    }

    #[test]
    fn repetitive_suffix_triggers_multi_band() {
        let g = guard();
        let normal = "Summarize the case and list possible next procedural steps. ".repeat(8);
        let rep_tail = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz";

        let prompt = format!("{}{}", normal, rep_tail);

        let roll = g.report(&prompt).rolling.unwrap();
        assert!(roll.longest_consecutive_suspicious >= 1);

        let res = g.validate_input_integrity(&prompt);
        // Could block on repetition directly too, but multi-band is allowed to win.
        assert!(
            matches!(res, Err(SecurityError::AdversarialMultiBandDetected { .. }))
                || matches!(
                    res,
                    Err(SecurityError::AdversarialRepetitionDetected { .. })
                )
        );
    }

    #[test]
    fn short_inputs_never_block_even_if_noisy() {
        let g = guard();
        let prompt = deterministic_junk(20); // < min_len
        assert!(g.validate_input_integrity(&prompt).is_ok());
        let rep = g.report(&prompt);
        assert!(rep.passed);
    }

    // ---------- Deterministic junk generator (no rand crate) ----------

    fn deterministic_junk(n: usize) -> String {
        let mut out = String::with_capacity(n);
        let mut x: u64 = 0x1234_5678_9abc_def0;

        for _ in 0..n {
            // xorshift64*
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x = x.wrapping_mul(0x2545F4914F6CDD1D);

            // Visible ASCII '!'..'~'
            let c = (33 + (x % 94) as u8) as char;
            out.push(c);
        }
        out
    }
}
