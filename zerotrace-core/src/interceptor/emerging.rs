//! Emerging Threats Guard (EMG):
//! - EMG26: Many-shot jailbreaking / context flooding detection.
//! - EMG22: Response timing jitter to reduce timing/token side-channels.
//! - EMG21: Basic CDR-style metadata stripping for JPEG/PNG (no decoding required).
//!
//! WHY THIS EXISTS:
//! LLM security failures rarely come from one “bad” prompt. They come from attackers
//! pushing system instructions out of the effective context, probing timing behavior,
//! and smuggling payloads through “harmless” media metadata. This module provides
//! cheap, deterministic, testable guardrails that can run early in the pipeline.
//!
//! Dependencies (Cargo.toml):
//! ```toml
//! [dependencies]
//! rand = "0.8"
//! thiserror = "1"
//! tracing = "0.1"
//! flate2 = "1"
//! crc32fast = "1"
//! async-trait = "0.1"
//! tokio = { version = "1", features = ["time"] }
//!
//! [dev-dependencies]
//! tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
//! ```

use async_trait::async_trait;
use crc32fast::Hasher as Crc32;
use flate2::{write::ZlibEncoder, Compression};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::io::Write;
use std::time::Duration;
use thiserror::Error;
use tracing::{info, warn};

/// Upper bounds: attackers love “infinite” inputs, and CPUs are not infinite.
const MAX_PROMPT_BYTES_HARD: usize = 256 * 1024; // 256 KiB hard cap for this guard
const MAX_IMAGE_BYTES_HARD: usize = 20 * 1024 * 1024; // 20 MiB hard cap for CDR step

/// Default context window assumption for many-shot overflow detection.
/// (Treat this as “chars/bytes we care about”, not “tokens”, unless you have a tokenizer.)
const DEFAULT_CONTEXT_WINDOW_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone)]
pub struct EmergingThreatsGuard {
    cfg: GuardConfig,
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub many_shot: ManyShotConfig,
    pub jitter: JitterConfig,
    pub image: ImageSanitizeConfig,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            many_shot: ManyShotConfig::default(),
            jitter: JitterConfig::default(),
            image: ImageSanitizeConfig::default(),
        }
    }
}

impl EmergingThreatsGuard {
    pub fn new(cfg: GuardConfig) -> Result<Self, GuardError> {
        cfg.validate()?;
        Ok(Self { cfg })
    }

    /// EMG26: Many-shot jailbreaking / context flooding
    ///
    /// WHY:
    /// Attackers “pad” prompts with repetitive content to push safety/system content out
    /// of effective context. Highly compressible large prompts are a strong signal.
    ///
    /// Security notes:
    /// - We do not log raw prompts. Only lengths and computed scores.
    /// - The check is bounded in CPU and memory via sampling and hard caps.
    ///
    /// Complexity:
    /// - Time: O(n) for sampling + compression (n = sampled bytes)
    /// - Space: O(n) for encoder output buffer (bounded by sample size)
    pub fn assess_many_shot_overflow(&self, prompt: &str) -> Result<ManyShotAssessment, GuardError> {
        validate_prompt(prompt)?;

        let prompt_len = prompt.len();
        let length_ratio = (prompt_len as f32) / (self.cfg.many_shot.context_window_bytes as f32);

        // Sample (bounds work for huge prompts)
        let sample = sample_bytes(prompt.as_bytes(), self.cfg.many_shot.max_sample_bytes);

        let compression_ratio = zlib_compression_ratio(sample)?;
        let repetition_score = repetition_score(sample, self.cfg.many_shot.repetition_ngram)?;

        let tripped = self.cfg.many_shot.is_tripped(prompt_len, length_ratio, compression_ratio, repetition_score);

        info!(
            emg = "EMG26",
            prompt_len,
            context_window = self.cfg.many_shot.context_window_bytes,
            length_ratio,
            compression_ratio,
            repetition_score,
            tripped,
            "many-shot overflow assessment"
        );

        Ok(ManyShotAssessment {
            tripped,
            prompt_len,
            context_window_bytes: self.cfg.many_shot.context_window_bytes,
            length_ratio,
            compression_ratio,
            repetition_score,
        })
    }

    /// EMG22: Side-channel timing jitter
    ///
    /// WHY:
    /// Attackers sometimes infer policy/tool behavior from micro-timing differences.
    /// Adding bounded jitter makes the timing signal noisier (not perfect, but cheap).
    ///
    /// Design:
    /// - `sample_jitter_delay` is pure and testable.
    /// - `apply_token_jitter` performs I/O (sleep) through an injected `Sleeper`.
    ///
    /// Complexity:
    /// - Time: O(1)
    /// - Space: O(1)
    pub fn sample_jitter_delay<R: rand::RngCore + ?Sized>(&self, rng: &mut R) -> Duration {
        self.cfg.jitter.sample(rng)
    }

    pub async fn apply_token_jitter<S: Sleeper, R: rand::RngCore + ?Sized>(
        &self,
        rng: &mut R,
        sleeper: &S,
    ) -> Result<Duration, GuardError> {
        let d = self.sample_jitter_delay(rng);

        // Log without revealing any “signal-bearing” payload.
        info!(emg = "EMG22", jitter_ms = d.as_millis() as u64, "applying token jitter");
        sleeper.sleep(d).await;
        Ok(d)
    }

    /// EMG21: Multi-modal injection (CDR-style metadata stripping)
    ///
    /// WHY:
    /// Metadata fields are a classic smuggling channel: EXIF, IPTC, iTXt, etc.
    /// This is not “virus scanning”. It is “strip metadata and reconstruct container”.
    ///
    /// Supported:
    /// - JPEG: strips APP1 (EXIF) and APP13 (IPTC/Photoshop), optionally COM.
    /// - PNG: strips tEXt/zTXt/iTXt/eXIf chunks, validates CRCs.
    ///
    /// Complexity:
    /// - JPEG: O(n) time, O(n) space (rebuild)
    /// - PNG:  O(n) time, O(n) space (rebuild + CRC checks)
    pub fn sanitize_image_metadata(&self, image_bytes: &[u8]) -> Result<SanitizedImage, GuardError> {
        validate_image_bytes(image_bytes)?;

        let fmt = detect_image_format(image_bytes);

        let (out, stripped) = match fmt {
            ImageFormat::Jpeg => sanitize_jpeg(image_bytes, &self.cfg.image),
            ImageFormat::Png => sanitize_png(image_bytes, &self.cfg.image),
            ImageFormat::Unknown => match self.cfg.image.unknown_format_policy {
                UnknownFormatPolicy::PassThrough => Ok((image_bytes.to_vec(), StripReport::default())),
                UnknownFormatPolicy::Reject => Err(ImageSanitizeError::UnsupportedFormat.into()),
            },
        }?;

        info!(
            emg = "EMG21",
            format = %fmt,
            in_bytes = image_bytes.len(),
            out_bytes = out.len(),
            stripped_app1 = stripped.jpeg_stripped_app1,
            stripped_app13 = stripped.jpeg_stripped_app13,
            stripped_com = stripped.jpeg_stripped_com,
            stripped_png_text = stripped.png_stripped_text_chunks,
            stripped_png_exif = stripped.png_stripped_exif_chunks,
            "image metadata sanitization complete"
        );

        Ok(SanitizedImage {
            format: fmt,
            bytes: out,
            report: stripped,
        })
    }
}

/// ---------- Config + validation ----------

impl GuardConfig {
    pub fn validate(&self) -> Result<(), GuardError> {
        self.many_shot.validate()?;
        self.jitter.validate()?;
        self.image.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ManyShotConfig {
    /// Approximate context window in bytes/chars you care about.
    pub context_window_bytes: usize,
    /// Threshold ratio of prompt/context where we even bother looking hard.
    pub min_length_ratio: f32,
    /// Absolute prompt length threshold (bytes) as a secondary gate.
    pub min_prompt_bytes: usize,
    /// Sample size for compression/repetition checks (bounded CPU).
    pub max_sample_bytes: usize,
    /// Low compression ratio => highly repetitive/padded.
    pub max_compression_ratio: f32,
    /// High repetition score => many repeated n-grams.
    pub min_repetition_score: f32,
    /// N-gram length for repetition scoring.
    pub repetition_ngram: usize,
}

impl Default for ManyShotConfig {
    fn default() -> Self {
        Self {
            context_window_bytes: DEFAULT_CONTEXT_WINDOW_BYTES,
            min_length_ratio: 0.80,
            min_prompt_bytes: 25_000,
            max_sample_bytes: 64 * 1024,
            max_compression_ratio: 0.35,
            min_repetition_score: 0.30,
            repetition_ngram: 12,
        }
    }
}

impl ManyShotConfig {
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.context_window_bytes == 0 {
            return Err(GuardError::InvalidConfig("context_window_bytes must be > 0".into()));
        }
        if !(0.0..=1.5).contains(&self.min_length_ratio) {
            return Err(GuardError::InvalidConfig("min_length_ratio out of bounds".into()));
        }
        if self.min_prompt_bytes == 0 {
            return Err(GuardError::InvalidConfig("min_prompt_bytes must be > 0".into()));
        }
        if self.max_sample_bytes == 0 || self.max_sample_bytes > MAX_PROMPT_BYTES_HARD {
            return Err(GuardError::InvalidConfig("max_sample_bytes out of bounds".into()));
        }
        if !(0.0..=1.0).contains(&self.max_compression_ratio) {
            return Err(GuardError::InvalidConfig("max_compression_ratio out of bounds".into()));
        }
        if !(0.0..=1.0).contains(&self.min_repetition_score) {
            return Err(GuardError::InvalidConfig("min_repetition_score out of bounds".into()));
        }
        if self.repetition_ngram < 4 || self.repetition_ngram > 64 {
            return Err(GuardError::InvalidConfig("repetition_ngram out of bounds".into()));
        }
        Ok(())
    }

    fn is_tripped(
        &self,
        prompt_len: usize,
        length_ratio: f32,
        compression_ratio: f32,
        repetition_score: f32,
    ) -> bool {
        let length_gate = prompt_len >= self.min_prompt_bytes && length_ratio >= self.min_length_ratio;

        // Trip if prompt is both big and “padding-like”.
        length_gate && (compression_ratio <= self.max_compression_ratio || repetition_score >= self.min_repetition_score)
    }
}

#[derive(Debug, Clone)]
pub struct JitterConfig {
    pub min_ms: u64,
    pub max_ms: u64,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self { min_ms: 5, max_ms: 50 }
    }
}

impl JitterConfig {
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.min_ms > self.max_ms {
            return Err(GuardError::InvalidConfig("jitter min_ms > max_ms".into()));
        }
        if self.max_ms > 5_000 {
            return Err(GuardError::InvalidConfig("jitter max_ms too large".into()));
        }
        Ok(())
    }

    pub fn sample<R: rand::RngCore + ?Sized>(&self, rng: &mut R) -> Duration {
        if self.min_ms == self.max_ms {
            return Duration::from_millis(self.min_ms);
        }
        let v = rng.gen_range(self.min_ms..=self.max_ms);
        Duration::from_millis(v)
    }
}

#[derive(Debug, Clone)]
pub struct ImageSanitizeConfig {
    pub strip_jpeg_comment: bool,
    pub unknown_format_policy: UnknownFormatPolicy,
    pub max_output_bytes: usize,
}

impl Default for ImageSanitizeConfig {
    fn default() -> Self {
        Self {
            strip_jpeg_comment: true,
            unknown_format_policy: UnknownFormatPolicy::PassThrough,
            max_output_bytes: MAX_IMAGE_BYTES_HARD,
        }
    }
}

impl ImageSanitizeConfig {
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_IMAGE_BYTES_HARD {
            return Err(GuardError::InvalidConfig("max_output_bytes out of bounds".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UnknownFormatPolicy {
    PassThrough,
    Reject,
}

/// ---------- Public result types ----------

#[derive(Debug, Clone, PartialEq)]
pub struct ManyShotAssessment {
    pub tripped: bool,
    pub prompt_len: usize,
    pub context_window_bytes: usize,
    pub length_ratio: f32,
    pub compression_ratio: f32,
    pub repetition_score: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SanitizedImage {
    pub format: ImageFormat,
    pub bytes: Vec<u8>,
    pub report: StripReport,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct StripReport {
    pub jpeg_stripped_app1: bool,
    pub jpeg_stripped_app13: bool,
    pub jpeg_stripped_com: bool,
    pub png_stripped_text_chunks: bool,
    pub png_stripped_exif_chunks: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Jpeg,
    Png,
    Unknown,
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageFormat::Jpeg => write!(f, "jpeg"),
            ImageFormat::Png => write!(f, "png"),
            ImageFormat::Unknown => write!(f, "unknown"),
        }
    }
}

/// ---------- Errors ----------

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid prompt: {0}")]
    InvalidPrompt(String),
    #[error("invalid image: {0}")]
    InvalidImage(String),
    #[error("compression failed")]
    Compression(#[from] CompressionError),
    #[error("image sanitization failed")]
    ImageSanitize(#[from] ImageSanitizeError),
}

#[derive(Debug, Error)]
#[error("compression error: {0}")]
pub struct CompressionError(String);

#[derive(Debug, Error)]
pub enum ImageSanitizeError {
    #[error("unsupported image format")]
    UnsupportedFormat,
    #[error("malformed image container")]
    Malformed,
    #[error("png crc mismatch")]
    PngCrcMismatch,
    #[error("output exceeds configured max bytes")]
    OutputTooLarge,
}

/// ---------- Sleeper abstraction (decouple I/O) ----------

#[async_trait]
pub trait Sleeper: Send + Sync {
    async fn sleep(&self, d: Duration);
}

pub struct TokioSleeper;

#[async_trait]
impl Sleeper for TokioSleeper {
    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

/// ---------- Pure helpers ----------

fn validate_prompt(prompt: &str) -> Result<(), GuardError> {
    if prompt.trim().is_empty() {
        return Err(GuardError::InvalidPrompt("empty".into()));
    }
    if prompt.len() > MAX_PROMPT_BYTES_HARD {
        return Err(GuardError::InvalidPrompt("too large".into()));
    }
    if prompt.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(GuardError::InvalidPrompt("contains disallowed control characters".into()));
    }
    Ok(())
}

fn validate_image_bytes(bytes: &[u8]) -> Result<(), GuardError> {
    if bytes.is_empty() {
        return Err(GuardError::InvalidImage("empty".into()));
    }
    if bytes.len() > MAX_IMAGE_BYTES_HARD {
        return Err(GuardError::InvalidImage("too large".into()));
    }
    Ok(())
}

fn sample_bytes<'a>(data: &'a [u8], max: usize) -> &'a [u8] {
    let n = data.len().min(max);
    &data[..n]
}

fn zlib_compression_ratio(data: &[u8]) -> Result<f32, GuardError> {
    if data.is_empty() {
        return Ok(1.0);
    }
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data)
        .map_err(|e| CompressionError(format!("write failed: {e}")))?;
    let out = enc
        .finish()
        .map_err(|e| CompressionError(format!("finish failed: {e}")))?;
    let ratio = (out.len() as f32) / (data.len() as f32);
    if !ratio.is_finite() {
        return Err(GuardError::Compression(CompressionError("ratio not finite".into())));
    }
    Ok(ratio.clamp(0.0, 1.0))
}

/// Repetition scoring using n-gram uniqueness.
/// Score is 1 - unique_ngrams/total_ngrams (higher = more repetitive).
fn repetition_score(data: &[u8], n: usize) -> Result<f32, GuardError> {
    if data.len() < n + 1 {
        return Ok(0.0);
    }
    // Use a cheap rolling hash; collisions are fine for a heuristic.
    let mut total: u32 = 0;
    let mut uniq = std::collections::HashSet::<u64>::new();
    uniq.reserve(4096);

    // FNV-ish rolling hash
    const PRIME: u64 = 1099511628211;
    const OFFSET: u64 = 1469598103934665603;

    for win in data.windows(n) {
        total += 1;
        let mut h = OFFSET;
        for &b in win {
            h ^= b as u64;
            h = h.wrapping_mul(PRIME);
        }
        uniq.insert(h);
        // Bound memory: if you hit this, it's probably not repetitive anyway.
        if uniq.len() > 200_000 {
            break;
        }
    }

    if total == 0 {
        return Ok(0.0);
    }
    let unique_ratio = (uniq.len() as f32) / (total as f32);
    let score = 1.0 - unique_ratio;
    Ok(score.clamp(0.0, 1.0))
}

fn detect_image_format(bytes: &[u8]) -> ImageFormat {
    // JPEG: FF D8
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        return ImageFormat::Jpeg;
    }
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if bytes.len() >= 8 && bytes[..8] == PNG_SIG {
        return ImageFormat::Png;
    }
    ImageFormat::Unknown
}

/// ---------- JPEG sanitization (strip APP1/APP13, optionally COM) ----------

fn sanitize_jpeg(input: &[u8], cfg: &ImageSanitizeConfig) -> Result<(Vec<u8>, StripReport), GuardError> {
    // Minimal validation
    if input.len() < 4 || input[0] != 0xFF || input[1] != 0xD8 {
        return Err(ImageSanitizeError::Malformed.into());
    }

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..2]); // SOI
    let mut i = 2usize;

    let mut report = StripReport::default();

    while i < input.len() {
        // Expect marker 0xFF ?? with possible fill bytes
        if input[i] != 0xFF {
            // After SOS (FF DA), scan data until EOI. But we are not decoding, so be conservative:
            // treat trailing bytes as scan data and copy them through.
            out.extend_from_slice(&input[i..]);
            break;
        }

        // Skip fill 0xFF bytes
        while i < input.len() && input[i] == 0xFF {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        let marker = input[i];
        i += 1;

        // EOI
        if marker == 0xD9 {
            out.extend_from_slice(&[0xFF, 0xD9]);
            break;
        }

        // Standalone markers (RSTn, TEM) have no length, but we can just copy them.
        let is_standalone = matches!(marker, 0x01 | 0xD0..=0xD7);
        if is_standalone {
            out.extend_from_slice(&[0xFF, marker]);
            continue;
        }

        // Need 2-byte length
        if i + 2 > input.len() {
            return Err(ImageSanitizeError::Malformed.into());
        }
        let len = u16::from_be_bytes([input[i], input[i + 1]]) as usize;
        i += 2;

        // Length includes the two length bytes, so minimum is 2.
        if len < 2 {
            return Err(ImageSanitizeError::Malformed.into());
        }
        let payload_len = len - 2;

        if i + payload_len > input.len() {
            return Err(ImageSanitizeError::Malformed.into());
        }

        let segment_start = i;
        let segment_end = i + payload_len;
        i = segment_end;

        let full_marker = 0xFF00u16 | marker as u16;

        // Strip EXIF/APP1 and IPTC/APP13 and optionally COM.
        let strip = match full_marker {
            0xFFE1 => {
                report.jpeg_stripped_app1 = true;
                true
            }
            0xFFED => {
                report.jpeg_stripped_app13 = true;
                true
            }
            0xFFFE if cfg.strip_jpeg_comment => {
                report.jpeg_stripped_com = true;
                true
            }
            _ => false,
        };

        if strip {
            continue;
        }

        // Copy marker + length + payload.
        out.extend_from_slice(&[0xFF, marker]);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&input[segment_start..segment_end]);

        if out.len() > cfg.max_output_bytes {
            return Err(ImageSanitizeError::OutputTooLarge.into());
        }

        // SOS marker: FF DA begins entropy-coded scan data. After this, JPEG structure changes.
        // We already handle “not 0xFF” case by copying through, but explicitly copying scan data
        // is safer and avoids accidentally stripping bytes inside scan data.
        if marker == 0xDA {
            // Copy remaining bytes verbatim (until EOI if present).
            out.extend_from_slice(&input[i..]);
            break;
        }
    }

    Ok((out, report))
}

/// ---------- PNG sanitization (strip text/exif chunks, validate CRCs) ----------

fn sanitize_png(input: &[u8], cfg: &ImageSanitizeConfig) -> Result<(Vec<u8>, StripReport), GuardError> {
    const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if input.len() < 8 || input[..8] != SIG {
        return Err(ImageSanitizeError::Malformed.into());
    }

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&SIG);

    let mut i = 8usize;
    let mut saw_ihdr = false;
    let mut saw_iend = false;

    let mut report = StripReport::default();

    while i + 12 <= input.len() {
        let len = u32::from_be_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]) as usize;
        let ty = &input[i + 4..i + 8];
        let chunk_start = i;
        let data_start = i + 8;
        let data_end = data_start + len;
        let crc_start = data_end;
        let crc_end = crc_start + 4;

        if crc_end > input.len() {
            return Err(ImageSanitizeError::Malformed.into());
        }

        // CRC validation
        let expected_crc = u32::from_be_bytes([input[crc_start], input[crc_start + 1], input[crc_start + 2], input[crc_start + 3]]);
        let mut hasher = Crc32::new();
        hasher.update(ty);
        hasher.update(&input[data_start..data_end]);
        let actual_crc = hasher.finalize();
        if actual_crc != expected_crc {
            return Err(ImageSanitizeError::PngCrcMismatch.into());
        }

        let ty_str = std::str::from_utf8(ty).unwrap_or("????");
        let is_ihdr = ty == b"IHDR";
        let is_iend = ty == b"IEND";

        if is_ihdr {
            saw_ihdr = true;
        }
        if !saw_ihdr {
            return Err(ImageSanitizeError::Malformed.into());
        }

        let strip = match ty {
            b"tEXt" | b"zTXt" | b"iTXt" => {
                report.png_stripped_text_chunks = true;
                true
            }
            b"eXIf" => {
                report.png_stripped_exif_chunks = true;
                true
            }
            _ => false,
        };

        if strip {
            i = crc_end;
            continue;
        }

        // Copy chunk verbatim (preserves CRC and ordering).
        out.extend_from_slice(&input[chunk_start..crc_end]);

        if out.len() > cfg.max_output_bytes {
            return Err(ImageSanitizeError::OutputTooLarge.into());
        }

        if is_iend {
            saw_iend = true;
            break;
        }

        // Move to next chunk
        i = crc_end;

        // Optional trace without leaking content.
        let _ = ty_str; // keep for future structured logging if you want it
    }

    if !saw_iend {
        return Err(ImageSanitizeError::Malformed.into());
    }

    Ok((out, report))
}

/// ---------- Convenience: create a deterministic RNG for tests ----------

pub fn seeded_rng() -> StdRng {
    StdRng::seed_from_u64(0xC0FFEE)
}
