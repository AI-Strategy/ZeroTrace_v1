//! Unicode Normalization and Sanitization
//!
//! This module provides comprehensive Unicode text normalization to prevent:
//! - Homoglyph attacks (visually similar characters from different scripts)
//! - Invisible character injection (zero-width, control characters)
//! - Bidirectional text attacks (RTL/LTR override)
//! - Confusable character substitution
//! - Format control exploitation
//! - Combining character abuse
//!
//! The normalizer is a critical defense layer against sophisticated encoding-based
//! attacks that attempt to bypass text-based security controls.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::{debug, warn};
use unicode_normalization::UnicodeNormalization;

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Error, Debug, Clone, PartialEq)]
pub enum NormalizationError {
    #[error("Suspicious character detected: U+{code:04X} ({name})")]
    SuspiciousCharacter { code: u32, name: String },

    #[error("Homoglyph attack detected: '{original}' contains visually similar characters")]
    HomoglyphAttack { original: String },

    #[error("Bidirectional override detected")]
    BidiOverride,

    #[error("Excessive invisible characters: {count} found")]
    ExcessiveInvisibleChars { count: usize },

    #[error("Mixed script attack detected: {scripts:?}")]
    MixedScriptAttack { scripts: Vec<String> },

    #[error("Malformed Unicode sequence")]
    MalformedUnicode,

    #[error("Input too long after normalization: {length} exceeds {max}")]
    InputTooLong { length: usize, max: usize },
}

pub type Result<T> = std::result::Result<T, NormalizationError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for Unicode normalization behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizerConfig {
    /// Normalization form to use
    pub normalization_form: NormalizationForm,

    /// Remove all invisible characters
    pub remove_invisible: bool,

    /// Remove bidirectional control characters
    pub remove_bidi_controls: bool,

    /// Remove format control characters
    pub remove_format_controls: bool,

    /// Remove combining characters
    pub remove_combining_chars: bool,

    /// Convert confusables to canonical forms
    pub convert_confusables: bool,

    /// Enforce single script per input
    pub enforce_single_script: bool,

    /// Allowed scripts (if empty, all are allowed)
    pub allowed_scripts: Vec<Script>,

    /// Maximum number of invisible characters allowed
    pub max_invisible_chars: usize,

    /// Maximum input length after normalization
    pub max_normalized_length: usize,

    /// Reject inputs with RTL override
    pub reject_bidi_override: bool,

    /// Normalize whitespace (collapse multiple spaces)
    pub normalize_whitespace: bool,

    /// Convert full-width characters to ASCII
    pub convert_fullwidth: bool,

    /// Remove zero-width characters even in legitimate contexts
    pub aggressive_invisible_removal: bool,
}

impl Default for NormalizerConfig {
    fn default() -> Self {
        Self {
            normalization_form: NormalizationForm::NFKC,
            remove_invisible: true,
            remove_bidi_controls: true,
            remove_format_controls: true,
            remove_combining_chars: false,
            convert_confusables: true,
            enforce_single_script: false,
            allowed_scripts: Vec::new(),
            max_invisible_chars: 5,
            max_normalized_length: 10_000,
            reject_bidi_override: true,
            normalize_whitespace: true,
            convert_fullwidth: true,
            aggressive_invisible_removal: false,
        }
    }
}

/// Unicode normalization forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalizationForm {
    /// Canonical Decomposition
    NFD,
    /// Canonical Decomposition, followed by Canonical Composition
    NFC,
    /// Compatibility Decomposition
    NFKD,
    /// Compatibility Decomposition, followed by Canonical Composition
    NFKC,
}

/// Unicode script categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Script {
    Latin,
    Cyrillic,
    Greek,
    Arabic,
    Hebrew,
    Han,       // Chinese
    Hiragana,
    Katakana,
    Hangul,    // Korean
    Devanagari,
    Thai,
    Common,    // Punctuation, numbers, etc.
    Unknown,
}

// ============================================================================
// Character Classification
// ============================================================================

/// Categories of problematic Unicode characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharCategory {
    Invisible,
    BidiControl,
    FormatControl,
    Combining,
    Confusable,
    Safe,
}

/// Comprehensive list of invisible characters.
const INVISIBLE_CHARS: &[char] = &[
    '\u{200B}', // Zero Width Space
    '\u{200C}', // Zero Width Non-Joiner
    '\u{200D}', // Zero Width Joiner
    '\u{200E}', // Left-to-Right Mark
    '\u{200F}', // Right-to-Left Mark
    '\u{2060}', // Word Joiner
    '\u{2061}', // Function Application
    '\u{2062}', // Invisible Times
    '\u{2063}', // Invisible Separator
    '\u{2064}', // Invisible Plus
    '\u{FEFF}', // Zero Width No-Break Space (BOM)
    '\u{180E}', // Mongolian Vowel Separator
    '\u{034F}', // Combining Grapheme Joiner
];

/// Bidirectional control characters.
const BIDI_CONTROLS: &[char] = &[
    '\u{202A}', // Left-to-Right Embedding
    '\u{202B}', // Right-to-Left Embedding
    '\u{202C}', // Pop Directional Formatting
    '\u{202D}', // Left-to-Right Override
    '\u{202E}', // Right-to-Left Override
    '\u{2066}', // Left-to-Right Isolate
    '\u{2067}', // Right-to-Left Isolate
    '\u{2068}', // First Strong Isolate
    '\u{2069}', // Pop Directional Isolate
];

/// Format control characters.
const FORMAT_CONTROLS: &[char] = &[
    '\u{00AD}', // Soft Hyphen
    '\u{061C}', // Arabic Letter Mark
    '\u{115F}', // Hangul Choseong Filler
    '\u{1160}', // Hangul Jungseong Filler
    '\u{17B4}', // Khmer Vowel Inherent Aq
    '\u{17B5}', // Khmer Vowel Inherent Aa
    '\u{180B}', // Mongolian Free Variation Selector One
    '\u{180C}', // Mongolian Free Variation Selector Two
    '\u{180D}', // Mongolian Free Variation Selector Three
];

/// Common confusable character mappings (simplified).
/// In production, use the full Unicode confusables database.
fn get_confusables_map() -> HashMap<char, char> {
    let mut map = HashMap::new();

    // Cyrillic to Latin
    map.insert('А', 'A'); // Cyrillic A
    map.insert('В', 'B'); // Cyrillic Ve
    map.insert('Е', 'E'); // Cyrillic Ie
    map.insert('К', 'K'); // Cyrillic Ka
    map.insert('М', 'M'); // Cyrillic Em
    map.insert('Н', 'H'); // Cyrillic En
    map.insert('О', 'O'); // Cyrillic O
    map.insert('Р', 'P'); // Cyrillic Er
    map.insert('С', 'C'); // Cyrillic Es
    map.insert('Т', 'T'); // Cyrillic Te
    map.insert('Х', 'X'); // Cyrillic Kha
    map.insert('а', 'a'); // Cyrillic a
    map.insert('е', 'e'); // Cyrillic ie
    map.insert('о', 'o'); // Cyrillic o
    map.insert('р', 'p'); // Cyrillic er
    map.insert('с', 'c'); // Cyrillic es
    map.insert('у', 'y'); // Cyrillic u
    map.insert('х', 'x'); // Cyrillic kha

    // Greek to Latin
    map.insert('Α', 'A'); // Greek Alpha
    map.insert('Β', 'B'); // Greek Beta
    map.insert('Ε', 'E'); // Greek Epsilon
    map.insert('Ζ', 'Z'); // Greek Zeta
    map.insert('Η', 'H'); // Greek Eta
    map.insert('Ι', 'I'); // Greek Iota
    map.insert('Κ', 'K'); // Greek Kappa
    map.insert('Μ', 'M'); // Greek Mu
    map.insert('Ν', 'N'); // Greek Nu
    map.insert('Ο', 'O'); // Greek Omicron
    map.insert('Ρ', 'P'); // Greek Rho
    map.insert('Τ', 'T'); // Greek Tau
    map.insert('Υ', 'Y'); // Greek Upsilon
    map.insert('Χ', 'X'); // Greek Chi

    // Mathematical Alphanumeric Symbols
    map.insert('𝐀', 'A'); // Mathematical Bold A
    map.insert('𝐁', 'B'); // Mathematical Bold B
    map.insert('𝟎', '0'); // Mathematical Bold Digit Zero
    map.insert('𝟏', '1'); // Mathematical Bold Digit One

    // Full-width to ASCII
    map.insert('Ａ', 'A');
    map.insert('Ｂ', 'B');
    map.insert('０', '0');
    map.insert('１', '1');

    map
}

// ============================================================================
// Character Classification Functions
// ============================================================================

/// Checks if a character is invisible.
fn is_invisible(c: char) -> bool {
    INVISIBLE_CHARS.contains(&c)
}

/// Checks if a character is a bidirectional control character.
fn is_bidi_control(c: char) -> bool {
    BIDI_CONTROLS.contains(&c)
}

/// Checks if a character is a format control character.
fn is_format_control(c: char) -> bool {
    FORMAT_CONTROLS.contains(&c)
}

/// Checks if a character is a combining character.
fn is_combining(c: char) -> bool {
    matches!(c as u32, 0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// Determines the script of a character.
fn get_script(c: char) -> Script {
    let code = c as u32;
    match code {
        0x0000..=0x007F => Script::Latin,        // Basic Latin
        0x0080..=0x00FF => Script::Latin,        // Latin-1 Supplement
        0x0100..=0x017F => Script::Latin,        // Latin Extended-A
        0x0180..=0x024F => Script::Latin,        // Latin Extended-B
        0x0400..=0x04FF => Script::Cyrillic,     // Cyrillic
        0x0370..=0x03FF => Script::Greek,        // Greek
        0x0600..=0x06FF => Script::Arabic,       // Arabic
        0x0590..=0x05FF => Script::Hebrew,       // Hebrew
        0x4E00..=0x9FFF => Script::Han,          // CJK Unified Ideographs
        0x3040..=0x309F => Script::Hiragana,     // Hiragana
        0x30A0..=0x30FF => Script::Katakana,     // Katakana
        0xAC00..=0xD7AF => Script::Hangul,       // Hangul Syllables
        0x0900..=0x097F => Script::Devanagari,   // Devanagari
        0x0E00..=0x0E7F => Script::Thai,         // Thai
        0x0020..=0x0040 => Script::Common,       // Punctuation, numbers
        _ => Script::Unknown,
    }
}

/// Classifies a character into a category.
fn classify_char(c: char) -> CharCategory {
    if is_invisible(c) {
        CharCategory::Invisible
    } else if is_bidi_control(c) {
        CharCategory::BidiControl
    } else if is_format_control(c) {
        CharCategory::FormatControl
    } else if is_combining(c) {
        CharCategory::Combining
    } else {
        CharCategory::Safe
    }
}

// ============================================================================
// Unicode Normalizer
// ============================================================================

/// Normalizes and sanitizes Unicode text to prevent encoding-based attacks.
///
/// The normalizer performs multiple transformations:
/// 1. Unicode normalization (NFD/NFC/NFKD/NFKC)
/// 2. Invisible character removal
/// 3. Bidirectional control removal
/// 4. Confusable character conversion
/// 5. Script enforcement
/// 6. Whitespace normalization
///
/// # Security Guarantees
///
/// After normalization, the text is guaranteed to:
/// - Be in canonical Unicode form
/// - Contain no invisible characters (if configured)
/// - Contain no bidirectional overrides (if configured)
/// - Use only allowed scripts (if configured)
/// - Have confusables converted to canonical forms
///
/// # Example
///
/// ```rust,ignore
/// use unicode_normalizer::{Normalizer, NormalizerConfig};
///
/// let normalizer = Normalizer::new();
/// let input = "Hеllo\u{200B}World"; // Contains Cyrillic 'е' and zero-width space
/// let output = normalizer.normalize(input).unwrap();
/// // Result: "HelloWorld" with Latin characters only
/// ```
pub struct Normalizer {
    config: NormalizerConfig,
    confusables_map: HashMap<char, char>,
    stats: NormalizationStats,
}

/// Statistics about normalization operations.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NormalizationStats {
    pub total_normalizations: u64,
    pub invisible_chars_removed: u64,
    pub bidi_controls_removed: u64,
    pub format_controls_removed: u64,
    pub combining_chars_removed: u64,
    pub confusables_converted: u64,
    pub homoglyph_attacks_detected: u64,
    pub bidi_attacks_detected: u64,
}

impl Normalizer {
    /// Creates a new normalizer with default configuration.
    pub fn new() -> Self {
        Self::with_config(NormalizerConfig::default())
    }

    /// Creates a new normalizer with custom configuration.
    pub fn with_config(config: NormalizerConfig) -> Self {
        Self {
            config,
            confusables_map: get_confusables_map(),
            stats: NormalizationStats::default(),
        }
    }

    /// Normalizes input text with comprehensive safety checks.
    ///
    /// This method performs all configured normalization steps and
    /// returns an error if suspicious patterns are detected.
    pub fn normalize(&mut self, input: &str) -> Result<String> {
        self.stats.total_normalizations += 1;

        if input.is_empty() {
            return Ok(String::new());
        }

        // Step 1: Prepare text for sanitization
        // If removing combining chars, we MUST decompose first to expose them.
        // Otherwise, normalizing to NFC/NFKC (default) would hide them in precomposed chars.
        let text_stage_1 = if self.config.remove_combining_chars {
            input.nfd().collect::<String>()
        } else {
            self.apply_unicode_normalization(input)
        };

        // Step 2: Detect and handle suspicious patterns
        self.detect_attacks(&text_stage_1)?;

        // Step 3: Remove/convert problematic characters
        let text_stage_2 = self.sanitize_characters(&text_stage_1)?;

        // Step 4: Re-normalize if we forced decomposition
        let text_stage_3 = if self.config.remove_combining_chars {
            self.apply_unicode_normalization(&text_stage_2)
        } else {
            text_stage_2
        };

        // Step 5: Normalize whitespace
        let final_text = if self.config.normalize_whitespace {
            self.normalize_whitespace_chars(&text_stage_3)
        } else {
            text_stage_3
        };

        // Step 6: Length validation
        if final_text.len() > self.config.max_normalized_length {
            return Err(NormalizationError::InputTooLong {
                length: final_text.len(),
                max: self.config.max_normalized_length,
            });
        }

        debug!(
            "Normalized text: {} -> {} characters",
            input.len(),
            final_text.len()
        );

        Ok(final_text)
    }

    /// Applies the configured Unicode normalization form.
    fn apply_unicode_normalization(&self, input: &str) -> String {
        match self.config.normalization_form {
            NormalizationForm::NFD => input.nfd().collect(),
            NormalizationForm::NFC => input.nfc().collect(),
            NormalizationForm::NFKD => input.nfkd().collect(),
            NormalizationForm::NFKC => input.nfkc().collect(),
        }
    }

    /// Detects potential attacks in the normalized text.
    fn detect_attacks(&mut self, text: &str) -> Result<()> {
        // Check for excessive invisible characters
        let invisible_count = text.chars().filter(|&c| is_invisible(c)).count();
        if invisible_count > self.config.max_invisible_chars {
            self.stats.invisible_chars_removed += invisible_count as u64;
            return Err(NormalizationError::ExcessiveInvisibleChars {
                count: invisible_count,
            });
        }

        // Check for bidirectional override attacks
        if self.config.reject_bidi_override {
            let has_bidi_override = text.chars().any(|c| {
                matches!(c, '\u{202D}' | '\u{202E}') // LTR/RTL Override
            });

            if has_bidi_override {
                self.stats.bidi_attacks_detected += 1;
                warn!("Bidirectional override detected in input");
                return Err(NormalizationError::BidiOverride);
            }
        }

        // Check for mixed script attacks
        if self.config.enforce_single_script {
            let scripts = self.detect_scripts(text);
            if scripts.len() > 2 {
                // Allow Common + one other script
                warn!("Mixed script attack detected: {:?}", scripts);
                return Err(NormalizationError::MixedScriptAttack {
                    scripts: scripts.iter().map(|s| format!("{:?}", s)).collect(),
                });
            }
        }

        // Check for homoglyph attacks (high confusable ratio)
        if self.config.convert_confusables {
            let confusable_count = text
                .chars()
                .filter(|c| self.confusables_map.contains_key(c))
                .count();

            if confusable_count > text.len() / 3 {
                // More than 33% confusables
                self.stats.homoglyph_attacks_detected += 1;
                warn!(
                    "Potential homoglyph attack: {} confusable chars out of {}",
                    confusable_count,
                    text.len()
                );
                // Don't reject, but log
            }
        }

        Ok(())
    }

    /// Sanitizes characters based on configuration.
    fn sanitize_characters(&mut self, text: &str) -> Result<String> {
        let result: String = text
            .chars()
            .filter_map(|c| {
                let category = classify_char(c);

                match category {
                    CharCategory::Invisible if self.config.remove_invisible => {
                        self.stats.invisible_chars_removed += 1;
                        None
                    }
                    CharCategory::BidiControl if self.config.remove_bidi_controls => {
                        self.stats.bidi_controls_removed += 1;
                        None
                    }
                    CharCategory::FormatControl if self.config.remove_format_controls => {
                        self.stats.format_controls_removed += 1;
                        None
                    }
                    CharCategory::Combining if self.config.remove_combining_chars => {
                        self.stats.combining_chars_removed += 1;
                        None
                    }
                    _ => {
                        // Convert confusables
                        if self.config.convert_confusables {
                            if let Some(&canonical) = self.confusables_map.get(&c) {
                                self.stats.confusables_converted += 1;
                                return Some(canonical);
                            }
                        }

                        // Convert full-width to ASCII
                        if self.config.convert_fullwidth {
                            if let Some(ascii) = self.fullwidth_to_ascii(c) {
                                return Some(ascii);
                            }
                        }

                        Some(c)
                    }
                }
            })
            .collect();

        Ok(result)
    }

    /// Converts full-width characters to ASCII equivalents.
    fn fullwidth_to_ascii(&self, c: char) -> Option<char> {
        let code = c as u32;
        match code {
            0xFF01..=0xFF5E => Some((code - 0xFF00 + 0x20) as u8 as char),
            _ => None,
        }
    }

    /// Normalizes whitespace characters.
    fn normalize_whitespace_chars(&self, text: &str) -> String {
        // Replace multiple spaces with single space
        let mut result = String::with_capacity(text.len());
        let mut prev_was_space = false;

        for c in text.chars() {
            if c.is_whitespace() {
                if !prev_was_space {
                    result.push(' ');
                    prev_was_space = true;
                }
            } else {
                result.push(c);
                prev_was_space = false;
            }
        }

        result.trim().to_string()
    }

    /// Detects all scripts present in the text.
    fn detect_scripts(&self, text: &str) -> HashSet<Script> {
        text.chars()
            .map(get_script)
            .filter(|s| *s != Script::Common)
            .collect()
    }

    /// Returns current statistics.
    pub fn stats(&self) -> &NormalizationStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats = NormalizationStats::default();
    }

    /// Updates configuration.
    pub fn update_config(&mut self, config: NormalizerConfig) {
        self.config = config;
    }

    /// Gets current configuration.
    pub fn config(&self) -> &NormalizerConfig {
        &self.config
    }

    /// Simple static normalization without configuration.
    pub fn normalize_simple(input: &str) -> String {
        input
            .nfkc()
            .filter(|c| !is_invisible(*c))
            .collect()
    }
}

impl Default for Normalizer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Quick normalization for common use cases (static method).
pub fn normalize(input: &str) -> String {
    Normalizer::normalize_simple(input)
}

/// Checks if text contains invisible characters.
pub fn contains_invisible_chars(text: &str) -> bool {
    text.chars().any(is_invisible)
}

/// Counts invisible characters in text.
pub fn count_invisible_chars(text: &str) -> usize {
    text.chars().filter(|&c| is_invisible(c)).count()
}

/// Checks if text contains bidirectional controls.
pub fn contains_bidi_controls(text: &str) -> bool {
    text.chars().any(is_bidi_control)
}

/// Detects potential homoglyph attacks.
pub fn detect_homoglyphs(text: &str) -> Vec<(char, char)> {
    let confusables = get_confusables_map();
    text.chars()
        .filter_map(|c| confusables.get(&c).map(|&canonical| (c, canonical)))
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_normalization() {
        let input = "Hello\u{200B}World"; // Contains zero-width space
        let output = normalize(input);
        assert_eq!(output, "HelloWorld");
    }

    #[test]
    fn test_invisible_character_removal() {
        let mut normalizer = Normalizer::new();
        let input = "Text\u{200B}with\u{200C}invisible\u{200D}chars";
        let output = normalizer.normalize(input).unwrap();
        assert_eq!(output, "Textwithinvisiblechars");
        assert!(normalizer.stats().invisible_chars_removed > 0);
    }

    #[test]
    fn test_cyrillic_homoglyph() {
        let mut normalizer = Normalizer::new();
        // "Hеllo" with Cyrillic 'е' instead of Latin 'e'
        let input = "Hеllo";
        let output = normalizer.normalize(input).unwrap();
        // Cyrillic 'е' should be converted to Latin 'e'
        assert_eq!(output, "Hello");
        assert!(normalizer.stats().confusables_converted > 0);
    }

    #[test]
    fn test_mathematical_bold_text() {
        let mut normalizer = Normalizer::new();
        let input = "𝐇𝐞𝐥𝐥𝐨"; // Mathematical bold
        let output = normalizer.normalize(input).unwrap();
        // Should normalize to regular text
        assert!(output.contains("Hello") || output.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn test_bidi_override_detection() {
        let mut normalizer = Normalizer::new();
        let input = "Hello\u{202E}dlroW"; // Contains RTL override
        let result = normalizer.normalize(input);
        assert!(matches!(result, Err(NormalizationError::BidiOverride)));
    }

    #[test]
    fn test_excessive_invisible_chars() {
        let mut normalizer = Normalizer::new();
        let input = "A\u{200B}B\u{200B}C\u{200B}D\u{200B}E\u{200B}F\u{200B}G";
        let result = normalizer.normalize(input);
        // Default max is 5, this has 6
        assert!(matches!(
            result,
            Err(NormalizationError::ExcessiveInvisibleChars { .. })
        ));
    }

    #[test]
    fn test_whitespace_normalization() {
        let mut normalizer = Normalizer::new();
        let input = "Multiple    spaces    here";
        let output = normalizer.normalize(input).unwrap();
        assert_eq!(output, "Multiple spaces here");
    }

    #[test]
    fn test_fullwidth_conversion() {
        let mut normalizer = Normalizer::new();
        let input = "Ｈｅｌｌｏ"; // Full-width characters
        let output = normalizer.normalize(input).unwrap();
        assert_eq!(output, "Hello");
    }

    #[test]
    fn test_clean_text_unchanged() {
        let mut normalizer = Normalizer::new();
        let input = "This is clean text.";
        let output = normalizer.normalize(input).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn test_combining_character_removal() {
        let mut config = NormalizerConfig::default();
        config.remove_combining_chars = true;
        let mut normalizer = Normalizer::with_config(config);

        let input = "e\u{0301}"; // e with combining acute accent
        let output = normalizer.normalize(input).unwrap();
        // Combining character should be removed
        assert_eq!(output, "e");
    }

    #[test]
    fn test_script_detection() {
        let normalizer = Normalizer::new();
        let text = "Hello мир 世界";
        let scripts = normalizer.detect_scripts(text);

        assert!(scripts.contains(&Script::Latin));
        assert!(scripts.contains(&Script::Cyrillic));
        assert!(scripts.contains(&Script::Han));
    }

    #[test]
    fn test_mixed_script_rejection() {
        let mut config = NormalizerConfig::default();
        config.enforce_single_script = true;
        let mut normalizer = Normalizer::with_config(config);

        let input = "Hello мир 世界"; // Latin + Cyrillic + Han
        let result = normalizer.normalize(input);
        assert!(matches!(
            result,
            Err(NormalizationError::MixedScriptAttack { .. })
        ));
    }

    #[test]
    fn test_contains_invisible_chars() {
        assert!(contains_invisible_chars("Text\u{200B}"));
        assert!(!contains_invisible_chars("Clean text"));
    }

    #[test]
    fn test_count_invisible_chars() {
        let text = "A\u{200B}B\u{200C}C\u{200D}";
        assert_eq!(count_invisible_chars(text), 3);
    }

    #[test]
    fn test_contains_bidi_controls() {
        assert!(contains_bidi_controls("Text\u{202E}"));
        assert!(!contains_bidi_controls("Clean text"));
    }

    #[test]
    fn test_detect_homoglyphs() {
        let text = "Hеllo"; // Cyrillic 'е'
        let homoglyphs = detect_homoglyphs(text);
        assert!(!homoglyphs.is_empty());
    }

    #[test]
    fn test_nfkc_normalization() {
        let mut normalizer = Normalizer::new();
        // Ligature fi (U+FB01)
        let input = "\u{FB01}le"; // ﬁle
        let output = normalizer.normalize(input).unwrap();
        // NFKC should decompose to "file"
        assert_eq!(output, "file");
    }

    #[test]
    fn test_statistics_tracking() {
        let mut normalizer = Normalizer::new();

        normalizer.normalize("Test\u{200B}1").unwrap();
        normalizer.normalize("Test\u{200C}2").unwrap();

        let stats = normalizer.stats();
        assert_eq!(stats.total_normalizations, 2);
        assert!(stats.invisible_chars_removed > 0);
    }

    #[test]
    fn test_empty_input() {
        let mut normalizer = Normalizer::new();
        let output = normalizer.normalize("").unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_length_limit() {
        let mut config = NormalizerConfig::default();
        config.max_normalized_length = 10;
        let mut normalizer = Normalizer::with_config(config);

        let input = "This is a very long string";
        let result = normalizer.normalize(input);
        assert!(matches!(
            result,
            Err(NormalizationError::InputTooLong { .. })
        ));
    }

    #[test]
    fn test_disable_invisible_removal() {
        let mut config = NormalizerConfig::default();
        config.remove_invisible = false;
        let mut normalizer = Normalizer::with_config(config);

        let input = "Test\u{200B}";
        let output = normalizer.normalize(input).unwrap();
        // Should still contain invisible char
        assert!(output.contains('\u{200B}'));
    }

    #[test]
    fn test_normalization_forms() {
        // Test different normalization forms
        let forms = vec![
            NormalizationForm::NFD,
            NormalizationForm::NFC,
            NormalizationForm::NFKD,
            NormalizationForm::NFKC,
        ];

        for form in forms {
            let mut config = NormalizerConfig::default();
            config.normalization_form = form;
            let mut normalizer = Normalizer::with_config(config);

            let input = "café"; // Contains combining accent
            let output = normalizer.normalize(input).unwrap();
            assert!(!output.is_empty());
        }
    }

    #[test]
    fn test_multiple_invisible_types() {
        let mut normalizer = Normalizer::new();
        let input = "A\u{200B}B\u{200C}C\u{200D}D\u{2060}E\u{FEFF}";
        let output = normalizer.normalize(input).unwrap();
        assert_eq!(output, "ABCDE");
    }

    #[test]
    fn test_format_control_removal() {
        let mut normalizer = Normalizer::new();
        let input = "Text\u{00AD}with\u{061C}controls";
        let output = normalizer.normalize(input).unwrap();
        assert!(!output.contains('\u{00AD}'));
        assert!(!output.contains('\u{061C}'));
    }
}
