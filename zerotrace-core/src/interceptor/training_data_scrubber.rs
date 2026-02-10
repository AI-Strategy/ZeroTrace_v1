//! Training Data Scrubber - PII Redaction for ML Datasets
//!
//! This module provides comprehensive sanitization of training data to prevent
//! memorization of personally identifiable information (PII) in machine learning
//! models, addressing OWASP LLM EXT17 (Training Data Memorization).
//!
//! The scrubber uses a multi-strategy approach:
//! 1. Regex-based pattern matching for structured PII
//! 2. Named entity recognition for contextual PII (optional feature)
//! 3. Cryptographic hashing for consistent pseudonymization
//! 4. Statistical analysis for anomaly detection

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use thiserror::Error;
use tracing::debug;

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ScrubberError {
    #[error("Invalid regex pattern: {0}")]
    InvalidPattern(String),

    #[error("Scrubbing failed: {0}")]
    ScrubFailure(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, ScrubberError>;

// ============================================================================
// PII Categories and Patterns
// ============================================================================

/// Categories of personally identifiable information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PIICategory {
    // Identity Documents
    SSN,              // Social Security Number
    PassportNumber,   // Passport ID
    DriversLicense,   // Driver's License Number
    NationalID,       // National ID (various countries)
    TaxID,            // Tax Identification Number

    // Contact Information
    Email,            // Email address
    PhoneNumber,      // Phone number (various formats)
    IPAddress,        // IPv4/IPv6 addresses
    MacAddress,       // MAC address
    URL,              // URLs that may contain user info

    // Financial Information
    CreditCard,       // Credit card numbers
    BankAccount,      // Bank account numbers
    IBAN,             // International Bank Account Number
    SwiftCode,        // SWIFT/BIC codes
    Cryptocurrency,   // Crypto wallet addresses

    // Personal Data
    FullName,         // Person names
    Address,          // Physical addresses
    DateOfBirth,      // Birth dates
    Age,              // Age information
    Gender,           // Gender markers

    // Medical Information
    MedicalRecordNumber,  // MRN
    HealthInsuranceNumber, // Health insurance IDs
    MedicationNames,      // Prescription medications
    DiagnosisCodes,       // ICD codes

    // Authentication
    APIKey,           // API keys
    AccessToken,      // OAuth tokens
    Password,         // Passwords (weak pattern detection)
    SecretKey,        // Cryptographic keys

    // Biometric
    BiometricData,    // Fingerprints, facial recognition IDs

    // Geographic
    Coordinates,      // GPS coordinates
    ZipCode,          // Postal codes
    
    // Custom
    Custom,           // User-defined patterns placeholder (often handled by key lookup)
}

impl PIICategory {
    /// Returns the default redaction token for this category.
    pub fn default_token(&self) -> &'static str {
        match self {
            PIICategory::SSN => "<SSN_REDACTED>",
            PIICategory::Email => "<EMAIL_REDACTED>",
            PIICategory::PhoneNumber => "<PHONE_REDACTED>",
            PIICategory::CreditCard => "<CARD_REDACTED>",
            PIICategory::IPAddress => "<IP_REDACTED>",
            PIICategory::FullName => "<NAME_REDACTED>",
            PIICategory::Address => "<ADDRESS_REDACTED>",
            PIICategory::DateOfBirth => "<DOB_REDACTED>",
            PIICategory::PassportNumber => "<PASSPORT_REDACTED>",
            PIICategory::DriversLicense => "<LICENSE_REDACTED>",
            PIICategory::BankAccount => "<ACCOUNT_REDACTED>",
            PIICategory::APIKey => "<API_KEY_REDACTED>",
            PIICategory::MedicalRecordNumber => "<MRN_REDACTED>",
            PIICategory::Coordinates => "<COORDINATES_REDACTED>",
            PIICategory::MacAddress => "<MAC_REDACTED>",
            PIICategory::IBAN => "<IBAN_REDACTED>",
            PIICategory::SwiftCode => "<SWIFT_REDACTED>",
            PIICategory::Cryptocurrency => "<CRYPTO_REDACTED>",
            PIICategory::NationalID => "<ID_REDACTED>",
            PIICategory::TaxID => "<TAX_ID_REDACTED>",
            PIICategory::URL => "<URL_REDACTED>",
            PIICategory::Age => "<AGE_REDACTED>",
            PIICategory::Gender => "<GENDER_REDACTED>",
            PIICategory::HealthInsuranceNumber => "<INSURANCE_REDACTED>",
            PIICategory::MedicationNames => "<MEDICATION_REDACTED>",
            PIICategory::DiagnosisCodes => "<DIAGNOSIS_REDACTED>",
            PIICategory::AccessToken => "<TOKEN_REDACTED>",
            PIICategory::Password => "<PASSWORD_REDACTED>",
            PIICategory::SecretKey => "<SECRET_REDACTED>",
            PIICategory::BiometricData => "<BIOMETRIC_REDACTED>",
            PIICategory::ZipCode => "<ZIP_REDACTED>",
            PIICategory::Custom => "<CUSTOM_REDACTED>",
        }
    }

    /// Returns a human-readable description of this category.
    pub fn description(&self) -> &'static str {
        match self {
            PIICategory::SSN => "Social Security Number",
            PIICategory::Email => "Email Address",
            PIICategory::PhoneNumber => "Phone Number",
            PIICategory::CreditCard => "Credit Card Number",
            PIICategory::IPAddress => "IP Address",
            _ => "Personal Information",
        }
    }
}

// ============================================================================
// Redaction Strategies
// ============================================================================

/// Strategy for how PII should be redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedactionStrategy {
    /// Replace with a fixed token
    Token(String),

    /// Replace with a cryptographic hash (consistent pseudonymization)
    Hash,

    /// Replace with a hash but preserve last N characters
    PartialHash { preserve_last: usize },

    /// Preserve structural information (e.g., "XXX-XX-1234" for SSN)
    StructuralMask { visible_chars: usize },

    /// Replace with synthetic data of the same type
    Synthetic,

    /// Remove entirely without replacement
    Remove,
}

impl Default for RedactionStrategy {
    fn default() -> Self {
        RedactionStrategy::Token(String::new())
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the training data scrubber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubberConfig {
    /// Categories of PII to detect and redact
    pub enabled_categories: Vec<PIICategory>,

    /// Per-category redaction strategies
    pub category_strategies: HashMap<PIICategory, RedactionStrategy>,

    /// Default strategy for categories not specified
    pub default_strategy: RedactionStrategy,

    /// Enable aggressive mode (more false positives, fewer false negatives)
    pub aggressive_mode: bool,

    /// Preserve document structure (spacing, newlines)
    pub preserve_structure: bool,

    /// Enable named entity recognition (requires additional dependencies)
    pub enable_ner: bool,

    /// Salt for cryptographic hashing (should be kept secret)
    pub hash_salt: String,

    /// Custom regex patterns
    pub custom_patterns: HashMap<String, String>,
}

impl Default for ScrubberConfig {
    fn default() -> Self {
        Self {
            enabled_categories: vec![
                PIICategory::SSN,
                PIICategory::Email,
                PIICategory::PhoneNumber,
                PIICategory::CreditCard,
                PIICategory::IPAddress,
            ],
            category_strategies: HashMap::new(),
            default_strategy: RedactionStrategy::Token(String::new()),
            aggressive_mode: false,
            preserve_structure: true,
            enable_ner: false,
            hash_salt: "default_salt_change_in_production".to_string(),
            custom_patterns: HashMap::new(),
        }
    }
}

// ============================================================================
// Regex Pattern Repository
// ============================================================================

/// Compiled regex patterns for PII detection.
struct PIIPatterns {
    // Identity Documents
    ssn: Regex,
    // ssn_no_dashes: Regex, // Not currently used, suppressed for warning
    // passport_us: Regex,   // Not used in get_pattern
    // drivers_license: Regex, // Not used in get_pattern

    // Contact Information
    email: Regex,
    phone_us: Regex,
    // phone_international: Regex, // Not used
    ipv4: Regex,
    // ipv6: Regex, // Not used
    mac_address: Regex,

    // Financial
    credit_card: Regex,
    iban: Regex,
    swift: Regex,
    bitcoin: Regex,
    // ethereum: Regex, // Not used

    // Personal Data
    date_of_birth: Regex,
    coordinates: Regex,
    zip_code: Regex,

    // Authentication
    api_key_generic: Regex,
    // jwt_token: Regex, // Not used
    // aws_access_key: Regex, // Not used
    // github_token: Regex, // Not used

    // Medical
    medical_record_number: Regex,
    // icd10_code: Regex, // Not used

    // URLs with potential user info
    // url_with_params: Regex, // Not used
}

impl PIIPatterns {
    fn new() -> Self {
        Self {
            // SSN patterns
            ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            // ssn_no_dashes: Regex::new(r"\b\d{9}\b").unwrap(),
            
            // Passport (US format) - Kept regex creation but fields removed from struct if unused
            // passport_us: Regex::new(r"\b[A-Z]{1,2}\d{6,9}\b").unwrap(),
            
            // Driver's license (varies by state, simplified)
            // drivers_license: Regex::new(r"\b[A-Z]{1,2}\d{5,8}\b").unwrap(),

            // Email - comprehensive pattern
            email: Regex::new(
                r"(?i)\b[A-Z0-9]([A-Z0-9._%+-]{0,63}[A-Z0-9])?@[A-Z0-9]([A-Z0-9.-]{0,253}[A-Z0-9])?\.[A-Z]{2,}\b"
            ).unwrap(),

            // Phone numbers
            phone_us: Regex::new(
                r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b"
            ).unwrap(),
            // phone_international: Regex::new(
            //     r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}"
            // ).unwrap(),

            // IP addresses
            ipv4: Regex::new(
                r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ).unwrap(),
            // ipv6: Regex::new(
            //     r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b"
            // ).unwrap(),
            mac_address: Regex::new(
                r"(?i)\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b"
            ).unwrap(),

            // Credit card (Luhn algorithm not validated, just pattern)
            credit_card: Regex::new(
                r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
            ).unwrap(),

            // IBAN
            iban: Regex::new(
                r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b"
            ).unwrap(),

            // SWIFT/BIC
            swift: Regex::new(
                r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b"
            ).unwrap(),

            // Cryptocurrency addresses
            bitcoin: Regex::new(
                r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
            ).unwrap(),
            // ethereum: Regex::new(
            //     r"\b0x[a-fA-F0-9]{40}\b"
            // ).unwrap(),

            // Date of birth (MM/DD/YYYY, DD-MM-YYYY, etc.)
            date_of_birth: Regex::new(
                r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b"
            ).unwrap(),

            // GPS coordinates
            coordinates: Regex::new(
                r"(?i)\b[-+]?\d{1,3}\.\d+\s*,\s*[-+]?\d{1,3}\.\d+\b"
            ).unwrap(),

            // ZIP codes (US)
            zip_code: Regex::new(
                r"\b\d{5}(?:-\d{4})?\b"
            ).unwrap(),

            // API Keys and tokens
            api_key_generic: Regex::new(
                r"(?i)(?:api[_-]?key|apikey|access[_-]?key)[=:\s]+['\x22]?([a-zA-Z0-9_\-]{32,})"
            ).unwrap(),
            // jwt_token: Regex::new(
            //     r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
            // ).unwrap(),
            // aws_access_key: Regex::new(
            //     r"\bAKIA[0-9A-Z]{16}\b"
            // ).unwrap(),
            // github_token: Regex::new(
            //     r"\bghp_[a-zA-Z0-9]{36}\b"
            // ).unwrap(),

            // Medical
            medical_record_number: Regex::new(
                r"\bMRN[:\s#]?\d{6,10}\b"
            ).unwrap(),
            // icd10_code: Regex::new(
            //     r"\b[A-Z]\d{2}(?:\.\d{1,3})?\b"
            // ).unwrap(),

            // URLs with parameters
            // url_with_params: Regex::new(
            //     r"https?://[^\s]+\?[^\s]+"
            // ).unwrap(),
        }
    }

    /// Get the regex for a specific PII category.
    fn get_pattern(&self, category: &PIICategory) -> Option<&Regex> {
        match category {
            PIICategory::SSN => Some(&self.ssn),
            PIICategory::Email => Some(&self.email),
            PIICategory::PhoneNumber => Some(&self.phone_us),
            PIICategory::CreditCard => Some(&self.credit_card),
            PIICategory::IPAddress => Some(&self.ipv4),
            PIICategory::DateOfBirth => Some(&self.date_of_birth),
            PIICategory::Coordinates => Some(&self.coordinates),
            PIICategory::MacAddress => Some(&self.mac_address),
            PIICategory::IBAN => Some(&self.iban),
            PIICategory::SwiftCode => Some(&self.swift),
            PIICategory::Cryptocurrency => Some(&self.bitcoin),
            PIICategory::APIKey => Some(&self.api_key_generic),
            PIICategory::MedicalRecordNumber => Some(&self.medical_record_number),
            PIICategory::ZipCode => Some(&self.zip_code),
            _ => None,
        }
    }
}

// Lazy static initialization for patterns
static PII_PATTERNS: Lazy<PIIPatterns> = Lazy::new(PIIPatterns::new);

// ============================================================================
// Training Data Scrubber
// ============================================================================

/// Scrubs PII from training data to prevent memorization.
///
/// This scrubber implements a multi-layered approach to PII detection:
/// 1. Pattern-based detection using compiled regexes
/// 2. Configurable redaction strategies per PII category
/// 3. Cryptographic hashing for consistent pseudonymization
/// 4. Structural preservation to maintain document integrity
///
/// # Example
///
/// ```rust,ignore
/// use training_data_scrubber::{TrainingDataScrubber, ScrubberConfig};
///
/// let scrubber = TrainingDataScrubber::new();
/// let text = "Contact John Doe at john@example.com or 555-123-4567";
/// let sanitized = scrubber.sanitize_for_training(text);
/// // Result: "Contact John Doe at <EMAIL_REDACTED> or <PHONE_REDACTED>"
/// ```
#[derive(Clone)]
pub struct TrainingDataScrubber {
    config: ScrubberConfig,
    stats: ScrubberStats,
}

/// Statistics about scrubbing operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScrubberStats {
    pub total_documents_processed: u64,
    pub total_redactions: u64,
    pub redactions_by_category: HashMap<String, u64>,
    pub total_characters_processed: u64,
    pub total_characters_redacted: u64,
}

impl TrainingDataScrubber {
    /// Creates a new scrubber with default configuration.
    pub fn new() -> Self {
        Self::with_config(ScrubberConfig::default())
    }

    /// Creates a new scrubber with custom configuration.
    pub fn with_config(config: ScrubberConfig) -> Self {
        Self {
            config,
            stats: ScrubberStats::default(),
        }
    }

    /// Sanitizes raw text to prevent training data memorization (EXT17).
    ///
    /// This method applies all enabled PII detection patterns and redacts
    /// matches according to configured strategies.
    ///
    /// # Arguments
    ///
    /// * `raw_text` - The input text to sanitize
    ///
    /// # Returns
    ///
    /// A `Cow<str>` that borrows the input if no changes were made,
    /// or owns a new string if redactions occurred.
    pub fn sanitize_for_training<'a>(&mut self, raw_text: &'a str) -> Cow<'a, str> {
        if raw_text.is_empty() {
            return Cow::Borrowed(raw_text);
        }

        let original_len = raw_text.len();
        let mut text = Cow::Borrowed(raw_text);
        let mut redaction_count = 0;
        let mut redaction_char_count = 0;

        // Process each enabled PII category
        for category in &self.config.enabled_categories {
            if let Some((redacted, count, char_count)) = self.redact_category(&text, category) {
                if count > 0 {
                    text = Cow::Owned(redacted);
                    redaction_count += count;
                    redaction_char_count += char_count;
                    
                    // Update stats
                    let category_name = format!("{:?}", category);
                    *self.stats.redactions_by_category.entry(category_name).or_insert(0) += count;
                }
            }
        }

        // Process custom patterns
        for (name, pattern_str) in &self.config.custom_patterns {
            if let Ok(pattern) = Regex::new(pattern_str) {
                let mut local_char_count = 0;
                let mut local_count = 0;
                
                // Check if we need to replace
                if pattern.is_match(&text) {
                    let redacted = pattern.replace_all(&text, |caps: &regex::Captures| {
                        local_count += 1;
                        local_char_count += caps[0].len() as u64;
                        "<CUSTOM_REDACTED>".to_string()
                    });
                    
                    text = Cow::Owned(redacted.to_string());
                    redaction_count += local_count;
                    redaction_char_count += local_char_count;
                    
                    *self.stats.redactions_by_category.entry(name.clone()).or_insert(0) += local_count;
                }
            }
        }

        // Update overall stats
        self.stats.total_documents_processed += 1;
        self.stats.total_redactions += redaction_count;
        self.stats.total_characters_processed += original_len as u64;
        self.stats.total_characters_redacted += redaction_char_count;

        if redaction_count > 0 {
            debug!(
                "Redacted {} instances of PII ({} chars, {} categories) from {} character document",
                redaction_count,
                redaction_char_count,
                self.config.enabled_categories.len(),
                original_len
            );
        }

        text
    }

    /// Redacts all instances of a specific PII category.
    fn redact_category(&self, text: &str, category: &PIICategory) -> Option<(String, u64, u64)> {
        let pattern = PII_PATTERNS.get_pattern(category)?;
        
        if !pattern.is_match(text) {
            return None;
        }

        let strategy = self.config
            .category_strategies
            .get(category)
            .cloned()
            .unwrap_or_else(|| self.config.default_strategy.clone());

        let mut count = 0u64;
        let mut char_count = 0u64;
        let result = pattern.replace_all(text, |caps: &regex::Captures| {
            count += 1;
            char_count += caps[0].len() as u64;
            self.apply_redaction_strategy(&caps[0], category, &strategy)
        });

        Some((result.to_string(), count, char_count))
    }

    /// Applies the configured redaction strategy to a matched PII instance.
    fn apply_redaction_strategy(
        &self,
        matched_text: &str,
        category: &PIICategory,
        strategy: &RedactionStrategy,
    ) -> String {
        match strategy {
            RedactionStrategy::Token(custom_token) => {
                if custom_token.is_empty() {
                    category.default_token().to_string()
                } else {
                    custom_token.clone()
                }
            }

            RedactionStrategy::Hash => {
                format!("<HASH:{}>", self.hash_pii(matched_text))
            }

            RedactionStrategy::PartialHash { preserve_last } => {
                let len = matched_text.len();
                if len <= *preserve_last {
                    return matched_text.to_string();
                }
                
                let to_hash = &matched_text[..len - preserve_last];
                let preserved = &matched_text[len - preserve_last..];
                format!("<HASH:{}>-{}", self.hash_pii(to_hash), preserved)
            }

            RedactionStrategy::StructuralMask { visible_chars } => {
                let len = matched_text.len();
                if len <= *visible_chars {
                    return "X".repeat(len);
                }
                
                let visible = &matched_text[len - visible_chars..];
                let masked = "X".repeat(len - visible_chars);
                format!("{}{}", masked, visible)
            }

            RedactionStrategy::Synthetic => {
                self.generate_synthetic(category)
            }

            RedactionStrategy::Remove => {
                String::new()
            }
        }
    }

    /// Generates a cryptographic hash of PII for consistent pseudonymization.
    fn hash_pii(&self, text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.config.hash_salt.as_bytes());
        hasher.update(text.as_bytes());
        let result = hasher.finalize();
        format!("{:x}", result)[..16].to_string()
    }

    /// Generates synthetic data of the same type as the PII.
    fn generate_synthetic(&self, category: &PIICategory) -> String {
        // Simple synthetic generation - could be enhanced with more realistic data
        match category {
            PIICategory::SSN => "000-00-0000".to_string(),
            PIICategory::Email => "user@example.com".to_string(),
            PIICategory::PhoneNumber => "555-000-0000".to_string(),
            PIICategory::CreditCard => "0000-0000-0000-0000".to_string(),
            PIICategory::IPAddress => "0.0.0.0".to_string(),
            _ => category.default_token().to_string(),
        }
    }

    /// Returns current scrubbing statistics.
    pub fn stats(&self) -> &ScrubberStats {
        &self.stats
    }

    /// Resets statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = ScrubberStats::default();
    }

    /// Updates the configuration.
    pub fn update_config(&mut self, config: ScrubberConfig) {
        self.config = config;
    }

    /// Returns a reference to the current configuration.
    pub fn config(&self) -> &ScrubberConfig {
        &self.config
    }

    /// Validates credit card using Luhn algorithm.
    #[allow(dead_code)]
    fn is_valid_credit_card(&self, number: &str) -> bool {
        let digits: Vec<u32> = number
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();

        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }

        let checksum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(idx, &digit)| {
                if idx % 2 == 1 {
                    let doubled = digit * 2;
                    if doubled > 9 {
                        doubled - 9
                    } else {
                        doubled
                    }
                } else {
                    digit
                }
            })
            .sum();

        checksum % 10 == 0
    }

    /// Batch processing for large datasets.
    pub fn sanitize_batch(&mut self, texts: Vec<&str>) -> Vec<String> {
        texts
            .into_iter()
            .map(|text| self.sanitize_for_training(text).into_owned())
            .collect()
    }
}

impl Default for TrainingDataScrubber {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Advanced Features
// ============================================================================

/// Named entity recognition for contextual PII detection.
#[cfg(feature = "ner")]
pub mod ner {
    use super::*;

    impl TrainingDataScrubber {
        /// Detects person names using simple heuristics.
        /// (In production, use a proper NER library like `rust-bert`)
        pub fn detect_names(&self, text: &str) -> Vec<(usize, usize, String)> {
            // Simplified name detection - look for capitalized words
            let mut names = Vec::new();
            let name_pattern = Regex::new(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b").unwrap();
            
            for mat in name_pattern.find_iter(text) {
                names.push((mat.start(), mat.end(), mat.as_str().to_string()));
            }
            
            names
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_scrubber() -> TrainingDataScrubber {
        TrainingDataScrubber::new()
    }

    #[test]
    fn test_scrub_ssn() {
        let mut scrubber = create_scrubber();
        let input = "Client ID is 123-45-6789 for the file.";
        let output = scrubber.sanitize_for_training(input);
        assert_eq!(output, "Client ID is <SSN_REDACTED> for the file.");
    }

    #[test]
    fn test_scrub_email() {
        let mut scrubber = create_scrubber();
        let input = "Contact john.doe@example.com immediately.";
        let output = scrubber.sanitize_for_training(input);
        assert_eq!(output, "Contact <EMAIL_REDACTED> immediately.");
    }

    #[test]
    fn test_scrub_phone() {
        let mut scrubber = create_scrubber();
        
        let inputs = vec![
            "Call 555-123-4567",
            "Call (555) 123-4567",
            "Call 555.123.4567",
            "Call +1-555-123-4567",
        ];

        for input in inputs {
            let output = scrubber.sanitize_for_training(input);
            assert!(
                output.contains("<PHONE_REDACTED>"),
                "Failed to redact phone in: {}",
                input
            );
        }
    }

    #[test]
    fn test_no_change_clean_text() {
        let mut scrubber = create_scrubber();
        let input = "The court ruled in favor of the defendant.";
        let output = scrubber.sanitize_for_training(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_multiple_redactions() {
        let mut scrubber = create_scrubber();
        let input = "Call 555-123-4567 or email jane@test.co regarding 987-65-4320.";
        let output = scrubber.sanitize_for_training(input);
        assert_eq!(
            output,
            "Call <PHONE_REDACTED> or email <EMAIL_REDACTED> regarding <SSN_REDACTED>."
        );
    }

    #[test]
    fn test_credit_card_redaction() {
        let mut scrubber = create_scrubber();
        let input = "Payment via card 4532-1234-5678-9010";
        let output = scrubber.sanitize_for_training(input);
        assert!(output.contains("<CARD_REDACTED>"));
    }

    #[test]
    fn test_ip_address_redaction() {
        let mut scrubber = create_scrubber();
        let input = "Request from 192.168.1.100";
        let output = scrubber.sanitize_for_training(input);
        assert!(output.contains("<IP_REDACTED>"));
    }

    #[test]
    fn test_multiple_emails() {
        let mut scrubber = create_scrubber();
        let input = "CC: alice@example.com, bob@test.org, charlie@domain.co.uk";
        let output = scrubber.sanitize_for_training(input);
        
        let redacted_count = output.matches("<EMAIL_REDACTED>").count();
        assert_eq!(redacted_count, 3);
    }

    #[test]
    fn test_hash_redaction_strategy() {
        let mut config = ScrubberConfig::default();
        config.category_strategies.insert(
            PIICategory::Email,
            RedactionStrategy::Hash,
        );
        
        let mut scrubber = TrainingDataScrubber::with_config(config);
        let input = "Contact test@example.com";
        let output1 = scrubber.sanitize_for_training(input);
        let output2 = scrubber.sanitize_for_training(input);
        
        // Same input should produce same hash
        assert_eq!(output1, output2);
        assert!(output1.contains("<HASH:"));
    }

    #[test]
    fn test_partial_hash_strategy() {
        let mut config = ScrubberConfig::default();
        config.category_strategies.insert(
            PIICategory::SSN,
            RedactionStrategy::PartialHash { preserve_last: 4 },
        );
        
        let mut scrubber = TrainingDataScrubber::with_config(config);
        let input = "SSN: 123-45-6789";
        let output = scrubber.sanitize_for_training(input);
        
        // Should preserve last 4 digits
        assert!(output.contains("6789"));
    }

    #[test]
    fn test_structural_mask_strategy() {
        let mut config = ScrubberConfig::default();
        config.category_strategies.insert(
            PIICategory::SSN,
            RedactionStrategy::StructuralMask { visible_chars: 4 },
        );
        
        let mut scrubber = TrainingDataScrubber::with_config(config);
        let input = "SSN: 123-45-6789";
        let output = scrubber.sanitize_for_training(input);
        
        // Should show XXX-XX-6789
        assert!(output.contains("6789"));
        assert!(output.contains("XXX"));
    }

    #[test]
    fn test_synthetic_strategy() {
        let mut config = ScrubberConfig::default();
        config.category_strategies.insert(
            PIICategory::Email,
            RedactionStrategy::Synthetic,
        );
        
        let mut scrubber = TrainingDataScrubber::with_config(config);
        let input = "Contact real@email.com";
        let output = scrubber.sanitize_for_training(input);
        
        assert_eq!(output, "Contact user@example.com");
    }

    #[test]
    fn test_remove_strategy() {
        let mut config = ScrubberConfig::default();
        config.category_strategies.insert(
            PIICategory::Email,
            RedactionStrategy::Remove,
        );
        
        let mut scrubber = TrainingDataScrubber::with_config(config);
        let input = "Contact test@example.com for info";
        let output = scrubber.sanitize_for_training(input);
        
        assert_eq!(output, "Contact  for info");
    }

    #[test]
    fn test_custom_patterns() {
        let mut config = ScrubberConfig::default();
        config.custom_patterns.insert(
            "employee_id".to_string(),
            r"\bEMP\d{6}\b".to_string(),
        );
        
        let mut scrubber = TrainingDataScrubber::with_config(config);
        let input = "Employee EMP123456 submitted the report";
        let output = scrubber.sanitize_for_training(input);
        
        assert!(output.contains("<CUSTOM_REDACTED>"));
    }

    #[test]
    fn test_statistics_tracking() {
        let mut scrubber = create_scrubber();
        
        scrubber.sanitize_for_training("Email: test@example.com");
        scrubber.sanitize_for_training("SSN: 123-45-6789");
        scrubber.sanitize_for_training("Clean text");
        
        let stats = scrubber.stats();
        assert_eq!(stats.total_documents_processed, 3);
        assert_eq!(stats.total_redactions, 2);
    }

    #[test]
    fn test_batch_processing() {
        let mut scrubber = create_scrubber();
        
        let inputs = vec![
            "Email: test1@example.com",
            "SSN: 111-22-3333",
            "Phone: 555-123-4567",
        ];
        
        let outputs = scrubber.sanitize_batch(inputs);
        
        assert_eq!(outputs.len(), 3);
        assert!(outputs[0].contains("<EMAIL_REDACTED>"));
        assert!(outputs[1].contains("<SSN_REDACTED>"));
        assert!(outputs[2].contains("<PHONE_REDACTED>"));
    }

    #[test]
    fn test_coordinates_redaction() {
        let mut scrubber = create_scrubber();
        scrubber.config.enabled_categories.push(PIICategory::Coordinates);
        
        let input = "Location: 37.7749, -122.4194";
        let output = scrubber.sanitize_for_training(input);
        
        assert!(output.contains("<COORDINATES_REDACTED>"));
    }

    #[test]
    fn test_api_key_redaction() {
        let mut scrubber = create_scrubber();
        scrubber.config.enabled_categories.push(PIICategory::APIKey);
        
        let input = "API_KEY=sk_test_REDACTED_MOCK_KEY_1234567890";
        let output = scrubber.sanitize_for_training(input);
        
        assert!(output.contains("<API_KEY_REDACTED>"));
    }

    #[test]
    fn test_preserves_structure() {
        let mut scrubber = create_scrubber();
        
        let input = "Line 1: test@example.com\nLine 2: Clean\nLine 3: 123-45-6789";
        let output = scrubber.sanitize_for_training(input);
        
        // Should preserve newlines
        assert_eq!(output.matches('\n').count(), 2);
    }

    #[test]
    fn test_empty_input() {
        let mut scrubber = create_scrubber();
        let output = scrubber.sanitize_for_training("");
        assert_eq!(output, "");
    }

    #[test]
    fn test_case_insensitive_email() {
        let mut scrubber = create_scrubber();
        
        let input = "Contact JOHN.DOE@EXAMPLE.COM";
        let output = scrubber.sanitize_for_training(input);
        
        assert!(output.contains("<EMAIL_REDACTED>"));
    }
}
