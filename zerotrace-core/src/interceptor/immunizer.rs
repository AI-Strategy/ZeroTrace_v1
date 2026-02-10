//! Immunization Rule Management System
//! 
//! This module implements the DBS Protocol Governance for threat immunization.
//! It translates Deep Research results into deterministic blocking rules and manages
//! their lifecycle from generation to deployment across the global intelligence network.

use crate::graph::neo4j::GraphClient;
use crate::interceptor::deep_research::DeepResearchResult;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Error, Debug)]
pub enum ImmunizationError {
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
    
    #[error("Confidence score out of range: {0}")]
    InvalidConfidence(f32),
    
    #[error("Graph database error: {0}")]
    GraphError(#[from] anyhow::Error),
    
    #[error("Global feed synchronization failed: {0}")]
    SyncError(String),
    
    #[error("Rule deployment failed: {0}")]
    DeploymentError(String),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
}

pub type Result<T> = std::result::Result<T, ImmunizationError>;

// ============================================================================
// Core Types
// ============================================================================

/// Represents the operational state of an immunization rule within the DBS Protocol.
/// 
/// The state determines how the rule is enforced and what actions are taken
/// when a pattern match occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleState {
    /// Rule is enforced immediately and blocks matching threats.
    /// Only applied when confidence > 0.99 AND false positive risk < 0.01.
    Active,
    
    /// Rule logs matches but does not block.
    /// Used for medium-confidence rules or during initial validation period.
    Staging,
    
    /// Rule requires manual review before any action.
    /// Applied when uncertainty exists or edge cases are detected.
    Review,
    
    /// Rule has been superseded or is no longer relevant.
    Deprecated,
}

impl RuleState {
    /// Returns true if this state allows automatic blocking.
    pub fn is_blocking(&self) -> bool {
        matches!(self, RuleState::Active)
    }
    
    /// Returns true if this state requires human intervention.
    pub fn requires_review(&self) -> bool {
        matches!(self, RuleState::Review)
    }
}

impl fmt::Display for RuleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleState::Active => write!(f, "ACTIVE"),
            RuleState::Staging => write!(f, "STAGING"),
            RuleState::Review => write!(f, "REVIEW"),
            RuleState::Deprecated => write!(f, "DEPRECATED"),
        }
    }
}

// ============================================================================
// Immunization Rule
// ============================================================================

/// A deterministic rule for blocking threats based on Deep Research analysis.
/// 
/// Each rule encapsulates a pattern, threat classification, confidence metrics,
/// and operational state following the DBS Protocol Governance framework.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImmunizationRule {
    /// Unique identifier for the rule
    pub id: String,
    
    /// Pattern to match (regex, signature, or other detection logic)
    pub pattern: String,
    
    /// Classification of the threat this rule addresses
    pub threat_type: String,
    
    /// Confidence score from Deep Research (0.0 - 1.0)
    pub confidence: f32,
    
    /// Estimated false positive risk (0.0 - 1.0)
    pub false_positive_risk: f32,
    
    /// Current operational state
    pub state: RuleState,
    
    /// ISO 8601 timestamp of rule creation
    pub created_at: String,
    
    /// ISO 8601 timestamp of last update
    pub updated_at: String,
    
    /// Optional metadata for tracking and auditing
    pub metadata: RuleMetadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RuleMetadata {
    /// Source of the threat intelligence
    pub source: Option<String>,
    
    /// Number of times this rule has triggered
    pub trigger_count: u64,
    
    /// Number of confirmed true positives
    pub true_positives: u64,
    
    /// Number of confirmed false positives
    pub false_positives: u64,
    
    /// Version number for rule evolution tracking
    pub version: u32,
    
    /// Tags for categorization and search
    pub tags: Vec<String>,
}

impl ImmunizationRule {
    /// Validates the rule's internal consistency.
    pub fn validate(&self) -> Result<()> {
        // Validate pattern is not empty
        if self.pattern.trim().is_empty() {
            return Err(ImmunizationError::InvalidPattern(
                "Pattern cannot be empty".to_string()
            ));
        }
        
        // Validate confidence score range
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(ImmunizationError::InvalidConfidence(self.confidence));
        }
        
        // Validate false positive risk range
        if !(0.0..=1.0).contains(&self.false_positive_risk) {
            return Err(ImmunizationError::InvalidConfidence(self.false_positive_risk));
        }
        
        // Validate threat type
        if self.threat_type.trim().is_empty() {
            return Err(ImmunizationError::MissingField(
                "threat_type".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Calculates the effective score considering both confidence and FP risk.
    pub fn effective_score(&self) -> f32 {
        self.confidence * (1.0 - self.false_positive_risk)
    }
    
    /// Returns the precision rate based on observed performance.
    pub fn precision(&self) -> Option<f32> {
        let total = self.metadata.true_positives + self.metadata.false_positives;
        if total == 0 {
            None
        } else {
            Some(self.metadata.true_positives as f32 / total as f32)
        }
    }
    
    /// Determines if the rule should be promoted to Active state.
    pub fn should_promote(&self) -> bool {
        self.state == RuleState::Staging 
            && self.metadata.trigger_count >= 10
            && self.precision().unwrap_or(0.0) > 0.95
    }
    
    /// Determines if the rule should be demoted due to poor performance.
    pub fn should_demote(&self) -> bool {
        if let Some(precision) = self.precision() {
            precision < 0.80 && self.metadata.trigger_count >= 5
        } else {
            false
        }
    }
}

// ============================================================================
// Rule Generation
// ============================================================================

/// Configuration for rule generation thresholds.
#[derive(Debug, Clone)]
pub struct RuleGenerationConfig {
    /// Minimum confidence for Active state
    pub active_confidence_threshold: f32,
    
    /// Maximum FP risk for Active state
    pub active_fp_threshold: f32,
    
    /// Minimum confidence for Staging state
    pub staging_confidence_threshold: f32,
    
    /// Enable automatic promotion from Staging to Active
    pub auto_promote: bool,
}

impl Default for RuleGenerationConfig {
    fn default() -> Self {
        Self {
            active_confidence_threshold: 0.99,
            active_fp_threshold: 0.01,
            staging_confidence_threshold: 0.80,
            auto_promote: true,
        }
    }
}

/// Translates a Deep Research result into a deterministic blocking rule.
/// 
/// # DBS Protocol Governance Implementation
/// 
/// 1. **High Confidence (>0.99) AND Zero/Low FP Risk (<0.01)** → ACTIVE
///    - Rule is immediately enforced and blocks matching patterns
///    - Automatically synchronized to the global intelligence feed
/// 
/// 2. **Medium Confidence (>0.80) OR Risk > 0.01** → STAGING
///    - Rule logs matches for validation but does not block
///    - Collects performance metrics for potential promotion
/// 
/// 3. **Any Uncertainty** → REVIEW
///    - Rule flagged for manual analyst review
///    - No automated action taken until approved
/// 
/// # Arguments
/// 
/// * `threat_type` - Classification of the threat (e.g., "SQL_INJECTION", "XSS")
/// * `result` - Deep Research analysis result with confidence metrics
/// * `config` - Optional configuration for threshold customization
/// 
/// # Returns
/// 
/// Returns `Ok(Some(rule))` if a valid rule can be generated, `Ok(None)` if no
/// pattern was recommended, or `Err` if validation fails.
/// 
/// # Example
/// 
/// ```rust,ignore
/// let result = deep_research_analyzer.analyze(threat).await?;
/// let rule = generate_rule_from_research("SQL_INJECTION", result, None).await?;
/// 
/// if let Some(rule) = rule {
///     deploy_rule(rule, &client).await?;
/// }
/// ```
pub async fn generate_rule_from_research(
    threat_type: &str,
    result: DeepResearchResult,
    config: Option<RuleGenerationConfig>,
) -> Result<Option<ImmunizationRule>> {
    let config = config.unwrap_or_default();
    
    // Extract pattern or return None if not recommended
    let pattern = match result.recommended_rule_pattern {
        Some(p) => p,
        None => {
            debug!("No rule pattern recommended for threat type: {}", threat_type);
            return Ok(None);
        }
    };
    
    // Determine state based on DBS Protocol governance
    let state = determine_rule_state(
        result.confidence_score,
        result.false_positive_risk,
        &config,
    );
    
    info!(
        "Generated {} rule for {}: confidence={:.4}, fp_risk={:.4}",
        state, threat_type, result.confidence_score, result.false_positive_risk
    );
    
    let now = chrono::Utc::now().to_rfc3339();
    let rule = ImmunizationRule {
        id: generate_rule_id(&pattern, threat_type),
        pattern,
        threat_type: threat_type.to_string(),
        confidence: result.confidence_score,
        false_positive_risk: result.false_positive_risk,
        state,
        created_at: now.clone(),
        updated_at: now,
        metadata: RuleMetadata {
            source: Some("DeepResearch".to_string()), // Fixed source
            version: 1,
            tags: vec![], // Fixed empty tags
            ..Default::default()
        },
    };
    
    // Validate before returning
    rule.validate()?;
    
    Ok(Some(rule))
}

/// Determines the appropriate rule state based on confidence and risk metrics.
fn determine_rule_state(
    confidence: f32,
    fp_risk: f32,
    config: &RuleGenerationConfig,
) -> RuleState {
    if confidence > config.active_confidence_threshold 
        && fp_risk < config.active_fp_threshold {
        RuleState::Active
    } else if confidence > config.staging_confidence_threshold {
        RuleState::Staging
    } else {
        RuleState::Review
    }
}

/// Generates a deterministic ID for a rule based on pattern and threat type.
fn generate_rule_id(pattern: &str, threat_type: &str) -> String {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(pattern.as_bytes());
    hasher.update(threat_type.as_bytes());
    let hash = hasher.finalize();
    
    format!("rule_{}", hex::encode(&hash[..8]))
}

// ============================================================================
// Rule Deployment
// ============================================================================

/// Configuration for rule deployment behavior.
#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    /// Enable synchronization to global intelligence feed
    pub enable_global_sync: bool,
    
    /// Enable local graph database logging
    pub enable_graph_logging: bool,
    
    /// Retry attempts for failed deployments
    pub max_retries: u32,
    
    /// Delay between retry attempts (milliseconds)
    pub retry_delay_ms: u64,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            enable_global_sync: true,
            enable_graph_logging: true,
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }
}

/// Deploys an immunization rule to the local engine and global intelligence feed.
/// 
/// This function handles the complete deployment lifecycle:
/// 1. Validates the rule
/// 2. Logs to the Neo4j graph database for audit trail
/// 3. Pushes Active rules to the Global Intelligence Feed
/// 4. Handles errors with automatic retry logic
/// 
/// # Arguments
/// 
/// * `rule` - The immunization rule to deploy
/// * `graph_client` - Neo4j client for audit logging (unused in static call)
/// * `config` - Optional deployment configuration
/// 
/// # Errors
/// 
/// Returns `ImmunizationError::DeploymentError` if deployment fails after all retries.
/// 
/// # Example
/// 
/// ```rust,ignore
/// let rule = generate_rule_from_research("XSS", research_result, None).await?;
/// if let Some(rule) = rule {
///     deploy_rule(rule, &graph_client, None).await?;
/// }
/// ```
pub async fn deploy_rule(
    rule: ImmunizationRule,
    _graph_client: &GraphClient,
    config: Option<DeploymentConfig>,
) -> Result<()> {
    let config = config.unwrap_or_default();
    
    // Validate rule before deployment
    rule.validate()?;
    
    info!(
        "DEPLOYING RULE: [{}] Pattern: '{}' (Confidence: {:.4}, FP Risk: {:.4}, Effective: {:.4})",
        rule.state, 
        rule.pattern, 
        rule.confidence,
        rule.false_positive_risk,
        rule.effective_score()
    );
    
    // Log to Neo4j graph database
    if config.enable_graph_logging {
        log_rule_to_graph(&rule).await?; // Removed graph_client argument
    }
    
    // Push Active rules to Global Intelligence Feed
    if rule.state.is_blocking() && config.enable_global_sync {
        push_to_global_feed(&rule, &config).await?;
    } else if rule.state.is_blocking() {
        warn!("Skipping global sync for Active rule (disabled in config)");
    }
    
    // Log staging rules for monitoring
    if rule.state == RuleState::Staging {
        info!("Rule in STAGING mode - collecting performance metrics");
    }
    
    // Flag review rules for analyst attention
    if rule.state.requires_review() {
        warn!("Rule requires REVIEW - flagging for analyst attention");
        // TODO: Integrate with alerting system
    }
    
    Ok(())
}

/// Logs rule deployment to the Neo4j graph database.
async fn log_rule_to_graph(
    rule: &ImmunizationRule,
) -> Result<()> {
    let message = format!(
        "Deployed {} rule for {} (ID: {}, Confidence: {:.4})",
        rule.state, rule.threat_type, rule.id, rule.confidence
    );
    
    // Use static method call
    GraphClient::log_trace("SYSTEM", "IMMUNIZER", &message).await;
    
    debug!("Logged rule to graph: {}", rule.id);
    Ok(())
}

/// Synchronizes an Active rule to the Global Intelligence Feed.
async fn push_to_global_feed(
    rule: &ImmunizationRule,
    config: &DeploymentConfig,
) -> Result<()> {
    info!(
        "SYNC: Pushing rule '{}' ({}) to ZeroTrace Global Intelligence...",
        rule.pattern, rule.id
    );
    
    let mut attempts = 0;
    let mut last_error = None;
    
    while attempts < config.max_retries {
        attempts += 1;
        
        match attempt_global_sync(rule).await {
            Ok(_) => {
                info!("Successfully synchronized rule {} to global feed", rule.id);
                return Ok(());
            }
            Err(e) => {
                error!(
                    "Failed to sync rule {} (attempt {}/{}): {}",
                    rule.id, attempts, config.max_retries, e
                );
                last_error = Some(e);
                
                if attempts < config.max_retries {
                    tokio::time::sleep(
                        tokio::time::Duration::from_millis(config.retry_delay_ms)
                    ).await;
                }
            }
        }
    }
    
    Err(ImmunizationError::SyncError(
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Unknown error".to_string())
    ))
}

/// Attempts to synchronize a rule to the global feed (stub implementation).
async fn attempt_global_sync(_rule: &ImmunizationRule) -> Result<()> {
    // TODO: Implement actual API call to global intelligence feed
    // This would typically involve:
    // - Serializing the rule to the feed's expected format
    // - Authenticating with the global service
    // - Sending the rule via REST/gRPC/message queue
    // - Handling response and confirmation
    
    // Simulate network operation
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Stub success
    Ok(())
}

// ============================================================================
// Rule Management
// ============================================================================

/// Updates a rule's state based on performance metrics.
pub async fn update_rule_state(
    rule: &mut ImmunizationRule,
    _graph_client: &GraphClient,
) -> Result<bool> {
    let old_state = rule.state;
    let mut state_changed = false;
    
    // Check for promotion
    if rule.should_promote() {
        info!("Promoting rule {} from {} to ACTIVE", rule.id, old_state);
        rule.state = RuleState::Active;
        state_changed = true;
    }
    
    // Check for demotion
    if rule.should_demote() {
        warn!("Demoting rule {} from {} to REVIEW", rule.id, old_state);
        rule.state = RuleState::Review;
        state_changed = true;
    }
    
    if state_changed {
        rule.updated_at = chrono::Utc::now().to_rfc3339();
        rule.metadata.version += 1;
        
        let message = format!(
            "State transition: {} -> {} (ID: {})",
            old_state, rule.state, rule.id
        );
        // Use static method call
        GraphClient::log_trace("SYSTEM", "IMMUNIZER", &message).await;
    }
    
    Ok(state_changed)
}

/// Records a rule trigger event and updates metrics.
pub fn record_trigger(rule: &mut ImmunizationRule, is_true_positive: bool) {
    rule.metadata.trigger_count += 1;
    
    if is_true_positive {
        rule.metadata.true_positives += 1;
    } else {
        rule.metadata.false_positives += 1;
    }
    
    rule.updated_at = chrono::Utc::now().to_rfc3339();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_rule(confidence: f32, fp_risk: f32, state: RuleState) -> ImmunizationRule {
        let now = chrono::Utc::now().to_rfc3339();
        ImmunizationRule {
            id: "test_rule_001".to_string(),
            pattern: r"(?i)(\bunion\b.+\bselect\b|\bselect\b.+\bunion\b)".to_string(),
            threat_type: "SQL_INJECTION".to_string(),
            confidence,
            false_positive_risk: fp_risk,
            state,
            created_at: now.clone(),
            updated_at: now,
            metadata: RuleMetadata::default(),
        }
    }
    
    #[test]
    fn test_rule_state_determination() {
        let config = RuleGenerationConfig::default();
        
        // High confidence, low risk -> Active
        assert_eq!(
            determine_rule_state(0.995, 0.005, &config),
            RuleState::Active
        );
        
        // Medium confidence -> Staging
        assert_eq!(
            determine_rule_state(0.85, 0.05, &config),
            RuleState::Staging
        );
        
        // Low confidence -> Review
        assert_eq!(
            determine_rule_state(0.75, 0.1, &config),
            RuleState::Review
        );
    }
    
    #[test]
    fn test_rule_validation() {
        let mut rule = create_test_rule(0.95, 0.02, RuleState::Staging);
        assert!(rule.validate().is_ok());
        
        // Invalid confidence
        rule.confidence = 1.5;
        assert!(rule.validate().is_err());
        
        // Empty pattern
        rule.confidence = 0.95;
        rule.pattern = "".to_string();
        assert!(rule.validate().is_err());
    }
    
    #[test]
    fn test_effective_score() {
        let rule = create_test_rule(0.9, 0.1, RuleState::Staging);
        assert!((rule.effective_score() - 0.81).abs() < 0.001);
    }
    
    #[test]
    fn test_promotion_logic() {
        let mut rule = create_test_rule(0.95, 0.02, RuleState::Staging);
        
        // Not enough triggers
        assert!(!rule.should_promote());
        
        // Add successful triggers
        for _ in 0..15 {
            record_trigger(&mut rule, true);
        }
        
        assert!(rule.should_promote());
        assert_eq!(rule.precision(), Some(1.0));
    }
    
    #[test]
    fn test_demotion_logic() {
        let mut rule = create_test_rule(0.95, 0.02, RuleState::Active);
        
        // Add triggers with poor performance
        for _ in 0..3 {
            record_trigger(&mut rule, true);
        }
        for _ in 0..7 {
            record_trigger(&mut rule, false);
        }
        
        assert!(rule.should_demote());
        assert!(rule.precision().unwrap() < 0.80);
    }
    
    #[test]
    fn test_rule_id_generation() {
        let id1 = generate_rule_id("pattern1", "SQL_INJECTION");
        let id2 = generate_rule_id("pattern1", "SQL_INJECTION");
        let id3 = generate_rule_id("pattern2", "SQL_INJECTION");
        
        // Same inputs produce same ID
        assert_eq!(id1, id2);
        
        // Different inputs produce different IDs
        assert_ne!(id1, id3);
        
        // IDs have correct format
        assert!(id1.starts_with("rule_"));
    }
}
