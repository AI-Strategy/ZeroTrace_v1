//! # Cross-Plugin Request Forgery (CPRF) Prevention System
//!
//! ## Purpose
//! Prevents indirect prompt injection attacks (EXT16) by enforcing context-aware
//! execution policies for AI agent tool calls. This mitigates the risk of malicious
//! external content (emails, websites) triggering state-changing operations.
//!
//! ## Architecture
//! - Context Tracking: Distinguishes trusted vs. untrusted execution environments
//! - Policy Engine: Declarative risk-based tool classification
//! - Audit Trail: Structured logging of all authorization decisions
//!
//! ## Security Model
//! Defense-in-depth layers:
//! 1. Context isolation (this module)
//! 2. Human-in-the-loop gates (upstream)
//! 3. Audit logging (compliance)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info, instrument, warn};

// ============================================================================
// TYPES & CONSTANTS
// ============================================================================

/// Execution context representing the trust boundary of the current operation.
///
/// ## Invariants
/// - Context transitions must be explicit and logged
/// - ExternalDataProcessing taint persists until explicit sanitization
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Hash)]
#[non_exhaustive]
pub enum ExecutionContext {
    /// Trusted internal operations initiated by authenticated users
    Standard,

    /// Tainted context processing untrusted external data
    /// Examples: email content, web scraping, third-party APIs
    ExternalDataProcessing,
    // Future: Add contexts like `Sandbox`, `ReadOnly`, `HighPrivilege`
}

/// Risk classification for tool operations.
///
/// Determines what security controls apply based on potential impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ToolRiskLevel {
    /// Read-only operations with no side effects
    Safe,

    /// State-changing operations requiring authorization
    HighRisk,

    /// Critical operations requiring multi-factor approval
    Critical,
}

/// Comprehensive security error taxonomy.
#[derive(Debug, Error, Serialize)]
#[non_exhaustive]
pub enum SecurityError {
    #[error("CPRF Blocked: Tool '{tool}' (risk={risk:?}) restricted in context '{context:?}'")]
    CPRFBlocked {
        tool: String,
        context: ExecutionContext,
        risk: ToolRiskLevel,
    },

    #[error("Invalid tool name: '{0}' (must be non-empty alphanumeric)")]
    InvalidToolName(String),

    #[error("Policy violation: {reason}")]
    PolicyViolation { reason: String },
}

// ============================================================================
// POLICY ENGINE
// ============================================================================

/// Declarative security policy for tool execution.
///
/// ## Design Rationale
/// - Centralized policy reduces scattered conditional logic
/// - Easy to audit and unit test
/// - Supports runtime policy updates (future: load from config)
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub high_risk_tools: Arc<HashSet<String>>,
    pub critical_tools: Arc<HashSet<String>>,
}

impl SecurityPolicy {
    /// Creates the default production security policy.
    ///
    /// ## Policy Rules
    /// - High-risk: State-changing operations (email, file export, database writes)
    /// - Critical: System execution and credential access
    pub fn default_production() -> Self {
        let high_risk = [
            "Email_Send",
            "File_Export",
            "SQL_Write",
            "Calendar_CreateEvent",
            "Slack_PostMessage",
            "HTTP_POST",
        ]
        .iter()
        .map(|&s| s.to_string())
        .collect();

        let critical = ["System_Execute", "Credential_Access", "Admin_DeleteUser"]
            .iter()
            .map(|&s| s.to_string())
            .collect();

        Self {
            high_risk_tools: Arc::new(high_risk),
            critical_tools: Arc::new(critical),
        }
    }

    /// Classifies a tool based on its potential security impact.
    ///
    /// ## Complexity
    /// - Time: O(1) average case (HashSet lookup)
    /// - Space: O(1) - no allocations
    pub fn classify_tool(&self, tool_name: &str) -> ToolRiskLevel {
        if self.critical_tools.contains(tool_name) {
            ToolRiskLevel::Critical
        } else if self.high_risk_tools.contains(tool_name) {
            ToolRiskLevel::HighRisk
        } else {
            ToolRiskLevel::Safe
        }
    }

    /// Determines if a tool is allowed in a given context.
    ///
    /// ## Security Logic
    /// - Standard context: All tools allowed (subject to HITL)
    /// - ExternalDataProcessing: Only Safe tools allowed
    pub fn is_allowed(&self, tool_name: &str, context: ExecutionContext) -> bool {
        let risk = self.classify_tool(tool_name);

        match context {
            ExecutionContext::Standard => true, // HITL enforced upstream
            ExecutionContext::ExternalDataProcessing => {
                matches!(risk, ToolRiskLevel::Safe)
            }
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::default_production()
    }
}

// ============================================================================
// CONTEXT SENTINEL (Main Component)
// ============================================================================

/// Context-aware security guard for AI agent tool execution.
///
/// ## Thread Safety
/// - Immutable after construction (safe to share across threads)
/// - Uses Arc for zero-cost policy sharing
///
/// ## Performance
/// - Tool validation: O(1) average case
/// - Zero allocations on success path
#[derive(Debug, Clone)]
pub struct ContextSentinel {
    active_context: ExecutionContext,
    policy: SecurityPolicy,
}

impl ContextSentinel {
    /// Creates a new sentinel with the specified execution context.
    ///
    /// # Arguments
    /// * `initial_context` - The trust boundary for this execution scope
    ///
    /// # Example
    /// ```rust
    /// use zerotrace_core::interceptor::cprf::{ContextSentinel, ExecutionContext};
    /// let sentinel = ContextSentinel::new(ExecutionContext::Standard);
    /// ```
    pub fn new(initial_context: ExecutionContext) -> Self {
        info!(
            context = ?initial_context,
            "ContextSentinel initialized"
        );

        Self {
            active_context: initial_context,
            policy: SecurityPolicy::default(),
        }
    }

    /// Creates a sentinel with a custom security policy.
    ///
    /// # Use Case
    /// Testing, staged rollouts, or organization-specific policies
    pub fn with_policy(initial_context: ExecutionContext, policy: SecurityPolicy) -> Self {
        Self {
            active_context: initial_context,
            policy,
        }
    }

    /// Validates tool execution authorization within the current context.
    ///
    /// ## Security Guarantees
    /// - Fails closed: Defaults to denial on ambiguous input
    /// - Audit trail: All decisions logged with structured metadata
    /// - No side effects: Pure authorization check
    ///
    /// ## Complexity
    /// - Time: O(1) average case (hash lookups)
    /// - Space: O(1) - only stack allocations for logging
    ///
    /// # Arguments
    /// * `tool_name` - The tool identifier to authorize (must be non-empty)
    ///
    /// # Returns
    /// - `Ok(())` if authorized
    /// - `Err(SecurityError)` if blocked or invalid
    ///
    /// # Example
    /// ```rust
    /// use zerotrace_core::interceptor::cprf::{ContextSentinel, ExecutionContext, SecurityError};
    /// let sentinel = ContextSentinel::new(ExecutionContext::Standard);
    /// // sentinel.execute_tool_call("Search_CaseLaw")?;
    /// ```
    #[instrument(skip(self), fields(context = ?self.active_context))]
    pub fn execute_tool_call(&self, tool_name: &str) -> Result<(), SecurityError> {
        // STEP 1: Input validation (fail fast on malformed input)
        if tool_name.is_empty() || !tool_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            error!(tool_name = tool_name, "Rejected invalid tool name");
            return Err(SecurityError::InvalidToolName(tool_name.to_string()));
        }

        // STEP 2: Risk classification
        let risk_level = self.policy.classify_tool(tool_name);

        // STEP 3: Context-aware authorization
        if !self.policy.is_allowed(tool_name, self.active_context) {
            warn!(
                tool = tool_name,
                context = ?self.active_context,
                risk = ?risk_level,
                "CPRF block triggered - high-risk tool in tainted context"
            );

            return Err(SecurityError::CPRFBlocked {
                tool: tool_name.to_string(),
                context: self.active_context,
                risk: risk_level,
            });
        }

        // STEP 4: Success audit (critical for compliance)
        info!(
            tool = tool_name,
            context = ?self.active_context,
            risk = ?risk_level,
            "Tool execution authorized"
        );

        Ok(())
    }

    /// Returns the current execution context.
    ///
    /// # Use Case
    /// Debugging, telemetry, conditional logic in caller
    pub fn current_context(&self) -> ExecutionContext {
        self.active_context
    }

    /// Transitions to a new execution context.
    ///
    /// ## Security Note
    /// Context transitions should be rare and explicit. Consider
    /// creating a new sentinel instead for clearer scope boundaries.
    ///
    /// # Example
    /// ```rust
    /// use zerotrace_core::interceptor::cprf::{ContextSentinel, ExecutionContext};
    /// let mut sentinel = ContextSentinel::new(ExecutionContext::Standard);
    /// sentinel.transition_context(ExecutionContext::ExternalDataProcessing);
    /// ```
    #[instrument(skip(self))]
    pub fn transition_context(&mut self, new_context: ExecutionContext) {
        warn!(
            from = ?self.active_context,
            to = ?new_context,
            "Execution context transition"
        );
        self.active_context = new_context;
    }
}
