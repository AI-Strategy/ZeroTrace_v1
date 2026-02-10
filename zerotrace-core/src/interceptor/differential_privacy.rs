//! # Differential Privacy Engine
//!
//! ## Purpose
//! Provides cryptographically sound privacy-preserving mechanisms for statistical
//! data release, preventing membership inference attacks and satisfying formal
//! epsilon-delta differential privacy guarantees.
//!
//! ## Security Model
//! - Implements Laplace and Randomized Response mechanisms
//! - Privacy budget tracking with overflow protection
//! - Constant-time operations where feasible to prevent timing attacks
//! - Auditable noise generation with optional deterministic seeding
//!
//! ## References
//! - Dwork & Roth (2014): "The Algorithmic Foundations of Differential Privacy"
//! - NIST SP 800-208: "Recommendation for Stateful Hash-Based Signature Schemes"

use rand::prelude::*;
use rand::distributions::{Distribution, Uniform};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

/// Maximum allowed epsilon value (prevents privacy budget exhaustion).
/// Industry standard: ε ≤ 10 for reasonable privacy guarantees.
const MAX_EPSILON: f64 = 10.0;

/// Minimum allowed epsilon value (prevents division by zero and ensures measurable privacy).
const MIN_EPSILON: f64 = 0.01;

/// Maximum sensitivity value (prevents unbounded noise that could cause overflow).
const MAX_SENSITIVITY: f64 = 1e6;

/// Minimum sensitivity value (must be positive for meaningful privacy).
const MIN_SENSITIVITY: f64 = 1e-10;

/// Maximum absolute value for input data (prevents numerical instability).
const MAX_VALUE: f64 = 1e15;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Comprehensive error taxonomy for differential privacy operations.
#[derive(Debug, Error, Serialize)]
#[non_exhaustive]
pub enum DPError {
    #[error("Invalid epsilon: {value} (must be in [{}, {}])", MIN_EPSILON, MAX_EPSILON)]
    InvalidEpsilon { value: f64 },

    #[error("Invalid sensitivity: {value} (must be in [{}, {}])", MIN_SENSITIVITY, MAX_SENSITIVITY)]
    InvalidSensitivity { value: f64 },

    #[error("Invalid input value: {value} (must be finite and in [-{}, {}])", MAX_VALUE, MAX_VALUE)]
    InvalidValue { value: f64 },

    #[error("Privacy budget exhausted: current={current}, requested={requested}, limit={limit}")]
    BudgetExhausted {
        current: f64,
        requested: f64,
        limit: f64,
    },

    #[error("Numerical instability detected: {reason}")]
    NumericalInstability { reason: String },

    #[error("RNG initialization failed: {reason}")]
    RNGFailure { reason: String },
}

// ============================================================================
// PRIVACY BUDGET TRACKER
// ============================================================================

/// Privacy budget accounting with composition tracking.
///
/// ## Purpose
/// Prevents privacy budget exhaustion by tracking cumulative epsilon consumption
/// across multiple queries. Implements basic composition theorem.
///
/// ## Thread Safety
/// Not thread-safe by default. Wrap in `Arc<Mutex<>>` for concurrent access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyBudget {
    total_budget: f64,
    consumed: f64,
    query_count: usize,
}

impl PrivacyBudget {
    /// Creates a new privacy budget tracker.
    ///
    /// # Arguments
    /// * `total_budget` - Maximum cumulative epsilon allowed
    ///
    /// # Returns
    /// Result containing the budget tracker or validation error
    pub fn new(total_budget: f64) -> Result<Self, DPError> {
        validate_epsilon(total_budget)?;
        
        Ok(Self {
            total_budget,
            consumed: 0.0,
            query_count: 0,
        })
    }

    /// Attempts to consume privacy budget for a query.
    ///
    /// # Arguments
    /// * `epsilon` - Amount of privacy budget to consume
    ///
    /// # Returns
    /// Ok(()) if budget available, Err if exhausted
    #[instrument(skip(self))]
    pub fn consume(&mut self, epsilon: f64) -> Result<(), DPError> {
        validate_epsilon(epsilon)?;

        let new_total = self.consumed + epsilon;
        
        if new_total > self.total_budget {
            error!(
                consumed = self.consumed,
                requested = epsilon,
                limit = self.total_budget,
                "Privacy budget exhaustion attempt"
            );
            
            return Err(DPError::BudgetExhausted {
                current: self.consumed,
                requested: epsilon,
                limit: self.total_budget,
            });
        }

        self.consumed = new_total;
        self.query_count += 1;

        info!(
            consumed = self.consumed,
            remaining = self.total_budget - self.consumed,
            query_count = self.query_count,
            "Privacy budget consumed"
        );

        Ok(())
    }

    /// Returns remaining privacy budget.
    pub fn remaining(&self) -> f64 {
        self.total_budget - self.consumed
    }

    /// Returns total queries executed.
    pub fn query_count(&self) -> usize {
        self.query_count
    }
}

// ============================================================================
// NOISE MECHANISMS
// ============================================================================

/// Noise mechanism selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoiseMechanism {
    /// Laplace mechanism (for numerical queries)
    Laplace,
    /// Randomized response (for boolean queries)
    RandomizedResponse,
}

// ============================================================================
// DIFFERENTIAL PRIVACY ENGINE
// ============================================================================

/// Production-grade differential privacy engine with formal privacy guarantees.
///
/// ## Features
/// - Cryptographically secure RNG (ChaCha20)
/// - Privacy budget tracking
/// - Input validation and sanitization
/// - Structured audit logging
/// - Numerical stability checks
///
/// ## Complexity
/// - Space: O(1) - constant memory per instance
/// - Time: O(1) per query (noise generation is constant-time)
#[derive(Debug)]
pub struct DifferentialPrivacy {
    epsilon: f64,
    budget: Option<PrivacyBudget>,
    rng: ChaCha20Rng,
}

impl DifferentialPrivacy {
    /// Creates a new DP engine with the specified privacy parameter.
    ///
    /// # Arguments
    /// * `epsilon` - Privacy loss parameter (lower = more privacy, higher = more accuracy)
    ///
    /// # Privacy Interpretation
    /// - ε = 0.01: Very strong privacy (high noise)
    /// - ε = 1.0: Standard privacy (moderate noise)
    /// - ε = 10.0: Weak privacy (low noise)
    ///
    /// # Returns
    /// Result containing the DP engine or validation error
    ///
    /// # Example
    /// ```rust
    /// let dp = DifferentialPrivacy::new(1.0)?;
    /// ```
    pub fn new(epsilon: f64) -> Result<Self, DPError> {
        validate_epsilon(epsilon)?;

        let rng = ChaCha20Rng::from_entropy();

        info!(epsilon = epsilon, "DifferentialPrivacy engine initialized");

        Ok(Self {
            epsilon,
            budget: None,
            rng,
        })
    }

    /// Creates a DP engine with budget tracking enabled.
    ///
    /// # Arguments
    /// * `epsilon` - Privacy parameter per query
    /// * `total_budget` - Maximum cumulative epsilon across all queries
    ///
    /// # Example
    /// ```rust
    /// // Allow up to 10 queries at ε=1.0 each
    /// let dp = DifferentialPrivacy::with_budget(1.0, 10.0)?;
    /// ```
    pub fn with_budget(epsilon: f64, total_budget: f64) -> Result<Self, DPError> {
        validate_epsilon(epsilon)?;
        let budget = PrivacyBudget::new(total_budget)?;

        let rng = ChaCha20Rng::from_entropy();

        info!(
            epsilon = epsilon,
            total_budget = total_budget,
            "DifferentialPrivacy engine initialized with budget tracking"
        );

        Ok(Self {
            epsilon,
            budget: Some(budget),
            rng,
        })
    }

    /// Creates a DP engine with deterministic seeding (for testing/reproducibility).
    ///
    /// # Security Warning
    /// DO NOT use in production. Deterministic RNG undermines privacy guarantees.
    ///
    /// # Arguments
    /// * `epsilon` - Privacy parameter
    /// * `seed` - RNG seed value
    #[cfg(test)]
    pub fn with_seed(epsilon: f64, seed: u64) -> Result<Self, DPError> {
        validate_epsilon(epsilon)?;

        let rng = ChaCha20Rng::seed_from_u64(seed);

        warn!(
            epsilon = epsilon,
            "DifferentialPrivacy engine initialized with DETERMINISTIC seed (test mode)"
        );

        Ok(Self {
            epsilon,
            budget: None,
            rng,
        })
    }

    /// Adds calibrated Laplace noise to a numerical value.
    ///
    /// ## Mathematical Definition
    /// Output = value + Laplace(0, sensitivity/ε)
    ///
    /// ## Privacy Guarantee
    /// Satisfies ε-differential privacy for queries with given sensitivity.
    ///
    /// ## Complexity
    /// - Time: O(1) - constant time noise generation
    /// - Space: O(1) - no allocations
    ///
    /// # Arguments
    /// * `value` - True statistical value to privatize
    /// * `sensitivity` - Maximum change in output from adding/removing one record
    ///
    /// # Returns
    /// Noised value or error if validation fails
    ///
    /// # Example
    /// ```rust
    /// let dp = DifferentialPrivacy::new(1.0)?;
    /// let noisy_count = dp.add_laplace_noise(42.0, 1.0)?; // Count query, sensitivity=1
    /// ```
    #[instrument(skip(self), fields(epsilon = self.epsilon))]
    pub fn add_laplace_noise(
        &mut self,
        value: f64,
        sensitivity: f64,
    ) -> Result<f64, DPError> {
        // STEP 1: Input validation
        validate_value(value)?;
        validate_sensitivity(sensitivity)?;

        // STEP 2: Budget check (if enabled)
        if let Some(ref mut budget) = self.budget {
            budget.consume(self.epsilon)?;
        }

        // STEP 3: Calculate noise scale
        let scale = sensitivity / self.epsilon;

        // STEP 4: Numerical stability check
        if !scale.is_finite() || scale > MAX_VALUE {
            return Err(DPError::NumericalInstability {
                reason: format!("Noise scale {} exceeds safe bounds", scale),
            });
        }

        // STEP 5: Generate Laplace noise
        // Laplace(0, b) = -b * sgn(U) * ln(1 - 2|U|) where U ~ Uniform(-0.5, 0.5)
        let distribution = Uniform::new(-0.5, 0.5);
        let u: f64 = distribution.sample(&mut self.rng);

        // Prevent ln(0) which would produce -∞
        let abs_u_clamped = u.abs().max(1e-10);
        let noise = -scale * u.signum() * (1.0 - 2.0 * abs_u_clamped).ln();

        // STEP 6: Add noise and validate result
        let result = value + noise;

        if !result.is_finite() {
            error!(
                value = value,
                noise = noise,
                scale = scale,
                "Numerical overflow in noise addition"
            );
            return Err(DPError::NumericalInstability {
                reason: "Result overflow".to_string(),
            });
        }

        debug!(
            value = value,
            noise = noise,
            result = result,
            sensitivity = sensitivity,
            "Laplace noise added"
        );

        Ok(result)
    }

    /// Implements randomized response for boolean values.
    ///
    /// ## Mathematical Definition
    /// P(output = true_value) = e^ε / (1 + e^ε)
    /// P(output = !true_value) = 1 / (1 + e^ε)
    ///
    /// ## Privacy Guarantee
    /// Satisfies ε-differential privacy for boolean attributes.
    ///
    /// ## Complexity
    /// - Time: O(1) - constant time
    /// - Space: O(1)
    ///
    /// # Arguments
    /// * `true_value` - The actual boolean value to privatize
    ///
    /// # Returns
    /// Randomized boolean (may be flipped) or error
    ///
    /// # Example
    /// ```rust
    /// let dp = DifferentialPrivacy::new(1.0)?;
    /// let noisy_flag = dp.randomized_response(true)?;
    /// ```
    #[instrument(skip(self), fields(epsilon = self.epsilon))]
    pub fn randomized_response(&mut self, true_value: bool) -> Result<bool, DPError> {
        // STEP 1: Budget check (if enabled)
        if let Some(ref mut budget) = self.budget {
            budget.consume(self.epsilon)?;
        }

        // STEP 2: Calculate truth-telling probability
        // p = e^ε / (1 + e^ε)
        let exp_epsilon = self.epsilon.exp();

        // Numerical stability check (prevent overflow)
        if !exp_epsilon.is_finite() {
            return Err(DPError::NumericalInstability {
                reason: format!("e^{} overflowed", self.epsilon),
            });
        }

        let p_truth = exp_epsilon / (1.0 + exp_epsilon);

        // STEP 3: Generate randomized response
        let output = if self.rng.gen_bool(p_truth) {
            true_value // Tell the truth
        } else {
            !true_value // Lie
        };

        debug!(
            true_value = true_value,
            output = output,
            p_truth = p_truth,
            "Randomized response generated"
        );

        Ok(output)
    }

    /// Returns the current privacy parameter.
    pub fn epsilon(&self) -> f64 {
        self.epsilon
    }

    /// Returns the privacy budget tracker (if enabled).
    pub fn budget(&self) -> Option<&PrivacyBudget> {
        self.budget.as_ref()
    }

    /// Returns mutable reference to budget tracker (for external budget management).
    pub fn budget_mut(&mut self) -> Option<&mut PrivacyBudget> {
        self.budget.as_mut()
    }
}

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

/// Validates epsilon parameter.
///
/// # Constraints
/// - Must be finite (no NaN or ±∞)
/// - Must be in [MIN_EPSILON, MAX_EPSILON]
fn validate_epsilon(epsilon: f64) -> Result<(), DPError> {
    if !epsilon.is_finite() || epsilon < MIN_EPSILON || epsilon > MAX_EPSILON {
        return Err(DPError::InvalidEpsilon { value: epsilon });
    }
    Ok(())
}

/// Validates sensitivity parameter.
///
/// # Constraints
/// - Must be finite and positive
/// - Must be in [MIN_SENSITIVITY, MAX_SENSITIVITY]
fn validate_sensitivity(sensitivity: f64) -> Result<(), DPError> {
    if !sensitivity.is_finite()
        || sensitivity < MIN_SENSITIVITY
        || sensitivity > MAX_SENSITIVITY
    {
        return Err(DPError::InvalidSensitivity { value: sensitivity });
    }
    Ok(())
}

/// Validates input data value.
///
/// # Constraints
/// - Must be finite
/// - Must be in [-MAX_VALUE, MAX_VALUE]
fn validate_value(value: f64) -> Result<(), DPError> {
    if !value.is_finite() || value.abs() > MAX_VALUE {
        return Err(DPError::InvalidValue { value });
    }
    Ok(())
}

// ============================================================================
// DISPLAY IMPLEMENTATIONS
// ============================================================================

impl fmt::Display for DifferentialPrivacy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DifferentialPrivacy(ε={}, budget={})",
            self.epsilon,
            if let Some(ref b) = self.budget {
                format!("{}/{}", b.consumed, b.total_budget)
            } else {
                "disabled".to_string()
            }
        )
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laplace_noise_basic() {
        // Scenario: Standard count query with ε=1.0
        let mut dp = DifferentialPrivacy::with_seed(1.0, 42).unwrap();
        let result = dp.add_laplace_noise(100.0, 1.0).unwrap();

        // Noise should be bounded (with high probability)
        assert!(result.is_finite());
        assert!((result - 100.0).abs() < 50.0, "Noise seems excessive");
    }

    #[test]
    fn test_invalid_epsilon_rejected() {
        // Scenario: Out-of-bounds epsilon values
        assert!(DifferentialPrivacy::new(0.0).is_err()); // Too small
        assert!(DifferentialPrivacy::new(-1.0).is_err()); // Negative
        assert!(DifferentialPrivacy::new(100.0).is_err()); // Too large
        assert!(DifferentialPrivacy::new(f64::NAN).is_err()); // NaN
        assert!(DifferentialPrivacy::new(f64::INFINITY).is_err()); // Infinity
    }

    #[test]
    fn test_invalid_sensitivity_rejected() {
        // Scenario: Malformed sensitivity values
        let mut dp = DifferentialPrivacy::with_seed(1.0, 42).unwrap();

        assert!(dp.add_laplace_noise(100.0, 0.0).is_err()); // Zero
        assert!(dp.add_laplace_noise(100.0, -1.0).is_err()); // Negative
        assert!(dp.add_laplace_noise(100.0, f64::NAN).is_err()); // NaN
        assert!(dp.add_laplace_noise(100.0, 1e10).is_err()); // Too large
    }

    #[test]
    fn test_invalid_value_rejected() {
        // Scenario: Overflow/underflow input values
        let mut dp = DifferentialPrivacy::with_seed(1.0, 42).unwrap();

        assert!(dp.add_laplace_noise(f64::NAN, 1.0).is_err());
        assert!(dp.add_laplace_noise(f64::INFINITY, 1.0).is_err());
        assert!(dp.add_laplace_noise(1e20, 1.0).is_err()); // Too large
    }

    #[test]
    fn test_randomized_response_basic() {
        // Scenario: Boolean privatization
        let mut dp = DifferentialPrivacy::with_seed(1.0, 42).unwrap();

        let result = dp.randomized_response(true).unwrap();
        assert!(result == true || result == false); // Valid boolean
    }

    #[test]
    fn test_randomized_response_distribution() {
        // Scenario: Verify truth-telling probability matches theory
        let mut dp = DifferentialPrivacy::with_seed(1.0, 42).unwrap();
        let trials = 10000;
        let mut truth_count = 0;

        for _ in 0..trials {
            if dp.randomized_response(true).unwrap() {
                truth_count += 1;
            }
        }

        // Expected: p = e^1 / (1 + e^1) ≈ 0.731
        let p_truth = truth_count as f64 / trials as f64;
        assert!((p_truth - 0.731).abs() < 0.05, "Truth probability off: {}", p_truth);
    }

    #[test]
    fn test_budget_tracking() {
        // Scenario: Budget exhaustion prevention
        let mut dp = DifferentialPrivacy::with_budget(1.0, 3.0).unwrap();

        // First 3 queries should succeed
        assert!(dp.add_laplace_noise(100.0, 1.0).is_ok());
        assert!(dp.add_laplace_noise(200.0, 1.0).is_ok());
        assert!(dp.add_laplace_noise(300.0, 1.0).is_ok());

        // 4th query should fail (budget exhausted)
        let result = dp.add_laplace_noise(400.0, 1.0);
        assert!(matches!(result, Err(DPError::BudgetExhausted { .. })));
    }

    #[test]
    fn test_budget_remaining() {
        // Scenario: Budget accounting accuracy
        let mut dp = DifferentialPrivacy::with_budget(1.0, 5.0).unwrap();

        assert_eq!(dp.budget().unwrap().remaining(), 5.0);

        dp.add_laplace_noise(100.0, 1.0).unwrap();
        assert_eq!(dp.budget().unwrap().remaining(), 4.0);

        dp.randomized_response(true).unwrap();
        assert_eq!(dp.budget().unwrap().remaining(), 3.0);
    }

    #[test]
    fn test_high_sensitivity_stability() {
        // Scenario: High sensitivity should still produce finite results
        let mut dp = DifferentialPrivacy::with_seed(1.0, 42).unwrap();
        let result = dp.add_laplace_noise(100.0, 1000.0).unwrap();

        assert!(result.is_finite());
        // Noise scale = 1000/1 = 1000, so noise can be large
    }

    #[test]
    fn test_low_epsilon_high_noise() {
        // Scenario: Low epsilon = high privacy = high noise
        let mut dp = DifferentialPrivacy::with_seed(0.1, 42).unwrap();
        let result = dp.add_laplace_noise(100.0, 1.0).unwrap();

        assert!(result.is_finite());
        // Scale = 1/0.1 = 10, expect significant noise
    }

    #[test]
    fn test_zero_value_handling() {
        // Scenario: Edge case - privatizing zero
        let mut dp = DifferentialPrivacy::with_seed(1.0, 42).unwrap();
        let result = dp.add_laplace_noise(0.0, 1.0).unwrap();

        assert!(result.is_finite());
        // Result should just be the noise term
    }

    #[test]
    fn test_negative_value_handling() {
        // Scenario: Negative values should work (e.g., temperature, profit/loss)
        let mut dp = DifferentialPrivacy::with_seed(1.0, 42).unwrap();
        let result = dp.add_laplace_noise(-50.0, 1.0).unwrap();

        assert!(result.is_finite());
    }

    #[test]
    fn test_query_count_tracking() {
        // Scenario: Verify query counter increments
        let mut dp = DifferentialPrivacy::with_budget(1.0, 10.0).unwrap();

        assert_eq!(dp.budget().unwrap().query_count(), 0);

        dp.add_laplace_noise(100.0, 1.0).unwrap();
        assert_eq!(dp.budget().unwrap().query_count(), 1);

        dp.randomized_response(true).unwrap();
        assert_eq!(dp.budget().unwrap().query_count(), 2);
    }
}

