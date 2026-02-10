use rand::prelude::*;
use rand::distributions::{Distribution, Uniform};

/// Differential Privacy Engine.
/// Implements basic mechanisms to add noise to statistical outputs, preventing membership inference.
pub struct DifferentialPrivacy {
    epsilon: f64, // Privacy budget
}

impl DifferentialPrivacy {
    pub fn new(epsilon: f64) -> Self {
        Self { epsilon }
    }

    /// Adds Laplace noise to a numerical value (e.g., a count or score).
    /// Mechanism: sensitive_value + Laplace(0, sensitivity/epsilon)
    pub fn add_laplace_noise(&self, value: f64, sensitivity: f64) -> f64 {
        let mut rng = rand::thread_rng();
        let scale = sensitivity / self.epsilon;
        
        // Generate Laplace noise using uniform distribution
        // X = \mu - b * sgn(U) * ln(1 - 2|U|) where U ~ Uniform(-0.5, 0.5)
        let u = Uniform::new(-0.5, 0.5).sample(&mut rng);
        let noise = -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln();

        value + noise
    }

    /// Randomized Response for boolean indicators.
    /// Flips the true answer with probability p.
    pub fn randomized_response(&self, true_value: bool) -> bool {
        let mut rng = rand::thread_rng();
        // Probability of telling the truth
        let p = self.epsilon.exp() / (1.0 + self.epsilon.exp());
        
        if rng.gen_bool(p) {
            true_value
        } else {
            !true_value // Lie
        }
    }
}
