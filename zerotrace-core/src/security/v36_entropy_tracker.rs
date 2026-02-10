use thiserror::Error;

#[derive(Debug, Error)]
pub enum EntropyError {
    #[error("Token-Drip Detected: Cumulative Entropy {0} exceeds threshold")]
    TokenDripDetected(f64),
}

pub struct EntropyTracker {
    pub alert_threshold: f64, // Threshold for 'Secret' density
}

impl Default for EntropyTracker {
    fn default() -> Self {
        Self::new(4.5) // Default high-entropy threshold
    }
}

impl EntropyTracker {
    pub fn new(threshold: f64) -> Self {
        Self {
            alert_threshold: threshold,
        }
    }

    pub fn calculate_cumulative_risk(&self, session_outputs: &[String]) -> Result<f64, EntropyError> {
        let total_text = session_outputs.join("");
        let byte_len = total_text.len() as f64;
        
        // 1. Calculate Shannon Entropy over the entire session history
        // If the entropy 'spikes' even though individual messages are small,
        // it indicates a structured data leak (Token-Drip).
        let entropy = self.compute_shannon_entropy(&total_text);
        
        // Only trigger if we have enough data (e.g., >= 20 chars) to be statistically relevant
        // and the entropy is suspiciously high (indicating compressed/encrypted/random data).
        if entropy > self.alert_threshold && byte_len >= 20.0 {
            return Err(EntropyError::TokenDripDetected(entropy));
        }
        
        Ok(entropy)
    }

    fn compute_shannon_entropy(&self, s: &str) -> f64 {
        if s.is_empty() { return 0.0; }
        
        let mut counts = [0usize; 256];
        for &b in s.as_bytes() { counts[b as usize] += 1; }
        
        counts.iter().filter(|&&c| c > 0).map(|&c| {
            let p = c as f64 / s.len() as f64;
            -p * p.log2()
        }).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_entropy_secret_drip() {
        let tracker = EntropyTracker::new(4.0);
        // Simulate dripping a high-entropy key: "8f3a1e..."
        // Each token is just one char, so per-token entropy is low (0).
        // But combined, they form a high-entropy string.
        let session = vec![
            "8".to_string(), "f".to_string(), "3".to_string(), "a".to_string(), 
            "1".to_string(), "e".to_string(), "9".to_string(), "c".to_string(),
            "7".to_string(), "b".to_string(), "2".to_string(), "d".to_string(),
            "4".to_string(), "0".to_string(), "5".to_string(), "6".to_string(),
            "A".to_string(), "F".to_string(), "B".to_string(), "E".to_string()
        ];
        
        let res = tracker.calculate_cumulative_risk(&session);
        assert!(matches!(res, Err(EntropyError::TokenDripDetected(_))));
    }

    #[test]
    fn test_low_entropy_english_drip() {
        let tracker = EntropyTracker::new(4.5);
        // English text has lower entropy (~3.5-4.0 bits/char usually)
        let session = vec![
            "t".to_string(), "h".to_string(), "e".to_string(), " ".to_string(),
            "q".to_string(), "u".to_string(), "i".to_string(), "c".to_string(),
            "k".to_string(), " ".to_string(), "b".to_string(), "r".to_string()
        ];
        
        let res = tracker.calculate_cumulative_risk(&session);
        assert!(res.is_ok());
    }
}
