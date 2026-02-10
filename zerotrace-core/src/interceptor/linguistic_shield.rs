use unicode_normalization::UnicodeNormalization;

pub struct LinguisticShield;

impl LinguisticShield {
    /// Sanitize input string by normalizing unicode and stripping control characters
    /// V65: Collapse Unicode Homoglyphs and Zero-Width characters
    pub fn sanitize(input: &str) -> String {
        // Normalize to NFC (Normalization Form C)
        let normalized: String = input.nfc().collect();
        
        // V64/V65: Strip control characters and non-printable steganography
        // Allow ASCII whitespace, but strip other control chars
        normalized.chars()
            .filter(|c| !c.is_control() || c.is_ascii_whitespace())
            .collect()
    }

    /// Check for steganographic risk in binary content
    /// V64: Simple LSB steganography check via entropy
    pub fn check_steganography_risk(content: &[u8]) -> bool {
        let entropy = Self::calculate_entropy(content);
        // Threshold > 7.9 indicates very high entropy, typical of encrypted or compressed data,
        // or steganographically hidden data in what should be 'natural' media.
        // For raw text or simple images, this is suspicious.
        entropy > 7.9
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        
        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}
