// src/security/v53_biometric_liveness.rs
// Vector 53: Biometric Injection Attack
// Defense: IAD (Injection Attack Detection). Verifies User Verification (UV) and AAGUID.

// Mocking webauthn structures to avoid huge dependency tree for this targeted implementation
pub struct AuthResult {
    pub uv_enforced: bool,
    pub aaguid: String,
}

#[derive(Debug, PartialEq)]
pub enum BiometricError {
    UvMissing,
    UntrustedHardware,
}

pub struct LivenessVerifier {
    trusted_aaguids: Vec<String>,
}

impl LivenessVerifier {
    pub fn new(trusted_guids: Vec<String>) -> Self {
        Self {
            trusted_aaguids: trusted_guids,
        }
    }

    pub fn verify_liveness(&self, result: &AuthResult) -> Result<(), BiometricError> {
        // V53 Defense: Check UV flag
        if !result.uv_enforced {
            return Err(BiometricError::UvMissing);
        }

        // Check AAGUID against hardware anchor list
        if !self.trusted_aaguids.contains(&result.aaguid) {
            return Err(BiometricError::UntrustedHardware);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_check() {
        let trusted = vec!["yubikey-guid-1".to_string(), "faceid-guid-2".to_string()];
        let verifier = LivenessVerifier::new(trusted);

        // Valid
        let valid_auth = AuthResult {
            uv_enforced: true,
            aaguid: "yubikey-guid-1".to_string(),
        };
        assert_eq!(verifier.verify_liveness(&valid_auth), Ok(()));

        // Missing UV (Injection)
        let injection_attempt = AuthResult {
            uv_enforced: false,
            aaguid: "yubikey-guid-1".to_string(),
        };
        assert_eq!(
            verifier.verify_liveness(&injection_attempt),
            Err(BiometricError::UvMissing)
        );

        // Untrusted Authenticator (Software Emulator)
        let emulator = AuthResult {
            uv_enforced: true,
            aaguid: "soft-token-999".to_string(),
        };
        assert_eq!(
            verifier.verify_liveness(&emulator),
            Err(BiometricError::UntrustedHardware)
        );
    }
}
