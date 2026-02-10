use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MfaError {
    #[error("Identity Forge Blocked: Signature Verification Failed")]
    IdentityForgeBlocked,
    #[error("Invalid Signature Format")]
    InvalidSignatureFormat,
}

pub struct MfaGuard {
    pub executive_public_key: VerifyingKey,
}

impl MfaGuard {
    pub fn new(public_key_bytes: [u8; 32]) -> Result<Self, MfaError> {
        let executive_public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| MfaError::InvalidSignatureFormat)?;
            
        Ok(Self { executive_public_key })
    }

    pub fn authorize_high_privilege_action(
        &self, 
        action_payload: &str, 
        signature_bytes: &[u8; 64]
    ) -> Result<(), MfaError> {
        let signature = Signature::from_bytes(signature_bytes);

        // Verify the signature against the human's public key
        // This ensures the command came from a human, not a 'Doppelgänger' AI.
        self.executive_public_key
            .verify(action_payload.as_bytes(), &signature)
            .map_err(|_| MfaError::IdentityForgeBlocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::{RngCore, rngs::OsRng};

    #[test]
    fn test_valid_signature_authorization() {
        let mut csprng = OsRng;
        let mut key_bytes = [0u8; 32];
        csprng.fill_bytes(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        
        let guard = MfaGuard::new(verifying_key.to_bytes()).unwrap();
        
        let payload = "DEPLOY_PROD";
        let signature = signing_key.sign(payload.as_bytes());
        
        assert!(guard.authorize_high_privilege_action(payload, &signature.to_bytes()).is_ok());
    }

    #[test]
    fn test_forged_signature_blocked() {
        let mut csprng = OsRng;
        let mut key_bytes = [0u8; 32];
        csprng.fill_bytes(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        
        // Attacker key (Doppelgänger)
        let mut attacker_bytes = [0u8; 32];
        csprng.fill_bytes(&mut attacker_bytes);
        let attacker_key = SigningKey::from_bytes(&attacker_bytes);
        
        let guard = MfaGuard::new(verifying_key.to_bytes()).unwrap();
        
        let payload = "DEPLOY_PROD";
        // Signed by attacker, not executive
        let forged_signature = attacker_key.sign(payload.as_bytes());
        
        assert!(matches!(
            guard.authorize_high_privilege_action(payload, &forged_signature.to_bytes()), 
            Err(MfaError::IdentityForgeBlocked)
        ));
    }
}
