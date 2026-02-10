use anyhow::{anyhow, Result};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Standard AES-GCM
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;

/// Simulates a cloud KMS client (AWS/GCP) for envelope encryption.
/// In a real production environment, this would use `aws-sdk-kms` or `google-cloud-kms`.
/// For this "Adversarial Vault" simulation, we implement a local AES-GCM decryptor
/// that uses a mock "Root Key" to unlock the vector payloads.
pub struct KmsClient {
    root_key: Key<Aes256Gcm>,
}

impl KmsClient {
    pub fn new(mock_key_bytes: &[u8; 32]) -> Self {
        Self {
            root_key: *Key::<Aes256Gcm>::from_slice(mock_key_bytes),
        }
    }

    /// Decrypts a payload that was envelope-encrypted with the KMS key.
    /// Expects the format: [NONCE (12 bytes) | CIPHERTEXT]
    pub async fn decrypt(&self, key_id: &str, encrypted_blob: &[u8]) -> Result<Vec<u8>> {
        // In real KMS, key_id would be sent to the cloud.
        // Here, we verify the key_id matches our "mock" configuration.
        if key_id != "arn:aws:kms:us-west-2:123456789012:key/mrk-adversarial-vault" {
             // We allow a specific test key ID
             if key_id != "test-u-key-id" {
                return Err(anyhow!("KMS Access Denied: Invalid Key ID '{}'", key_id));
             }
        }

        if encrypted_blob.len() < 12 {
            return Err(anyhow!("Invalid Ciphertext: Too short"));
        }

        let nonce_bytes = &encrypted_blob[0..12];
        let ciphertext = &encrypted_blob[12..];

        let cipher = Aes256Gcm::new(&self.root_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption Failed (Auth Tag Mismatch): {}", e))
    }
}

/// Helper to simulate the decrypt function call style from the user prompt
pub async fn decrypt(key_id: &str, encrypted_blob: Vec<u8>) -> Result<Vec<u8>> {
    // For the static helper, we generate a deterministic key based on the key_id hash or fixed seed
    // This is purely for the "Vault Manager" to compile and run logic.
    // In production, the VaultManager would hold an instance of KmsClient.
    
    // FIX: To make this robust without holding state, we use a fixed zero-key for the simulation
    // or we assume the blob is actually just plaintext for this specific test step if we can't share keys?
    // User asked for "AES-GCM Encrypted Blobs". 
    // Let's use a fixed key related to the "ZeroTrace" string for simulation.
    
    let key_bytes = b"ZeroTrace_Adversarial_Vault_Key!"; // 32 bytes
    let client = KmsClient::new(key_bytes);
    client.decrypt(key_id, &encrypted_blob).await
}
