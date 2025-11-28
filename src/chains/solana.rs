use crate::chains::ChainKey;
use crate::error::{KeystoreError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Size of Ed25519 secret key in bytes
const SECRET_KEY_SIZE: usize = 32;

/// Size of Ed25519 public key in bytes
const PUBLIC_KEY_SIZE: usize = 32;

#[derive(Clone)]
pub struct SolanaKey {
    signing_key: SigningKey,
}

impl SolanaKey {
    /// Creates a Solana key from an existing Ed25519 signing key.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - An Ed25519 signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        SolanaKey { signing_key }
    }

    /// Returns a reference to the underlying signing key.
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Derives the Ed25519 verifying (public) key from the signing key.
    ///
    /// This is computed on-demand rather than stored to save memory.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Computes the Solana address (base58-encoded public key).
    ///
    /// # Returns
    ///
    /// A base58-encoded string representation of the public key (typically 32-44 characters)
    #[must_use]
    pub fn address(&self) -> String {
        bs58::encode(self.verifying_key().as_bytes()).into_string()
    }

    /// Serializes the keypair to a 64-byte array (32-byte secret + 32-byte public).
    ///
    /// This format is compatible with Solana's keypair file format.
    ///
    /// # Returns
    ///
    /// A 64-byte array containing the secret key followed by the public key
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..SECRET_KEY_SIZE].copy_from_slice(&self.signing_key.to_bytes());
        let verifying_key = self.signing_key.verifying_key();
        bytes[SECRET_KEY_SIZE..].copy_from_slice(verifying_key.as_bytes());
        bytes
    }
}

impl ChainKey for SolanaKey {
    const SECRET_KEY_SIZE: usize = 32;
    const KEYSTORE_SIZE: usize = 64;
    const CHAIN_ID: &'static str = "solana";

    fn to_keystore_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_keystore_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::KEYSTORE_SIZE {
            return Err(KeystoreError::InvalidKey {
                chain: Self::CHAIN_ID.into(),
                reason: format!(
                    "Expected {} bytes, got {}",
                    Self::KEYSTORE_SIZE,
                    bytes.len()
                ),
            });
        }

        // SAFETY: Length checked above, so slice access is safe
        let secret_bytes: [u8; SECRET_KEY_SIZE] = bytes[..SECRET_KEY_SIZE]
            .try_into()
            .expect("length already validated");
        let public_bytes: [u8; PUBLIC_KEY_SIZE] = bytes[SECRET_KEY_SIZE..]
            .try_into()
            .expect("length already validated");

        let signing_key = SigningKey::from_bytes(&secret_bytes);

        // Validate that stored public key matches the derived one
        let verifying_key =
            VerifyingKey::from_bytes(&public_bytes).map_err(|e| KeystoreError::InvalidKey {
                chain: Self::CHAIN_ID.into(),
                reason: format!("Invalid public key: {e}"),
            })?;

        if signing_key.verifying_key().as_bytes() != verifying_key.as_bytes() {
            return Err(KeystoreError::InvalidKey {
                chain: Self::CHAIN_ID.into(),
                reason: "Public key does not match secret key".into(),
            });
        }

        Ok(SolanaKey { signing_key })
    }

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);
        SolanaKey { signing_key }
    }

    fn address(&self) -> String {
        SolanaKey::address(self)
    }
}

impl Drop for SolanaKey {
    fn drop(&mut self) {
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

impl std::fmt::Debug for SolanaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaKey")
            .field("address", &self.address())
            .finish()
    }
}

impl TryFrom<&[u8]> for SolanaKey {
    type Error = crate::error::KeystoreError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_keystore_bytes(bytes)
    }
}

impl std::fmt::Display for SolanaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address())
    }
}

impl PartialEq for SolanaKey {
    fn eq(&self, other: &Self) -> bool {
        self.address() == other.address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_generate_solana_key() {
        let mut rng = thread_rng();
        let key = SolanaKey::generate(&mut rng);

        let address = key.address();
        assert!(!address.is_empty());
        assert!(address.len() >= 32 && address.len() <= 44);
    }

    #[test]
    fn test_keystore_bytes_roundtrip() {
        let mut rng = thread_rng();
        let key = SolanaKey::generate(&mut rng);

        let bytes = key.to_keystore_bytes();
        assert_eq!(bytes.len(), 64);

        let restored = SolanaKey::from_keystore_bytes(&bytes).unwrap();
        assert_eq!(key.address(), restored.address());
    }

    #[test]
    fn test_keypair_consistency() {
        let mut rng = thread_rng();
        let key = SolanaKey::generate(&mut rng);

        let derived_public = key.signing_key().verifying_key();
        assert_eq!(derived_public.as_bytes(), key.verifying_key().as_bytes());
    }

    #[test]
    fn test_invalid_keypair_mismatch() {
        let mut rng = thread_rng();
        let key1 = SolanaKey::generate(&mut rng);
        let key2 = SolanaKey::generate(&mut rng);

        let mut bytes = vec![0u8; 64];
        bytes[..32].copy_from_slice(&key1.signing_key().to_bytes());
        bytes[32..].copy_from_slice(key2.verifying_key().as_bytes());

        let result = SolanaKey::from_keystore_bytes(&bytes);
        assert!(result.is_err());
    }
}
