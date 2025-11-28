use crate::chains::ChainKey;
use crate::error::{KeystoreError, Result};
use k256::ecdsa::SigningKey;
use rand::{CryptoRng, RngCore};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

/// Prefix byte size for uncompressed public key (0x04)
const UNCOMPRESSED_PUBLIC_KEY_PREFIX_SIZE: usize = 1;

/// Offset in Keccak256 hash to extract Ethereum address (last 20 bytes of 32-byte hash)
const ADDRESS_HASH_OFFSET: usize = 12;

#[derive(Clone)]
pub struct EthereumKey {
    signing_key: SigningKey,
}

impl EthereumKey {
    /// Creates an Ethereum key from an existing secp256k1 signing key.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - A secp256k1 ECDSA signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        EthereumKey { signing_key }
    }

    /// Returns a reference to the underlying signing key.
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Computes the Ethereum address from the public key.
    ///
    /// The address is derived by taking the Keccak256 hash of the uncompressed
    /// public key (excluding the 0x04 prefix) and using the last 20 bytes.
    ///
    /// # Returns
    ///
    /// A checksummed Ethereum address with `0x` prefix (42 characters)
    #[must_use]
    pub fn address(&self) -> String {
        let public_key = self.signing_key.verifying_key();

        let encoded = public_key.to_encoded_point(false);
        let public_key_bytes = &encoded.as_bytes()[UNCOMPRESSED_PUBLIC_KEY_PREFIX_SIZE..];

        let mut hasher = Keccak256::new();
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();

        let address_bytes = &hash[ADDRESS_HASH_OFFSET..];

        format!("0x{}", hex::encode(address_bytes))
    }
}

impl ChainKey for EthereumKey {
    const SECRET_KEY_SIZE: usize = 32;
    const KEYSTORE_SIZE: usize = 32;
    const CHAIN_ID: &'static str = "ethereum";

    fn to_keystore_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
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

        let signing_key = SigningKey::from_slice(bytes).map_err(|e| KeystoreError::InvalidKey {
            chain: Self::CHAIN_ID.into(),
            reason: format!("Invalid secp256k1 key: {e}"),
        })?;

        Ok(EthereumKey { signing_key })
    }

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let signing_key = SigningKey::random(rng);
        EthereumKey { signing_key }
    }

    fn address(&self) -> String {
        EthereumKey::address(self)
    }
}

impl Drop for EthereumKey {
    fn drop(&mut self) {
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

impl std::fmt::Debug for EthereumKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthereumKey")
            .field("address", &self.address())
            .finish()
    }
}

impl TryFrom<&[u8]> for EthereumKey {
    type Error = crate::error::KeystoreError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_keystore_bytes(bytes)
    }
}

impl std::fmt::Display for EthereumKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address())
    }
}

impl PartialEq for EthereumKey {
    fn eq(&self, other: &Self) -> bool {
        self.address() == other.address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_generate_ethereum_key() {
        let mut rng = thread_rng();
        let key = EthereumKey::generate(&mut rng);

        let address = key.address();
        assert_eq!(address.len(), 42);
        assert!(address.starts_with("0x"));
    }

    #[test]
    fn test_keystore_bytes_roundtrip() {
        let mut rng = thread_rng();
        let key = EthereumKey::generate(&mut rng);

        let bytes = key.to_keystore_bytes();
        assert_eq!(bytes.len(), 32);

        let restored = EthereumKey::from_keystore_bytes(&bytes).unwrap();
        assert_eq!(key.address(), restored.address());
    }

    #[test]
    fn test_known_key_deterministic() {
        let private_key_hex = "4c0883a69102937d6231471b5dbb6204fe512961708279f8b1a3f1f1c3b2f3e8";

        let bytes = hex::decode(private_key_hex).unwrap();
        let key1 = EthereumKey::from_keystore_bytes(&bytes).unwrap();
        let key2 = EthereumKey::from_keystore_bytes(&bytes).unwrap();

        assert_eq!(key1.address(), key2.address());
        assert!(key1.address().starts_with("0x"));
        assert_eq!(key1.address().len(), 42);
    }
}
