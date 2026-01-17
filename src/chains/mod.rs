use crate::error::Result;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

pub mod macros;

#[cfg(feature = "ethereum")]
pub mod ethereum;
#[cfg(feature = "solana")]
pub mod solana;

#[cfg(feature = "ethereum")]
pub use ethereum::EthereumKey;
#[cfg(feature = "solana")]
pub use solana::SolanaKey;

/// Trait for blockchain-specific key types.
///
/// This trait defines the interface for different blockchain key implementations,
/// allowing the keystore to be generic over the chain type.
///
/// # Safety
///
/// Implementors should ensure that `from_keystore_bytes` properly validates
/// the input and returns an error for invalid key material.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "ethereum")]
/// # {
/// use crypto_keystore_rs::{ChainKey, EthereumKey};
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
/// let key = EthereumKey::generate(&mut rng);
/// let address = key.address();
/// # }
/// ```
pub trait ChainKey: Sized + Clone {
    /// Size of the secret key material in bytes (typically 32)
    const SECRET_KEY_SIZE: usize;

    /// Total size to store in keystore (32 for ETH, 64 for Solana)
    const KEYSTORE_SIZE: usize;

    /// Chain identifier for the keystore JSON
    const CHAIN_ID: &'static str;

    /// Serialize key material for encryption
    fn to_keystore_bytes(&self) -> Zeroizing<Vec<u8>>;

    /// Deserialize from decrypted bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid or the wrong length
    fn from_keystore_bytes(bytes: &[u8]) -> Result<Self>;

    /// Generate a new random key
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self;

    /// Get the blockchain address as a string
    #[must_use]
    fn address(&self) -> String;

    /// Validate keystore bytes length
    ///
    /// Provides default validation that bytes match expected KEYSTORE_SIZE.
    /// Called by `from_keystore_bytes` implementations.
    fn validate_keystore_size(bytes: &[u8]) -> Result<()> {
        if bytes.len() != Self::KEYSTORE_SIZE {
            return Err(crate::error::KeystoreError::InvalidKey {
                chain: Self::CHAIN_ID.into(),
                reason: format!(
                    "Expected {} bytes, got {}",
                    Self::KEYSTORE_SIZE,
                    bytes.len()
                ),
            });
        }
        Ok(())
    }
}
