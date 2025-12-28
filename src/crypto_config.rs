//! Cryptographic configuration constants for keystores
//!
//! This module centralizes all cryptographic parameters used in keystore
//! encryption and key derivation.

/// AES cipher mode used for keystore encryption
pub(crate) const CIPHER_NAME: &str = "aes-128-ctr";

/// Size of derived encryption key in bytes
pub(crate) const DEFAULT_KEY_SIZE: usize = 32;

/// Size of initialization vector for AES-CTR
pub(crate) const DEFAULT_IV_SIZE: usize = 16;

/// Size of encryption key portion (first 16 bytes of derived key)
pub(crate) const ENCRYPTION_KEY_SIZE: usize = 16;

/// Size of MAC key portion (last 16 bytes of derived key)
pub(crate) const MAC_KEY_SIZE: usize = 16;

/// Length of key derivation function output
pub(crate) const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32;

/// Supported pseudo-random function for PBKDF2
pub(crate) const SUPPORTED_PRF: &str = "hmac-sha256";

// Scrypt parameters with production/test variants
#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) const DEFAULT_KDF_PARAMS_LOG_N: u8 = 18; // N = 262144 (production)

#[cfg(any(test, feature = "test-utils"))]
pub(crate) const DEFAULT_KDF_PARAMS_LOG_N: u8 = 4; // N = 16 (fast for tests)

/// Scrypt r parameter (block size)
pub(crate) const DEFAULT_KDF_PARAMS_R: u32 = 8;

/// Scrypt p parameter (parallelization)
pub(crate) const DEFAULT_KDF_PARAMS_P: u32 = 1;

/// Computed Scrypt N parameter (2^LOG_N)
#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) const SCRYPT_N: u32 = 1 << DEFAULT_KDF_PARAMS_LOG_N; // 262144

#[cfg(any(test, feature = "test-utils"))]
pub(crate) const SCRYPT_N: u32 = 1 << DEFAULT_KDF_PARAMS_LOG_N; // 16
