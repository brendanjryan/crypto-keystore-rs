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

/// Supported pseudo-random function for PBKDF2
pub(crate) const SUPPORTED_PRF: &str = "hmac-sha256";
