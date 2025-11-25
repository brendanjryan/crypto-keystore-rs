use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("Invalid password or corrupted keystore")]
    DecryptionFailed,

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),

    #[error("Invalid key material for {chain}: {reason}")]
    InvalidKey { chain: String, reason: String },

    #[error("Keystore version {0} not supported")]
    UnsupportedVersion(u32),

    #[error("Unsupported KDF type: {0}")]
    UnsupportedKdf(String),

    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("Invalid KDF parameters: {0}")]
    InvalidKdfParams(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Hex decode error: {0}")]
    HexError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

pub type Result<T> = std::result::Result<T, KeystoreError>;
