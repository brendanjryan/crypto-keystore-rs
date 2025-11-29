use std::io;
use thiserror::Error;

#[remain::sorted]
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("Corrupted keystore data")]
    CorruptedData,

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Hex decode error: {0}")]
    HexError(String),

    #[error("Incorrect password")]
    IncorrectPassword,

    #[error("Invalid KDF parameters: {0}")]
    InvalidKdfParams(String),

    #[error("Invalid key material for {chain}: {reason}")]
    InvalidKey { chain: String, reason: String },

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Keystore has not been decrypted yet")]
    KeyNotDecrypted,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),

    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("Unsupported KDF type: {0}")]
    UnsupportedKdf(String),

    #[error("Keystore version {0} not supported")]
    UnsupportedVersion(u32),
}

pub type Result<T> = std::result::Result<T, KeystoreError>;
