#![allow(dead_code)]

use serde_json::json;
use tempfile::{tempdir, TempDir};

/// Standard test password for consistent testing
pub const TEST_PASSWORD: &str = "test_password_123";
pub const TEST_WRONG_PASSWORD: &str = "wrong_password_456";

/// Creates a temporary directory for keystore testing
/// Automatically cleaned up when TempDir is dropped
pub fn create_temp_keystore_dir() -> TempDir {
    tempdir().expect("Failed to create temp directory")
}

/// Validates that a string is a properly formatted Ethereum address
/// Format: 0x followed by 40 hexadecimal characters
#[cfg(feature = "ethereum")]
pub fn assert_valid_ethereum_address(addr: &str) {
    assert_eq!(
        addr.len(),
        42,
        "Ethereum address should be 42 characters long"
    );
    assert!(
        addr.starts_with("0x"),
        "Ethereum address should start with 0x"
    );
    assert!(
        addr[2..].chars().all(|c| c.is_ascii_hexdigit()),
        "Ethereum address should contain only hexadecimal characters after 0x"
    );
}

/// Validates that a string is a properly formatted Solana address
/// Format: Base58 encoded string between 32-44 characters
#[cfg(feature = "solana")]
pub fn assert_valid_solana_address(addr: &str) {
    assert!(
        addr.len() >= 32 && addr.len() <= 44,
        "Solana address should be between 32 and 44 characters"
    );
    assert!(
        bs58::decode(addr).into_vec().is_ok(),
        "Solana address should be valid base58"
    );
}

/// Helper to create a keystore JSON with a specific version for testing
pub fn create_keystore_json_with_version(version: u32) -> String {
    json!({
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "83dbcc02d8ccb40e466191a123791e0e"
            },
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf": "scrypt",
            "dklen": 32,
            "n": 16,  // Use weak params for fast testing
            "p": 1,
            "r": 8,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": version,
        "chain": "ethereum"
    })
    .to_string()
}

/// Helper to create a keystore JSON with a specific cipher for testing
pub fn create_keystore_json_with_cipher(cipher: &str) -> String {
    json!({
        "crypto": {
            "cipher": cipher,
            "cipherparams": {
                "iv": "83dbcc02d8ccb40e466191a123791e0e"
            },
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf": "scrypt",
            "dklen": 32,
            "n": 16,  // Use weak params for fast testing
            "p": 1,
            "r": 8,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "ethereum"
    })
    .to_string()
}

/// Helper to create a keystore JSON with a specific scrypt N parameter
pub fn create_keystore_json_with_scrypt_n(n: u32) -> String {
    json!({
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "83dbcc02d8ccb40e466191a123791e0e"
            },
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": n,
                "p": 1,
                "r": 8,
                "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
            },
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "ethereum"
    })
    .to_string()
}

/// Helper to create a keystore JSON with a specific PBKDF2 PRF
pub fn create_keystore_json_with_prf(prf: &str) -> String {
    json!({
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "83dbcc02d8ccb40e466191a123791e0e"
            },
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf": "pbkdf2",
            "dklen": 32,
            "c": 262144,
            "prf": prf,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "ethereum"
    })
    .to_string()
}

/// Helper to create a keystore JSON with missing required fields
pub fn create_incomplete_keystore_json() -> String {
    json!({
        "version": 4
    })
    .to_string()
}

/// Helper to create invalid hex in ciphertext
pub fn create_keystore_json_with_invalid_hex() -> String {
    json!({
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "83dbcc02d8ccb40e466191a123791e0e"
            },
            "ciphertext": "ZZZZ_invalid_hex_ZZZZ",
            "kdf": "scrypt",
            "dklen": 32,
            "n": 16,  // Use weak params for fast testing
            "p": 1,
            "r": 8,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "ethereum"
    })
    .to_string()
}

/// Helper to create a keystore JSON with unsupported KDF
pub fn create_keystore_json_with_unsupported_kdf() -> String {
    json!({
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "83dbcc02d8ccb40e466191a123791e0e"
            },
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf": "argon2",
            "dklen": 32,
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "ethereum"
    })
    .to_string()
}

/// Fixture structure for test keystores with known values
pub struct KeystoreFixture {
    pub json: String,
    pub password: String,
    pub expected_address: Option<String>,
}

impl KeystoreFixture {
    /// Creates a minimal valid Ethereum v3 keystore fixture
    #[cfg(feature = "ethereum")]
    pub fn ethereum_v3_minimal() -> Self {
        Self {
            json: include_str!("../fixtures/ethereum_v3.json").to_string(),
            password: "testpassword".to_string(),
            expected_address: Some("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".to_string()),
        }
    }

    /// Creates an Ethereum v4 keystore with Scrypt KDF
    #[cfg(feature = "ethereum")]
    pub fn ethereum_v4_scrypt() -> Self {
        Self {
            json: include_str!("../fixtures/ethereum_v4_scrypt.json").to_string(),
            password: "testpassword".to_string(),
            expected_address: None, // Will be validated separately
        }
    }

    /// Creates an Ethereum v4 keystore with PBKDF2 KDF
    #[cfg(feature = "ethereum")]
    pub fn ethereum_v4_pbkdf2() -> Self {
        Self {
            json: include_str!("../fixtures/ethereum_v4_pbkdf2.json").to_string(),
            password: "testpassword".to_string(),
            expected_address: None,
        }
    }

    /// Creates a Solana v4 keystore
    #[cfg(feature = "solana")]
    pub fn solana_v4() -> Self {
        Self {
            json: include_str!("../fixtures/solana_v4.json").to_string(),
            password: "testpassword".to_string(),
            expected_address: None,
        }
    }
}

/// Helper to assert that an error matches a specific variant
#[macro_export]
macro_rules! assert_error_variant {
    ($result:expr, $pattern:pat) => {
        match $result {
            Err($pattern) => {}
            other => panic!(
                "Expected error variant {}, but got: {:?}",
                stringify!($pattern),
                other
            ),
        }
    };
}
