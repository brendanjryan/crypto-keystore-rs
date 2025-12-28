mod common;

use common::*;
use crypto_keystore_rs::{ChainKey, KeystoreError};

#[cfg(feature = "ethereum")]
use crypto_keystore_rs::{EthereumKey, EthereumKeystore, Keystore};

#[cfg(feature = "solana")]
use crypto_keystore_rs::{SolanaKey, SolanaKeystore};

// =======================
// InvalidKey Error Tests
// =======================

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_rejects_wrong_key_length() {
    let bytes_too_short = vec![0u8; 16]; // Wrong size, should be 32
    let result = EthereumKey::from_keystore_bytes(&bytes_too_short);
    assert!(matches!(result, Err(KeystoreError::InvalidKey { .. })));

    let bytes_too_long = vec![0u8; 64]; // Wrong size, should be 32
    let result = EthereumKey::from_keystore_bytes(&bytes_too_long);
    assert!(matches!(result, Err(KeystoreError::InvalidKey { .. })));
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_rejects_invalid_secp256k1_bytes() {
    // All 0xFF is not a valid secp256k1 private key (greater than curve order)
    let invalid_bytes = vec![0xFF; 32];
    let result = EthereumKey::from_keystore_bytes(&invalid_bytes);
    assert!(matches!(result, Err(KeystoreError::InvalidKey { .. })));

    // All zeros is not a valid private key
    let zero_bytes = vec![0x00; 32];
    let result = EthereumKey::from_keystore_bytes(&zero_bytes);
    assert!(matches!(result, Err(KeystoreError::InvalidKey { .. })));
}

#[test]
#[cfg(feature = "solana")]
fn solana_rejects_wrong_key_length() {
    let bytes_too_short = vec![0u8; 32]; // Wrong size, should be 64
    let result = SolanaKey::from_keystore_bytes(&bytes_too_short);
    assert!(matches!(result, Err(KeystoreError::InvalidKey { .. })));

    let bytes_too_long = vec![0u8; 128]; // Wrong size, should be 64
    let result = SolanaKey::from_keystore_bytes(&bytes_too_long);
    assert!(matches!(result, Err(KeystoreError::InvalidKey { .. })));
}

// ==========================
// UnsupportedVersion Error Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn rejects_unsupported_version_99() {
    let json = create_keystore_json_with_version(99);
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    if let Err(ref e) = result {
        println!("Actual error: {:?}", e);
    }
    assert!(matches!(result, Err(KeystoreError::UnsupportedVersion(99))));
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_unsupported_version_0() {
    let json = create_keystore_json_with_version(0);
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::UnsupportedVersion(0))));
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_unsupported_version_2() {
    let json = create_keystore_json_with_version(2);
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::UnsupportedVersion(2))));
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_future_version_5() {
    let json = create_keystore_json_with_version(5);
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::UnsupportedVersion(5))));
}

// ==========================
// UnsupportedCipher Error Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn rejects_aes_256_gcm_cipher() {
    let json = create_keystore_json_with_cipher("aes-256-gcm");
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::UnsupportedCipher(_))));
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_aes_128_cbc_cipher() {
    let json = create_keystore_json_with_cipher("aes-128-cbc");
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::UnsupportedCipher(_))));
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_unknown_cipher() {
    let json = create_keystore_json_with_cipher("unknown-cipher");
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::UnsupportedCipher(_))));
}

// ====================
// UnsupportedKdf Error Tests
// ====================

#[test]
#[cfg(feature = "ethereum")]
fn rejects_argon2_kdf() {
    let json = create_keystore_json_with_unsupported_kdf();
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    // Unknown KDF types fail during deserialization, not KDF validation
    assert!(result.is_err());
    assert!(matches!(result, Err(KeystoreError::SerializationError(_))));
}

// ==========================
// InvalidKdfParams Error Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn rejects_non_power_of_two_scrypt_n() {
    // Scrypt N must be a power of 2
    let json = create_keystore_json_with_scrypt_n(12345);
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(result.is_err());
    // Note: scrypt library will return an error for invalid params
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_scrypt_n_too_small() {
    // N must be >= 2
    let json = create_keystore_json_with_scrypt_n(1);
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_unsupported_pbkdf2_prf() {
    // Only hmac-sha256 is supported
    let json = create_keystore_json_with_prf("hmac-sha512");
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::UnsupportedKdf(_))));
}

// ====================
// HexError Error Tests
// ====================

#[test]
#[cfg(feature = "ethereum")]
fn rejects_invalid_hex_in_ciphertext() {
    let json = create_keystore_json_with_invalid_hex();
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(result.is_err());
    // Will fail during hex decoding
}

// ====================
// IoError Error Tests
// ====================

#[test]
#[cfg(feature = "ethereum")]
fn load_from_nonexistent_file_fails() {
    let result = EthereumKeystore::load_from_file("/nonexistent/path/keystore.json", TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::IoError(_))));
}

#[test]
#[cfg(feature = "ethereum")]
fn load_from_invalid_path_fails() {
    let result = EthereumKeystore::load_from_file("/dev/null/impossible/path.json", TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::IoError(_))));
}

// ==============================
// SerializationError Error Tests
// ==============================

#[test]
#[cfg(feature = "ethereum")]
fn rejects_malformed_json() {
    let bad_json = "not valid json at all{{{";
    let result = EthereumKeystore::from_json(bad_json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::SerializationError(_))));
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_incomplete_keystore_json() {
    let json = create_incomplete_keystore_json();
    let result = EthereumKeystore::from_json(&json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::SerializationError(_))));
}

#[test]
#[cfg(feature = "ethereum")]
fn rejects_empty_json() {
    let empty_json = "{}";
    let result = EthereumKeystore::from_json(empty_json, TEST_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::SerializationError(_))));
}

// ==========================
// KeyNotDecrypted Error Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn accessing_key_before_decryption_fails() {
    // Use pre-generated keystore JSON to avoid slow KDF
    let json = r#"{
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf": "scrypt",
            "dklen": 32,
            "n": 16,
            "p": 1,
            "r": 8,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "ethereum"
    }"#;

    // Deserialize without decrypting (using serde_json directly)
    let keystore_without_key: Keystore<EthereumKey> = serde_json::from_str(json).unwrap();

    // Attempting to access the key should fail
    assert!(!keystore_without_key.is_decrypted());
    assert!(matches!(
        keystore_without_key.key(),
        Err(KeystoreError::KeyNotDecrypted)
    ));
}

#[test]
#[cfg(feature = "ethereum")]
fn accessing_address_before_decryption_fails() {
    // Use pre-generated keystore JSON to avoid slow KDF
    let json = r#"{
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf": "scrypt",
            "dklen": 32,
            "n": 16,
            "p": 1,
            "r": 8,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "ethereum"
    }"#;

    let keystore_without_key: Keystore<EthereumKey> = serde_json::from_str(json).unwrap();

    assert!(matches!(
        keystore_without_key.address(),
        Err(KeystoreError::KeyNotDecrypted)
    ));
}

// ==========================
// IncorrectPassword Error Tests
// (Already tested in ethereum.rs and solana.rs)
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn wrong_password_returns_incorrect_password_error() {
    // Use a pre-generated keystore to avoid slow KDF
    let json = r#"{
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
            "kdf": "scrypt",
            "dklen": 32,
            "n": 16,
            "p": 1,
            "r": 8,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "ethereum"
    }"#;

    let result = EthereumKeystore::from_json(json, TEST_WRONG_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::IncorrectPassword)));
}

#[test]
#[cfg(feature = "solana")]
fn solana_wrong_password_returns_incorrect_password_error() {
    // Use a pre-generated keystore to avoid slow KDF
    let json = r#"{
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
            "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c8f5f4552091a69125d5dfcb7b8c2659029395bdf02d8ccb40e466191a123791e",
            "kdf": "scrypt",
            "dklen": 32,
            "n": 16,
            "p": 1,
            "r": 8,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
        },
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
        "version": 4,
        "chain": "solana"
    }"#;

    let result = SolanaKeystore::from_json(json, TEST_WRONG_PASSWORD);
    assert!(matches!(result, Err(KeystoreError::IncorrectPassword)));
}

// ========================
// Password Edge Cases
// ========================
// Note: Edge case password tests (empty, long, special chars, unicode)
// have been moved to integration tests to avoid slow KDF operations in error tests.
// These are tested indirectly through the roundtrip tests in ethereum.rs/solana.rs.
