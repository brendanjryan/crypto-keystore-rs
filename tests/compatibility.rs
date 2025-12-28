mod common;

use common::TEST_PASSWORD;
use crypto_keystore_rs::{KdfConfig, VERSION_4};

#[cfg(feature = "ethereum")]
use crypto_keystore_rs::EthereumKeystore;

#[cfg(feature = "solana")]
use crypto_keystore_rs::SolanaKeystore;

// ==========================
// Version 4 (Multi-Chain) Format Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn v4_ethereum_keystore_roundtrip() {
    // Create a V4 Ethereum keystore
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let original_address = keystore.key().unwrap().address();

    // Verify it's V4 with chain field
    assert_eq!(keystore.version(), VERSION_4);
    assert_eq!(keystore.chain(), Some("ethereum"));

    // Serialize and deserialize
    let json = keystore.to_json().unwrap();
    let loaded = EthereumKeystore::from_json(&json, TEST_PASSWORD).unwrap();

    // Verify properties preserved
    assert_eq!(loaded.version(), VERSION_4);
    assert_eq!(loaded.chain(), Some("ethereum"));
    assert_eq!(loaded.key().unwrap().address(), original_address);
}

#[test]
#[cfg(feature = "solana")]
fn v4_solana_keystore_roundtrip() {
    // Create a V4 Solana keystore
    let keystore =
        SolanaKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let original_address = keystore.key().unwrap().address();

    // Verify it's V4 with chain field
    assert_eq!(keystore.version(), VERSION_4);
    assert_eq!(keystore.chain(), Some("solana"));

    // Serialize and deserialize
    let json = keystore.to_json().unwrap();
    let loaded = SolanaKeystore::from_json(&json, TEST_PASSWORD).unwrap();

    // Verify properties preserved
    assert_eq!(loaded.version(), VERSION_4);
    assert_eq!(loaded.chain(), Some("solana"));
    assert_eq!(loaded.key().unwrap().address(), original_address);
}

// ==========================
// KDF Compatibility Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn keystore_uses_scrypt_kdf_by_default() {
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let json = keystore.to_json().unwrap();

    // Should use Scrypt KDF
    assert!(json.contains("\"kdf\":\"scrypt\"") || json.contains("\"kdf\": \"scrypt\""));

    // Should be able to load it back
    let loaded = EthereumKeystore::from_json(&json, TEST_PASSWORD).unwrap();
    assert_eq!(
        keystore.key().unwrap().address(),
        loaded.key().unwrap().address()
    );
}

#[test]
#[cfg(feature = "ethereum")]
fn roundtrip_preserves_kdf_type_scrypt() {
    // Create keystore (uses Scrypt by default)
    let keystore1 =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let json1 = keystore1.to_json().unwrap();

    // Verify it uses scrypt
    assert!(json1.contains("\"kdf\":\"scrypt\"") || json1.contains("\"kdf\": \"scrypt\""));

    // Load and re-serialize
    let keystore2 = EthereumKeystore::from_json(&json1, TEST_PASSWORD).unwrap();
    let json2 = keystore2.to_json().unwrap();

    // Should still use scrypt
    assert!(json2.contains("\"kdf\":\"scrypt\"") || json2.contains("\"kdf\": \"scrypt\""));
}

// ==========================
// Cross-Version Compatibility
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn newly_created_keystores_use_v4_format() {
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();

    assert_eq!(keystore.version(), VERSION_4);
    assert_eq!(keystore.chain(), Some("ethereum"));
}

#[test]
#[cfg(feature = "solana")]
fn solana_keystores_use_v4_format() {
    let keystore =
        SolanaKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();

    assert_eq!(keystore.version(), VERSION_4);
    assert_eq!(keystore.chain(), Some("solana"));
}

// ==========================
// Keystore Size Compatibility
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_keystore_stores_32_byte_key() {
    use crypto_keystore_rs::ChainKey;

    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let key_bytes = keystore.key().unwrap().to_keystore_bytes();

    // Ethereum keys are 32 bytes (private key only)
    assert_eq!(key_bytes.len(), 32);
}

#[test]
#[cfg(feature = "solana")]
fn solana_keystore_stores_64_byte_keypair() {
    use crypto_keystore_rs::ChainKey;

    let keystore =
        SolanaKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let key_bytes = keystore.key().unwrap().to_keystore_bytes();

    // Solana stores full keypair: 32 bytes secret + 32 bytes public
    assert_eq!(key_bytes.len(), 64);
}
