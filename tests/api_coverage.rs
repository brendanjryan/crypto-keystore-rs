mod common;

use common::TEST_PASSWORD;
use crypto_keystore_rs::{KdfConfig, Keystore, VERSION_4};
use rand::SeedableRng;

#[cfg(feature = "ethereum")]
use crypto_keystore_rs::{ChainKey, EthereumKey, EthereumKeystore};

#[cfg(feature = "solana")]
use crypto_keystore_rs::{SolanaKey, SolanaKeystore};

// ==========================
// Metadata Accessor Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn keystore_id_returns_valid_uuid() {
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();

    let id = keystore.id();
    assert!(!id.is_empty());

    // Verify it's a valid UUID
    let uuid_result = uuid::Uuid::parse_str(id);
    assert!(uuid_result.is_ok(), "ID should be a valid UUID: {}", id);
}

#[test]
#[cfg(feature = "ethereum")]
fn keystore_version_returns_v4() {
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    assert_eq!(keystore.version(), VERSION_4);
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_keystore_chain_returns_ethereum() {
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    assert_eq!(keystore.chain(), Some("ethereum"));
}

#[test]
#[cfg(feature = "solana")]
fn solana_keystore_chain_returns_solana() {
    let keystore =
        SolanaKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    assert_eq!(keystore.chain(), Some("solana"));
}

#[test]
#[cfg(feature = "ethereum")]
fn decrypted_keystore_is_decrypted_returns_true() {
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    assert!(keystore.is_decrypted());
}

#[test]
#[cfg(feature = "ethereum")]
fn non_decrypted_keystore_is_decrypted_returns_false() {
    // Create and serialize a keystore
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let json = keystore.to_json().unwrap();

    // Deserialize without decrypting
    let keystore_without_key: Keystore<EthereumKey> = serde_json::from_str(&json).unwrap();

    assert!(!keystore_without_key.is_decrypted());
}

// ==========================
// to_json() Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn to_json_produces_valid_json() {
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let json = keystore.to_json().unwrap();

    // Verify it's valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify required fields exist
    assert!(parsed["crypto"].is_object());
    assert!(parsed["id"].is_string());
    assert_eq!(parsed["version"], 4);
    assert_eq!(parsed["chain"], "ethereum");
}

#[test]
#[cfg(feature = "ethereum")]
fn to_json_roundtrip_preserves_keystore() {
    let keystore =
        EthereumKeystore::new_with_config(TEST_PASSWORD, KdfConfig::scrypt_interactive()).unwrap();
    let original_address = keystore.key().unwrap().address();

    // Serialize to JSON
    let json1 = keystore.to_json().unwrap();

    // Deserialize and decrypt
    let loaded = EthereumKeystore::from_json(&json1, TEST_PASSWORD).unwrap();

    // Serialize again
    let json2 = loaded.to_json().unwrap();

    // Verify addresses match
    assert_eq!(loaded.key().unwrap().address(), original_address);

    // JSONs should be semantically equivalent
    let v1: serde_json::Value = serde_json::from_str(&json1).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&json2).unwrap();

    // Compare all fields except potentially crypto params (which may have different random values)
    assert_eq!(v1["id"], v2["id"]);
    assert_eq!(v1["version"], v2["version"]);
    assert_eq!(v1["chain"], v2["chain"]);
}

// ==========================
// new_with_rng() Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn new_with_rng_produces_deterministic_results_with_same_seed() {
    use rand::rngs::StdRng;

    let mut rng1 = StdRng::seed_from_u64(42);
    let mut rng2 = StdRng::seed_from_u64(42);

    let key1 = EthereumKey::generate(&mut rng1);
    let key2 = EthereumKey::generate(&mut rng2);

    let ks1 = EthereumKeystore::from_key_with_rng_and_config(
        &mut rng1,
        key1,
        TEST_PASSWORD,
        KdfConfig::scrypt_interactive(),
    )
    .unwrap();
    let ks2 = EthereumKeystore::from_key_with_rng_and_config(
        &mut rng2,
        key2,
        TEST_PASSWORD,
        KdfConfig::scrypt_interactive(),
    )
    .unwrap();

    // Same seed should produce same address
    assert_eq!(ks1.key().unwrap().address(), ks2.key().unwrap().address());
}

#[test]
#[cfg(feature = "ethereum")]
fn new_with_rng_produces_different_results_with_different_seeds() {
    use rand::rngs::StdRng;

    let mut rng1 = StdRng::seed_from_u64(42);
    let mut rng2 = StdRng::seed_from_u64(99);

    let key1 = EthereumKey::generate(&mut rng1);
    let key2 = EthereumKey::generate(&mut rng2);

    let ks1 = EthereumKeystore::from_key_with_rng_and_config(
        &mut rng1,
        key1,
        TEST_PASSWORD,
        KdfConfig::scrypt_interactive(),
    )
    .unwrap();
    let ks2 = EthereumKeystore::from_key_with_rng_and_config(
        &mut rng2,
        key2,
        TEST_PASSWORD,
        KdfConfig::scrypt_interactive(),
    )
    .unwrap();

    // Different seeds should produce different addresses
    assert_ne!(ks1.key().unwrap().address(), ks2.key().unwrap().address());
}

// ==========================
// from_key() and from_key_with_rng() Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn from_key_preserves_address() {
    use rand::thread_rng;

    let mut rng = thread_rng();
    let key = EthereumKey::generate(&mut rng);
    let expected_address = key.address();

    let keystore =
        EthereumKeystore::from_key_with_config(key, TEST_PASSWORD, KdfConfig::scrypt_interactive())
            .unwrap();

    assert_eq!(keystore.key().unwrap().address(), expected_address);
}

#[test]
#[cfg(feature = "ethereum")]
fn from_key_with_rng_preserves_address() {
    use rand::rngs::StdRng;

    // Generate a key with one RNG
    let mut key_rng = StdRng::seed_from_u64(42);
    let key = EthereumKey::generate(&mut key_rng);
    let expected_address = key.address();

    // Create keystore with a different RNG
    let mut keystore_rng = StdRng::seed_from_u64(99);
    let keystore = EthereumKeystore::from_key_with_rng_and_config(
        &mut keystore_rng,
        key,
        TEST_PASSWORD,
        KdfConfig::scrypt_interactive(),
    )
    .unwrap();

    // Address should match the original key
    assert_eq!(keystore.key().unwrap().address(), expected_address);
}

#[test]
#[cfg(feature = "ethereum")]
fn from_key_with_rng_with_different_seeds_produces_different_keystores() {
    use rand::rngs::StdRng;

    // Create same key twice
    let mut rng1 = StdRng::seed_from_u64(42);
    let key1 = EthereumKey::generate(&mut rng1);
    let address1 = key1.address();

    let key2 = key1.clone();

    // Create keystores with different encryption RNG seeds
    let mut enc_rng1 = StdRng::seed_from_u64(100);
    let keystore1 = EthereumKeystore::from_key_with_rng_and_config(
        &mut enc_rng1,
        key1,
        TEST_PASSWORD,
        KdfConfig::scrypt_interactive(),
    )
    .unwrap();

    let mut enc_rng2 = StdRng::seed_from_u64(200);
    let keystore2 = EthereumKeystore::from_key_with_rng_and_config(
        &mut enc_rng2,
        key2,
        TEST_PASSWORD,
        KdfConfig::scrypt_interactive(),
    )
    .unwrap();

    // Should have different UUIDs (different random IVs/salts)
    assert_ne!(keystore1.id(), keystore2.id());

    // But same address (same key)
    assert_eq!(keystore1.key().unwrap().address(), address1);
    assert_eq!(keystore2.key().unwrap().address(), address1);
}

// ==========================
// Chain-Specific Key Methods
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_key_from_signing_key_works() {
    use k256::ecdsa::SigningKey;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let signing_key = SigningKey::random(&mut rng);
    let eth_key = EthereumKey::from_signing_key(signing_key);

    // Should produce a valid Ethereum address
    let address = eth_key.address();
    assert_eq!(address.len(), 42);
    assert!(address.starts_with("0x"));
}

#[test]
#[cfg(feature = "solana")]
fn solana_key_from_signing_key_works() {
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let sol_key = SolanaKey::from_signing_key(signing_key);

    // Should produce a valid Solana address
    let address = sol_key.address();
    assert!(address.len() >= 32 && address.len() <= 44);
    assert!(bs58::decode(&address).into_vec().is_ok());
}
