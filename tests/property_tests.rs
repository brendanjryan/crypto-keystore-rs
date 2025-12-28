mod common;

use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

#[cfg(feature = "ethereum")]
use crypto_keystore_rs::{ChainKey, EthereumKey, EthereumKeystore, KdfConfig};

#[cfg(feature = "solana")]
use crypto_keystore_rs::SolanaKeystore;

#[cfg(all(feature = "solana", not(feature = "ethereum")))]
use crypto_keystore_rs::KdfConfig;

// ==========================
// Property Tests for Keystore
// ==========================
//
// Note: These tests use:
// - 25 cases (vs default 256) for good coverage with reasonable time
// - N=2^4 (16 iterations) for ultra-fast testing - tests correctness, not security
// This keeps each test under 5 seconds while still validating crypto logic.

// Ultra-fast config for property testing - NOT secure, only for testing logic
fn test_kdf_config() -> KdfConfig {
    KdfConfig::custom_scrypt(4, 8, 1) // N=16
}

#[cfg(feature = "ethereum")]
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 25,
        .. ProptestConfig::default()
    })]
    #[test]
    fn keystore_roundtrip_preserves_address(password in "[a-zA-Z0-9]{8,32}") {
        // Create keystore with random password
        let keystore = EthereumKeystore::new_with_config(&password, test_kdf_config())?;
        let original_address = keystore.key()?.address();

        // Serialize and deserialize
        let json = keystore.to_json()?;
        let loaded = EthereumKeystore::from_json(&json, &password)?;

        // Address should be preserved
        prop_assert_eq!(loaded.key()?.address(), original_address);
    }

    #[test]
    fn encryption_always_uses_unique_iv_and_uuid(password in "[a-zA-Z0-9]{8,32}") {
        // Create two keystores with the same password
        let ks1 = EthereumKeystore::new_with_config(&password, test_kdf_config())?;
        let ks2 = EthereumKeystore::new_with_config(&password, test_kdf_config())?;

        // They should have different UUIDs (random)
        prop_assert_ne!(ks1.id(), ks2.id());

        // JSONs should be different (different IVs, salts, UUIDs)
        let json1 = ks1.to_json()?;
        let json2 = ks2.to_json()?;
        prop_assert_ne!(json1, json2);
    }

    #[test]
    fn wrong_password_always_fails(
        correct_pw in "[a-zA-Z0-9]{8,32}",
        wrong_pw in "[a-zA-Z0-9]{8,32}"
    ) {
        prop_assume!(correct_pw != wrong_pw);

        let keystore = EthereumKeystore::new_with_config(&correct_pw, test_kdf_config())?;
        let json = keystore.to_json()?;

        // Wrong password should always fail
        let result = EthereumKeystore::from_json(&json, &wrong_pw);
        prop_assert!(result.is_err());
    }

    #[test]
    fn password_length_does_not_affect_correctness(password_len in 1usize..=128) {
        let password = "a".repeat(password_len);

        let keystore = EthereumKeystore::new_with_config(&password, test_kdf_config())?;
        let address = keystore.key()?.address();
        let json = keystore.to_json()?;

        // Should be able to decrypt with same password regardless of length
        let loaded = EthereumKeystore::from_json(&json, &password)?;
        prop_assert_eq!(loaded.key()?.address(), address);
    }

    #[test]
    fn keystore_metadata_is_consistent(password in "[a-zA-Z0-9]{8,32}") {
        let keystore = EthereumKeystore::new_with_config(&password, test_kdf_config())?;

        // Metadata should be consistent
        prop_assert!(keystore.is_decrypted());
        prop_assert_eq!(keystore.version(), crypto_keystore_rs::VERSION_4);
        prop_assert_eq!(keystore.chain(), Some("ethereum"));

        // ID should be valid UUID
        prop_assert!(uuid::Uuid::parse_str(keystore.id()).is_ok());
    }
}

// ==========================
// Property Tests for Solana
// ==========================

#[cfg(feature = "solana")]
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 25,
        .. ProptestConfig::default()
    })]
    #[test]
    fn solana_keystore_roundtrip_preserves_address(password in "[a-zA-Z0-9]{8,32}") {
        let keystore = SolanaKeystore::new_with_config(&password, test_kdf_config())?;
        let original_address = keystore.key()?.address();

        let json = keystore.to_json()?;
        let loaded = SolanaKeystore::from_json(&json, &password)?;

        prop_assert_eq!(loaded.key()?.address(), original_address);
    }

    #[test]
    fn solana_wrong_password_always_fails(
        correct_pw in "[a-zA-Z0-9]{8,32}",
        wrong_pw in "[a-zA-Z0-9]{8,32}"
    ) {
        prop_assume!(correct_pw != wrong_pw);

        let keystore = SolanaKeystore::new_with_config(&correct_pw, test_kdf_config())?;
        let json = keystore.to_json()?;

        let result = SolanaKeystore::from_json(&json, &wrong_pw);
        prop_assert!(result.is_err());
    }
}

// ==========================
// Property Tests for Password Handling
// ==========================

#[cfg(feature = "ethereum")]
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 25,
        .. ProptestConfig::default()
    })]
    #[test]
    fn password_with_special_characters_works(
        alphanumeric in "[a-zA-Z0-9]{1,20}",
        special in prop::sample::select(vec!["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+"])
    ) {
        let password = format!("{}{}", alphanumeric, special);

        let keystore = EthereumKeystore::new_with_config(&password, test_kdf_config())?;
        let address = keystore.key()?.address();
        let json = keystore.to_json()?;

        let loaded = EthereumKeystore::from_json(&json, &password)?;
        prop_assert_eq!(loaded.key()?.address(), address);
    }

    #[test]
    fn identical_passwords_decrypt_to_same_address(password in "[a-zA-Z0-9]{8,32}") {
        // Create two keystores with same password from same key
        let key = EthereumKey::generate(&mut rand::thread_rng());
        let address = key.address();

        let ks1 = EthereumKeystore::from_key_with_config(key.clone(), &password, test_kdf_config())?;
        let ks2 = EthereumKeystore::from_key_with_config(key, &password, test_kdf_config())?;

        let json1 = ks1.to_json()?;
        let json2 = ks2.to_json()?;

        // Both should decrypt to the same address
        let loaded1 = EthereumKeystore::from_json(&json1, &password)?;
        let loaded2 = EthereumKeystore::from_json(&json2, &password)?;

        let addr1 = loaded1.key()?.address();
        let addr2 = loaded2.key()?.address();
        prop_assert_eq!(addr1, addr2.clone());
        prop_assert_eq!(addr2, address);
    }
}
