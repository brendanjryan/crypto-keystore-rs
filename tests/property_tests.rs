mod common;

use proptest::prelude::*;

#[cfg(feature = "ethereum")]
use crypto_keystore_rs::{ChainKey, EthereumKey, EthereumKeystore};

#[cfg(feature = "solana")]
use crypto_keystore_rs::SolanaKeystore;

// ==========================
// Property Tests for Keystore
// ==========================

#[cfg(feature = "ethereum")]
proptest! {
    #[test]
    fn keystore_roundtrip_preserves_address(password in "[a-zA-Z0-9]{8,32}") {
        // Create keystore with random password
        let keystore = EthereumKeystore::new(&password)?;
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
        let ks1 = EthereumKeystore::new(&password)?;
        let ks2 = EthereumKeystore::new(&password)?;

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

        let keystore = EthereumKeystore::new(&correct_pw)?;
        let json = keystore.to_json()?;

        // Wrong password should always fail
        let result = EthereumKeystore::from_json(&json, &wrong_pw);
        prop_assert!(result.is_err());
    }

    #[test]
    fn password_length_does_not_affect_correctness(password_len in 1usize..=128) {
        let password = "a".repeat(password_len);

        let keystore = EthereumKeystore::new(&password)?;
        let address = keystore.key()?.address();
        let json = keystore.to_json()?;

        // Should be able to decrypt with same password regardless of length
        let loaded = EthereumKeystore::from_json(&json, &password)?;
        prop_assert_eq!(loaded.key()?.address(), address);
    }

    #[test]
    fn keystore_metadata_is_consistent(password in "[a-zA-Z0-9]{8,32}") {
        let keystore = EthereumKeystore::new(&password)?;

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
    #[test]
    fn solana_keystore_roundtrip_preserves_address(password in "[a-zA-Z0-9]{8,32}") {
        let keystore = SolanaKeystore::new(&password)?;
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

        let keystore = SolanaKeystore::new(&correct_pw)?;
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
    #[test]
    fn password_with_special_characters_works(
        alphanumeric in "[a-zA-Z0-9]{1,20}",
        special in prop::sample::select(vec!["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+"])
    ) {
        let password = format!("{}{}", alphanumeric, special);

        let keystore = EthereumKeystore::new(&password)?;
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

        let ks1 = EthereumKeystore::from_key(key.clone(), &password)?;
        let ks2 = EthereumKeystore::from_key(key, &password)?;

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
