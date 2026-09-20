#![cfg(feature = "ethereum")]
use crypto_keystore_rs::{EthereumKeystore, KdfConfig, KeystoreError};
use serde_json::{json, Value};
fn fixture(config: KdfConfig) -> Value {
    serde_json::to_value(EthereumKeystore::new_with_config("password", config).unwrap()).unwrap()
}
#[test]
fn rejects_short_derived_keys_without_panicking() {
    for config in [
        KdfConfig::custom_pbkdf2(1),
        KdfConfig::custom_scrypt(4, 8, 1),
    ] {
        let base = fixture(config);
        for len in [0, 1, 10, 15, 16, 31] {
            let mut value = base.clone();
            value["crypto"]["dklen"] = json!(len);
            assert!(matches!(
                EthereumKeystore::from_json(&value.to_string(), "password"),
                Err(KeystoreError::InvalidKdfParams(_))
            ));
        }
    }
}
#[test]
fn rejects_invalid_iv_mac_and_ciphertext_lengths_before_kdf() {
    let base = fixture(KdfConfig::custom_pbkdf2(1));
    for (pointer, valid_len) in [
        ("/crypto/cipherparams/iv", 16),
        ("/crypto/mac", 32),
        ("/crypto/ciphertext", 32),
    ] {
        for len in [0, 1, valid_len - 1, valid_len + 1] {
            let mut value = base.clone();
            *value.pointer_mut(pointer).unwrap() = json!("00".repeat(len));
            value["crypto"]["c"] = json!(u32::MAX);
            assert!(matches!(
                EthereumKeystore::from_json(&value.to_string(), "password"),
                Err(KeystoreError::CorruptedData)
            ));
        }
    }
}
#[test]
fn rejects_invalid_creation_parameters_before_derivation() {
    for config in [
        KdfConfig::custom_pbkdf2(0),
        KdfConfig::custom_scrypt(0, 8, 1),
        KdfConfig::custom_scrypt(32, 8, 1),
        KdfConfig::custom_scrypt(255, 8, 1),
    ] {
        assert!(matches!(
            EthereumKeystore::new_with_config("password", config),
            Err(KeystoreError::InvalidKdfParams(_))
        ));
    }
}
