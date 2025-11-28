#![cfg(feature = "ethereum")]

use crypto_keystore_rs::{ChainKey, EthereumKey, EthereumKeystore};
use rand::thread_rng;
use tempfile::tempdir;

// Common test constants
const TEST_PASSWORD: &str = "TEST_PASSWORD_123";
const TEST_WRONG_PASSWORD: &str = "wrong_password";

#[test]
fn creates_new_keystore_and_loads_with_correct_password() {
    let password = TEST_PASSWORD;

    let keystore = EthereumKeystore::new(password).unwrap();
    let original_address = keystore.key().unwrap().address();

    let dir = tempdir().unwrap();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let loaded = EthereumKeystore::load_from_file(&filepath, password).unwrap();

    assert_eq!(loaded.key().unwrap().address(), original_address);
}

#[test]
fn fails_to_load_keystore_with_incorrect_password() {
    let password = TEST_PASSWORD;

    let keystore = EthereumKeystore::new(password).unwrap();

    let dir = tempdir().unwrap();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let result = EthereumKeystore::load_from_file(&filepath, TEST_WRONG_PASSWORD);

    assert!(result.is_err());
}

#[test]
fn serializes_keystore_with_correct_json_format() {
    let password = "TEST_PASSWORD";

    let keystore = EthereumKeystore::new(password).unwrap();

    let dir = tempdir().unwrap();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let json_content = std::fs::read_to_string(&filepath).unwrap();

    assert!(json_content.contains("\"version\": 4"));
    assert!(json_content.contains("\"chain\": \"ethereum\""));
    assert!(json_content.contains("\"cipher\": \"aes-128-ctr\""));
    assert!(json_content.contains("\"ciphertext\""));
    assert!(json_content.contains("\"mac\""));
}

#[test]
fn creates_keystore_from_existing_ethereum_key() {
    let mut rng = thread_rng();
    let password = "TEST_PASSWORD";

    let original_key = EthereumKey::generate(&mut rng);
    let original_address = original_key.address();

    let keystore = EthereumKeystore::from_key(original_key, password).unwrap();

    let dir = tempdir().unwrap();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let loaded = EthereumKeystore::load_from_file(&filepath, password).unwrap();

    assert_eq!(loaded.key().unwrap().address(), original_address);
}

#[test]
fn generates_unique_addresses_for_multiple_keystores() {
    let password = "TEST_PASSWORD";

    let keystore1 = EthereumKeystore::new(password).unwrap();
    let keystore2 = EthereumKeystore::new(password).unwrap();

    let addr1 = keystore1.key().unwrap().address();
    let addr2 = keystore2.key().unwrap().address();

    assert_ne!(addr1, addr2);
}
