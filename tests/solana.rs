#![cfg(feature = "solana")]

mod common;

use common::{
    assert_valid_solana_address, create_temp_keystore_dir, TEST_PASSWORD, TEST_WRONG_PASSWORD,
};
use crypto_keystore_rs::{ChainKey, SolanaKey, SolanaKeystore};
use rand::thread_rng;

#[test]
fn creates_new_keystore_and_loads_with_correct_password() {
    let password = TEST_PASSWORD;

    let keystore = SolanaKeystore::new(password).unwrap();
    let original_address = keystore.key().unwrap().address();
    assert_valid_solana_address(&original_address);

    let dir = create_temp_keystore_dir();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let loaded = SolanaKeystore::load_from_file(&filepath, password).unwrap();

    assert_eq!(loaded.key().unwrap().address(), original_address);
}

#[test]
fn fails_to_load_keystore_with_incorrect_password() {
    let password = TEST_PASSWORD;

    let keystore = SolanaKeystore::new(password).unwrap();

    let dir = create_temp_keystore_dir();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let result = SolanaKeystore::load_from_file(&filepath, TEST_WRONG_PASSWORD);

    assert!(result.is_err());
}

#[test]
fn serializes_keystore_with_correct_json_format() {
    let password = "TEST_PASSWORD";

    let keystore = SolanaKeystore::new(password).unwrap();

    let dir = create_temp_keystore_dir();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let json_content = std::fs::read_to_string(&filepath).unwrap();

    assert!(json_content.contains("\"version\": 4"));
    assert!(json_content.contains("\"chain\": \"solana\""));
    assert!(json_content.contains("\"cipher\": \"aes-128-ctr\""));
    assert!(json_content.contains("\"ciphertext\""));
    assert!(json_content.contains("\"mac\""));
}

#[test]
fn creates_keystore_from_existing_solana_key() {
    let mut rng = thread_rng();
    let password = "TEST_PASSWORD";

    let original_key = SolanaKey::generate(&mut rng);
    let original_address = original_key.address();

    let keystore = SolanaKeystore::from_key(original_key, password).unwrap();

    let dir = create_temp_keystore_dir();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let loaded = SolanaKeystore::load_from_file(&filepath, password).unwrap();

    assert_eq!(loaded.key().unwrap().address(), original_address);
}

#[test]
fn generates_unique_addresses_for_multiple_keystores() {
    let password = "TEST_PASSWORD";

    let keystore1 = SolanaKeystore::new(password).unwrap();
    let keystore2 = SolanaKeystore::new(password).unwrap();

    let addr1 = keystore1.key().unwrap().address();
    let addr2 = keystore2.key().unwrap().address();

    assert_ne!(addr1, addr2);
}

#[test]
fn stores_and_restores_full_keypair_correctly() {
    let mut rng = thread_rng();
    let password = "TEST_PASSWORD";

    let original_key = SolanaKey::generate(&mut rng);

    let keystore_bytes = original_key.to_keystore_bytes();
    assert_eq!(keystore_bytes.len(), 64);

    let keystore = SolanaKeystore::from_key(original_key, password).unwrap();

    let dir = create_temp_keystore_dir();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let loaded = SolanaKeystore::load_from_file(&filepath, password).unwrap();

    let restored_bytes = loaded.key().unwrap().to_keystore_bytes();
    assert_eq!(keystore_bytes, restored_bytes);
}
