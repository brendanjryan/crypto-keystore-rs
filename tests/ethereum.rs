use crypto_keystore_rs::{ChainKey, EthereumKey, EthereumKeystore};
use rand::thread_rng;
use tempfile::tempdir;

#[test]
fn test_ethereum_keystore_create_and_load() {
    let password = "test_password_123";

    let keystore = EthereumKeystore::new(password).unwrap();
    let original_address = keystore.key().unwrap().public_key();

    let dir = tempdir().unwrap();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let loaded = EthereumKeystore::load_from_file(&filepath, password).unwrap();

    assert_eq!(loaded.key().unwrap().public_key(), original_address);
}

#[test]
fn test_ethereum_keystore_wrong_password_fails() {
    let password = "correct_password";

    let keystore = EthereumKeystore::new(password).unwrap();

    let dir = tempdir().unwrap();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let result = EthereumKeystore::load_from_file(&filepath, "wrong_password");

    assert!(result.is_err());
}

#[test]
fn test_ethereum_keystore_json_format() {
    let password = "test_password";

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
fn test_ethereum_from_existing_key() {
    let mut rng = thread_rng();
    let password = "test_password";

    let original_key = EthereumKey::generate(&mut rng);
    let original_address = original_key.public_key();

    let keystore = EthereumKeystore::from_key(original_key, password).unwrap();

    let dir = tempdir().unwrap();
    let uuid = keystore.save_to_file(dir.path()).unwrap();

    let filepath = dir.path().join(format!("{uuid}.json"));
    let loaded = EthereumKeystore::load_from_file(&filepath, password).unwrap();

    assert_eq!(loaded.key().unwrap().public_key(), original_address);
}

#[test]
fn test_ethereum_multiple_keystores() {
    let password = "test_password";

    let keystore1 = EthereumKeystore::new(password).unwrap();
    let keystore2 = EthereumKeystore::new(password).unwrap();

    let addr1 = keystore1.key().unwrap().public_key();
    let addr2 = keystore2.key().unwrap().public_key();

    assert_ne!(addr1, addr2);
}
