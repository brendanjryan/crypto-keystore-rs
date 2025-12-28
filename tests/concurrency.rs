mod common;

use common::TEST_PASSWORD;

#[cfg(feature = "ethereum")]
use crypto_keystore_rs::{ChainKey, EthereumKey, EthereumKeystore};

#[cfg(feature = "solana")]
use crypto_keystore_rs::{SolanaKey, SolanaKeystore};

// ==========================
// Send + Sync Trait Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_keystore_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<EthereumKeystore>();
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_keystore_is_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<EthereumKeystore>();
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_key_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<EthereumKey>();
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_key_is_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<EthereumKey>();
}

#[test]
#[cfg(feature = "solana")]
fn solana_keystore_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<SolanaKeystore>();
}

#[test]
#[cfg(feature = "solana")]
fn solana_keystore_is_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<SolanaKeystore>();
}

#[test]
#[cfg(feature = "solana")]
fn solana_key_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<SolanaKey>();
}

#[test]
#[cfg(feature = "solana")]
fn solana_key_is_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<SolanaKey>();
}

// ==========================
// Concurrent Operations Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn concurrent_keystore_creation_produces_unique_results() {
    use std::sync::Arc;
    use std::thread;

    let password = Arc::new(TEST_PASSWORD.to_string());

    // Create keystores concurrently
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let password = Arc::clone(&password);
            thread::spawn(move || EthereumKeystore::new(&*password).unwrap())
        })
        .collect();

    let keystores: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All keystores should have unique IDs and addresses
    let ids: std::collections::HashSet<_> = keystores.iter().map(|ks| ks.id()).collect();
    assert_eq!(ids.len(), 5, "All keystores should have unique IDs");

    let addresses: std::collections::HashSet<_> = keystores
        .iter()
        .map(|ks| ks.key().unwrap().address())
        .collect();
    assert_eq!(
        addresses.len(),
        5,
        "All keystores should have unique addresses"
    );
}

#[test]
#[cfg(feature = "ethereum")]
fn concurrent_keystore_encryption_from_same_key() {
    use rand::thread_rng;
    use std::sync::Arc;
    use std::thread;

    let mut rng = thread_rng();
    let key = EthereumKey::generate(&mut rng);
    let expected_address = key.address();
    let key = Arc::new(key);
    let password = Arc::new(TEST_PASSWORD.to_string());

    // Create multiple keystores from the same key concurrently
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let key = Arc::clone(&key);
            let password = Arc::clone(&password);
            thread::spawn(move || EthereumKeystore::from_key((*key).clone(), &*password).unwrap())
        })
        .collect();

    let keystores: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All should have the same address (same key)
    for keystore in &keystores {
        assert_eq!(keystore.key().unwrap().address(), expected_address);
    }

    // But different UUIDs (different random IVs/salts)
    let ids: std::collections::HashSet<_> = keystores.iter().map(|ks| ks.id()).collect();
    assert_eq!(ids.len(), 5, "All keystores should have unique IDs");
}

#[test]
#[cfg(feature = "ethereum")]
fn concurrent_keystore_decryption_is_safe() {
    use std::sync::Arc;
    use std::thread;

    // Create a keystore
    let keystore = EthereumKeystore::new(TEST_PASSWORD).unwrap();
    let json = keystore.to_json().unwrap();
    let expected_address = keystore.key().unwrap().address();

    let json = Arc::new(json);
    let password = Arc::new(TEST_PASSWORD.to_string());

    // Decrypt the same keystore concurrently
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let json = Arc::clone(&json);
            let password = Arc::clone(&password);
            thread::spawn(move || EthereumKeystore::from_json(&*json, &*password).unwrap())
        })
        .collect();

    let keystores: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All should decrypt to the same address
    for keystore in keystores {
        assert_eq!(keystore.key().unwrap().address(), expected_address);
    }
}
