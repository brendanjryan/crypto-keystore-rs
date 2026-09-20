#![cfg(any(feature = "ethereum", feature = "solana"))]
use crypto_keystore_rs::{
    ChainKey, KdfConfig, Keystore, KeystoreBuilder, KeystoreError, VERSION_3, VERSION_4,
};
use serde_json::json;

fn check_versions<K: ChainKey + std::fmt::Debug>() {
    for version in [0, 2, 6, 99] {
        assert!(
            matches!(KeystoreBuilder::<K>::new().with_random_key().with_version(version)
            .with_kdf_config(KdfConfig::custom_pbkdf2(0)).build("password"),
            Err(KeystoreError::UnsupportedVersion(v)) if v == version)
        );
    }
    let store = KeystoreBuilder::<K>::new()
        .with_random_key()
        .with_version(VERSION_4)
        .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
        .build("password")
        .unwrap();
    let base = serde_json::to_value(&store).unwrap();
    assert_eq!(
        Keystore::<K>::from_json(&store.to_json().unwrap(), "password")
            .unwrap()
            .address()
            .unwrap(),
        store.address().unwrap()
    );
    for chain in [
        json!(null),
        json!("unknown"),
        json!(if K::CHAIN_ID == "ethereum" {
            "solana"
        } else {
            "ethereum"
        }),
    ] {
        let mut value = base.clone();
        value["chain"] = chain;
        value["crypto"]["n"] = json!(1u32 << 31);
        assert!(matches!(
            Keystore::<K>::from_json(&value.to_string(), "password"),
            Err(KeystoreError::UnsupportedChain(_))
        ));
    }
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_version_matrix() {
    use crypto_keystore_rs::{EthereumKey, EthereumKeystore};
    check_versions::<EthereumKey>();
    let store = KeystoreBuilder::<EthereumKey>::new()
        .with_random_key()
        .with_version(VERSION_3)
        .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
        .build("password")
        .unwrap();
    assert_eq!(store.chain(), None);
    assert!(serde_json::to_value(&store).unwrap().get("chain").is_none());
    assert_eq!(
        EthereumKeystore::from_json(&store.to_json().unwrap(), "password")
            .unwrap()
            .address()
            .unwrap(),
        store.address().unwrap()
    );
}

#[test]
#[cfg(feature = "solana")]
fn solana_version_matrix() {
    use crypto_keystore_rs::{SolanaKey, SolanaKeystore};
    check_versions::<SolanaKey>();
    assert!(matches!(
        KeystoreBuilder::<SolanaKey>::new()
            .with_random_key()
            .with_version(VERSION_3)
            .with_kdf_config(KdfConfig::custom_pbkdf2(0))
            .build("password"),
        Err(KeystoreError::UnsupportedChain(_))
    ));
    let store =
        SolanaKeystore::new_with_config("password", KdfConfig::custom_scrypt(4, 8, 1)).unwrap();
    let mut value = serde_json::to_value(store).unwrap();
    value["version"] = json!(3);
    value.as_object_mut().unwrap().remove("chain");
    assert!(matches!(
        SolanaKeystore::from_json(&value.to_string(), "password"),
        Err(KeystoreError::UnsupportedChain(_))
    ));
}
