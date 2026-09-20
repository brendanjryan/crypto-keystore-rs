#![cfg(any(feature = "ethereum", feature = "solana"))]
use crypto_keystore_rs::{
    ChainKey, KdfConfig, Keystore, KeystoreBuilder, KeystoreError, VERSION_4, VERSION_5,
};
use serde_json::{json, Value};

fn check_authenticated_format<K: ChainKey + std::fmt::Debug>() {
    for config in [
        KdfConfig::custom_pbkdf2(2),
        KdfConfig::custom_scrypt(4, 8, 1),
    ] {
        let original = KeystoreBuilder::<K>::new()
            .with_random_key()
            .with_kdf_config(config)
            .with_uuid("3198bc9c-6672-5ab3-d995-4942343ae5b6")
            .build("password")
            .unwrap();
        assert_eq!(original.version(), VERSION_5);
        let base = serde_json::to_value(&original).unwrap();
        let loaded = Keystore::<K>::from_json(&base.to_string(), "password").unwrap();
        assert_eq!(loaded.address().unwrap(), original.address().unwrap());
        assert!(matches!(
            Keystore::<K>::from_json(&base.to_string(), "wrong"),
            Err(KeystoreError::IncorrectPassword)
        ));
        for field in [
            "/crypto/cipherparams/iv",
            "/crypto/ciphertext",
            "/crypto/mac",
            "/crypto/salt",
        ] {
            let mut changed = base.clone();
            let bytes = hex::decode(changed.pointer(field).unwrap().as_str().unwrap()).unwrap();
            let mut tampered = bytes;
            tampered[0] ^= 1;
            *changed.pointer_mut(field).unwrap() = json!(hex::encode(tampered));
            assert!(
                matches!(
                    Keystore::<K>::from_json(&changed.to_string(), "password"),
                    Err(KeystoreError::IncorrectPassword)
                ),
                "{field}"
            );
        }
        let mut changed = base.clone();
        changed["id"] = json!("4198bc9c-6672-5ab3-d995-4942343ae5b6");
        assert!(matches!(
            Keystore::<K>::from_json(&changed.to_string(), "password"),
            Err(KeystoreError::IncorrectPassword)
        ));
        // PBKDF2's first 32 bytes do not change when requesting 64 bytes.
        // Rejecting this mutation therefore exercises metadata authentication.
        let mut changed = base.clone();
        changed["crypto"]["dklen"] = json!(64);
        assert!(matches!(
            Keystore::<K>::from_json(&changed.to_string(), "password"),
            Err(KeystoreError::IncorrectPassword)
        ));
        let mut changed = base.clone();
        changed["version"] = json!(VERSION_4);
        assert!(matches!(
            Keystore::<K>::from_json(&changed.to_string(), "password"),
            Err(KeystoreError::UnsupportedCipher(_))
        ));
        changed["crypto"]["cipher"] = json!("aes-128-ctr");
        assert!(Keystore::<K>::from_json(&changed.to_string(), "password").is_err());
        // JSON whitespace and object ordering are not authenticated.
        let mut reversed = serde_json::Map::new();
        for (key, value) in base.as_object().unwrap().iter().rev() {
            reversed.insert(key.clone(), value.clone());
        }
        assert!(Keystore::<K>::from_json(
            &serde_json::to_string_pretty(&Value::Object(reversed)).unwrap(),
            "password"
        )
        .is_ok());
    }
}

fn check_migration<K: ChainKey + std::fmt::Debug>() {
    let legacy = KeystoreBuilder::<K>::new()
        .with_random_key()
        .with_version(VERSION_4)
        .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
        .build("old")
        .unwrap();
    let loaded = Keystore::<K>::from_json(&legacy.to_json().unwrap(), "old").unwrap();
    let upgraded = KeystoreBuilder::new()
        .with_key(loaded.key().unwrap().clone())
        .with_uuid(loaded.id())
        .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
        .build("new")
        .unwrap();
    assert_eq!(upgraded.version(), VERSION_5);
    assert_eq!(upgraded.id(), legacy.id());
    assert_eq!(
        Keystore::<K>::from_json(&upgraded.to_json().unwrap(), "new")
            .unwrap()
            .address()
            .unwrap(),
        legacy.address().unwrap()
    );
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_authentication_and_migration() {
    check_authenticated_format::<crypto_keystore_rs::EthereumKey>();
    check_migration::<crypto_keystore_rs::EthereumKey>();
}
#[test]
#[cfg(feature = "solana")]
fn solana_authentication_and_migration() {
    check_authenticated_format::<crypto_keystore_rs::SolanaKey>();
    check_migration::<crypto_keystore_rs::SolanaKey>();
}

// Independently generated with Node.js crypto (OpenSSL), PBKDF2-HMAC-SHA256,
// password "testpassword", private scalar 1, zero salt/nonce, and c=2.
#[test]
#[cfg(feature = "ethereum")]
fn decrypts_independent_aes_gcm_vector() {
    let store = crypto_keystore_rs::EthereumKeystore::from_json(
        include_str!("fixtures/ethereum_v5_pbkdf2.json"),
        "testpassword",
    )
    .unwrap();
    assert_eq!(
        store.address().unwrap(),
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    );
}
