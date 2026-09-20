use crypto_keystore_rs::{KeystoreError, KeystoreVersion};

#[test]
fn version_conversions_and_predicates_agree() {
    for (number, version) in [
        (3, KeystoreVersion::V3),
        (4, KeystoreVersion::V4),
        (5, KeystoreVersion::V5),
    ] {
        assert_eq!(KeystoreVersion::from_u32(number).unwrap(), version);
        assert_eq!(version.as_u32(), number);
        assert_eq!(version.is_v3(), number == 3);
        assert_eq!(version.is_v4(), number == 4);
        assert_eq!(version.is_v5(), number == 5);
        assert_eq!(version.to_string(), format!("v{number}"));
    }
    assert_eq!(KeystoreVersion::default(), KeystoreVersion::V5);
    for version in [0, 1, 2, 6, u32::MAX] {
        assert!(
            matches!(KeystoreVersion::from_u32(version), Err(KeystoreError::UnsupportedVersion(v)) if v == version)
        );
    }
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_key_conversions_preserve_the_secret() {
    use crypto_keystore_rs::{ChainKey, EthereumKey};
    let mut secret = [0; 32];
    secret[31] = 1;
    let key = EthereumKey::try_from(secret.as_slice()).unwrap();
    assert_eq!(key.signing_key().to_bytes().as_slice(), secret);
    assert_eq!(
        key,
        EthereumKey::from_signing_key(key.signing_key().clone())
    );
    secret[31] = 2;
    assert_ne!(key, EthereumKey::try_from(secret.as_slice()).unwrap());
    assert!(EthereumKey::try_from(&secret[..31]).is_err());
    assert_eq!(key.to_keystore_bytes().len(), 32);
}

#[test]
#[cfg(feature = "solana")]
fn solana_key_conversions_preserve_both_halves() {
    use crypto_keystore_rs::{ChainKey, SolanaKey};
    let key = SolanaKey::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
    let bytes = key.to_bytes();
    assert_eq!(&bytes[..32], key.signing_key().as_bytes());
    assert_eq!(&bytes[32..], key.verifying_key().as_bytes());
    assert_eq!(key.to_keystore_bytes().as_slice(), bytes);
    assert_eq!(SolanaKey::try_from(bytes.as_slice()).unwrap(), key);
    assert_ne!(
        key,
        SolanaKey::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[2; 32]))
    );
    assert!(SolanaKey::try_from(&bytes[..63]).is_err());
}

#[test]
#[cfg(feature = "ethereum")]
fn default_constructors_keep_production_kdf_parameters() {
    use crypto_keystore_rs::{ChainKey, EthereumKeystore};
    let original = EthereumKeystore::new("password").unwrap();
    let copy = EthereumKeystore::from_key(original.key().unwrap().clone(), "password").unwrap();
    for store in [&original, &copy] {
        let value = serde_json::to_value(store).unwrap();
        assert_eq!(value["crypto"]["kdf"], "scrypt");
        assert_eq!(value["crypto"]["n"], 1 << 18);
        assert_eq!(value["crypto"]["r"], 8);
        assert_eq!(value["crypto"]["p"], 1);
        assert_eq!(store.version_enum().unwrap(), KeystoreVersion::V5);
    }
    let loaded = EthereumKeystore::from_json(&copy.to_json().unwrap(), "password").unwrap();
    assert_eq!(
        original.key().unwrap().to_keystore_bytes(),
        loaded.key().unwrap().to_keystore_bytes()
    );
}

#[test]
#[cfg(feature = "ethereum")]
fn builder_accepts_each_typed_version() {
    use crypto_keystore_rs::{EthereumKey, KdfConfig, KeystoreBuilder};
    for version in [
        KeystoreVersion::V3,
        KeystoreVersion::V4,
        KeystoreVersion::V5,
    ] {
        let store = KeystoreBuilder::<EthereumKey>::default()
            .with_random_key()
            .with_version_enum(version)
            .with_kdf_config(KdfConfig::custom_pbkdf2(2))
            .build("password")
            .unwrap();
        assert_eq!(store.version_enum().unwrap(), version);
    }
}
