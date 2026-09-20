#![cfg(any(feature = "ethereum", feature = "solana"))]
use crypto_keystore_rs::{ChainKey, KdfConfig, Keystore, KeystoreBuilder, KeystoreError};
use serde_json::json;

fn check<K: ChainKey>(versions: &[u32]) {
    for &version in versions {
        for config in [
            KdfConfig::custom_pbkdf2(2),
            KdfConfig::custom_scrypt(4, 8, 1),
        ] {
            let store = KeystoreBuilder::<K>::new()
                .with_random_key()
                .with_version(version)
                .with_kdf_config(config)
                .build("password")
                .unwrap();
            let value = serde_json::to_value(&store).unwrap();
            assert!(matches!(
                Keystore::<K>::from_json(&value.to_string(), "wrong"),
                Err(KeystoreError::IncorrectPassword)
            ));
            for field in ["ciphertext", "mac"] {
                let mut changed = value.clone();
                let mut bytes = hex::decode(changed["crypto"][field].as_str().unwrap()).unwrap();
                bytes[0] ^= 1;
                changed["crypto"][field] = json!(hex::encode(bytes));
                assert!(matches!(
                    Keystore::<K>::from_json(&changed.to_string(), "password"),
                    Err(KeystoreError::IncorrectPassword)
                ));
            }
        }
    }
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_legacy_mac_is_checked() {
    check::<crypto_keystore_rs::EthereumKey>(&[3, 4]);
}
#[test]
#[cfg(feature = "solana")]
fn solana_legacy_mac_is_checked() {
    check::<crypto_keystore_rs::SolanaKey>(&[4]);
}
