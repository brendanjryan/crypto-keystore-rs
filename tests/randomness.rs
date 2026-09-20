#![cfg(any(feature = "ethereum", feature = "solana"))]
use crypto_keystore_rs::{ChainKey, KdfConfig, Keystore};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn check_randomness<K: ChainKey>() {
    let key = K::generate(&mut StdRng::seed_from_u64(1));
    for config in [
        KdfConfig::custom_pbkdf2(2),
        KdfConfig::custom_scrypt(4, 8, 1),
    ] {
        let mut rng = StdRng::seed_from_u64(2);
        let mut expected_rng = rng.clone();
        let mut previous = None;
        for _ in 0..2 {
            let mut salt = [0; 32];
            let mut nonce = [0; 12];
            expected_rng.fill_bytes(&mut salt);
            expected_rng.fill_bytes(&mut nonce);
            let store =
                Keystore::from_key_with_rng_and_config(&mut rng, key.clone(), "password", config)
                    .unwrap();
            let value = serde_json::to_value(&store).unwrap();
            assert_eq!(value["crypto"]["salt"], hex::encode(salt));
            assert_eq!(value["crypto"]["cipherparams"]["iv"], hex::encode(nonce));
            if let Some((old_salt, old_nonce)) = previous {
                assert_ne!(salt, old_salt);
                assert_ne!(nonce, old_nonce);
            }
            previous = Some((salt, nonce));
            let loaded = Keystore::<K>::from_json(&store.to_json().unwrap(), "password").unwrap();
            assert_eq!(
                *loaded.key().unwrap().to_keystore_bytes(),
                *key.to_keystore_bytes()
            );
        }
    }
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_uses_the_supplied_salt_and_nonce() {
    check_randomness::<crypto_keystore_rs::EthereumKey>();
}

#[test]
#[cfg(feature = "solana")]
fn solana_uses_the_supplied_salt_and_nonce() {
    check_randomness::<crypto_keystore_rs::SolanaKey>();
}
