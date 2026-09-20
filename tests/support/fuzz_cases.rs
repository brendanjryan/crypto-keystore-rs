use crypto_keystore_rs::{ChainKey, ImportLimits, KdfConfig, KdfLimits, Keystore};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::json;

pub(super) fn limits() -> ImportLimits {
    ImportLimits {
        max_input_bytes: 64 * 1024,
        kdf: KdfLimits {
            max_dklen: 64,
            max_pbkdf2_iterations: 8,
            max_scrypt_memory_bytes: 64 * 1024,
            max_scrypt_work: 1024,
        },
    }
}

fn import<K: ChainKey>(input: &str) {
    if let Ok(store) = Keystore::<K>::from_json_with_import_limits(input, "testpassword", limits())
    {
        let saved = store.to_json().unwrap();
        let loaded =
            Keystore::<K>::from_json_with_import_limits(&saved, "testpassword", limits()).unwrap();
        assert_eq!(
            *store.key().unwrap().to_keystore_bytes(),
            *loaded.key().unwrap().to_keystore_bytes()
        );
        assert!(
            Keystore::<K>::from_json_with_import_limits(input, "wrong-password", limits()).is_err()
        );
    }
}

pub fn imports(data: &[u8]) {
    if let Ok(input) = std::str::from_utf8(data) {
        #[cfg(feature = "ethereum")]
        import::<crypto_keystore_rs::EthereumKey>(input);
        #[cfg(feature = "solana")]
        import::<crypto_keystore_rs::SolanaKey>(input);
    }
}

fn authenticated_for<K: ChainKey>(data: &[u8]) {
    let mut seed = [0; 32];
    let len = data.len().min(seed.len());
    seed[..len].copy_from_slice(&data[..len]);
    let mut rng = StdRng::from_seed(seed);
    let key = K::generate(&mut rng);
    let config = if data[0] & 1 == 0 {
        KdfConfig::custom_pbkdf2(1 + u32::from(data[1] % 8))
    } else {
        KdfConfig::custom_scrypt(1 + data[1] % 5, 8, 1)
    };
    let password = String::from_utf8_lossy(&data[3..data.len().min(131)]);
    let store =
        Keystore::from_key_with_rng_and_config(&mut rng, key.clone(), &password, config).unwrap();
    let mut value = serde_json::to_value(&store).unwrap();
    let loaded =
        Keystore::<K>::from_json_with_import_limits(&value.to_string(), &password, limits())
            .unwrap();
    assert_eq!(
        *loaded.key().unwrap().to_keystore_bytes(),
        *key.to_keystore_bytes()
    );
    assert!(Keystore::<K>::from_json_with_import_limits(
        &value.to_string(),
        format!("{password}!"),
        limits()
    )
    .is_err());
    match data[2] % 8 {
        field @ 0..=3 => {
            let path = [
                "/crypto/cipherparams/iv",
                "/crypto/ciphertext",
                "/crypto/mac",
                "/crypto/salt",
            ][field as usize];
            let bytes = hex::decode(value.pointer(path).unwrap().as_str().unwrap()).unwrap();
            let mut bytes = bytes;
            let index = data[1] as usize % bytes.len();
            bytes[index] ^= 1;
            *value.pointer_mut(path).unwrap() = json!(hex::encode(bytes));
        }
        4 => {
            let mut id = value["id"].as_str().unwrap().to_string();
            id.replace_range(..1, if id.starts_with('0') { "1" } else { "0" });
            value["id"] = json!(id);
        }
        5 => value["crypto"]["dklen"] = json!(64),
        6 => value["chain"] = json!("wrong-chain"),
        _ => value["version"] = json!(4),
    }
    assert!(
        Keystore::<K>::from_json_with_import_limits(&value.to_string(), &password, limits())
            .is_err()
    );
}

pub fn authenticated(data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    #[cfg(feature = "ethereum")]
    authenticated_for::<crypto_keystore_rs::EthereumKey>(data);
    #[cfg(feature = "solana")]
    authenticated_for::<crypto_keystore_rs::SolanaKey>(data);
}
