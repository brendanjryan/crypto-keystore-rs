#![cfg(any(feature = "ethereum", feature = "solana"))]
#[path = "support/fuzz_cases.rs"]
mod cases;

fn valid_seeds<K: crypto_keystore_rs::ChainKey>(key: K, chain: &str, versions: &[u32]) {
    for version in versions {
        for kdf in ["pbkdf2", "scrypt"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "fuzz/corpus/imports/fast-{chain}-v{version}-{kdf}.json"
            ));
            let input = std::fs::read_to_string(path).unwrap();
            let loaded = crypto_keystore_rs::Keystore::<K>::from_json_with_import_limits(
                &input,
                "testpassword",
                cases::limits(),
            )
            .unwrap();
            assert_eq!(
                *loaded.key().unwrap().to_keystore_bytes(),
                *key.to_keystore_bytes()
            );
        }
    }
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_seeds_decrypt_within_fuzz_limits() {
    use crypto_keystore_rs::ChainKey;
    valid_seeds(
        crypto_keystore_rs::EthereumKey::from_keystore_bytes(&[1; 32]).unwrap(),
        "ethereum",
        &[3, 4, 5],
    );
}

#[test]
#[cfg(feature = "solana")]
fn solana_seeds_decrypt_within_fuzz_limits() {
    valid_seeds(
        crypto_keystore_rs::SolanaKey::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
            &[1; 32],
        )),
        "solana",
        &[4, 5],
    );
}

#[test]
fn replay_fuzz_corpora() {
    for (directory, exercise) in [
        ("imports", cases::imports as fn(&[u8])),
        ("authenticated", cases::authenticated as fn(&[u8])),
    ] {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus")
            .join(directory);
        let mut count = 0;
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                exercise(&std::fs::read(path).unwrap());
                count += 1;
            }
        }
        assert!(count > 0, "empty {directory} corpus");
    }
}

#[test]
fn every_authenticated_field_is_checked_for_both_kdfs() {
    for kdf in 0..2 {
        for field in 0..8 {
            cases::authenticated(&[kdf, 7, field, b'p', 0, 0xff]);
        }
    }
}
