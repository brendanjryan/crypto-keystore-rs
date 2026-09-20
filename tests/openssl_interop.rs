#![cfg(any(feature = "ethereum", feature = "solana"))]
use crypto_keystore_rs::{ChainKey, KdfConfig, Keystore, KeystoreBuilder};
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

fn openssl(request: Value) -> Value {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/openssl.cjs");
    let mut child = Command::new("node")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Node.js is required for the OpenSSL interoperability suite");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn check<K: ChainKey>(key: K, versions: &[u32]) {
    let password = "unicode é password\0with-nul";
    let expected = hex::encode(key.to_keystore_bytes());
    for &version in versions {
        for config in [
            KdfConfig::custom_pbkdf2(2),
            KdfConfig::custom_scrypt(4, 8, 1),
        ] {
            let store = KeystoreBuilder::new()
                .with_key(key.clone())
                .with_version(version)
                .with_kdf_config(config)
                .build(password)
                .unwrap();
            let mut value = serde_json::to_value(&store).unwrap();
            assert_eq!(
                openssl(json!({"operation":"decrypt", "keystore":value, "password":password}))
                    ["plaintext"],
                expected
            );
            if version == 5 {
                // Change both random fields so this checks independent encryption, not a replay.
                value["crypto"]["salt"] = json!("07".repeat(32));
                value["crypto"]["cipherparams"]["iv"] = json!("09".repeat(12));
                let external = openssl(
                    json!({"operation":"encrypt", "keystore":value, "password":password, "plaintext":expected}),
                );
                let loaded = Keystore::<K>::from_json(&external.to_string(), password).unwrap();
                assert_eq!(
                    hex::encode(loaded.key().unwrap().to_keystore_bytes()),
                    expected
                );
                assert!(Keystore::<K>::from_json(&external.to_string(), "wrong").is_err());
            }
        }
    }
}

#[test]
#[ignore = "requires Node.js/OpenSSL; executed by the interoperability CI job"]
#[cfg(feature = "ethereum")]
fn ethereum_openssl_interoperability() {
    let mut secret = [0; 32];
    secret[31] = 1;
    check(
        crypto_keystore_rs::EthereumKey::from_keystore_bytes(&secret).unwrap(),
        &[3, 5],
    );
}

#[test]
#[ignore = "requires Node.js/OpenSSL; executed by the interoperability CI job"]
#[cfg(feature = "solana")]
fn solana_openssl_interoperability() {
    check(
        crypto_keystore_rs::SolanaKey::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
            &[1; 32],
        )),
        &[5],
    );
}
