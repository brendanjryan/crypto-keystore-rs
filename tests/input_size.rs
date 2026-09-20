#![cfg(any(feature = "ethereum", feature = "solana"))]
use crypto_keystore_rs::{ImportLimits, KdfConfig, KdfLimits, KeystoreError};
use serde_json::{json, Value};

#[cfg(feature = "ethereum")]
use crypto_keystore_rs::EthereumKeystore as Store;
#[cfg(all(feature = "solana", not(feature = "ethereum")))]
use crypto_keystore_rs::SolanaKeystore as Store;

fn fixture() -> Value {
    serde_json::to_value(Store::new_with_config("password", KdfConfig::custom_pbkdf2(2)).unwrap())
        .unwrap()
}

#[test]
fn default_imports_reject_oversized_json_and_files() {
    let mut value = fixture();
    value["padding"] = json!("x".repeat(2 * 1024 * 1024));
    let json = value.to_string();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oversized.json");
    std::fs::write(&path, &json).unwrap();
    for result in [
        Store::from_json(&json, "password"),
        Store::from_json_with_limits(&json, "password", KdfLimits::default()),
        Store::load_from_file(&path, "password"),
        Store::load_from_file_with_limits(&path, "password", KdfLimits::default()),
    ] {
        assert!(matches!(
            result,
            Err(KeystoreError::InputTooLarge { max_bytes: 65_536 })
        ));
    }
    // Callers can explicitly permit large extension fields without raising KDF budgets.
    let limits = ImportLimits {
        max_input_bytes: json.len(),
        ..ImportLimits::default()
    };
    assert!(Store::from_json_with_import_limits(&json, "password", limits).is_ok());
    assert!(Store::load_from_file_with_import_limits(path, "password", limits).is_ok());
}

#[test]
fn exact_input_boundary_counts_utf8_bytes_and_whitespace() {
    let mut value = fixture();
    value["padding"] = json!("é".repeat(8));
    let json = format!(" \n{}\n ", value);
    assert!(json.len() > json.chars().count());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    std::fs::write(&path, &json).unwrap();
    for max_input_bytes in [
        0,
        json.chars().count(),
        json.len() - 1,
        json.len(),
        usize::MAX,
    ] {
        let limits = ImportLimits {
            max_input_bytes,
            ..ImportLimits::default()
        };
        for result in [
            Store::from_json_with_import_limits(&json, "password", limits),
            Store::load_from_file_with_import_limits(&path, "password", limits),
        ] {
            if max_input_bytes >= json.len() {
                assert!(result.is_ok());
            } else {
                assert!(
                    matches!(result, Err(KeystoreError::InputTooLarge { max_bytes }) if max_bytes == max_input_bytes)
                );
            }
        }
    }
}

#[test]
fn default_input_boundary_is_inclusive() {
    let mut json = fixture().to_string();
    json.push_str(&" ".repeat(ImportLimits::default().max_input_bytes - json.len()));
    assert!(Store::from_json(&json, "password").is_ok());
    json.push(' ');
    assert!(matches!(
        Store::from_json(&json, "password"),
        Err(KeystoreError::InputTooLarge { .. })
    ));
}

#[test]
fn size_is_checked_before_json_parsing_or_utf8_validation() {
    let limits = ImportLimits {
        max_input_bytes: 4,
        ..ImportLimits::default()
    };
    assert!(matches!(
        Store::from_json_with_import_limits("invalid", "password", limits),
        Err(KeystoreError::InputTooLarge { .. })
    ));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.json");
    std::fs::write(&path, [0xff; 5]).unwrap();
    assert!(matches!(
        Store::load_from_file_with_import_limits(&path, "password", limits),
        Err(KeystoreError::InputTooLarge { .. })
    ));
    std::fs::write(&path, [0xff; 4]).unwrap();
    assert!(
        matches!(Store::load_from_file_with_import_limits(path, "password", limits), Err(KeystoreError::IoError(err)) if err.kind() == std::io::ErrorKind::InvalidData)
    );
}

#[test]
fn custom_input_limit_preserves_kdf_limits() {
    let json = fixture().to_string();
    let limits = ImportLimits {
        max_input_bytes: json.len(),
        kdf: KdfLimits {
            max_pbkdf2_iterations: 1,
            ..KdfLimits::default()
        },
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    std::fs::write(&path, &json).unwrap();
    for result in [
        Store::from_json_with_import_limits(&json, "password", limits),
        Store::load_from_file_with_import_limits(path, "password", limits),
    ] {
        assert!(matches!(result, Err(KeystoreError::InvalidKdfParams(_))));
    }
}

#[test]
fn encoded_field_lengths_are_checked_before_decoding() {
    let base = fixture();
    for (pointer, valid_len) in [
        ("/crypto/cipherparams/iv", 24),
        ("/crypto/mac", 32),
        (
            "/crypto/ciphertext",
            base["crypto"]["ciphertext"].as_str().unwrap().len(),
        ),
    ] {
        for len in [valid_len - 1, valid_len, 16 * 1024] {
            let mut value = base.clone();
            *value.pointer_mut(pointer).unwrap() = json!("z".repeat(len));
            // Invalid KDF parameters must not be evaluated for malformed fields.
            value["crypto"]["c"] = json!(u32::MAX);
            let result = Store::from_json(&value.to_string(), "password");
            if len == valid_len {
                assert!(matches!(result, Err(KeystoreError::HexError(_))));
            } else {
                assert!(matches!(result, Err(KeystoreError::CorruptedData)));
            }
        }
    }
}
