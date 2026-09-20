#![cfg(feature = "ethereum")]
use crypto_keystore_rs::{EthereumKeystore, KdfConfig, KdfLimits, KeystoreError};
use serde_json::{json, Value};
fn fixture(config: KdfConfig) -> Value {
    serde_json::to_value(EthereumKeystore::new_with_config("password", config).unwrap()).unwrap()
}
#[test]
fn rejects_excessive_pbkdf2_before_allocating_or_deriving() {
    for (field, excessive) in [("dklen", u32::MAX), ("c", u32::MAX)] {
        let mut value = fixture(KdfConfig::custom_pbkdf2(1));
        value["crypto"][field] = json!(excessive);
        assert!(matches!(
            EthereumKeystore::from_json(&value.to_string(), "password"),
            Err(KeystoreError::InvalidKdfParams(_))
        ));
    }
}
#[test]
fn rejects_excessive_scrypt_memory_work_and_overflow() {
    let base = fixture(KdfConfig::custom_scrypt(4, 8, 1));
    for (n, r, p) in [
        (1u32 << 31, 8, 1),
        (16, 8, 1_000_000),
        (1 << 31, u32::MAX, u32::MAX),
    ] {
        let mut value = base.clone();
        value["crypto"]["n"] = json!(n);
        value["crypto"]["r"] = json!(r);
        value["crypto"]["p"] = json!(p);
        assert!(matches!(
            EthereumKeystore::from_json(&value.to_string(), "password"),
            Err(KeystoreError::InvalidKdfParams(_))
        ));
    }
}
#[test]
fn custom_limits_enforce_exact_boundaries_for_both_kdfs() {
    let pbkdf2 = fixture(KdfConfig::custom_pbkdf2(2)).to_string();
    let scrypt = fixture(KdfConfig::custom_scrypt(4, 8, 1)).to_string();
    let limits = KdfLimits {
        max_dklen: 32,
        max_pbkdf2_iterations: 2,
        max_scrypt_memory_bytes: 128 * 8 * (16 + 1 + 2),
        max_scrypt_work: 16 * 8,
    };
    for json in [&pbkdf2, &scrypt] {
        assert!(EthereumKeystore::from_json_with_limits(json, "password", limits).is_ok());
        assert!(matches!(
            EthereumKeystore::from_json_with_limits(
                json,
                "password",
                KdfLimits {
                    max_dklen: 31,
                    ..limits
                }
            ),
            Err(KeystoreError::InvalidKdfParams(_))
        ));
    }
    for stricter in [
        KdfLimits {
            max_scrypt_memory_bytes: limits.max_scrypt_memory_bytes - 1,
            ..limits
        },
        KdfLimits {
            max_scrypt_work: limits.max_scrypt_work - 1,
            ..limits
        },
    ] {
        assert!(matches!(
            EthereumKeystore::from_json_with_limits(&scrypt, "password", stricter),
            Err(KeystoreError::InvalidKdfParams(_))
        ));
    }
    let stricter = KdfLimits {
        max_pbkdf2_iterations: 1,
        ..limits
    };
    assert!(matches!(
        EthereumKeystore::from_json_with_limits(&pbkdf2, "password", stricter),
        Err(KeystoreError::InvalidKdfParams(_))
    ));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    std::fs::write(&path, pbkdf2).unwrap();
    assert!(matches!(
        EthereumKeystore::load_from_file_with_limits(path, "password", stricter),
        Err(KeystoreError::InvalidKdfParams(_))
    ));
}
