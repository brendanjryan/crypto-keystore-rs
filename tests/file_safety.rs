#![cfg(feature = "ethereum")]
use crypto_keystore_rs::{
    EthereumKey, EthereumKeystore, KdfConfig, KeystoreBuilder, KeystoreError,
};
use serde_json::{json, Value};

fn store() -> EthereumKeystore {
    EthereumKeystore::new_with_config("password", KdfConfig::custom_scrypt(4, 8, 1)).unwrap()
}

#[test]
fn rejects_path_ids_at_import_and_build() {
    let base = serde_json::to_value(store()).unwrap();
    for id in ["../outside", "/tmp/outside", "..\\outside", "invalid"] {
        let mut value = base.clone();
        value["id"] = json!(id);
        assert!(serde_json::from_value::<EthereumKeystore>(value).is_err());
        assert!(matches!(
            KeystoreBuilder::<EthereumKey>::new()
                .with_random_key()
                .with_uuid(id)
                .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
                .build("password"),
            Err(KeystoreError::InvalidId(_))
        ));
    }
}

#[test]
fn normalizes_valid_uuid_spellings() {
    let mut value = serde_json::to_value(store()).unwrap();
    value["id"] = json!("urn:uuid:3198BC9C-6672-5AB3-D995-4942343AE5B6");
    let parsed: EthereumKeystore = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.id(), "3198bc9c-6672-5ab3-d995-4942343ae5b6");
}

#[test]
fn replaces_existing_file_with_complete_keystore() {
    let dir = tempfile::tempdir().unwrap();
    let store = store();
    let path = dir.path().join(format!("{}.json", store.id()));
    std::fs::write(&path, "old contents").unwrap();
    store.save_to_file(dir.path()).unwrap();
    let loaded = EthereumKeystore::load_from_file(path, "password").unwrap();
    assert_eq!(store.address().unwrap(), loaded.address().unwrap());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
#[cfg(unix)]
fn replaces_symlinks_without_following_them_and_sets_private_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside.json");
    std::fs::write(&outside, "keep me").unwrap();
    let store = store();
    let target = dir.path().join(format!("{}.json", store.id()));
    symlink(&outside, &target).unwrap();
    store.save_to_file(dir.path()).unwrap();
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "keep me");
    assert!(!std::fs::symlink_metadata(&target)
        .unwrap()
        .file_type()
        .is_symlink());
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    store.save_to_file(dir.path()).unwrap();
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let _: Value = serde_json::from_str(&std::fs::read_to_string(target).unwrap()).unwrap();
}
