#![cfg(feature = "ethereum")]
use crypto_keystore_rs::{
    ChainKey, EthereumKey, EthereumKeystore, KdfConfig, KeystoreBuilder, KeystoreError,
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

#[test]
fn creates_missing_directories() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("new/nested");
    let store = store();
    store.save_to_file(&nested).unwrap();
    let loaded =
        EthereumKeystore::load_from_file(nested.join(format!("{}.json", store.id())), "password")
            .unwrap();
    assert_eq!(
        loaded.key().unwrap().to_keystore_bytes(),
        store.key().unwrap().to_keystore_bytes()
    );
}

#[test]
fn failed_persist_leaves_existing_destination_and_cleans_temporary_files() {
    let dir = tempfile::tempdir().unwrap();
    let store = store();
    let destination = dir.path().join(format!("{}.json", store.id()));
    std::fs::create_dir(&destination).unwrap();
    let sentinel = destination.join("keep");
    std::fs::write(&sentinel, "original").unwrap();
    assert!(matches!(
        store.save_to_file(dir.path()),
        Err(KeystoreError::IoError(_))
    ));
    assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "original");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn rejects_a_file_used_as_the_output_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, "original").unwrap();
    assert!(matches!(
        store().save_to_file(&path),
        Err(KeystoreError::IoError(_))
    ));
    assert_eq!(std::fs::read_to_string(path).unwrap(), "original");
}

#[test]
#[cfg(unix)]
fn unwritable_directory_preserves_the_old_keystore() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = store();
    store.save_to_file(dir.path()).unwrap();
    let path = dir.path().join(format!("{}.json", store.id()));
    let before = std::fs::read(&path).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    // Privileged users may bypass mode bits; exercise this case only when enforced.
    let probe = tempfile::NamedTempFile::new_in(dir.path());
    if let Ok(probe) = probe {
        drop(probe);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let result = store.save_to_file(dir.path());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(result, Err(KeystoreError::IoError(_))));
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn concurrent_writes_are_read_as_complete_keystores() {
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().unwrap();
    let stores: Vec<_> = (0..2)
        .map(|_| {
            KeystoreBuilder::<EthereumKey>::new()
                .with_random_key()
                .with_uuid("3198bc9c-6672-5ab3-d995-4942343ae5b6")
                .with_kdf_config(KdfConfig::custom_pbkdf2(2))
                .build("password")
                .unwrap()
        })
        .collect();
    let expected: Vec<_> = stores
        .iter()
        .map(|s| s.key().unwrap().to_keystore_bytes())
        .collect();
    stores[0].save_to_file(dir.path()).unwrap();
    let path = dir.path().join(format!("{}.json", stores[0].id()));
    let barrier = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        for store in &stores {
            let barrier = barrier.clone();
            let dir = dir.path();
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..16 {
                    store.save_to_file(dir).unwrap();
                }
            });
        }
        barrier.wait();
        for _ in 0..32 {
            let result = EthereumKeystore::load_from_file(&path, "password");
            let key = result.unwrap().key().unwrap().to_keystore_bytes();
            assert!(expected.contains(&key));
        }
    });
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
