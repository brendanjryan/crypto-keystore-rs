#![cfg(feature = "ethereum")]
use crypto_keystore_rs::{
    ChainKey, EthereumKey, EthereumKeystore, KdfConfig, KeystoreBuilder, VERSION_3, VERSION_4,
};
use serde_json::{json, Value};

// https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage/
// https://github.com/ethereum/go-ethereum/blob/master/accounts/keystore/testdata/very-light-scrypt.json
#[test]
fn decrypts_external_web3_vectors() {
    for (input, password, address) in [
        (
            include_str!("fixtures/ethereum_v3.json"),
            "testpassword",
            "0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
        ),
        (
            include_str!("fixtures/ethereum_v3_scrypt.json"),
            "",
            "0x45dea0fb0bba44f4fcf290bba71fd57d7117cbb8",
        ),
    ] {
        let store = EthereumKeystore::from_json(input, password).unwrap();
        assert_eq!(store.address().unwrap().to_lowercase(), address);
        if password == "testpassword" {
            assert_eq!(
                hex::encode(store.key().unwrap().to_keystore_bytes()),
                "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
            );
        }
    }
}

#[test]
fn v3_serializes_nested_parameters_and_v4_preserves_flat_parameters() {
    for config in [
        KdfConfig::custom_pbkdf2(1),
        KdfConfig::custom_scrypt(4, 8, 1),
    ] {
        for version in [VERSION_3, VERSION_4] {
            let store = KeystoreBuilder::<EthereumKey>::new()
                .with_random_key()
                .with_version(version)
                .with_kdf_config(config)
                .build("password")
                .unwrap();
            let value = serde_json::to_value(&store).unwrap();
            assert_eq!(
                value["crypto"].get("kdfparams").is_some(),
                version == VERSION_3
            );
            assert_eq!(value["crypto"].get("dklen").is_some(), version == VERSION_4);
            assert_eq!(
                EthereumKeystore::from_json(&value.to_string(), "password")
                    .unwrap()
                    .address()
                    .unwrap(),
                store.address().unwrap()
            );
        }
    }
}

#[test]
fn rejects_ambiguous_nested_and_flat_parameters() {
    let base: Value = serde_json::from_str(include_str!("fixtures/ethereum_v3.json")).unwrap();
    for field in ["dklen", "c", "salt", "n", "r", "p", "prf"] {
        let mut value = base.clone();
        value["crypto"][field] = json!(1);
        assert!(serde_json::from_value::<EthereumKeystore>(value).is_err());
    }
}
