#![cfg(feature = "ethereum")]
use crypto_keystore_rs::{EthereumKeystore, KdfConfig, KdfLimits};
use proptest::prelude::*;
use serde_json::json;

fn limits() -> KdfLimits {
    KdfLimits {
        max_dklen: 64,
        max_pbkdf2_iterations: 8,
        max_scrypt_memory_bytes: 64 * 1024,
        max_scrypt_work: 1024,
    }
}

proptest! {
    #[test]
    fn arbitrary_json_returns_without_panicking(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let input = String::from_utf8_lossy(&bytes);
        let _ = EthereumKeystore::from_json_with_limits(&input, "password", limits());
    }

    #[test]
    fn malformed_fields_return_without_panicking(
        field in 0usize..6,
        bytes in prop::collection::vec(any::<u8>(), 0..128),
        number in any::<u32>(),
    ) {
        let store = EthereumKeystore::new_with_config("password", KdfConfig::custom_pbkdf2(1)).unwrap();
        let mut value = serde_json::to_value(store).unwrap();
        match field {
            0 => value["crypto"]["cipherparams"]["iv"] = json!(hex::encode(bytes)),
            1 => value["crypto"]["ciphertext"] = json!(hex::encode(bytes)),
            2 => value["crypto"]["mac"] = json!(hex::encode(bytes)),
            3 => value["crypto"]["salt"] = json!(hex::encode(bytes)),
            4 => value["crypto"]["dklen"] = json!(number),
            _ => value["crypto"]["c"] = json!(number),
        }
        let _ = EthereumKeystore::from_json_with_limits(&value.to_string(), "password", limits());
    }
}
