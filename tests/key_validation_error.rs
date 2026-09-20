use crypto_keystore_rs::{ChainKey, KdfConfig, Keystore, KeystoreError, Result};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
struct RejectedKey;
impl ChainKey for RejectedKey {
    const SECRET_KEY_SIZE: usize = 32;
    const KEYSTORE_SIZE: usize = 32;
    const CHAIN_ID: &'static str = "rejected";
    fn to_keystore_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![42; 32])
    }
    fn from_keystore_bytes(bytes: &[u8]) -> Result<Self> {
        assert_eq!(bytes, &[42; 32]);
        Err(KeystoreError::InvalidKey {
            chain: Self::CHAIN_ID.into(),
            reason: "rejected after decryption".into(),
        })
    }
    fn generate<R: RngCore + CryptoRng>(_: &mut R) -> Self {
        Self
    }
    fn address(&self) -> String {
        "rejected".into()
    }
}

#[test]
fn propagates_key_validation_failure_after_decryption() {
    let store =
        Keystore::from_key_with_config(RejectedKey, "password", KdfConfig::custom_scrypt(4, 8, 1))
            .unwrap();
    let error =
        Keystore::<RejectedKey>::from_json(&store.to_json().unwrap(), "password").unwrap_err();
    assert!(matches!(error, KeystoreError::InvalidKey { .. }));
}
