mod common;

use crypto_keystore_rs::{ChainKey, KeystoreError};

#[cfg(feature = "ethereum")]
use crypto_keystore_rs::EthereumKey;

#[cfg(feature = "solana")]
use crypto_keystore_rs::SolanaKey;

// ==========================
// Ethereum Test Vectors
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_known_private_key_to_address() {
    // Test vector from https://ethereum.org/en/developers/docs/accounts/
    // Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    let private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let expected_address = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    let private_key_bytes = hex::decode(private_key_hex).unwrap();
    let key = EthereumKey::from_keystore_bytes(&private_key_bytes).unwrap();

    assert_eq!(
        key.address().to_lowercase(),
        expected_address.to_lowercase()
    );
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_test_vector_1() {
    // Another well-known test vector
    // Private key: 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let expected_address = "0xfcad0b19bb29d4674531d6f115237e16afce377c";

    let private_key_bytes = hex::decode(private_key_hex).unwrap();
    let key = EthereumKey::from_keystore_bytes(&private_key_bytes).unwrap();

    assert_eq!(
        key.address().to_lowercase(),
        expected_address.to_lowercase()
    );
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_test_vector_2() {
    // Private key: 1
    let private_key_bytes = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];
    let expected_address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";

    let key = EthereumKey::from_keystore_bytes(&private_key_bytes).unwrap();

    assert_eq!(
        key.address().to_lowercase(),
        expected_address.to_lowercase()
    );
}

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_rejects_zero_private_key() {
    // Private key cannot be all zeros
    let private_key_bytes = vec![0u8; 32];
    let result = EthereumKey::from_keystore_bytes(&private_key_bytes);

    assert!(result.is_err());
    assert!(matches!(result, Err(KeystoreError::InvalidKey { .. })));
}

// ==========================
// Solana Test Vectors
// ==========================

#[test]
#[cfg(feature = "solana")]
fn solana_known_keypair_to_address() {
    // Ed25519 test vector from RFC 8032 (Test 1)
    // Secret key (32 bytes) + Public key (32 bytes)
    let secret_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let public_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    let mut keypair_bytes = hex::decode(secret_hex).unwrap();
    keypair_bytes.extend_from_slice(&hex::decode(public_hex).unwrap());

    let key = SolanaKey::from_keystore_bytes(&keypair_bytes).unwrap();
    let address = key.address();

    // Solana addresses are base58-encoded public keys
    // Compute expected address from public key
    let expected_address = bs58::encode(&hex::decode(public_hex).unwrap()).into_string();
    assert_eq!(address, expected_address);
}

#[test]
#[cfg(feature = "solana")]
fn solana_test_vector_from_seed_1() {
    // Ed25519 test vector from RFC 8032 (Test 2)
    let secret_hex = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    let public_hex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

    let mut keypair_bytes = hex::decode(secret_hex).unwrap();
    keypair_bytes.extend_from_slice(&hex::decode(public_hex).unwrap());

    let key = SolanaKey::from_keystore_bytes(&keypair_bytes).unwrap();
    let address = key.address();

    // Verify the address is valid base58 and matches expected public key
    assert_eq!(address.len(), 44); // Solana addresses are 44 chars in base58
    let expected_address = bs58::encode(&hex::decode(public_hex).unwrap()).into_string();
    assert_eq!(address, expected_address);
}

#[test]
#[cfg(feature = "solana")]
fn solana_rejects_mismatched_keypair() {
    // Create a keypair where public key doesn't match secret key
    let secret_bytes = vec![1u8; 32];
    let wrong_public = vec![2u8; 32];

    let mut keypair_bytes = secret_bytes;
    keypair_bytes.extend_from_slice(&wrong_public);

    let result = SolanaKey::from_keystore_bytes(&keypair_bytes);

    // Should reject mismatched keypair
    assert!(result.is_err());
    assert!(matches!(result, Err(KeystoreError::InvalidKey { .. })));
}

// ==========================
// KDF Test Vectors
// ==========================

#[test]
fn scrypt_kdf_produces_consistent_output() {
    use scrypt::{scrypt, Params as ScryptParams};

    // Verify Scrypt produces consistent, deterministic output
    let password = b"test_password";
    let salt = b"test_salt";
    let log_n = 4; // N = 16 (fast for testing)
    let r = 8;
    let p = 1;
    let dklen = 32;

    let params = ScryptParams::new(log_n, r, p, dklen).unwrap();

    let mut output1 = vec![0u8; dklen];
    scrypt(password, salt, &params, &mut output1).unwrap();

    let mut output2 = vec![0u8; dklen];
    scrypt(password, salt, &params, &mut output2).unwrap();

    // Same inputs should produce same output
    assert_eq!(output1, output2);
    assert_eq!(output1.len(), dklen);
}

#[test]
fn pbkdf2_produces_consistent_output() {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    // Verify PBKDF2 produces consistent, deterministic output
    let password = b"test_password";
    let salt = b"test_salt";
    let iterations = 1000;

    let mut output1 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output1);

    let mut output2 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output2);

    // Same inputs should produce same output
    assert_eq!(output1, output2);
    assert_eq!(output1.len(), 32);
}

// ==========================
// MAC Computation Test Vectors
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn keccak256_mac_is_deterministic() {
    use sha3::{Digest, Keccak256};

    // Verify Keccak256 MAC computation is deterministic
    let mac_key = b"test_mac_key_123";
    let ciphertext = b"test_ciphertext_data";

    let mut hasher1 = Keccak256::new();
    hasher1.update(mac_key);
    hasher1.update(ciphertext);
    let mac1 = hasher1.finalize();

    let mut hasher2 = Keccak256::new();
    hasher2.update(mac_key);
    hasher2.update(ciphertext);
    let mac2 = hasher2.finalize();

    // Same inputs should produce same MAC
    assert_eq!(mac1, mac2);
    assert_eq!(mac1.len(), 32); // Keccak256 produces 32 bytes
}

#[test]
fn sha256_mac_is_deterministic() {
    use sha2::{Digest, Sha256};

    // Verify SHA256 MAC computation is deterministic
    let mac_key = b"test_mac_key_123";
    let ciphertext = b"test_ciphertext_data";

    let mut hasher1 = Sha256::new();
    hasher1.update(mac_key);
    hasher1.update(ciphertext);
    let mac1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(mac_key);
    hasher2.update(ciphertext);
    let mac2 = hasher2.finalize();

    // Same inputs should produce same MAC
    assert_eq!(mac1, mac2);
    assert_eq!(mac1.len(), 32); // SHA256 produces 32 bytes
}

// ==========================
// Roundtrip Correctness Tests
// ==========================

#[test]
#[cfg(feature = "ethereum")]
fn ethereum_keystore_bytes_roundtrip_preserves_key() {
    // Verify that to_keystore_bytes -> from_keystore_bytes is lossless
    let private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let private_key_bytes = hex::decode(private_key_hex).unwrap();

    let key1 = EthereumKey::from_keystore_bytes(&private_key_bytes).unwrap();
    let serialized = key1.to_keystore_bytes();
    let key2 = EthereumKey::from_keystore_bytes(&serialized).unwrap();

    assert_eq!(key1.address(), key2.address());
    assert_eq!(serialized, private_key_bytes);
}

#[test]
#[cfg(feature = "solana")]
fn solana_keystore_bytes_roundtrip_preserves_keypair() {
    // Verify that to_keystore_bytes -> from_keystore_bytes is lossless
    let secret_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let public_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    let mut keypair_bytes = hex::decode(secret_hex).unwrap();
    keypair_bytes.extend_from_slice(&hex::decode(public_hex).unwrap());

    let key1 = SolanaKey::from_keystore_bytes(&keypair_bytes).unwrap();
    let serialized = key1.to_keystore_bytes();
    let key2 = SolanaKey::from_keystore_bytes(&serialized).unwrap();

    assert_eq!(key1.address(), key2.address());
    assert_eq!(serialized, keypair_bytes);
}
