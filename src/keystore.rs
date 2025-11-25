use crate::chains::ChainKey;
use crate::error::{KeystoreError, Result};
use aes::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use rand::{CryptoRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

#[cfg(feature = "ethereum")]
use sha3::Keccak256;

type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

/// AES-128-CTR cipher identifier for Web3 Secret Storage format
const CIPHER_NAME: &str = "aes-128-ctr";

/// Size of encryption key and salt in bytes
const DEFAULT_KEY_SIZE: usize = 32;

/// Size of initialization vector in bytes
const DEFAULT_IV_SIZE: usize = 16;

/// Derived key length for KDF output
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32;

/// Size of encryption key slice from derived key (first 16 bytes)
const ENCRYPTION_KEY_SIZE: usize = 16;

/// Size of MAC key slice from derived key (second 16 bytes)
const MAC_KEY_SIZE: usize = 16;

/// Supported PRF (Pseudo-Random Function) for PBKDF2
const SUPPORTED_PRF: &str = "hmac-sha256";

/// Keystore version 3 - Ethereum Legacy Format
///
/// The original Web3 Secret Storage Definition format used by Ethereum.
/// - Always uses Keccak256 for MAC calculation
/// - No `chain` field in the JSON
/// - Maintains compatibility with existing Ethereum tooling
const VERSION_3: u32 = 3;

/// Keystore version 4 - Multi-Chain Format
///
/// Extended format supporting multiple blockchains (Ethereum, Solana, etc.).
/// - Includes a `chain` field to identify the blockchain
/// - Uses chain-specific MAC algorithms:
///   - `chain="ethereum"` → Keccak256 (for Ethereum compatibility)
///   - `chain="solana"` or others → SHA256
const VERSION_4: u32 = 4;

// Use weaker params in tests for speed, production params otherwise
#[cfg(not(any(test, feature = "test-utils")))]
/// Scrypt log2(N) parameter for production (2^18 = 262,144 iterations)
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 18;

#[cfg(any(test, feature = "test-utils"))]
/// Scrypt log2(N) parameter for tests (2^4 = 16 iterations, INSECURE!)
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 4;

/// Scrypt r parameter (block size)
const DEFAULT_KDF_PARAMS_R: u32 = 8;

/// Scrypt p parameter (parallelization)
const DEFAULT_KDF_PARAMS_P: u32 = 1;

/// Computed Scrypt N value for production (2^18 = 262,144)
#[cfg(not(any(test, feature = "test-utils")))]
const SCRYPT_N: u32 = 1 << DEFAULT_KDF_PARAMS_LOG_N;

/// Computed Scrypt N value for tests (2^4 = 16)
#[cfg(any(test, feature = "test-utils"))]
const SCRYPT_N: u32 = 1 << DEFAULT_KDF_PARAMS_LOG_N;

/// A generic keystore supporting multiple blockchain key types.
///
/// The keystore uses the Web3 Secret Storage format with AES-128-CTR encryption
/// and Scrypt/PBKDF2 key derivation. Keys are encrypted at rest and only decrypted
/// when loaded with the correct password.
///
/// # Type Parameters
///
/// * `K` - The blockchain key type implementing [`ChainKey`]
///
/// # Examples
///
/// ```
/// use crypto_keystore_rs::{EthereumKeystore, ChainKey};
///
/// let keystore = EthereumKeystore::new("my_password").unwrap();
/// println!("Address: {}", keystore.key().unwrap().public_key());
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct Keystore<K: ChainKey> {
    /// The decrypted key: only present after successful decryption
    #[serde(skip)]
    key: Option<K>,

    /// Encrypted key material and cryptographic parameters
    crypto: CryptoJson,

    /// Unique identifier (UUID v4)
    id: String,

    /// Format version
    /// - 3 for Ethereum legacy
    /// - 4 for multi-chain
    version: u32,

    /// Chain identifier ("ethereum", "solana", etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: Option<String>,
}

impl<'de, K: ChainKey> Deserialize<'de> for Keystore<K> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct KeystoreHelper {
            crypto: CryptoJson,
            id: String,
            version: u32,
            chain: Option<String>,
        }

        let helper = KeystoreHelper::deserialize(deserializer)?;
        Ok(Keystore {
            key: None,
            crypto: helper.crypto,
            id: helper.id,
            version: helper.version,
            chain: helper.chain,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CryptoJson {
    cipher: String,
    cipherparams: CipherparamsJson,
    ciphertext: String,

    #[serde(flatten)]
    kdfparams: KdfparamsType,

    mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CipherparamsJson {
    iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kdf", rename_all = "lowercase")]
enum KdfparamsType {
    Scrypt {
        dklen: u32,
        n: u32,
        p: u32,
        r: u32,
        salt: String,
    },
    Pbkdf2 {
        dklen: u32,
        c: u32,
        prf: String,
        salt: String,
    },
}

impl<K: ChainKey> Keystore<K> {
    /// Helper to decode hex string with context for better error messages.
    #[inline]
    fn decode_hex(hex_str: &str, context: &str) -> Result<Vec<u8>> {
        hex::decode(hex_str).map_err(|e| KeystoreError::HexError(format!("Invalid {context}: {e}")))
    }

    /// Helper to generate random bytes using a cryptographically secure RNG.
    #[inline]
    fn generate_random_bytes<R: RngCore + CryptoRng>(rng: &mut R, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Derives encryption key from password using specified KDF parameters.
    fn derive_key(password: &str, kdfparams: &KdfparamsType) -> Result<Vec<u8>> {
        match kdfparams {
            KdfparamsType::Pbkdf2 {
                dklen,
                c,
                prf,
                salt,
            } => {
                if prf != SUPPORTED_PRF {
                    return Err(KeystoreError::UnsupportedKdf(format!(
                        "Unsupported PRF: {prf}, expected {SUPPORTED_PRF}"
                    )));
                }

                let salt_bytes = Self::decode_hex(salt, "KDF salt")?;

                let mut key = vec![0u8; *dklen as usize];
                pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bytes, *c, &mut key);
                Ok(key)
            }
            KdfparamsType::Scrypt {
                dklen,
                n,
                r,
                p,
                salt,
            } => {
                let salt_bytes = Self::decode_hex(salt, "KDF salt")?;

                // Validate n is a power of 2 and compute log2 using integer operations
                if !n.is_power_of_two() {
                    return Err(KeystoreError::InvalidKdfParams(format!(
                        "Scrypt n parameter must be a power of 2, got {n}"
                    )));
                }
                let log_n = n.trailing_zeros() as u8;
                let params = ScryptParams::new(log_n, *r, *p, *dklen as usize).map_err(|e| {
                    KeystoreError::InvalidKdfParams(format!("Invalid scrypt params: {e}"))
                })?;

                let mut key = vec![0u8; *dklen as usize];
                scrypt(password.as_bytes(), &salt_bytes, &params, &mut key).map_err(|e| {
                    KeystoreError::CryptoError(format!("Scrypt derivation failed: {e}"))
                })?;

                Ok(key)
            }
        }
    }

    /// Computes MAC for given key and ciphertext.
    /// Uses Keccak256 for Ethereum (v3 or chain="ethereum"), SHA256 otherwise.
    fn compute_mac(mac_key: &[u8], ciphertext: &[u8], use_keccak: bool) -> Result<Vec<u8>> {
        if use_keccak {
            #[cfg(feature = "ethereum")]
            {
                use sha3::Digest as _;
                let mut hasher = Keccak256::new();
                hasher.update(mac_key);
                hasher.update(ciphertext);
                Ok(hasher.finalize().to_vec())
            }
            #[cfg(not(feature = "ethereum"))]
            {
                Err(KeystoreError::UnsupportedChain(
                    "ethereum feature not enabled".to_string(),
                ))
            }
        } else {
            let mut hasher = Sha256::new();
            hasher.update(mac_key);
            hasher.update(ciphertext);
            Ok(hasher.finalize().to_vec())
        }
    }

    /// Creates a new keystore with a randomly generated key.
    ///
    /// Uses the system's cryptographically secure random number generator.
    ///
    /// # Arguments
    ///
    /// * `password` - Password to encrypt the keystore
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_keystore_rs::EthereumKeystore;
    ///
    /// let keystore = EthereumKeystore::new("my_secure_password").unwrap();
    /// ```
    pub fn new(password: &str) -> Result<Self> {
        Self::new_with_rng(&mut rand::thread_rng(), password)
    }

    /// Creates a new keystore with a randomly generated key using a custom RNG.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `password` - Password to encrypt the keystore
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_keystore_rs::EthereumKeystore;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let keystore = EthereumKeystore::new_with_rng(&mut rng, "my_secure_password").unwrap();
    /// ```
    pub fn new_with_rng<R: RngCore + CryptoRng>(rng: &mut R, password: &str) -> Result<Self> {
        let key = K::generate(rng);
        Self::from_key_with_rng(rng, key, password)
    }

    /// Creates a keystore from an existing key.
    ///
    /// Uses the system's cryptographically secure random number generator.
    ///
    /// # Arguments
    ///
    /// * `key` - The blockchain key to encrypt
    /// * `password` - Password to encrypt the keystore
    pub fn from_key(key: K, password: &str) -> Result<Self> {
        Self::from_key_with_rng(&mut rand::thread_rng(), key, password)
    }

    /// Creates a keystore from an existing key using a custom RNG.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `key` - The blockchain key to encrypt
    /// * `password` - Password to encrypt the keystore
    pub fn from_key_with_rng<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: K,
        password: &str,
    ) -> Result<Self> {
        let mut salt = Self::generate_random_bytes(rng, DEFAULT_KEY_SIZE);

        let mut derived_key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
        let scrypt_params = ScryptParams::new(
            DEFAULT_KDF_PARAMS_LOG_N,
            DEFAULT_KDF_PARAMS_R,
            DEFAULT_KDF_PARAMS_P,
            DEFAULT_KEY_SIZE,
        )
        .map_err(|e| KeystoreError::CryptoError(format!("Invalid scrypt params: {e}")))?;

        scrypt(password.as_bytes(), &salt, &scrypt_params, &mut derived_key)
            .map_err(|e| KeystoreError::CryptoError(format!("Scrypt derivation failed: {e}")))?;

        let encryption_key = &derived_key[..ENCRYPTION_KEY_SIZE];
        let mac_key = &derived_key[ENCRYPTION_KEY_SIZE..ENCRYPTION_KEY_SIZE + MAC_KEY_SIZE];

        let mut iv = Self::generate_random_bytes(rng, DEFAULT_IV_SIZE);

        let mut cipher = Aes128Ctr::new(encryption_key.into(), iv.as_slice().into());
        let mut ciphertext = key.to_keystore_bytes();
        cipher.apply_keystream(&mut ciphertext);

        let use_keccak = K::CHAIN_ID == "ethereum";
        let mac = Self::compute_mac(mac_key, &ciphertext, use_keccak)?;

        let crypto = CryptoJson {
            cipher: CIPHER_NAME.to_string(),
            cipherparams: CipherparamsJson {
                iv: hex::encode(&iv),
            },
            ciphertext: hex::encode(&ciphertext),
            kdfparams: KdfparamsType::Scrypt {
                dklen: DEFAULT_KDF_PARAMS_DKLEN as u32,
                n: SCRYPT_N,
                p: DEFAULT_KDF_PARAMS_P,
                r: DEFAULT_KDF_PARAMS_R,
                salt: hex::encode(&salt),
            },
            mac: hex::encode(&mac),
        };

        // Zeroize sensitive key material
        derived_key.zeroize();
        salt.zeroize();
        iv.zeroize();

        let uuid = Uuid::new_v4();

        Ok(Keystore {
            key: Some(key),
            crypto,
            id: uuid.to_string(),
            version: VERSION_4,
            chain: Some(K::CHAIN_ID.to_string()),
        })
    }

    /// Saves the keystore to a JSON file in the specified directory.
    ///
    /// The file will be named `{uuid}.json` where uuid is the keystore's unique identifier.
    /// If the directory doesn't exist, it will be created.
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory path where the keystore file will be saved
    ///
    /// # Returns
    ///
    /// The UUID of the keystore (used as the filename)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crypto_keystore_rs::EthereumKeystore;
    ///
    /// let keystore = EthereumKeystore::new("password").unwrap();
    /// let uuid = keystore.save_to_file("./keystores").unwrap();
    /// println!("Saved to: ./keystores/{}.json", uuid);
    /// ```
    pub fn save_to_file<P: AsRef<Path>>(&self, dir: P) -> Result<&str> {
        let dir = dir.as_ref();

        if !dir.exists() {
            fs::create_dir_all(dir)?;
        }

        let filename = format!("{}.json", self.id);
        let filepath = dir.join(&filename);

        let json = serde_json::to_string_pretty(self)?;
        fs::write(&filepath, json)?;

        Ok(&self.id)
    }

    /// Loads and decrypts a keystore from a JSON file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the keystore JSON file
    /// * `password` - Password to decrypt the keystore
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File doesn't exist or can't be read
    /// - JSON is malformed
    /// - Password is incorrect (MAC verification fails)
    /// - Keystore format is unsupported
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crypto_keystore_rs::EthereumKeystore;
    ///
    /// let keystore = EthereumKeystore::load_from_file(
    ///     "./keystores/abc-123.json",
    ///     "password"
    /// ).unwrap();
    /// ```
    pub fn load_from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        Self::from_json(&contents, password)
    }

    /// Decrypts a keystore from a JSON string.
    ///
    /// # Arguments
    ///
    /// * `json` - JSON string containing the encrypted keystore
    /// * `password` - Password to decrypt the keystore
    ///
    /// # Errors
    ///
    /// Returns an error if password is incorrect or format is invalid.
    pub fn from_json(json: &str, password: &str) -> Result<Self> {
        let mut keystore: Keystore<K> = serde_json::from_str(json)?;

        if keystore.version != VERSION_3 && keystore.version != VERSION_4 {
            return Err(KeystoreError::UnsupportedVersion(keystore.version));
        }

        if keystore.crypto.cipher != CIPHER_NAME {
            return Err(KeystoreError::UnsupportedCipher(
                keystore.crypto.cipher.clone(),
            ));
        }

        // Derive key based on KDF type
        let mut derived_key = Self::derive_key(password, &keystore.crypto.kdfparams)?;

        let encryption_key = &derived_key[..ENCRYPTION_KEY_SIZE];
        let mac_key = &derived_key[ENCRYPTION_KEY_SIZE..ENCRYPTION_KEY_SIZE + MAC_KEY_SIZE];

        let ciphertext_bytes = Self::decode_hex(&keystore.crypto.ciphertext, "ciphertext")?;
        let expected_mac_bytes = Self::decode_hex(&keystore.crypto.mac, "MAC")?;

        // Determine MAC algorithm: Keccak256 for v3 (Ethereum legacy) or v4 with chain="ethereum",
        // SHA256 for all other chains
        let use_keccak =
            keystore.version == VERSION_3 || keystore.chain.as_deref() == Some("ethereum");

        let computed_mac = Self::compute_mac(mac_key, &ciphertext_bytes, use_keccak)?;

        // !! == Constant-time MAC comparison == !!
        if computed_mac.len() != expected_mac_bytes.len()
            || !bool::from(computed_mac.ct_eq(&expected_mac_bytes))
        {
            return Err(KeystoreError::MacVerificationFailed);
        }

        let iv_bytes = Self::decode_hex(&keystore.crypto.cipherparams.iv, "IV")?;

        // Decrypt using AES-128-CTR
        let mut cipher = Aes128Ctr::new(encryption_key.into(), iv_bytes.as_slice().into());
        let mut plaintext = ciphertext_bytes;
        cipher.apply_keystream(&mut plaintext);

        let key = K::from_keystore_bytes(&plaintext)?;

        // Zeroize sensitive key material
        plaintext.zeroize();
        derived_key.zeroize();

        keystore.key = Some(key);

        Ok(keystore)
    }

    /// Returns a reference to the decrypted key.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore has not been decrypted yet.
    #[inline]
    pub fn key(&self) -> Result<&K> {
        self.key.as_ref().ok_or(KeystoreError::DecryptionFailed)
    }

    /// Returns `true` if the keystore has been decrypted and the key is available.
    #[inline]
    #[must_use]
    pub fn is_decrypted(&self) -> bool {
        self.key.is_some()
    }

    /// Returns the keystore UUID.
    #[inline]
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the keystore version.
    ///
    /// - [`VERSION_3`] (3) - Ethereum legacy format
    /// - [`VERSION_4`] (4) - Multi-chain format
    #[inline]
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the chain identifier if present.
    #[inline]
    #[must_use]
    pub fn chain(&self) -> Option<&str> {
        self.chain.as_deref()
    }

    /// Serializes the keystore to a JSON string.
    #[inline]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct TestKey(Vec<u8>);

    impl ChainKey for TestKey {
        const SECRET_KEY_SIZE: usize = 32;
        const KEYSTORE_SIZE: usize = 32;
        const CHAIN_ID: &'static str = "test";

        fn to_keystore_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn from_keystore_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != Self::KEYSTORE_SIZE {
                return Err(KeystoreError::InvalidKey {
                    chain: Self::CHAIN_ID.into(),
                    reason: format!(
                        "Expected {} bytes, got {}",
                        Self::KEYSTORE_SIZE,
                        bytes.len()
                    ),
                });
            }
            Ok(TestKey(bytes.to_vec()))
        }

        fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
            let mut bytes = vec![0u8; Self::KEYSTORE_SIZE];
            rng.fill_bytes(&mut bytes);
            TestKey(bytes)
        }

        fn public_key(&self) -> String {
            hex::encode(&self.0)
        }
    }

    #[test]
    fn test_keystore_new() {
        let password = "test_password";

        let keystore = Keystore::<TestKey>::new(password).unwrap();
        assert_eq!(keystore.version, VERSION_4);
        assert_eq!(keystore.chain, Some("test".to_string()));
    }

    #[test]
    fn test_keystore_encrypt_decrypt() {
        let password = "test_password";

        let keystore = Keystore::<TestKey>::new(password).unwrap();
        let original_key = keystore.key().unwrap().0.clone();

        let json = serde_json::to_string(&keystore).unwrap();
        let loaded = Keystore::<TestKey>::from_json(&json, password).unwrap();

        assert_eq!(loaded.key().unwrap().0, original_key);
    }

    #[test]
    fn test_keystore_wrong_password() {
        let password = "correct_password";

        let keystore = Keystore::<TestKey>::new(password).unwrap();
        let json = serde_json::to_string(&keystore).unwrap();

        let result = Keystore::<TestKey>::from_json(&json, "wrong_password");
        assert!(result.is_err());
    }
}
