use crate::chains::ChainKey;
use crate::crypto_config::*;
use crate::error::{KeystoreError, Result};
use crate::kdf_config::{KdfConfig, KdfParams};
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

/// Type-safe keystore format version.
///
/// This enum represents the supported keystore versions with type safety,
/// preventing invalid version numbers and making the API clearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeystoreVersion {
    /// Version 3 - Ethereum Legacy Format
    ///
    /// The original Web3 Secret Storage Definition format used by Ethereum.
    /// - Always uses Keccak256 for MAC calculation
    /// - No `chain` field in the JSON
    /// - Maintains compatibility with existing Ethereum tooling
    V3,

    /// Version 4 - Multi-Chain Format
    ///
    /// Extended format supporting multiple blockchains (Ethereum, Solana, etc.).
    /// - Includes a `chain` field to identify the blockchain
    /// - Uses chain-specific MAC algorithms:
    ///   - `chain="ethereum"` → Keccak256 (for Ethereum compatibility)
    ///   - `chain="solana"` or others → SHA256
    V4,
}

impl KeystoreVersion {
    /// Converts the version to its numeric representation.
    #[inline]
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            KeystoreVersion::V3 => 3,
            KeystoreVersion::V4 => 4,
        }
    }

    /// Creates a KeystoreVersion from a u32 value.
    ///
    /// # Errors
    ///
    /// Returns an error if the version number is not supported.
    #[inline]
    pub const fn from_u32(version: u32) -> Result<Self> {
        match version {
            3 => Ok(KeystoreVersion::V3),
            4 => Ok(KeystoreVersion::V4),
            _ => Err(KeystoreError::UnsupportedVersion(version)),
        }
    }

    /// Returns `true` if this is the Ethereum legacy format (V3).
    #[inline]
    #[must_use]
    pub const fn is_v3(self) -> bool {
        matches!(self, KeystoreVersion::V3)
    }

    /// Returns `true` if this is the multi-chain format (V4).
    #[inline]
    #[must_use]
    pub const fn is_v4(self) -> bool {
        matches!(self, KeystoreVersion::V4)
    }
}

impl Default for KeystoreVersion {
    /// Returns the default version (V4 - multi-chain format).
    #[inline]
    fn default() -> Self {
        KeystoreVersion::V4
    }
}

impl std::fmt::Display for KeystoreVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.as_u32())
    }
}

/// Keystore version 3 - Ethereum Legacy Format
///
/// The original Web3 Secret Storage Definition format used by Ethereum.
/// - Always uses Keccak256 for MAC calculation
/// - No `chain` field in the JSON
/// - Maintains compatibility with existing Ethereum tooling
pub const VERSION_3: u32 = 3;

/// Keystore version 4 - Multi-Chain Format
///
/// Extended format supporting multiple blockchains (Ethereum, Solana, etc.).
/// - Includes a `chain` field to identify the blockchain
/// - Uses chain-specific MAC algorithms:
///   - `chain="ethereum"` → Keccak256 (for Ethereum compatibility)
///   - `chain="solana"` or others → SHA256
pub const VERSION_4: u32 = 4;

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
/// # #[cfg(feature = "ethereum")]
/// # {
/// use crypto_keystore_rs::{EthereumKeystore, ChainKey, KdfConfig};
///
/// // Use fast KDF for doctests
/// let keystore = EthereumKeystore::new_with_config(
///     "my_password",
///     KdfConfig::custom_scrypt(4, 8, 1)
/// ).unwrap();
/// println!("Address: {}", keystore.key().unwrap().address());
/// # }
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

#[remain::sorted]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kdf", rename_all = "lowercase")]
enum KdfparamsType {
    Pbkdf2 {
        dklen: u32,
        c: u32,
        prf: String,
        salt: String,
    },
    Scrypt {
        dklen: u32,
        n: u32,
        p: u32,
        r: u32,
        salt: String,
    },
}

impl<K: ChainKey> Keystore<K> {
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

                let salt_bytes = hex::decode(salt)
                    .map_err(|e| KeystoreError::HexError(format!("Invalid KDF salt: {e}")))?;

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
                let salt_bytes = hex::decode(salt)
                    .map_err(|e| KeystoreError::HexError(format!("Invalid KDF salt: {e}")))?;

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

    /// Determines whether to use Keccak256 (Ethereum) or SHA256 (other chains) for MAC.
    ///
    /// Returns true for:
    /// - Version 3 keystores (Ethereum legacy format)
    /// - Version 4 keystores with chain="ethereum"
    #[inline]
    fn should_use_keccak(version: u32, chain: Option<&str>) -> bool {
        version == VERSION_3 || chain == Some("ethereum")
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
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKeystore, KdfConfig};
    ///
    /// // Use fast KDF for doctests
    /// let keystore = EthereumKeystore::new_with_config(
    ///     "my_secure_password",
    ///     KdfConfig::custom_scrypt(4, 8, 1)
    /// ).unwrap();
    /// # }
    /// ```
    pub fn new<S: AsRef<str>>(password: S) -> Result<Self> {
        let key = K::generate(&mut rand::thread_rng());
        Self::from_key_with_rng_and_config(
            &mut rand::thread_rng(),
            key,
            password,
            KdfConfig::default(),
        )
    }

    /// Creates a keystore from an existing key.
    ///
    /// Uses the system's cryptographically secure random number generator.
    ///
    /// # Arguments
    ///
    /// * `key` - The blockchain key to encrypt
    /// * `password` - Password to encrypt the keystore
    pub fn from_key<S: AsRef<str>>(key: K, password: S) -> Result<Self> {
        Self::from_key_with_rng_and_config(
            &mut rand::thread_rng(),
            key,
            password,
            KdfConfig::default(),
        )
    }

    /// Creates a new keystore with custom KDF configuration.
    ///
    /// This allows you to choose different KDF parameters based on your security
    /// and performance requirements.
    ///
    /// # Arguments
    ///
    /// * `password` - Password to encrypt the keystore
    /// * `config` - KDF configuration (use presets like `KdfConfig::custom_scrypt(4, 8, 1)`)
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKeystore, KdfConfig};
    ///
    /// // Fast for testing or interactive applications
    /// let keystore = EthereumKeystore::new_with_config(
    ///     "password",
    ///     KdfConfig::custom_scrypt(4, 8, 1)
    /// ).unwrap();
    ///
    /// // Strong for cold storage
    /// let keystore = EthereumKeystore::new_with_config(
    ///     "password",
    ///     KdfConfig::scrypt_sensitive()
    /// ).unwrap();
    /// # }
    /// ```
    pub fn new_with_config<S: AsRef<str>>(password: S, config: KdfConfig) -> Result<Self> {
        let key = K::generate(&mut rand::thread_rng());
        Self::from_key_with_rng_and_config(&mut rand::thread_rng(), key, password, config)
    }

    /// Creates a keystore from an existing key with custom KDF configuration.
    ///
    /// # Arguments
    ///
    /// * `key` - The blockchain key to encrypt
    /// * `password` - Password to encrypt the keystore
    /// * `config` - KDF configuration
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKey, EthereumKeystore, KdfConfig, ChainKey};
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let key = EthereumKey::generate(&mut rng);
    ///
    /// let keystore = EthereumKeystore::from_key_with_config(
    ///     key,
    ///     "password",
    ///     KdfConfig::custom_scrypt(4, 8, 1)
    /// ).unwrap();
    /// # }
    /// ```
    pub fn from_key_with_config<S: AsRef<str>>(
        key: K,
        password: S,
        config: KdfConfig,
    ) -> Result<Self> {
        Self::from_key_with_rng_and_config(&mut rand::thread_rng(), key, password, config)
    }

    /// Creates a keystore from an existing key using a custom RNG and KDF configuration.
    ///
    /// This is the most flexible constructor, allowing full control over randomness
    /// and key derivation parameters.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `key` - The blockchain key to encrypt
    /// * `password` - Password to encrypt the keystore
    /// * `config` - KDF configuration
    pub fn from_key_with_rng_and_config<R: RngCore + CryptoRng, S: AsRef<str>>(
        rng: &mut R,
        key: K,
        password: S,
        config: KdfConfig,
    ) -> Result<Self> {
        let mut salt = Self::generate_random_bytes(rng, DEFAULT_KEY_SIZE);

        let (mut derived_key, kdfparams) = match config.params() {
            KdfParams::Scrypt { log_n, r, p, dklen } => {
                let mut derived = vec![0u8; dklen as usize];
                let scrypt_params =
                    ScryptParams::new(log_n, r, p, dklen as usize).map_err(|e| {
                        KeystoreError::CryptoError(format!("Invalid scrypt params: {e}"))
                    })?;

                scrypt(
                    password.as_ref().as_bytes(),
                    &salt,
                    &scrypt_params,
                    &mut derived,
                )
                .map_err(|e| {
                    KeystoreError::CryptoError(format!("Scrypt derivation failed: {e}"))
                })?;

                let kdf_params = KdfparamsType::Scrypt {
                    dklen,
                    n: 1u32 << log_n,
                    r,
                    p,
                    salt: hex::encode(&salt),
                };

                (derived, kdf_params)
            }
            KdfParams::Pbkdf2 { iterations, dklen } => {
                let mut derived = vec![0u8; dklen as usize];
                pbkdf2_hmac::<Sha256>(
                    password.as_ref().as_bytes(),
                    &salt,
                    iterations,
                    &mut derived,
                );

                let kdf_params = KdfparamsType::Pbkdf2 {
                    dklen,
                    c: iterations,
                    prf: SUPPORTED_PRF.to_string(),
                    salt: hex::encode(&salt),
                };

                (derived, kdf_params)
            }
        };

        let encryption_key = &derived_key[..ENCRYPTION_KEY_SIZE];
        let mac_key = &derived_key[ENCRYPTION_KEY_SIZE..ENCRYPTION_KEY_SIZE + MAC_KEY_SIZE];

        let mut iv = Self::generate_random_bytes(rng, DEFAULT_IV_SIZE);

        let mut cipher = Aes128Ctr::new(encryption_key.into(), iv.as_slice().into());
        let mut ciphertext = key.to_keystore_bytes();
        cipher.apply_keystream(&mut ciphertext);

        let use_keccak = Self::should_use_keccak(VERSION_4, Some(K::CHAIN_ID));
        let mac = Self::compute_mac(mac_key, &ciphertext, use_keccak)?;

        let crypto = CryptoJson {
            cipher: CIPHER_NAME.to_string(),
            cipherparams: CipherparamsJson {
                iv: hex::encode(&iv),
            },
            ciphertext: hex::encode(&ciphertext),
            kdfparams,
            mac: hex::encode(&mac),
        };

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
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKeystore, KdfConfig};
    ///
    /// // Use fast KDF for doctests
    /// let keystore = EthereumKeystore::new_with_config(
    ///     "password",
    ///     KdfConfig::custom_scrypt(4, 8, 1)
    /// ).unwrap();
    /// let uuid = keystore.save_to_file("./keystores").unwrap();
    /// println!("Saved to: ./keystores/{}.json", uuid);
    /// # }
    /// ```
    pub fn save_to_file<P: AsRef<Path>>(&self, dir: P) -> Result<&str> {
        let dir = dir.as_ref();

        if !dir.exists() {
            fs::create_dir_all(dir)?;
        }

        let filepath = dir.join(format!("{}.json", self.id));

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
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::EthereumKeystore;
    ///
    /// let keystore = EthereumKeystore::load_from_file(
    ///     "./keystores/abc-123.json",
    ///     "password"
    /// ).unwrap();
    /// # }
    /// ```
    pub fn load_from_file<P: AsRef<Path>, S: AsRef<str>>(path: P, password: S) -> Result<Self> {
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
    pub fn from_json<S: AsRef<str>>(json: &str, password: S) -> Result<Self> {
        let mut keystore: Keystore<K> = serde_json::from_str(json)?;

        if keystore.version != VERSION_3 && keystore.version != VERSION_4 {
            return Err(KeystoreError::UnsupportedVersion(keystore.version));
        }

        if keystore.crypto.cipher != CIPHER_NAME {
            return Err(KeystoreError::UnsupportedCipher(
                keystore.crypto.cipher.clone(),
            ));
        }

        let mut derived_key = Self::derive_key(password.as_ref(), &keystore.crypto.kdfparams)?;

        let encryption_key = &derived_key[..ENCRYPTION_KEY_SIZE];
        let mac_key = &derived_key[ENCRYPTION_KEY_SIZE..ENCRYPTION_KEY_SIZE + MAC_KEY_SIZE];

        let ciphertext_bytes = hex::decode(&keystore.crypto.ciphertext)
            .map_err(|e| KeystoreError::HexError(format!("Invalid ciphertext: {e}")))?;
        let expected_mac_bytes = hex::decode(&keystore.crypto.mac)
            .map_err(|e| KeystoreError::HexError(format!("Invalid MAC: {e}")))?;

        let use_keccak = Self::should_use_keccak(keystore.version, keystore.chain.as_deref());

        let computed_mac = Self::compute_mac(mac_key, &ciphertext_bytes, use_keccak)?;

        if computed_mac.len() != expected_mac_bytes.len()
            || !bool::from(computed_mac.ct_eq(&expected_mac_bytes))
        {
            return Err(KeystoreError::IncorrectPassword);
        }

        let iv_bytes = hex::decode(&keystore.crypto.cipherparams.iv)
            .map_err(|e| KeystoreError::HexError(format!("Invalid IV: {e}")))?;

        let mut cipher = Aes128Ctr::new(encryption_key.into(), iv_bytes.as_slice().into());
        let mut plaintext = ciphertext_bytes;
        cipher.apply_keystream(&mut plaintext);

        let key = K::from_keystore_bytes(&plaintext)?;

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
        self.key.as_ref().ok_or(KeystoreError::KeyNotDecrypted)
    }

    /// Returns the blockchain address for the decrypted key.
    ///
    /// This is a convenience method that combines `key()` and `address()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore has not been decrypted yet.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKeystore, KdfConfig};
    ///
    /// // Use fast KDF for doctests
    /// let keystore = EthereumKeystore::new_with_config(
    ///     "password",
    ///     KdfConfig::custom_scrypt(4, 8, 1)
    /// ).unwrap();
    /// let address = keystore.address().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn address(&self) -> Result<String> {
        Ok(self.key()?.address())
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

    /// Returns the keystore version as a type-safe enum.
    ///
    /// This is a safer alternative to `version()` that returns a `KeystoreVersion` enum
    /// instead of a raw u32.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKeystore, KeystoreVersion, KdfConfig};
    ///
    /// // Use fast KDF for doctests
    /// let keystore = EthereumKeystore::new_with_config(
    ///     "password",
    ///     KdfConfig::custom_scrypt(4, 8, 1)
    /// ).unwrap();
    /// assert_eq!(keystore.version_enum().unwrap(), KeystoreVersion::V4);
    /// # }
    /// ```
    #[inline]
    pub fn version_enum(&self) -> Result<KeystoreVersion> {
        KeystoreVersion::from_u32(self.version)
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

/// Builder for constructing keystores with custom configuration.
///
/// Provides a flexible API for creating keystores with various options:
/// - Custom or random keys
/// - Custom RNG for deterministic testing
/// - Custom KDF configuration
/// - Custom UUID
/// - Custom version
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "ethereum")]
/// # {
/// use crypto_keystore_rs::{EthereumKey, EthereumKeystore, KeystoreBuilder, KdfConfig, ChainKey};
/// use rand::thread_rng;
///
/// // Simple usage - use fast KDF for doctests
/// let keystore = KeystoreBuilder::<EthereumKey>::new()
///     .with_random_key()
///     .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
///     .build("password")
///     .unwrap();
///
/// // Advanced usage with custom key
/// let mut rng = thread_rng();
/// let key = EthereumKey::generate(&mut rng);
///
/// let keystore = KeystoreBuilder::new()
///     .with_key(key)
///     .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
///     .build("password")
///     .unwrap();
/// # }
/// ```
pub struct KeystoreBuilder<K: ChainKey> {
    key: Option<K>,
    kdf_config: KdfConfig,
    version: u32,
    uuid: Option<String>,
}

impl<K: ChainKey> KeystoreBuilder<K> {
    /// Creates a new keystore builder with default settings.
    ///
    /// Defaults:
    /// - No key (must be set with `with_key()` or `with_random_key()`)
    /// - KDF: Scrypt with N=2^18 (secure defaults)
    /// - Version: 4 (multi-chain format)
    /// - UUID: Auto-generated
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        KeystoreBuilder {
            key: None,
            kdf_config: KdfConfig::default(),
            version: VERSION_4,
            uuid: None,
        }
    }

    /// Sets the key to encrypt.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKey, KeystoreBuilder, ChainKey, KdfConfig};
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let key = EthereumKey::generate(&mut rng);
    ///
    /// // Use fast KDF for doctests
    /// let keystore = KeystoreBuilder::new()
    ///     .with_key(key)
    ///     .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
    ///     .build("password")
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub fn with_key(mut self, key: K) -> Self {
        self.key = Some(key);
        self
    }

    /// Generates a new random key using the system RNG.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKey, KeystoreBuilder, KdfConfig};
    ///
    /// // Use fast KDF for doctests
    /// let keystore = KeystoreBuilder::<EthereumKey>::new()
    ///     .with_random_key()
    ///     .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
    ///     .build("password")
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub fn with_random_key(mut self) -> Self {
        self.key = Some(K::generate(&mut rand::thread_rng()));
        self
    }

    /// Sets the KDF configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKey, KeystoreBuilder, KdfConfig};
    ///
    /// // Fast for testing
    /// let keystore = KeystoreBuilder::<EthereumKey>::new()
    ///     .with_random_key()
    ///     .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
    ///     .build("password")
    ///     .unwrap();
    ///
    /// // Strong for cold storage
    /// let keystore = KeystoreBuilder::<EthereumKey>::new()
    ///     .with_random_key()
    ///     .with_kdf_config(KdfConfig::scrypt_sensitive())
    ///     .build("password")
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub fn with_kdf_config(mut self, config: KdfConfig) -> Self {
        self.kdf_config = config;
        self
    }

    /// Sets the keystore format version.
    ///
    /// - [`VERSION_3`] (3) - Ethereum legacy format
    /// - [`VERSION_4`] (4) - Multi-chain format (recommended)
    #[inline]
    #[must_use]
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Sets the keystore format version using a type-safe enum.
    ///
    /// This is a safer alternative to `with_version()` that accepts a `KeystoreVersion` enum
    /// instead of a raw u32.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKey, KeystoreBuilder, KeystoreVersion};
    ///
    /// let keystore = KeystoreBuilder::<EthereumKey>::new()
    ///     .with_random_key()
    ///     .with_version_enum(KeystoreVersion::V3)
    ///     .build("password")
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub fn with_version_enum(mut self, version: KeystoreVersion) -> Self {
        self.version = version.as_u32();
        self
    }

    /// Sets a custom UUID for the keystore.
    ///
    /// By default, a random UUID v4 is generated. This method allows
    /// setting a specific UUID for testing or migration purposes.
    ///
    /// # Arguments
    ///
    /// * `uuid` - A valid UUID string
    #[inline]
    #[must_use]
    pub fn with_uuid<S: Into<String>>(mut self, uuid: S) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    /// Builds the keystore by encrypting the key with the given password.
    ///
    /// # Arguments
    ///
    /// * `password` - Password to encrypt the keystore
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No key was set (must call `with_key()` or `with_random_key()` first)
    /// - KDF parameters are invalid
    /// - Encryption fails
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKey, KeystoreBuilder, KdfConfig};
    ///
    /// // Use fast KDF for doctests
    /// let keystore = KeystoreBuilder::<EthereumKey>::new()
    ///     .with_random_key()
    ///     .with_kdf_config(KdfConfig::custom_scrypt(4, 8, 1))
    ///     .build("my_secure_password")
    ///     .unwrap();
    /// # }
    /// ```
    pub fn build<S: AsRef<str>>(self, password: S) -> Result<Keystore<K>> {
        let key = self
            .key
            .ok_or_else(|| KeystoreError::CryptoError("No key set in builder".into()))?;

        let mut keystore = Keystore::from_key_with_rng_and_config(
            &mut rand::thread_rng(),
            key,
            password,
            self.kdf_config,
        )?;

        if let Some(uuid) = self.uuid {
            keystore.id = uuid;
        }
        keystore.version = self.version;

        Ok(keystore)
    }
}

impl<K: ChainKey> Default for KeystoreBuilder<K> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf_config::KdfConfig;

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

        fn address(&self) -> String {
            hex::encode(&self.0)
        }
    }

    #[test]
    fn test_keystore_new() {
        let password = "test_password";

        let keystore =
            Keystore::<TestKey>::new_with_config(password, KdfConfig::custom_scrypt(4, 8, 1))
                .unwrap();
        assert_eq!(keystore.version, VERSION_4);
        assert_eq!(keystore.chain, Some("test".to_string()));
    }

    #[test]
    fn test_keystore_encrypt_decrypt() {
        let password = "test_password";

        let keystore =
            Keystore::<TestKey>::new_with_config(password, KdfConfig::custom_scrypt(4, 8, 1))
                .unwrap();
        let original_key = keystore.key().unwrap().0.clone();

        let json = serde_json::to_string(&keystore).unwrap();
        let loaded = Keystore::<TestKey>::from_json(&json, password).unwrap();

        assert_eq!(loaded.key().unwrap().0, original_key);
    }

    #[test]
    fn test_keystore_wrong_password() {
        let password = "correct_password";

        let keystore =
            Keystore::<TestKey>::new_with_config(password, KdfConfig::custom_scrypt(4, 8, 1))
                .unwrap();
        let json = serde_json::to_string(&keystore).unwrap();

        let result = Keystore::<TestKey>::from_json(&json, "wrong_password");
        assert!(result.is_err());
    }
}
