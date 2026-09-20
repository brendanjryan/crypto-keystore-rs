use crate::chains::ChainKey;
use crate::crypto_config::*;
use crate::error::{KeystoreError, Result};
use crate::import_limits::ImportLimits;
use crate::kdf_config::{KdfConfig, KdfLimits, KdfParams};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use pbkdf2::pbkdf2_hmac;
use rand::{CryptoRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(feature = "ethereum")]
use sha3::Keccak256;

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

    /// Authenticated multi-chain format using AES-256-GCM.
    /// Protects the nonce, ciphertext, and keystore metadata against tampering.
    V5,
}

impl KeystoreVersion {
    /// Converts the version to its numeric representation.
    #[inline]
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            KeystoreVersion::V3 => 3,
            KeystoreVersion::V4 => 4,
            KeystoreVersion::V5 => 5,
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
            5 => Ok(KeystoreVersion::V5),
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

    /// Returns `true` for the authenticated format.
    #[inline]
    #[must_use]
    pub const fn is_v5(self) -> bool {
        matches!(self, KeystoreVersion::V5)
    }
}

impl Default for KeystoreVersion {
    /// Returns the default version (V5 - authenticated multi-chain format).
    #[inline]
    fn default() -> Self {
        KeystoreVersion::V5
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

/// Authenticated multi-chain format using AES-256-GCM.
pub const VERSION_5: u32 = 5;

/// A generic keystore supporting multiple blockchain key types.
///
/// New keystores use AES-256-GCM authenticated encryption (v5) and
/// Scrypt/PBKDF2 key derivation. Legacy v3/v4 AES-128-CTR files remain readable.
/// Keys are encrypted at rest and only decrypted with the correct password.
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
#[derive(Debug, Clone)]
pub struct Keystore<K: ChainKey> {
    /// The decrypted key: only present after successful decryption
    key: Option<K>,

    /// Encrypted key material and cryptographic parameters
    crypto: CryptoJson,

    /// Unique identifier (UUID v4)
    id: String,

    /// Format version
    /// - 3 for Ethereum legacy
    /// - 4 for legacy multi-chain
    /// - 5 for authenticated multi-chain
    version: u32,

    /// Chain identifier ("ethereum", "solana", etc.)
    chain: Option<String>,
}

impl<K: ChainKey> Serialize for Keystore<K> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut crypto = serde_json::to_value(&self.crypto).map_err(serde::ser::Error::custom)?;
        if self.version == VERSION_3 {
            let mut params =
                serde_json::to_value(&self.crypto.kdfparams).map_err(serde::ser::Error::custom)?;
            let params = params
                .as_object_mut()
                .expect("KDF parameters serialize as an object");
            params.remove("kdf");
            let crypto = crypto
                .as_object_mut()
                .expect("crypto serializes as an object");
            for key in params.keys() {
                crypto.remove(key);
            }
            crypto.insert(
                "kdfparams".into(),
                serde_json::Value::Object(std::mem::take(params)),
            );
        }
        let mut state =
            serializer.serialize_struct("Keystore", 3 + usize::from(self.chain.is_some()))?;
        state.serialize_field("crypto", &crypto)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("version", &self.version)?;
        if let Some(chain) = &self.chain {
            state.serialize_field("chain", chain)?;
        }
        state.end()
    }
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
            id: Uuid::parse_str(&helper.id)
                .map_err(serde::de::Error::custom)?
                .to_string(),
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

    #[serde(flatten, deserialize_with = "deserialize_kdfparams")]
    kdfparams: KdfparamsType,

    mac: String,
}

fn deserialize_kdfparams<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<KdfparamsType, D::Error> {
    let mut fields = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
    if let Some(nested) = fields.remove("kdfparams") {
        let serde_json::Value::Object(mut params) = nested else {
            return Err(serde::de::Error::custom("kdfparams must be an object"));
        };
        if params.contains_key("kdf")
            || ["dklen", "c", "prf", "n", "r", "p", "salt"]
                .iter()
                .any(|key| fields.contains_key(*key))
        {
            return Err(serde::de::Error::custom("ambiguous KDF parameters"));
        }
        let kdf = fields
            .remove("kdf")
            .ok_or_else(|| serde::de::Error::missing_field("kdf"))?;
        params.insert("kdf".into(), kdf);
        fields = params;
    }
    serde_json::from_value(serde_json::Value::Object(fields)).map_err(serde::de::Error::custom)
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
    fn validate_version_chain(version: u32, chain: Option<&str>) -> Result<()> {
        KeystoreVersion::from_u32(version)?;
        let valid = if version == VERSION_3 {
            K::CHAIN_ID == "ethereum" && chain.is_none_or(|chain| chain == "ethereum")
        } else {
            chain == Some(K::CHAIN_ID)
        };
        if !valid {
            return Err(KeystoreError::UnsupportedChain(
                chain.unwrap_or("missing chain").into(),
            ));
        }
        Ok(())
    }

    /// Helper to generate random bytes using a cryptographically secure RNG.
    #[inline]
    fn generate_random_bytes<R: RngCore + CryptoRng>(rng: &mut R, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Derives encryption key from password using specified KDF parameters.
    fn derive_key(password: &str, kdfparams: &KdfparamsType) -> Result<Zeroizing<Vec<u8>>> {
        let dklen = match kdfparams {
            KdfparamsType::Pbkdf2 { dklen, .. } | KdfparamsType::Scrypt { dklen, .. } => *dklen,
        };
        if dklen < DEFAULT_KEY_SIZE as u32 {
            return Err(KeystoreError::InvalidKdfParams(
                "dklen must be at least 32".into(),
            ));
        }
        match kdfparams {
            KdfparamsType::Pbkdf2 {
                dklen,
                c,
                prf,
                salt,
            } => {
                if *c == 0 {
                    return Err(KeystoreError::InvalidKdfParams(
                        "PBKDF2 iterations must be positive".into(),
                    ));
                }
                if prf != SUPPORTED_PRF {
                    return Err(KeystoreError::UnsupportedKdf(format!(
                        "Unsupported PRF: {prf}, expected {SUPPORTED_PRF}"
                    )));
                }

                let salt_bytes = hex::decode(salt)
                    .map_err(|e| KeystoreError::HexError(format!("Invalid KDF salt: {e}")))?;

                let mut key = Zeroizing::new(vec![0u8; *dklen as usize]);
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

                if *n < 2 || !n.is_power_of_two() {
                    return Err(KeystoreError::InvalidKdfParams(format!(
                        "Scrypt n parameter must be a power of 2 greater than 1, got {n}"
                    )));
                }
                let log_n = n.trailing_zeros() as u8;
                let params = ScryptParams::new(log_n, *r, *p, *dklen as usize).map_err(|e| {
                    KeystoreError::InvalidKdfParams(format!("Invalid scrypt params: {e}"))
                })?;

                let mut key = Zeroizing::new(vec![0u8; *dklen as usize]);
                scrypt(password.as_bytes(), &salt_bytes, &params, &mut key).map_err(|e| {
                    KeystoreError::CryptoError(format!("Scrypt derivation failed: {e}"))
                })?;

                Ok(key)
            }
        }
    }

    fn validate_kdf_limits(params: &KdfparamsType, limits: KdfLimits) -> Result<()> {
        let (dklen, within_budget) = match params {
            KdfparamsType::Pbkdf2 { dklen, c, .. } => (*dklen, *c <= limits.max_pbkdf2_iterations),
            KdfparamsType::Scrypt { dklen, n, r, p, .. } => {
                let (n, r, p) = (u64::from(*n), u64::from(*r), u64::from(*p));
                let memory = (128 * r).checked_mul(n + p + 2);
                let work = n.checked_mul(r).and_then(|nr| nr.checked_mul(p));
                (
                    *dklen,
                    memory.is_some_and(|bytes| bytes <= limits.max_scrypt_memory_bytes)
                        && work.is_some_and(|units| units <= limits.max_scrypt_work),
                )
            }
        };
        if dklen > limits.max_dklen || !within_budget {
            return Err(KeystoreError::InvalidKdfParams(
                "KDF exceeds import resource limits".into(),
            ));
        }
        Ok(())
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
    /// # }
    /// ```
    ///
    /// For production/cold storage, use stronger parameters:
    /// ```ignore
    /// let keystore = EthereumKeystore::new_with_config(
    ///     "password",
    ///     KdfConfig::scrypt_sensitive()
    /// ).unwrap();
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
        Self::encrypt(
            rng,
            key,
            password,
            config,
            VERSION_5,
            Uuid::new_v4().to_string(),
        )
    }

    fn apply_legacy_keystream(version: u32, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()> {
        // Web3 v3 increments the full counter; v4 preserves the original format.
        if version == VERSION_3 {
            ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| KeystoreError::CorruptedData)?
                .try_apply_keystream(data)
        } else {
            ctr::Ctr64BE::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| KeystoreError::CorruptedData)?
                .try_apply_keystream(data)
        }
        .map_err(|_| KeystoreError::CorruptedData)
    }

    fn authenticated_metadata(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&(
            "crypto-keystore",
            self.version,
            &self.id,
            &self.chain,
            &self.crypto.cipher,
            &self.crypto.kdfparams,
        ))
        .map_err(Into::into)
    }

    fn encrypt<R: RngCore + CryptoRng, S: AsRef<str>>(
        rng: &mut R,
        key: K,
        password: S,
        config: KdfConfig,
        version: u32,
        id: String,
    ) -> Result<Self> {
        let chain = (version != VERSION_3).then_some(K::CHAIN_ID);
        Self::validate_version_chain(version, chain)?;
        let salt = Self::generate_random_bytes(rng, DEFAULT_KEY_SIZE);

        let kdfparams = match config.params() {
            KdfParams::Scrypt { log_n, r, p, dklen } => KdfparamsType::Scrypt {
                dklen,
                n: 1u32.checked_shl(u32::from(log_n)).ok_or_else(|| {
                    KeystoreError::InvalidKdfParams("scrypt log_n must be less than 32".into())
                })?,
                r,
                p,
                salt: hex::encode(&salt),
            },
            KdfParams::Pbkdf2 { iterations, dklen } => KdfparamsType::Pbkdf2 {
                dklen,
                c: iterations,
                prf: SUPPORTED_PRF.to_string(),
                salt: hex::encode(&salt),
            },
        };
        let derived_key = Self::derive_key(password.as_ref(), &kdfparams)?;

        let authenticated = version == VERSION_5;
        let iv = Self::generate_random_bytes(
            rng,
            if authenticated {
                GCM_NONCE_SIZE
            } else {
                DEFAULT_IV_SIZE
            },
        );
        let mut ciphertext = key.to_keystore_bytes();
        let mut keystore = Keystore {
            key: Some(key),
            crypto: CryptoJson {
                cipher: if authenticated {
                    AUTHENTICATED_CIPHER_NAME
                } else {
                    CIPHER_NAME
                }
                .into(),
                cipherparams: CipherparamsJson {
                    iv: hex::encode(&iv),
                },
                ciphertext: String::new(),
                kdfparams,
                mac: String::new(),
            },
            id,
            version,
            chain: chain.map(str::to_owned),
        };
        let mac = if authenticated {
            let cipher = Aes256Gcm::new_from_slice(&derived_key[..DEFAULT_KEY_SIZE])
                .map_err(|_| KeystoreError::CorruptedData)?;
            cipher
                .encrypt_in_place_detached(
                    Nonce::from_slice(&iv),
                    &keystore.authenticated_metadata()?,
                    &mut ciphertext,
                )
                .map_err(|_| KeystoreError::CryptoError("AES-GCM encryption failed".into()))?
                .to_vec()
        } else {
            Self::apply_legacy_keystream(
                version,
                &derived_key[..ENCRYPTION_KEY_SIZE],
                &iv,
                &mut ciphertext,
            )?;
            Self::compute_mac(
                &derived_key[ENCRYPTION_KEY_SIZE..ENCRYPTION_KEY_SIZE + MAC_KEY_SIZE],
                &ciphertext,
                Self::should_use_keccak(version, chain),
            )?
        };
        keystore.crypto.ciphertext = hex::encode(&ciphertext);
        keystore.crypto.mac = hex::encode(mac);
        Ok(keystore)
    }

    /// Saves the keystore to a JSON file in the specified directory.
    ///
    /// The file will be named `{uuid}.json` where uuid is the keystore's unique identifier.
    /// If the directory doesn't exist, it will be created. Existing files are replaced
    /// atomically; symbolic links are replaced without writing to their targets.
    ///
    /// On Unix systems, the file is created with mode 0600 (owner read/write only)
    /// to protect sensitive key material.
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

        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        file.write_all(json.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist(&filepath).map_err(|err| err.error)?;

        Ok(&self.id)
    }

    /// Loads and decrypts a keystore from a JSON file, limited to 64 KiB.
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
        Self::load_from_file_with_limits(path, password, KdfLimits::default())
    }

    /// Loads a keystore with explicit KDF ceilings and the default 64 KiB input limit.
    pub fn load_from_file_with_limits<P: AsRef<Path>, S: AsRef<str>>(
        path: P,
        password: S,
        limits: KdfLimits,
    ) -> Result<Self> {
        Self::load_from_file_with_import_limits(
            path,
            password,
            ImportLimits {
                kdf: limits,
                ..ImportLimits::default()
            },
        )
    }

    /// Loads a keystore with explicit input-size and KDF resource ceilings.
    ///
    /// Reads at most `max_input_bytes + 1` bytes, rejecting oversized files with
    /// `InputTooLarge` before parsing. Raising limits permits more resource use.
    pub fn load_from_file_with_import_limits<P: AsRef<Path>, S: AsRef<str>>(
        path: P,
        password: S,
        limits: ImportLimits,
    ) -> Result<Self> {
        let contents = Self::read_limited(fs::File::open(path)?, limits.max_input_bytes)?;
        let json = std::str::from_utf8(&contents)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        Self::from_json_with_import_limits(json, password, limits)
    }

    fn read_limited(reader: impl Read, max_bytes: usize) -> Result<Vec<u8>> {
        let mut contents = Vec::new();
        reader
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut contents)?;
        if contents.len() > max_bytes {
            return Err(KeystoreError::InputTooLarge { max_bytes });
        }
        Ok(contents)
    }

    /// Decrypts a keystore from a JSON string, limited to 64 KiB.
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
        Self::from_json_with_limits(json, password, KdfLimits::default())
    }

    /// Decrypts JSON after checking caller-selected KDF resource ceilings.
    ///
    /// Enforces the default 64 KiB input limit before parsing. Returns
    /// `InvalidKdfParams` before KDF allocation or derivation if the KDF exceeds
    /// the limits. Raising limits permits more work on untrusted input.
    pub fn from_json_with_limits<S: AsRef<str>>(
        json: &str,
        password: S,
        limits: KdfLimits,
    ) -> Result<Self> {
        Self::from_json_with_import_limits(
            json,
            password,
            ImportLimits {
                kdf: limits,
                ..ImportLimits::default()
            },
        )
    }

    /// Decrypts JSON with explicit input-size and KDF resource ceilings.
    ///
    /// Returns `InputTooLarge` before parsing when the UTF-8 input exceeds
    /// `max_input_bytes`, counting whitespace and ignored fields.
    ///
    /// ```no_run
    /// # #[cfg(feature = "ethereum")]
    /// # {
    /// use crypto_keystore_rs::{EthereumKeystore, ImportLimits};
    /// # let json = "{}";
    /// let limits = ImportLimits { max_input_bytes: 4096, ..ImportLimits::default() };
    /// let store = EthereumKeystore::from_json_with_import_limits(json, "password", limits);
    /// # }
    /// ```
    pub fn from_json_with_import_limits<S: AsRef<str>>(
        json: &str,
        password: S,
        limits: ImportLimits,
    ) -> Result<Self> {
        if json.len() > limits.max_input_bytes {
            return Err(KeystoreError::InputTooLarge {
                max_bytes: limits.max_input_bytes,
            });
        }
        let mut keystore: Keystore<K> = serde_json::from_str(json)?;

        Self::validate_version_chain(keystore.version, keystore.chain.as_deref())?;

        let authenticated = keystore.version == VERSION_5;
        let cipher_name = if authenticated {
            AUTHENTICATED_CIPHER_NAME
        } else {
            CIPHER_NAME
        };
        if keystore.crypto.cipher != cipher_name {
            return Err(KeystoreError::UnsupportedCipher(
                keystore.crypto.cipher.clone(),
            ));
        }

        if K::KEYSTORE_SIZE.checked_mul(2) != Some(keystore.crypto.ciphertext.len())
            || keystore.crypto.mac.len()
                != 2 * if authenticated {
                    GCM_TAG_SIZE
                } else {
                    DEFAULT_KEY_SIZE
                }
            || keystore.crypto.cipherparams.iv.len()
                != 2 * if authenticated {
                    GCM_NONCE_SIZE
                } else {
                    DEFAULT_IV_SIZE
                }
        {
            return Err(KeystoreError::CorruptedData);
        }
        let ciphertext_bytes = hex::decode(&keystore.crypto.ciphertext)
            .map_err(|e| KeystoreError::HexError(format!("Invalid ciphertext: {e}")))?;
        let expected_mac_bytes = hex::decode(&keystore.crypto.mac)
            .map_err(|e| KeystoreError::HexError(format!("Invalid MAC: {e}")))?;
        let iv_bytes = hex::decode(&keystore.crypto.cipherparams.iv)
            .map_err(|e| KeystoreError::HexError(format!("Invalid IV: {e}")))?;

        Self::validate_kdf_limits(&keystore.crypto.kdfparams, limits.kdf)?;
        let derived_key = Self::derive_key(password.as_ref(), &keystore.crypto.kdfparams)?;
        let mut plaintext = Zeroizing::new(ciphertext_bytes);
        if authenticated {
            let cipher = Aes256Gcm::new_from_slice(&derived_key[..DEFAULT_KEY_SIZE])
                .map_err(|_| KeystoreError::CorruptedData)?;
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&iv_bytes),
                    &keystore.authenticated_metadata()?,
                    &mut plaintext,
                    Tag::from_slice(&expected_mac_bytes),
                )
                .map_err(|_| KeystoreError::IncorrectPassword)?;
        } else {
            let encryption_key = &derived_key[..ENCRYPTION_KEY_SIZE];
            let mac_key = &derived_key[ENCRYPTION_KEY_SIZE..ENCRYPTION_KEY_SIZE + MAC_KEY_SIZE];
            let use_keccak = Self::should_use_keccak(keystore.version, keystore.chain.as_deref());
            let computed_mac = Self::compute_mac(mac_key, &plaintext, use_keccak)?;
            if !bool::from(computed_mac.ct_eq(&expected_mac_bytes)) {
                return Err(KeystoreError::IncorrectPassword);
            }
            Self::apply_legacy_keystream(
                keystore.version,
                encryption_key,
                &iv_bytes,
                &mut plaintext,
            )?;
        }

        let key = K::from_keystore_bytes(&plaintext)?;

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
    /// - [`VERSION_4`] (4) - Legacy multi-chain format
    /// - [`VERSION_5`] (5) - Authenticated multi-chain format
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
    /// assert_eq!(keystore.version_enum().unwrap(), KeystoreVersion::V5);
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
    /// - Version: 5 (authenticated multi-chain format)
    /// - UUID: Auto-generated
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        KeystoreBuilder {
            key: None,
            kdf_config: KdfConfig::default(),
            version: VERSION_5,
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
    /// # }
    /// ```
    ///
    /// For production/cold storage, use stronger parameters:
    /// ```ignore
    /// let keystore = KeystoreBuilder::<EthereumKey>::new()
    ///     .with_random_key()
    ///     .with_kdf_config(KdfConfig::scrypt_sensitive())
    ///     .build("password")
    ///     .unwrap();
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
    /// - [`VERSION_4`] (4) - Legacy multi-chain format
    /// - [`VERSION_5`] (5) - Authenticated multi-chain format (recommended)
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
        let uuid = self
            .uuid
            .map(|id| {
                Uuid::parse_str(&id)
                    .map(|uuid| uuid.to_string())
                    .map_err(|_| KeystoreError::InvalidId(id))
            })
            .transpose()?;
        let key = self
            .key
            .ok_or_else(|| KeystoreError::CryptoError("No key set in builder".into()))?;

        Keystore::encrypt(
            &mut rand::thread_rng(),
            key,
            password,
            self.kdf_config,
            self.version,
            uuid.unwrap_or_else(|| Uuid::new_v4().to_string()),
        )
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
    use zeroize::Zeroizing;

    #[derive(Debug, Clone)]
    struct TestKey(Vec<u8>);

    impl ChainKey for TestKey {
        const SECRET_KEY_SIZE: usize = 32;
        const KEYSTORE_SIZE: usize = 32;
        const CHAIN_ID: &'static str = "test";

        fn to_keystore_bytes(&self) -> Zeroizing<Vec<u8>> {
            Zeroizing::new(self.0.clone())
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

    // OpenSSL AES-128-CTR vectors; the v4 column uses AES-ECB on each
    // counter block with only the low 64 bits incremented.
    #[test]
    #[cfg(feature = "ethereum")]
    fn legacy_counter_boundaries_match_independent_vectors() {
        struct FixedRng([u8; 16]);
        impl CryptoRng for FixedRng {}
        impl RngCore for FixedRng {
            fn next_u32(&mut self) -> u32 {
                let mut bytes = [0; 4];
                self.fill_bytes(&mut bytes);
                u32::from_le_bytes(bytes)
            }
            fn next_u64(&mut self) -> u64 {
                let mut bytes = [0; 8];
                self.fill_bytes(&mut bytes);
                u64::from_le_bytes(bytes)
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                if dest.len() == 16 {
                    dest.copy_from_slice(&self.0);
                } else {
                    dest.fill(0);
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        for (iv, v3, v4) in [
            (
                "0000000000000000fffffffffffffffe",
                "1e8efbc96e5dda122904e48d091edc4cb3a854c9ae7d31982dbf902e534aa279",
                "1e8efbc96e5dda122904e48d091edc4cb3a854c9ae7d31982dbf902e534aa279",
            ),
            (
                "0000000000000000ffffffffffffffff",
                "b3a854c9ae7d31982dbf902e534aa27892f3f62b9b9e7141fbfd926ab5ce5797",
                "b3a854c9ae7d31982dbf902e534aa278c716315cb12f3b283ee90e67d987d894",
            ),
            (
                "ffffffffffffffffffffffffffffffff",
                "02427e9cef0641e4bca2b0f2a16d2855c716315cb12f3b283ee90e67d987d894",
                "02427e9cef0641e4bca2b0f2a16d2855b059a764f03590533f203378c9474a56",
            ),
        ] {
            for (version, expected) in [(VERSION_3, v3), (VERSION_4, v4)] {
                let mut secret = [0; 32];
                secret[31] = 1;
                let key = crate::EthereumKey::from_keystore_bytes(&secret).unwrap();
                let mut rng = FixedRng(hex::decode(iv).unwrap().try_into().unwrap());
                let store = Keystore::encrypt(
                    &mut rng,
                    key,
                    "password",
                    KdfConfig::custom_pbkdf2(2),
                    version,
                    "3198bc9c-6672-5ab3-d995-4942343ae5b6".into(),
                )
                .unwrap();
                assert_eq!(store.crypto.ciphertext, expected, "v{version}, IV {iv}");
                let loaded =
                    crate::EthereumKeystore::from_json(&store.to_json().unwrap(), "password")
                        .unwrap();
                assert_eq!(loaded.key().unwrap().to_keystore_bytes().as_slice(), secret);
            }
        }
    }

    #[test]
    fn bounded_reader_consumes_only_one_byte_beyond_the_limit() {
        for limit in [0, 1, 16, 64 * 1024] {
            let mut reader = std::io::Cursor::new(vec![b' '; limit + 1024]);
            assert!(matches!(
                Keystore::<TestKey>::read_limited(&mut reader, limit),
                Err(KeystoreError::InputTooLarge { max_bytes }) if max_bytes == limit
            ));
            assert_eq!(reader.position(), (limit + 1) as u64);
            let contents = vec![b' '; limit];
            assert_eq!(
                Keystore::<TestKey>::read_limited(contents.as_slice(), limit).unwrap(),
                contents
            );
        }
    }

    #[test]
    fn test_keystore_new() {
        let password = "test_password";

        let keystore =
            Keystore::<TestKey>::new_with_config(password, KdfConfig::custom_scrypt(4, 8, 1))
                .unwrap();
        assert_eq!(keystore.version, VERSION_5);
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
