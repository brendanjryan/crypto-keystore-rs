/// KDF (Key Derivation Function) configuration presets and custom parameters.
///
/// This module provides convenient presets for common use cases as well as the
/// ability to specify custom KDF parameters.
///
/// # Examples
///
/// ```
/// use crypto_keystore_rs::KdfConfig;
///
/// // Use default secure parameters (Scrypt with N=2^18)
/// let config = KdfConfig::scrypt_default();
///
/// // Use faster parameters for interactive applications
/// let config = KdfConfig::scrypt_interactive();
///
/// // Use stronger parameters for cold storage
/// let config = KdfConfig::scrypt_sensitive();
///
/// // Use PBKDF2 instead of Scrypt
/// let config = KdfConfig::pbkdf2_default();
///
/// // Custom parameters
/// let config = KdfConfig::custom_scrypt(15, 8, 1);
/// ```

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfType {
    /// Scrypt - memory-hard key derivation function (recommended)
    Scrypt,
    /// PBKDF2 with HMAC-SHA256
    Pbkdf2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfParams {
    /// Scrypt parameters: log_n (N = 2^log_n), r, p, dklen
    Scrypt {
        /// log₂ of the CPU/memory cost parameter N (must be power of 2)
        log_n: u8,
        /// Block size parameter
        r: u32,
        /// Parallelization parameter
        p: u32,
        /// Derived key length in bytes
        dklen: u32,
    },
    /// PBKDF2 parameters: iterations, dklen
    Pbkdf2 {
        /// Number of iterations
        iterations: u32,
        /// Derived key length in bytes
        dklen: u32,
    },
}

/// Configuration for Key Derivation Functions (KDF).
///
/// Provides convenient presets for common use cases as well as custom parameter support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfConfig {
    pub(crate) kdf_type: KdfType,
    pub(crate) params: KdfParams,
}

impl KdfConfig {
    /// Returns the KDF type (Scrypt or PBKDF2).
    #[inline]
    #[must_use]
    pub fn kdf_type(&self) -> KdfType {
        self.kdf_type
    }

    /// Returns the KDF parameters.
    #[inline]
    #[must_use]
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Default Scrypt parameters (N=2^18, r=8, p=1, dklen=32).
    ///
    /// Recommended for production use. Provides strong security with reasonable
    /// performance on modern hardware.
    ///
    /// - N = 262,144 (2^18) - Strong resistance to brute-force attacks
    /// - Memory requirement: ~256 MB
    /// - Time on modern CPU: ~1-2 seconds
    #[inline]
    #[must_use]
    pub fn scrypt_default() -> Self {
        KdfConfig {
            kdf_type: KdfType::Scrypt,
            params: KdfParams::Scrypt {
                log_n: 18, // N = 262,144
                r: 8,
                p: 1,
                dklen: 32,
            },
        }
    }

    /// Interactive Scrypt parameters (N=2^14, r=8, p=1, dklen=32).
    ///
    /// Optimized for interactive applications where encryption/decryption speed
    /// is important but you still want reasonable security.
    ///
    /// - N = 16,384 (2^14) - Good balance of speed and security
    /// - Memory requirement: ~16 MB
    /// - Time on modern CPU: ~100-200 ms
    #[inline]
    #[must_use]
    pub fn scrypt_interactive() -> Self {
        KdfConfig {
            kdf_type: KdfType::Scrypt,
            params: KdfParams::Scrypt {
                log_n: 14, // N = 16,384
                r: 8,
                p: 1,
                dklen: 32,
            },
        }
    }

    /// Sensitive Scrypt parameters (N=2^20, r=8, p=1, dklen=32).
    ///
    /// Maximum security parameters for cold storage or high-value keys.
    /// Takes significantly longer but provides strongest protection.
    ///
    /// - N = 1,048,576 (2^20) - Maximum resistance to brute-force attacks
    /// - Memory requirement: ~1 GB
    /// - Time on modern CPU: ~5-10 seconds
    #[inline]
    #[must_use]
    pub fn scrypt_sensitive() -> Self {
        KdfConfig {
            kdf_type: KdfType::Scrypt,
            params: KdfParams::Scrypt {
                log_n: 20, // N = 1,048,576
                r: 8,
                p: 1,
                dklen: 32,
            },
        }
    }

    /// Default PBKDF2 parameters (iterations=262,144, dklen=32).
    ///
    /// PBKDF2 with HMAC-SHA256. Widely supported but less memory-hard than Scrypt.
    /// Consider using Scrypt instead for new keystores.
    ///
    /// - 262,144 iterations - Reasonable security for PBKDF2
    /// - Compatible with systems that don't support Scrypt
    #[inline]
    #[must_use]
    pub fn pbkdf2_default() -> Self {
        KdfConfig {
            kdf_type: KdfType::Pbkdf2,
            params: KdfParams::Pbkdf2 {
                iterations: 262_144,
                dklen: 32,
            },
        }
    }

    /// Create custom Scrypt parameters.
    ///
    /// # Arguments
    ///
    /// * `log_n` - log₂ of N (N = 2^log_n, must be < 32)
    /// * `r` - Block size parameter (typically 8)
    /// * `p` - Parallelization parameter (typically 1)
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_keystore_rs::KdfConfig;
    ///
    /// // Fast testing parameters (N=16)
    /// let config = KdfConfig::custom_scrypt(4, 8, 1);
    ///
    /// // Standard parameters (N=262,144)
    /// let config = KdfConfig::custom_scrypt(18, 8, 1);
    /// ```
    #[inline]
    #[must_use]
    pub fn custom_scrypt(log_n: u8, r: u32, p: u32) -> Self {
        KdfConfig {
            kdf_type: KdfType::Scrypt,
            params: KdfParams::Scrypt {
                log_n,
                r,
                p,
                dklen: 32,
            },
        }
    }

    /// Create custom PBKDF2 parameters.
    ///
    /// # Arguments
    ///
    /// * `iterations` - Number of PBKDF2 iterations
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_keystore_rs::KdfConfig;
    ///
    /// // Standard PBKDF2 parameters
    /// let config = KdfConfig::custom_pbkdf2(262_144);
    ///
    /// // Faster parameters for testing
    /// let config = KdfConfig::custom_pbkdf2(1000);
    /// ```
    #[inline]
    #[must_use]
    pub fn custom_pbkdf2(iterations: u32) -> Self {
        KdfConfig {
            kdf_type: KdfType::Pbkdf2,
            params: KdfParams::Pbkdf2 {
                iterations,
                dklen: 32,
            },
        }
    }
}

impl Default for KdfConfig {
    /// Returns the default KDF configuration (Scrypt with N=2^18).
    #[inline]
    fn default() -> Self {
        Self::scrypt_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrypt_default_has_expected_parameters() {
        let config = KdfConfig::scrypt_default();
        assert_eq!(config.kdf_type(), KdfType::Scrypt);
        match config.params() {
            KdfParams::Scrypt { log_n, r, p, dklen } => {
                assert_eq!(log_n, 18); // N = 262,144
                assert_eq!(r, 8);
                assert_eq!(p, 1);
                assert_eq!(dklen, 32);
            }
            _ => panic!("Expected Scrypt params"),
        }
    }

    #[test]
    fn scrypt_interactive_is_faster_than_default() {
        let default_config = KdfConfig::scrypt_default();
        let interactive_config = KdfConfig::scrypt_interactive();

        let default_log_n = match default_config.params() {
            KdfParams::Scrypt { log_n, .. } => log_n,
            _ => panic!("Expected Scrypt params"),
        };

        let interactive_log_n = match interactive_config.params() {
            KdfParams::Scrypt { log_n, .. } => log_n,
            _ => panic!("Expected Scrypt params"),
        };

        // Interactive should have lower N (faster)
        assert!(interactive_log_n < default_log_n);
    }

    #[test]
    fn scrypt_sensitive_is_stronger_than_default() {
        let default_config = KdfConfig::scrypt_default();
        let sensitive_config = KdfConfig::scrypt_sensitive();

        let default_log_n = match default_config.params() {
            KdfParams::Scrypt { log_n, .. } => log_n,
            _ => panic!("Expected Scrypt params"),
        };

        let sensitive_log_n = match sensitive_config.params() {
            KdfParams::Scrypt { log_n, .. } => log_n,
            _ => panic!("Expected Scrypt params"),
        };

        // Sensitive should have higher N (stronger)
        assert!(sensitive_log_n > default_log_n);
    }

    #[test]
    fn pbkdf2_default_has_expected_parameters() {
        let config = KdfConfig::pbkdf2_default();
        assert_eq!(config.kdf_type(), KdfType::Pbkdf2);
        match config.params() {
            KdfParams::Pbkdf2 { iterations, dklen } => {
                assert_eq!(iterations, 262_144);
                assert_eq!(dklen, 32);
            }
            _ => panic!("Expected PBKDF2 params"),
        }
    }

    #[test]
    fn custom_scrypt_uses_provided_parameters() {
        let config = KdfConfig::custom_scrypt(10, 4, 2);
        match config.params() {
            KdfParams::Scrypt { log_n, r, p, dklen } => {
                assert_eq!(log_n, 10);
                assert_eq!(r, 4);
                assert_eq!(p, 2);
                assert_eq!(dklen, 32);
            }
            _ => panic!("Expected Scrypt params"),
        }
    }

    #[test]
    fn custom_pbkdf2_uses_provided_iterations() {
        let config = KdfConfig::custom_pbkdf2(100_000);
        match config.params() {
            KdfParams::Pbkdf2 { iterations, dklen } => {
                assert_eq!(iterations, 100_000);
                assert_eq!(dklen, 32);
            }
            _ => panic!("Expected PBKDF2 params"),
        }
    }

    #[test]
    fn default_trait_returns_scrypt_default() {
        let config = KdfConfig::default();
        assert_eq!(config, KdfConfig::scrypt_default());
    }
}
