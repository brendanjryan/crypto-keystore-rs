/// Macro to reduce boilerplate when implementing new blockchain key types.
///
/// This macro generates common implementations for ChainKey types, including
/// basic trait implementations and utility functions. You still need to provide
/// chain-specific logic for address generation and key validation.
///
/// # Example
///
/// ```ignore
/// use crypto_keystore_rs::impl_chain_key_boilerplate;
///
/// pub struct MyChainKey {
///     signing_key: SomeSigningKey,
/// }
///
/// impl_chain_key_boilerplate! {
///     MyChainKey,
///     chain_id = "mychain",
///     secret_size = 32,
///     keystore_size = 32
/// }
///
/// // Then implement the actual ChainKey trait methods with your logic
/// impl ChainKey for MyChainKey {
///     // ... custom implementations ...
/// }
/// ```
#[macro_export]
macro_rules! impl_chain_key_boilerplate {
    (
        $key_type:ty,
        chain_id = $chain_id:expr,
        secret_size = $secret_size:expr,
        keystore_size = $keystore_size:expr
    ) => {
        // These constants would be used in the ChainKey impl
        impl $key_type {
            /// Chain identifier
            pub const CHAIN_ID: &'static str = $chain_id;

            /// Size of secret key material
            pub const SECRET_KEY_SIZE: usize = $secret_size;

            /// Size of keystore storage
            pub const KEYSTORE_SIZE: usize = $keystore_size;
        }

        // Debug implementation that doesn't leak key material
        impl std::fmt::Debug for $key_type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($key_type))
                    .field("address", &self.address())
                    .finish_non_exhaustive()
            }
        }

        // Display shows the address
        impl std::fmt::Display for $key_type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{} ({})", self.address(), $chain_id)
            }
        }
    };
}

/// Extended macro that includes ChainKey trait implementation skeleton.
///
/// Use this when you want the macro to generate the basic ChainKey implementation,
/// and you'll provide the chain-specific logic via closures or method bodies.
///
/// # Example
///
/// ```ignore
/// define_chain_key! {
///     MyChainKey {
///         signing_key: SomeSigningKey,
///     },
///     chain_id = "mychain",
///     secret_size = 32,
///     keystore_size = 32,
///
///     // Implement address generation
///     address_fn = |key| {
///         // Custom address derivation
///         format!("0x{}", hex::encode(key.signing_key.public_key()))
///     },
///
///     // Implement key generation
///     generate_fn = |rng| {
///         MyChainKey {
///             signing_key: SomeSigningKey::random(rng),
///         }
///     },
///
///     // Implement serialization
///     to_bytes_fn = |key| {
///         key.signing_key.to_bytes().to_vec()
///     },
///
///     // Implement deserialization
///     from_bytes_fn = |bytes| {
///         Self::validate_keystore_size(bytes)?;
///         let signing_key = SomeSigningKey::from_bytes(bytes)?;
///         Ok(MyChainKey { signing_key })
///     }
/// }
/// ```
///
/// Note: This is a more advanced pattern. For most cases, manually implementing
/// ChainKey with the help of `impl_chain_key_boilerplate!` is clearer.
#[macro_export]
macro_rules! define_chain_key {
    // This would be a very complex macro, so we provide it as a pattern/example
    // rather than a full implementation. The simpler impl_chain_key_boilerplate
    // is more practical for actual use.
    ($($tt:tt)*) => {
        compile_error!(
            "define_chain_key! is not yet implemented. \
             Use impl_chain_key_boilerplate! and manually implement ChainKey."
        );
    };
}

#[cfg(test)]
mod tests {
    use crate::chains::ChainKey;
    use crate::error::Result;
    use rand::{CryptoRng, RngCore};
    use zeroize::Zeroizing;

    // Example minimal key type for testing the macro
    #[derive(Clone)]
    struct ExampleKey {
        bytes: Vec<u8>,
    }

    impl_chain_key_boilerplate! {
        ExampleKey,
        chain_id = "example",
        secret_size = 32,
        keystore_size = 32
    }

    // Implement ChainKey for the example
    impl ChainKey for ExampleKey {
        const SECRET_KEY_SIZE: usize = ExampleKey::SECRET_KEY_SIZE;
        const KEYSTORE_SIZE: usize = ExampleKey::KEYSTORE_SIZE;
        const CHAIN_ID: &'static str = ExampleKey::CHAIN_ID;

        fn to_keystore_bytes(&self) -> Zeroizing<Vec<u8>> {
            Zeroizing::new(self.bytes.clone())
        }

        fn from_keystore_bytes(bytes: &[u8]) -> Result<Self> {
            Self::validate_keystore_size(bytes)?;
            Ok(ExampleKey {
                bytes: bytes.to_vec(),
            })
        }

        fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
            let mut bytes = vec![0u8; 32];
            rng.fill_bytes(&mut bytes);
            ExampleKey { bytes }
        }

        fn address(&self) -> String {
            format!("example_{}", hex::encode(&self.bytes[..8]))
        }
    }

    #[test]
    fn macro_generates_constants() {
        // Verify constants are set correctly
        assert_eq!(ExampleKey::CHAIN_ID, "example");
        assert_eq!(ExampleKey::SECRET_KEY_SIZE, 32);
        assert_eq!(ExampleKey::KEYSTORE_SIZE, 32);
    }

    #[test]
    fn macro_generates_debug_impl() {
        let key = ExampleKey {
            bytes: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("ExampleKey"));
        assert!(debug_str.contains("address"));
        assert!(debug_str.contains("example_"));
    }

    #[test]
    fn macro_generates_display_impl() {
        let key = ExampleKey { bytes: vec![1; 32] };
        let display_str = format!("{}", key);
        assert!(display_str.contains("example_"));
        assert!(display_str.contains("example"));
    }
}
