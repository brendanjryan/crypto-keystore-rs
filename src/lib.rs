//! # crypto-keystore-rs
//!
//! A multi-chain keystore library supporting Ethereum and Solana with the Web3 Secret Storage format.
//!
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(feature = "ethereum")]
//! # {
//! use crypto_keystore_rs::{EthereumKeystore, ChainKey};
//!
//! let keystore = EthereumKeystore::new("my_password").unwrap();
//! let uuid = keystore.save_to_file("./keystores").unwrap();
//!
//! let loaded = EthereumKeystore::load_from_file(
//!     format!("./keystores/{}.json", uuid),
//!     "my_password"
//! ).unwrap();
//!
//! println!("Ethereum address: {}", loaded.key().unwrap().address());
//! # }
//! ```

pub mod chains;
mod crypto_config;
pub mod error;
pub mod keystore;

pub use chains::ChainKey;
pub use error::{KeystoreError, Result};
pub use keystore::{Keystore, VERSION_3, VERSION_4};

// == Keys ==

#[cfg(feature = "ethereum")]
pub use chains::EthereumKey;

#[cfg(feature = "solana")]
pub use chains::SolanaKey;

// == Keystores ==

#[cfg(feature = "ethereum")]
pub type EthereumKeystore = Keystore<EthereumKey>;

#[cfg(feature = "solana")]
pub type SolanaKeystore = Keystore<SolanaKey>;
