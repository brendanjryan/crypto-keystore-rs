# crypto-keystore-rs

> [!WARNING]
> This repo has not been audited -- use at your own risk! 

A multi-chain keystore library for Rust supporting Ethereum and Solana with the Web3 Secret Storage format.

This library extends the core web3 keystore spec [ref](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage/) but supports address schemes other than Ethereum.

* [Docs](https://docs.rs/crypto-keystore-rs/latest/crypto_keystore_rs/)
* [Crate](https://crates.io/crates/crypto-keystore-rs)

## Features

- **Multi-chain support**: Ethereum (secp256k1) and Solana (Ed25519) keys
- **Web3 compatibility**: Authenticated v5 format, with legacy v3 (Ethereum) and v4 (chain-neutral) support
- **Secure**: Uses audited cryptographic libraries from [RustCrypto](https://github.com/RustCrypto)
- **Memory cleanup**: Temporary secret buffers are zeroized on drop
- **Opt-in functionality**: Only compile what you need (ethereum, solana, or both)

## Installation

This README includes unreleased v5 changes on `main`; published 0.2 releases use
the legacy default format.

Add this to your `Cargo.toml`:

```toml
[dependencies]
crypto-keystore-rs = "0.2"
```

### Feature Flags

By default, both Ethereum and Solana support are enabled. You can opt into specific chains:

```toml
[dependencies]
# Only Ethereum
crypto-keystore-rs = { version = "0.2", default-features = false, features = ["ethereum"] }

# Only Solana
crypto-keystore-rs = { version = "0.2", default-features = false, features = ["solana"] }

# Both (default)
crypto-keystore-rs = "0.2"
```

## Usage

### Import limits

Keystore imports default to a 64 KiB JSON/file limit and bounded KDF work. To
configure input size separately from KDF budgets:

```rust
use crypto_keystore_rs::{EthereumKeystore, ImportLimits, KdfLimits};

let limits = ImportLimits {
    max_input_bytes: 4096,
    kdf: KdfLimits {
        max_pbkdf2_iterations: 600_000,
        ..KdfLimits::default()
    },
};
let loaded = EthereumKeystore::load_from_file_with_import_limits(
    "keystore.json", "password", limits,
)?;
```

`from_json_with_import_limits` applies the same policy to JSON strings. Existing
`*_with_limits` methods still accept `KdfLimits` and use the default input cap.
Oversized input returns `KeystoreError::InputTooLarge` before JSON parsing.

### Ethereum Example

```rust
use crypto_keystore_rs::EthereumKeystore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "secure_password_123";

    // Create a new Ethereum keystore with a random key
    let keystore = EthereumKeystore::new(password)?;
    let address = keystore.key()?.address();
    println!("Ethereum address: {}", address);

    // Save to file
    let uuid = keystore.save_to_file("./keystores")?;
    println!("Saved keystore with ID: {}", uuid);

    // Load from file
    let loaded = EthereumKeystore::load_from_file(
        format!("./keystores/{}.json", uuid),
        password
    )?;

    assert_eq!(loaded.key()?.address(), address);

    Ok(())
}
```

### Solana Example

```rust
use crypto_keystore_rs::SolanaKeystore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "secure_password_123";

    // Create a new Solana keystore with a random key
    let keystore = SolanaKeystore::new(password)?;
    let address = keystore.key()?.address();
    println!("Solana address: {}", address);

    // Save to file
    let uuid = keystore.save_to_file("./keystores")?;
    println!("Saved keystore with ID: {}", uuid);

    // Load from file
    let loaded = SolanaKeystore::load_from_file(
        format!("./keystores/{}.json", uuid),
        password
    )?;

    assert_eq!(loaded.key()?.address(), address);

    Ok(())
}
```

## Architecture

### `ChainKey` Trait

The library uses a trait-based design in order to encapsulate different key encodings on a per chain/VM basis.

```rust
pub trait ChainKey: Sized + Clone {
    const SECRET_KEY_SIZE: usize;
    const KEYSTORE_SIZE: usize;
    const CHAIN_ID: &'static str;

    fn to_keystore_bytes(&self) -> zeroize::Zeroizing<Vec<u8>>;
    fn from_keystore_bytes(bytes: &[u8]) -> Result<Self>;
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
    fn address(&self) -> String;
}
```

### Keystore Format

New keystores use **version 5**, with AES-256-GCM authenticating the nonce,
ciphertext, UUID, chain, and cryptographic parameters. See [format and migration
details](FORMAT.md). Legacy v3/v4 files remain readable; their MACs do not
authenticate the IV.

The library uses a JSON-based keystore format inspired by the Web3 Secret Storage Definition, but extended to support chains other than Ethereum.

**Legacy version 4 (chain-neutral):**
```json
{
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": { "iv": "..." },
    "ciphertext": "...",
    "kdf": "scrypt",
    "dklen": 32,
    "n": 262144,
    "p": 1,
    "r": 8,
    "salt": "...",
    "mac": "..."
  },
  "id": "uuid-v4",
  "version": 4,
  "chain": "ethereum"
}
```

**Version 3 (Ethereum backward compatible):**

The library can also read standard Ethereum Web3 Secret Storage v3 keystores.

## Development

### Building

```bash
make build          # Build the library
make release        # Build optimized release
make test           # Run tests
make check          # Run fmt, clippy, tests
make fix            # Auto-fix formatting and clippy warnings
```

### Running Tests

```bash
cargo test                                     # All tests
cargo test --no-default-features --features ethereum  # Ethereum only
cargo test --no-default-features --features solana    # Solana only
make coverage                                  # Source coverage; requires cargo-llvm-cov
make mutations                                 # Requires cargo-mutants and Python 3
make fuzz                                      # Requires cargo-fuzz and nightly Rust
make interop                                   # Requires Node.js 22 (OpenSSL)
```
