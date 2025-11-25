# crypto-keystore-rs

> [!WARNING]
> This repo has not been audited -- use at your own risk! 

A multi-chain keystore library for Rust supporting Ethereum and Solana with the Web3 Secret Storage format.

This library is an extension of [`eth-keystore`](https://docs.rs/eth-keystore/0.5.0/eth_keystore/) but with support for arbitrary key formats alongside `ethereum` keys -- starting with Solana.

## Features

- **Multi-chain support**: Ethereum (secp256k1) and Solana (Ed25519) keys
- **Web3 compatibility**: Supports Web3 Secret Storage format v3 (Ethereum) and v4 (chain-neutral)
- **Secure**: Uses audited cryptographic libraries from [RustCrypto](https://github.com/RustCrypto)
- **Zero-copy**: Keys are zeroized on drop to prevent memory leaks
- **Opt-in functionality**: Only compile what you need (ethereum, solana, or both)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
crypto-keystore-rs = "0.1"
```

### Feature Flags

By default, both Ethereum and Solana support are enabled. You can opt into specific chains:

```toml
[dependencies]
# Only Ethereum
crypto-keystore-rs = { version = "0.1", default-features = false, features = ["ethereum"] }

# Only Solana
crypto-keystore-rs = { version = "0.1", default-features = false, features = ["solana"] }

# Both (default)
crypto-keystore-rs = "0.1"
```

## Usage

### Ethereum Example

```rust
use crypto_keystore_rs::{EthereumKeystore, ChainKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "secure_password_123";

    // Create a new Ethereum keystore with a random key
    let keystore = EthereumKeystore::new(password)?;
    let address = keystore.key()?.public_key();
    println!("Ethereum address: {}", address);

    // Save to file
    let uuid = keystore.save_to_file("./keystores")?;
    println!("Saved keystore with ID: {}", uuid);

    // Load from file
    let loaded = EthereumKeystore::load_from_file(
        format!("./keystores/{}.json", uuid),
        password
    )?;

    assert_eq!(loaded.key()?.public_key(), address);

    Ok(())
}
```

### Solana Example

```rust
use crypto_keystore_rs::{SolanaKeystore, ChainKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "secure_password_123";

    // Create a new Solana keystore with a random key
    let keystore = SolanaKeystore::new(password)?;
    let address = keystore.key()?.public_key();
    println!("Solana address: {}", address);

    // Save to file
    let uuid = keystore.save_to_file("./keystores")?;
    println!("Saved keystore with ID: {}", uuid);

    // Load from file
    let loaded = SolanaKeystore::load_from_file(
        format!("./keystores/{}.json", uuid),
        password
    )?;

    assert_eq!(loaded.key()?.public_key(), address);

    Ok(())
}
```

## Architecture

### `ChainKey` Trait

The library uses a trait-based design in order to encapsulate different key encodings on a per chain/VM basis.

```rust
pub trait ChainKey: Sized {
    const SECRET_KEY_SIZE: usize;
    const KEYSTORE_SIZE: usize;
    const CHAIN_ID: &'static str;

    fn to_keystore_bytes(&self) -> Vec<u8>;
    fn from_keystore_bytes(bytes: &[u8]) -> Result<Self>;
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
    fn public_key(&self) -> String;
    fn mac_algorithm() -> MacAlgorithm;
}
```

### Keystore Format

The library uses a JSON-based keystore format inspired by the Web3 Secret Storage Definition, but extended to support chains other than Ethereum.:

**Version 4 (Chain-neutral):**
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

## Differences from eth-keystore-rs

This library is a fork and redesign of [eth-keystore-rs](https://github.com/roynalnaruto/eth-keystore-rs) with the following changes:

### Breaking Changes
- **New API**: Generic `Keystore<K: ChainKey>` instead of standalone functions
- **Different return types**: Methods return `Result<Keystore<K>>` instead of tuples

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
```
