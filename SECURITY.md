# Security Policy

## Threat Model

This library is designed to securely store cryptographic private keys for blockchain wallets
(Ethereum, Solana) using the Web3 Secret Storage format.

### What This Library Protects Against

1. **At-Rest Key Exposure**
   - New v5 keystores encrypt private keys with AES-256-GCM using password-derived keys. Legacy v3/v4 files use AES-128-CTR.
   - Uses memory-hard KDFs (Scrypt, PBKDF2) to resist brute-force attacks
   - Default Scrypt parameters (N=2^18) provide strong protection

2. **Password Brute-Force Attacks**
   - Scrypt default: N=262,144, r=8, p=1 (~256 MB memory, ~1-2 seconds)
   - PBKDF2 default: 600,000 iterations (OWASP recommended)
   - Sensitive mode: N=2^20 (~1 GB memory, ~5-10 seconds)

3. **Timing Attacks on Password Verification**
   - MAC comparison uses constant-time equality (`subtle::ConstantTimeEq`)
   - Password correctness is not leaked via timing side-channels

4. **Memory Disclosure**
   - Sensitive data (derived keys, plaintext, IVs) is zeroized after use
   - Chain key types implement `ZeroizeOnDrop`
   - `to_keystore_bytes()` returns `Zeroizing<Vec<u8>>` for automatic cleanup

5. **File Permission Exposure (Unix)**
   - Keystore files are written with mode 0600 (owner read/write only)

### What This Library Does NOT Protect Against

1. **Weak Passwords**
   - The library does not enforce password strength requirements
   - Users are responsible for choosing strong, unique passwords
   - Recommendation: 12+ characters with mixed case, numbers, and symbols

2. **Memory Forensics While Running**
   - While keys are in use, they exist in memory
   - A sufficiently privileged attacker with memory access can extract keys
   - For highest security, use hardware security modules (HSMs)

3. **Malicious Dependencies**
   - Users should audit dependencies and use `cargo audit`
   - Consider using vendored dependencies in high-security contexts

4. **Side-Channel Attacks Beyond Timing**
   - Power analysis, electromagnetic emissions, etc. are out of scope
   - Use dedicated hardware for protection against these attacks

5. **Compromised System**
   - If the system is compromised (rootkit, keylogger), all bets are off
   - Key material can be captured during password entry or key generation

6. **Key Generation Entropy**
   - The library relies on the OS CSPRNG (`rand::thread_rng()`)
   - On systems with poor entropy sources, keys may be predictable

## Format Authentication

Version 5 authenticates the nonce, ciphertext, UUID, chain, cipher, and KDF
parameters. See [the format definition and migration example](FORMAT.md).
Legacy v3/v4 MACs do not cover the IV; migration requires decrypting and
re-encrypting a trusted copy, not editing its version number.

Import methods reject JSON larger than 64 KiB by default, including whitespace
and ignored fields. File reads are bounded before parsing, and ciphertext, IV,
and MAC lengths are checked before hex decoding. `ImportLimits` configures the
input byte ceiling separately from `KdfLimits`; use `from_json_with_import_limits`
or `load_from_file_with_import_limits` to override it. Direct Serde deserialization
does not apply these import limits or decrypt keys.

KDF import limits reject excessive derived-key lengths, PBKDF2 iterations, and
scrypt memory/work before derivation. Applications handling untrusted files should
set budgets appropriate to their hardware and bound concurrent imports.

## Cryptographic Choices

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Encryption (v5) | AES-256-GCM | 256-bit key, 128-bit tag |
| Encryption (legacy v3/v4) | AES-128-CTR | 128-bit |
| MAC (Ethereum) | Keccak256 | 256-bit |
| MAC (Other chains) | SHA256 | 256-bit |
| KDF (default) | Scrypt | Memory-hard |
| KDF (alternative) | PBKDF2-HMAC-SHA256 | CPU-hard |
| Ethereum keys | secp256k1 ECDSA | ~128-bit |
| Solana keys | Ed25519 | ~128-bit |

## Dependency Security

This library uses well-audited RustCrypto implementations:

- `aes`, `ctr` - AES encryption
- `sha2`, `sha3` - Hash functions
- `pbkdf2`, `scrypt` - Key derivation
- `k256` - secp256k1 (Ethereum)
- `ed25519-dalek` - Ed25519 (Solana)
- `subtle` - Constant-time operations
- `zeroize` - Memory sanitization

Run `cargo audit` regularly to check for known vulnerabilities.



## Security Best Practices for Users

1. **Use strong, unique passwords** for each keystore
2. **Use Scrypt** (default) rather than PBKDF2 for new keystores
3. **Back up keystores securely** - encrypted cloud storage or offline media
4. **Run `cargo audit`** in your CI/CD pipeline
5. **Keep dependencies updated** to receive security patches
6. **Consider hardware wallets** for high-value keys
7. **Test with small amounts** before storing significant value

## Changelog

### v0.2.2 (Security Improvements)
- Added `ZeroizeOnDrop` for `EthereumKey` and `SolanaKey`
- `to_keystore_bytes()` now returns `Zeroizing<Vec<u8>>`
- Zeroize IV, ciphertext, and MAC bytes after decryption
- Set restrictive file permissions (0600) on Unix
- Increased PBKDF2 default iterations to 600,000 (OWASP)
- Added EIP-55 checksummed Ethereum addresses
