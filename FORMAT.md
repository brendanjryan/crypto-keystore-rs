# Keystore formats

New keystores use version 5. Versions 3 and 4 remain readable and can be created
explicitly with `KeystoreBuilder::with_version_enum`. Older releases cannot read
version 5; retain an encrypted backup when migrating.

## Version 5

Version 5 uses AES-256-GCM and the first 32 bytes of the scrypt or PBKDF2-derived
key. The existing `crypto` fields have these meanings:

- `cipher`: `aes-256-gcm`.
- `cipherparams.iv`: a fresh 12-byte nonce, encoded as hexadecimal.
- `ciphertext`: encrypted chain-key bytes, encoded as hexadecimal.
- `mac`: the detached 16-byte GCM authentication tag, encoded as hexadecimal.
- `kdf` and its parameters: the flattened layout used by version 4.

The nonce and ciphertext are authenticated by GCM. Additional authenticated data
is the compact UTF-8 JSON encoding of this ordered array:

```text
["crypto-keystore", version, id, chain, cipher, kdf_parameters]
```

`id` is a canonical lowercase hyphenated UUID. `chain` and `cipher` are strings.
`kdf_parameters` is an object serialized with this exact field order:

- PBKDF2: `kdf`, `dklen`, `c`, `prf`, `salt`.
- Scrypt: `kdf`, `dklen`, `n`, `p`, `r`, `salt`.

Numbers are unsigned decimal integers. Strings use JSON escaping; salt is the
stored hexadecimal string. No insignificant whitespace is included in this
encoding. The external JSON document may have different whitespace or field
ordering: authentication reconstructs the ordered representation from parsed
values. Unknown extension fields are ignored and are not authenticated.

New files use fresh random salt and nonce values. Tampered authenticated fields
or a wrong password return an error before any key is exposed. The independent
OpenSSL fixture in `tests/fixtures/ethereum_v5_pbkdf2.json` pins the encoding.

## Legacy formats

Version 3 supports Ethereum's Web3 Secret Storage format, including nested
`crypto.kdfparams`. Version 4 uses chain-specific legacy MACs and flattened KDF
parameters. Previously generated flattened v3 files also remain readable.

Version 3 increments the full 128-bit AES-CTR counter in big-endian order. Version
4 preserves the original 64-bit big-endian counter, leaving the upper 64 IV bits
unchanged. They differ only when the lower 64 bits carry during encryption.
Older releases also used the 64-bit counter for v3; those nonstandard v3 files
require the old counter behavior to recover the original key if a carry occurred.
The legacy MAC cannot distinguish these counter interpretations.

The v3/v4 MAC does not cover the IV. Reading a legacy file cannot detect every
form of tampering; verify the expected address when migrating a trusted copy.
Changing only its `version` field does not upgrade its encryption.

```rust
use crypto_keystore_rs::{EthereumKeystore, KeystoreBuilder};

let legacy = EthereumKeystore::load_from_file("legacy.json", old_password)?;
let upgraded = KeystoreBuilder::new()
    .with_key(legacy.key()?.clone())
    .with_uuid(legacy.id())
    .build(new_password)?;
upgraded.save_to_file("keystores")?;
```

This re-encrypts the same key as v5 with a fresh salt and nonce, preserving the
UUID. The builder can also explicitly create Ethereum v3 files for tools that
require the legacy format.
