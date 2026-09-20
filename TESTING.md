# Testing

Run `cargo test --all-features`, `cargo fmt --check`, and
`cargo clippy --all-targets --all-features -- -D warnings` before submitting changes.
CI also tests Ethereum-only, Solana-only, and no-chain builds, Linux/macOS/Windows,
and the declared Rust 1.85 minimum. Production KDF defaults are exercised explicitly;
fast parameters are supplied to tests that do not need expensive derivation.

## Security regressions and mutation testing

Install `cargo-mutants` 27.1.0 with `cargo install cargo-mutants --version 27.1.0 --locked`.
Run `make mutations` (Python 3 required).

The first stage copies the source into a temporary directory and introduces seven
specific regressions: constant salts, constant nonces, skipped legacy MAC checks,
missing authenticated metadata, an absent input cap, a relaxed KDF budget, and a
skipped version check. Every variant must compile and fail an assertion. Compile
failures, timeouts, and unexpected process exits fail the checker; they do not count
as caught mutations. Reports are written to `security-mutations.out/`.

The second stage runs generated mutants using `.cargo/mutants.toml`. The initial
scope covers key-size validation, versions/chains, random bytes, legacy cipher
selection, and bounded file reads. Any surviving mutant fails CI. Review survivors
and improve assertions; do not weaken the gate simply to make it pass. One initial
survivor motivated explicit v3 chain-field cases.

Generated KDF-budget mutations are deliberately outside this initial scope: removing
those guards can make hostile-input tests allocate enormous buffers or perform
billions of iterations. The hand-written budget mutation raises a tiny test limit by
one, exercising the same security property with bounded work. To broaden the mutation
scope, use a disposable runner with an OS memory/process budget and a wall-clock limit.
Do not run an unrestricted campaign against adversarial KDF tests on a developer host.

Direct RNG tests hold the key/password constant and compare serialized salt/nonce
bytes with an independently advanced deterministic RNG. The UUID cannot hide a
constant-salt/nonce regression. Property tests also compare the fields individually.

## Fuzzing

Install nightly Rust and `cargo-fuzz` 0.13.1; run `make fuzz`. AddressSanitizer is enabled
by default. The PR smoke runs last 30 seconds per target; daily runs last ten minutes.
Both have a five-second per-input timeout and a 1 GiB RSS ceiling.

- `imports` exercises arbitrary UTF-8 JSON, both chains, and all readable formats.
  Successful imports must serialize/reimport to identical key bytes and reject a
  wrong password.
- `authenticated` builds valid v5 files with small PBKDF2/scrypt settings, both
  chains, and varied passwords. It checks exact key recovery and rejects mutations
  to the nonce, salt, ciphertext, tag, UUID, derived length, chain, or version.

Both targets use strict input/KDF budgets. Shared harness code in
`tests/support/fuzz_cases.rs` is also exercised by ordinary tests. Commit minimized
regressions to `fuzz/corpus/<target>/` with descriptive names; CI replays every seed.
Generated hash-named corpus entries and build artifacts are ignored. CI uploads
corpora and crashes for investigation. A clean short run is not a security proof.

A wrong-password oracle must not just append a NUL: HMAC key padding can make short
passwords differing only by trailing zero bytes equivalent. The structured oracle
appends a nonzero byte instead; passwords containing embedded NULs still round-trip.

## Interoperability

With Node.js 22 installed, run `make interop`. The explicit CI job runs the tests
that ordinary Cargo runs mark ignored because they require Node/OpenSSL.

The Node implementation derives keys independently and reconstructs v5 AAD in its
specified field order. It decrypts Rust v3/v5 files and generates new v5 ciphertext
and tags for Rust to import, covering both KDFs and both supported key sizes. Test
passwords include Unicode and an embedded NUL. Ethereum uses a full-width encoding
of scalar 1 to retain leading-zero coverage. Existing go-ethereum/Web3 fixtures and
independent counter-carry vectors cover legacy input and counter compatibility.
All test keys and passwords are synthetic and public.

## File behavior

Tests cover missing directories, failed destination replacement, unwritable Unix
directories, symlink replacement, permissions, and simultaneous readers/writers of
the same UUID. Successful reads must recover one complete expected key. Permission
failure tests skip only when a privileged process demonstrably bypasses Unix mode bits.

`save_to_file` promises atomic replacement, not power-loss durability. It syncs the
file before rename but does not sync the parent directory afterward. Keep backups.
A stronger crash-durability contract would require platform-specific directory syncing
and filesystem fault-injection tests; process-kill tests alone cannot prove power-loss
behavior.

## CI and release checks

- `make coverage` generates a source-line report with `cargo-llvm-cov` 0.9.1 and enforces
  a 90% floor. Coverage reports include test helpers within `src/` but exclude files
  under `tests/`; doctests run separately without instrumentation. Use missing lines
  to identify worthwhile cases rather than treating a percentage as security assurance.
- The security audit runs on every PR, main push, and daily, with read-only permissions.
  Its stable required-check name is `audit`. `cargo deny --all-features check advisories`
  can run locally without a custom advisory policy.
- API compatibility is checked against commit
  `35ccd88e67cdc2d02994310387b2ed02c2b87a54`, the integrated v5 API baseline. This avoids
  conflating this test-only change with the intentional earlier v5 API migration.
  Advance the baseline when adopting a new release API. Semver checks do not replace
  on-disk format compatibility tests.
- Before publishing v5, retain the format/migration corpus, review release-version
  compatibility, and obtain an independent cryptographic review of the format and
  implementation. Automated tests do not constitute that external review.
