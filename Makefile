.PHONY: build release clean check test fix coverage mutations fuzz interop

build:
	cargo build

release:
	cargo build --release

clean:
	cargo clean

test:
	cargo test

check:
	cargo fmt --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test
	cargo build

fix:
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged

coverage:
	cargo llvm-cov --release --all-features --ignore-filename-regex '/tests/' --fail-under-lines 90 --html

mutations:
	python3 scripts/check-security-mutations.py
	cargo mutants --jobs 2

fuzz:
	cargo +nightly fuzz run imports -- -max_total_time=30 -max_len=65537 -timeout=5 -rss_limit_mb=1024
	cargo +nightly fuzz run authenticated -- -max_total_time=30 -max_len=65537 -timeout=5 -rss_limit_mb=1024

interop:
	cargo test --release --all-features --test openssl_interop -- --ignored
