.PHONY: build release clean check test fix

build:
	cargo build

release:
	cargo build --release

clean:
	cargo clean

test:
	cargo nextest run --features test-utils

check:
	cargo fmt --check
	cargo clippy -- -D warnings
	cargo nextest run --features test-utils
	cargo build

fix:
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged
