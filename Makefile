.PHONY: build release clean check test fix

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
