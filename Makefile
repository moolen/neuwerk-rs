.PHONY: build test test.integration

build:
	cargo build

test:
	cargo test

test.integration:
	cargo run --bin e2e_harness
