.PHONY: build test test.integration ha.up ha.down

build:
	cargo build

test:
	cargo test

test.integration: build
	cargo run --bin e2e_harness

ha.up: build
	sudo ./scripts/ha_local.sh up

ha.down:
	sudo ./scripts/ha_local.sh down
