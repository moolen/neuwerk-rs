# Fuzz Targets

This directory contains `cargo-fuzz` targets for high-risk parser/runtime surfaces:

- `packet_parse`
- `overlay_decap`
- `tls_reassembly`

Run examples:

```bash
cargo fuzz run packet_parse
cargo fuzz run overlay_decap
cargo fuzz run tls_reassembly
make fuzz.check
make fuzz.smoke
make fuzz.nightly
```

Prerequisites:

- `cargo install cargo-fuzz`
- nightly Rust toolchain (`cargo +nightly fuzz ...`)
- LLVM toolchain (libFuzzer)

Notes:

- `make fuzz.smoke` runs deterministic bounded campaigns (`-runs`) across all targets.
- `make fuzz.nightly` runs time-bounded sanitizer campaigns (`address` + `undefined` by default).
- Set `NEUWERK_FUZZ_REQUIRED=1` to make missing `cargo-fuzz` a hard failure.
- Seed corpora under `fuzz/corpus/*` include both minimal bytes and protocol-shaped samples
  (IPv4/TCP/UDP/ARP frames, overlay mode/port combinations, and fragmented TLS record streams)
  to improve early path coverage before mutational exploration.
