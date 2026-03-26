# Neuwerk Repository Guidance

## Architectural Philosophy
- Strict separation of dataplane and control plane.
- Dataplane contains only packet processing and stateful NAT logic.
- Control plane handles DNS proxying, cluster replication, and future management APIs.
- No DNS parsing or control-plane logic inside the dataplane.

## Supported Traffic Flows
- DNS queries targeted at Neuwerk itself
- Neuwerk-originated upstream DNS traffic
- Neuwerk-originated cluster replication traffic
- Traffic under policy (DPDK data plane)

## Packaged Runtime Config
- Treat `/etc/neuwerk/config.yaml` as the canonical operator-facing packaged runtime contract.
- Do not reintroduce `/etc/neuwerk/appliance.env`, `/etc/neuwerk/neuwerk.env`, or shell env-to-CLI bootstrap wrappers in packaging/docs work.

## DPDK Build And Cloud-Test Notes
- Azure cloud tests expect a DPDK-enabled Neuwerk binary. Build it with `cargo build --release --features dpdk`.
- Do not deploy a plain `cargo build --release` binary to DPDK test VMs. The service will fail at startup with `dpdk io backend not available`.
- The accepted Azure baseline in this repo is Ubuntu 24.04 with Ubuntu APT DPDK `23.11` LTS. When documenting or changing the DPDK runtime, keep that version assumption explicit.
- A local DPDK build requires the DPDK shared libraries and headers installed on the build machine so `--features dpdk` can link successfully.
- The `cloud-tests/azure` `cps.matrix*` targets do not automatically sync a newly built Neuwerk binary to Neuwerk VMs. They mainly push policy, apply runtime env overrides, and restart `neuwerk.service`.
- After Neuwerk dataplane code changes, explicitly deploy the matching `target/release/neuwerk` binary to the Neuwerk VMs before trusting CPS results. Reuse the binary-sync path from `cloud-tests/azure/scripts/cps-instance-matrix.sh` or an equivalent manual `ssh_jump` + `install` flow.
- If you want the harness to manage binary rollout automatically, use a workflow that passes `NEUWERK_BINARY_PATH` through the instance-matrix/scaling scripts rather than assuming `cps.matrix` will do it.

## Runtime Configuration Documentation
- `www/src/content/docs/reference/runtime-configuration.mdx` is the canonical operator-facing reference for supported `/etc/neuwerk/config.yaml` runtime paths.
- Any change that adds, removes, renames, or changes the default or operator-visible behavior of a supported runtime config path must update `www/src/content/docs/reference/runtime-configuration.mdx` in the same change.
- Do not add CI-only, packer/build-only, fuzz/benchmark, e2e-harness, cloud-test-harness-only, or generated internal runtime state to that page unless it becomes supported operator-facing configuration.
