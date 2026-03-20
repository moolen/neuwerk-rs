# Azure E2E Test Bench

This folder provisions the Azure verification bench for functional and performance testing of the neuwerk dataplane.

## Requirements

- Terraform and Azure CLI.
- Logged in via `az login`.
- A DPDK-runtime-compatible neuwerk binary if you want to override the default asset. Azure defaults to `cloud-tests/azure/terraform/assets/neuwerk-dpdk24`, which matches the bench image DPDK runtime.
- SSH keypair at `cloud-tests/.secrets/ssh/azure_e2e`.
- Ubuntu 24.04 image defaults unless you override the image variables in Terraform.

## Primary Workflows

1. `cd cloud-tests/azure/terraform`
2. `terraform init`
3. `terraform apply`
4. `cd ..`
5. `make health`
6. `make policy-smoke`
7. `make performance.scenario`

`performance.scenario` is the primary documented perf entrypoint. It runs the shared cloud-agnostic performance scenario across:

- Direct path: `consumer -> upstream`
- Neuwerk path: `consumer -> neuwerk -> upstream`

The scenario currently orchestrates four phases:

- Throughput: IMIX PPS sweep by default (`PERF_THROUGHPUT_MODE=tcp_udp` switches back to the older TCP/UDP stream sweeps).
- CPS: completed TCP connection-rate sweep.
- NAT: connection-scale and churn validation.
- TLS/DPI: HTTPS throughput plus TLS-intercept scenarios.

## Lower-Level Helpers

The following targets remain available for debugging and focused benchmarking, but they are no longer the recommended top-level workflow:

- `make throughput.matrix`
- `make pps.matrix`
- `make cps.matrix`
- `make connscale.matrix`
- `make http-perf.setup`
- `make http-perf.quick`
- `make http-perf.run`
- `make scaling.benchmark`
- `make scaling.report THROUGHPUT_RESULT=<...> HTTP_MATRIX_SUMMARY=<...>`

Azure-specific operational helpers are unchanged:

- `make ui.port-forward`
- `make lifecycle-rollout`
- `make lifecycle-termination-drain`
- `make shape.netopt-path.apply`
- `make cps.instance-matrix.netopt-path`

## Notes

- Readiness checks use `https://<mgmt-ip>:8443/ready`.
- Policy API calls use `https://<mgmt-ip>:8443/api/v1/*`.
- VMSS instance IPs are resolved at runtime via Azure CLI because the instance addresses are not stable Terraform outputs.
- Terraform now defaults `neuwerk_binary_path` to the bundled `neuwerk-dpdk24` asset so `terraform apply` and the Azure make targets use a DPDK-runtime-compatible binary out of the box.
- If you override `neuwerk_binary_path`, the binary must match the Azure bench image DPDK runtime. A locally built `target/release/neuwerk` linked against a newer DPDK will fail to start on the stock image.
- Azure consumers allocate `consumer_secondary_private_ip_count` additional private IPs per NIC by default. The current default is `31`, so one consumer VM gets `32` source IPs for connection-heavy tests.
- `performance.scenario` uses those source IP inventories to attempt both direct-path and neuwerk-path runs. Direct-path phases rely on consumer source IPs that share the upstream subnet.
- `scripts/cps-matrix.sh` uses the shared runner `cloud-tests/common/run-cps-matrix.sh` and defaults to the Rust TCP backend. `CPS_CLIENT_BACKEND=python` is still available for comparison, but TRex is no longer supported.
- `performance.scenario` is bounded for routine runs: IMIX throughput only, no repeats, short HTTP windows (`RAMP_SECONDS=5`, `STEADY_SECONDS=10`), single payload tier (`1024`), and one repeat per phase. The default end-to-end runtime target is roughly 15 to 30 minutes.
- HTTP perf scripts live under `scripts/http-perf-*.sh`, use k6 from the consumer VMs, and now write scenario-owned artifacts under the parent `performance-*` artifact root when launched via `performance.scenario`.
- HTTP perf runs classify obvious load-generator failures as `status: "invalid"` in `result.json` and `matrix-summary.json`.
- `new_connection_heavy` HTTP runs fan out across all resolved consumer VMs automatically; single-consumer runs are still useful for debugging but more likely to be generator-limited.
- `cps.instance-matrix` and `scaling.benchmark` remain the right tools when you want the harness to manage shape changes and binary rollout as part of the experiment loop.
