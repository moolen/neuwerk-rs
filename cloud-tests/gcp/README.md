# GCP E2E Test Bench

This folder provisions a GCP test bench mirroring the Azure traffic shape:

- `consumer -> dataplane ILB -> neuwerk MIG -> upstream ILB/backend`
- Symmetric UDR-style steering for `consumer -> upstream` and `upstream -> consumer`
- Shared policy smoke harness via `cloud-tests/common/run-policy-smoke.sh`

## Requirements
- Terraform and `gcloud`.
- ADC auth: `gcloud auth application-default login`.
- Explicit neuwerk binary built with DPDK feature: `cargo build --release --features dpdk`.
- Explicit tar.gz runtime bundle containing the matching DPDK userspace libs and PMDs required by that binary.
- GCP bench images assume Ubuntu 24.04 userspace and gVNIC with the Ubuntu APT DPDK `23.11` LTS runtime. Keep that provenance aligned with both the binary and the runtime bundle you upload.
- SSH keypair at `cloud-tests/.secrets/ssh/gcp_e2e`.

## Quick Start
1. `cd cloud-tests/gcp/terraform`
2. `terraform init`
3. `terraform apply -var 'neuwerk_binary_path=/absolute/path/to/neuwerk' -var 'neuwerk_dpdk_runtime_bundle_path=/absolute/path/to/dpdk-runtime.tar.gz'`
4. `cd ..`
5. `make health`
6. `make policy-smoke`
7. `make performance.scenario`
8. `cd terraform && terraform destroy`

The repo no longer ships a default GCP binary or DPDK runtime tarball. Pass the exact artifacts from your build pipeline so the uploaded GCS objects have clear provenance.

## Performance Scenario

`make performance.scenario` is the primary performance workflow. It runs the shared cloud-agnostic scenario across:

- Direct path: `consumer -> upstream`
- Neuwerk path: `consumer -> neuwerk -> upstream`

The scenario orchestrates:

- Throughput: TCP and UDP stream sweeps.
- CPS: completed TCP connection-rate sweep.
- NAT: connection-scale and churn validation.
- TLS/DPI: HTTPS throughput and TLS-intercept scenarios.

If the deployed GCP topology does not expose enough same-subnet consumer source IPs for the direct path, the direct-path phases are skipped automatically.

## Notes
- Default project/region/zone are set in `terraform/variables.tf` and can be overridden via `-var`.
- Neuwerk VMs use gVNIC NIC type and bootstrap DPDK dataplane selection from the dataplane NIC PCI/MAC (targeting GCP gVNIC/net_gve PMD path).
- `terraform apply` now requires both `neuwerk_binary_path` and `neuwerk_dpdk_runtime_bundle_path`; there is no implicit in-repo artifact fallback.
- Neuwerk NIC queue counts are explicitly configurable:
  - `neuwerk_mgmt_queue_count` (default `1`) is applied to the management NIC.
  - `neuwerk_total_nic_queue_count` (default `8`) is the queue budget; dataplane NIC gets `total - mgmt` (minimum `1`).
  - Example for `n2-standard-8`: keep defaults so management gets `1` queue and dataplane gets `7`.
- Neuwerk cloud-init installs hugepages/IOMMU settings and reboots once during first bootstrap.
- Policy management API checks use `https://<fw-mgmt-ip>:8443/{health,ready}` through the jumpbox.
- Dataplane ILB backend health checks use TCP on `:8080` (DPDK dataplane probe path on dataplane NIC).
- GCP does not allow overriding subnet-local routes with VPC static routes; steering is applied with per-host guest routes on consumer/upstream VMs that point to subnet-local dataplane ILB VIPs.
- `policy-smoke` is the primary functional scenario.
- `performance.scenario` is the primary performance scenario.
- Lower-level helpers remain available for focused debugging: `make throughput.matrix`, `make cps.matrix`, `make connscale.matrix`, `make http-perf.setup`, `make http-perf.quick`, and `make http-perf.run`.
- `make cps.matrix` defaults to the Rust TCP client; TRex is no longer supported.
- Build recommendation tables with `make scaling.report THROUGHPUT_RESULT=<.../throughput/result.json> HTTP_MATRIX_SUMMARY=<.../http-perf-matrix/matrix-summary.json>`.
