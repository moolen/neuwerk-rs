# GCP E2E Test Bench

This folder provisions a GCP test bench mirroring the Azure traffic shape:

- `consumer -> dataplane ILB -> firewall MIG -> upstream ILB/backend`
- Symmetric UDR-style steering for `consumer -> upstream` and `upstream -> consumer`
- Shared policy smoke harness via `cloud-tests/common/run-policy-smoke.sh`

## Requirements
- Terraform and `gcloud`.
- ADC auth: `gcloud auth application-default login`.
- Built firewall binary with DPDK feature: `cargo build --release --features dpdk`.
- SSH keypair at `cloud-tests/.secrets/ssh/gcp_e2e`.

## Quick Start
1. `cd cloud-tests/gcp/terraform`
2. `terraform init`
3. `terraform apply`
4. `cd ..`
5. `make health`
6. `make run-tests`
7. `make throughput.matrix`
8. `make http-perf.setup`
9. `make http-perf.quick`
10. `make http-perf.run`
11. `cd terraform && terraform destroy`

## Notes
- Default project/region/zone are set in `terraform/variables.tf` and can be overridden via `-var`.
- Firewall VMs use gVNIC NIC type and bootstrap DPDK dataplane selection from the dataplane NIC PCI/MAC (targeting GCP gVNIC/net_gve PMD path).
- Firewall NIC queue counts are explicitly configurable:
  - `firewall_mgmt_queue_count` (default `1`) is applied to the management NIC.
  - `firewall_total_nic_queue_count` (default `8`) is the queue budget; dataplane NIC gets `total - mgmt` (minimum `1`).
  - Example for `n2-standard-8`: keep defaults so management gets `1` queue and dataplane gets `7`.
- Firewall cloud-init installs hugepages/IOMMU settings and reboots once during first bootstrap.
- Policy management API checks use `https://<fw-mgmt-ip>:8443/{health,ready}` through the jumpbox.
- Dataplane ILB backend health checks use TCP on `:8080` (DPDK dataplane probe path on dataplane NIC).
- GCP does not allow overriding subnet-local routes with VPC static routes; steering is applied with per-host guest routes on consumer/upstream VMs that point to subnet-local dataplane ILB VIPs.
- Raw IP throughput matrix is available via `make throughput.matrix` and writes standardized artifacts (`context.json`, `workload.json`, `result.json`, `matrix-summary.json`) under `cloud-tests/gcp/artifacts/throughput-matrix-*` using the shared runner `cloud-tests/common/run-throughput-matrix.sh`.
- Cross-cloud HTTP/HTTPS/DPI matrix is available via `make http-perf.run` (quick single-combo smoke: `make http-perf.quick`), powered by common scripts under `cloud-tests/common/http-perf-*`.
- `http-perf.run` includes payload and connection dimensions by default (`PAYLOAD_TIERS=1024,32768`, `CONNECTION_MODES=keep_alive,new_connection_heavy`) and writes `matrix-summary.json`.
- Build recommendation tables with `make scaling.report THROUGHPUT_RESULT=<.../throughput/result.json> HTTP_MATRIX_SUMMARY=<.../http-perf-matrix/matrix-summary.json>`.
