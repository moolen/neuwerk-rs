# AWS E2E Test Bench

This folder provisions an AWS verification bench for:
- DPDK dataplane mode
- `gwlb` architecture (GWLB + GENEVE steering)
- `eni_no_encap` architecture (direct route steering to firewall dataplane ENI, no GWLB/GENEVE)
- Shared cloud policy smoke validation (`cloud-tests/common/run-policy-smoke.sh`)

## Requirements
- Terraform (>= 1.6).
- AWS credentials with permissions to create VPC, EC2, GWLB, VPC endpoints, IAM, and S3 resources.
- SSH keypair at `cloud-tests/.secrets/ssh/aws_e2e` and `cloud-tests/.secrets/ssh/aws_e2e.pub`.
- Built firewall binary at `target/release/firewall` (override via Terraform var `firewall_binary_path`).

## Quick Start
1. `cd cloud-tests/aws/terraform`
2. `terraform init`
3. `terraform plan -var 'firewall_binary_path=../../../target/release/firewall'`
4. `terraform apply -var 'firewall_binary_path=../../../target/release/firewall'`
5. `cd ..`
6. `make health`
7. `make policy-smoke`
8. `make run-tests`
9. `cd terraform && terraform destroy`

## Architecture Switch
- `traffic_architecture=gwlb` (default): keeps the existing GWLB endpoint + GENEVE path.
- `traffic_architecture=eni_no_encap`: routes `consumer_subnet_cidr <-> upstream_subnet_cidr` via the firewall dataplane ENI with `--encap none`.
- Example (no-encap bench):
  - `terraform apply -var 'firewall_binary_path=../../../target/release/firewall' -var 'traffic_architecture=eni_no_encap'`

## Notes
- The bench is currently single-AZ and single-firewall-instance oriented for deterministic verification.
- SSH key defaults to `cloud-tests/.secrets/ssh/aws_e2e`.
- `policy-smoke` reuses the common cloud runner and skips standalone throughput; `run-tests` includes throughput.
- AWS smoke defaults exclude `tls_intercept_http_path_enforcement`; override with `RUNNER_ARGS` (or `AWS_RUNNER_TESTS`) to run a custom test set.
- Throughput-sensitive knobs: `firewall_encap_mtu` (default `1800`), `firewall_dpdk_mbuf_data_room` (default `4096`), `firewall_dpdk_port_mtu` (GWLB default `1800`; set `0` to disable), `firewall_dpdk_port_mtu_no_encap` (eni_no_encap default `1800`; set `0` to disable), optional `firewall_dpdk_queue_override` (default `0`), `firewall_dpdk_state_shards` (default `32`), and `firewall_dpdk_overlay_debug` (keep `false` for perf).
- If the firewall binary is linked against DPDK `.so.24` (default `make build` output), avoid `.so.26` runtime preload settings; ABI mixing can fail startup (`EAL: Cannot init trace`).
- DPDK metrics now export ENA allowance xstats when available as `dpdk_xstat{name=...}` (for example `bw_in_allowance_exceeded`, `pps_allowance_exceeded`).
