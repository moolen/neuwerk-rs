# AWS E2E Test Bench

This folder provisions an AWS verification bench for:
- DPDK dataplane mode
- `gwlb` architecture (GWLB + GENEVE steering)
- `eni_no_encap` architecture (direct route steering to neuwerk dataplane ENI, no GWLB/GENEVE)
- Shared cloud policy smoke validation (`cloud-tests/common/run-policy-smoke.sh`)

## Requirements
- Terraform (>= 1.6).
- AWS credentials with permissions to create VPC, EC2, GWLB, VPC endpoints, IAM, and S3 resources.
- SSH keypair at `cloud-tests/.secrets/ssh/aws_e2e` and `cloud-tests/.secrets/ssh/aws_e2e.pub`.
- Built neuwerk binary at `target/release/neuwerk` (override via Terraform var `neuwerk_binary_path`).

## Quick Start
1. `cd cloud-tests/aws/terraform`
2. `terraform init`
3. `terraform plan -var 'neuwerk_binary_path=../../../target/release/neuwerk'`
4. `terraform apply -var 'neuwerk_binary_path=../../../target/release/neuwerk'`
5. `cd ..`
6. `make health`
7. `make policy-smoke`
8. `make performance.scenario`
9. `cd terraform && terraform destroy`

## Performance Scenario

`make performance.scenario` is the primary performance workflow. It runs the shared cloud-agnostic scenario across:

- Direct path: `consumer -> upstream`
- Neuwerk path: `consumer -> neuwerk -> upstream`

The scenario orchestrates:

- Throughput: TCP and UDP stream sweeps.
- CPS: completed TCP connection-rate sweep.
- NAT: connection-scale and churn validation.
- TLS/DPI: HTTPS throughput and TLS-intercept scenarios.

If the deployed AWS topology does not expose enough same-subnet consumer source IPs for the direct path, the direct-path phases are skipped automatically.

## Architecture Switch
- `traffic_architecture=gwlb` (default): keeps the existing GWLB endpoint + GENEVE path.
- `traffic_architecture=eni_no_encap`: routes `consumer_subnet_cidr <-> upstream_subnet_cidr` via the neuwerk dataplane ENI with `--encap none`.
- Example (no-encap bench):
  - `terraform apply -var 'neuwerk_binary_path=../../../target/release/neuwerk' -var 'traffic_architecture=eni_no_encap'`

## Notes
- `gwlb` architecture now runs neuwerk nodes via an ASG with an EC2 terminating lifecycle hook, and the neuwerk process runs with `--integration aws-asg` for drain/heartbeat/completion handling.
- `eni_no_encap` remains single-neuwerk-instance oriented for deterministic direct-route verification.
- SSH key defaults to `cloud-tests/.secrets/ssh/aws_e2e`.
- `policy-smoke` is the primary functional scenario.
- `performance.scenario` is the primary performance scenario.
- Lower-level helpers remain available for focused debugging: `make throughput.matrix`, `make cps.matrix`, `make connscale.matrix`, `make http-perf.setup`, `make http-perf.quick`, and `make http-perf.run`.
- `make cps.matrix` defaults to the Rust TCP client; TRex is no longer supported.
- Build recommendation tables with `make scaling.report THROUGHPUT_RESULT=<.../throughput/result.json> HTTP_MATRIX_SUMMARY=<.../http-perf-matrix/matrix-summary.json>`.
- ASG lifecycle rollout experiment: `make lifecycle-rollout` (writes `cloud-tests/aws/artifacts/aws-connectivity-rollout-*.{log,consumer-flow.log,result.json}`).
- AWS smoke defaults exclude `tls_intercept_http_path_enforcement`; override with `RUNNER_ARGS` (or `AWS_RUNNER_TESTS`) to run a custom test set.
- Throughput-sensitive knobs: `neuwerk_encap_mtu` (default `1800`), `neuwerk_dpdk_mbuf_data_room` (default `4096`), `neuwerk_dpdk_port_mtu` (GWLB default `1800`; set `0` to disable), `neuwerk_dpdk_port_mtu_no_encap` (eni_no_encap default `1800`; set `0` to disable), optional `neuwerk_dpdk_queue_override` (default `0`), `neuwerk_dpdk_state_shards` (default `32`), and `neuwerk_dpdk_overlay_debug` (keep `false` for perf).
- If the neuwerk binary is linked against DPDK `.so.24` (default `make build` output), avoid `.so.26` runtime preload settings; ABI mixing can fail startup (`EAL: Cannot init trace`).
- DPDK metrics now export ENA allowance xstats when available as `dpdk_xstat{name=...}` (for example `bw_in_allowance_exceeded`, `pps_allowance_exceeded`).
