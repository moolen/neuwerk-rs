# Azure E2E Test Bench

This folder provisions the Azure test bench described in `ROADMAP/AZURE-E2E.md`.

## Requirements
- Terraform and Azure CLI.
- Logged in via `az login`.
- Built firewall binary with `--features dpdk` (use `make build`).
- SSH keypair at `cloud-tests/.secrets/ssh/azure_e2e`.
- Default image is Ubuntu 24.04 (Noble). Override `image_offer`/`image_sku` if you switch regions or use a custom image.

## Quick Start
1. `cd cloud-tests/azure/terraform`
2. `terraform init`
3. `make build`
4. `terraform apply -var 'firewall_binary_path=../../../target/release/firewall'`
5. Use scripts in `cloud-tests/azure/scripts`.
6. Run the cloud policy smoke suite with `make policy-smoke`.
7. Open a local tunnel to one firewall UI and mint a JWT with `make ui.port-forward` (override with `INDEX=<n>` and `UI_LOCAL_PORT=<port>`).
8. Run VMSS lifecycle rollout validation with `make lifecycle-rollout` (consumer-side sustained mixed traffic with an error budget default of `0.01%`; override via `MAX_ERROR_RATE_PCT`).
9. Run termination drain-path validation with `make lifecycle-termination-drain` (targets one VMSS instance, triggers lifecycle action, and asserts termination/drain metrics via streamed max values). Use `TRIGGER_ACTION=terminate` (default) or `TRIGGER_ACTION=reboot`.
10. Run HTTP webhook perf setup with `make http-perf.setup`.
11. Run a quick single-scenario HTTP webhook perf run with `make http-perf.quick`.
12. Run the full HTTP webhook perf matrix with `make http-perf.run` (override with `HTTP_PERF_SCENARIOS`, `RPS_TIERS`, `PAYLOAD_TIERS`, `CONNECTION_MODES`, `HTTP_REPEATS`).
13. Run raw IP throughput matrix (TCP+UDP stream sweep with repeated runs) via `make throughput.matrix`.
14. Build recommendation tables with `make scaling.report THROUGHPUT_RESULT=<.../throughput/result.json> HTTP_MATRIX_SUMMARY=<.../http-perf-matrix/matrix-summary.json>`.

## Notes
- Readiness checks use `https://<mgmt-ip>:8443/ready`.
- Policy API calls use `https://<mgmt-ip>:8443/api/v1/*`.
- VMSS instance IPs are resolved at runtime by the scripts via Azure CLI because VMSS instance addresses are not stable Terraform outputs.
- If you do not provide a firewall binary path, Terraform uploads a placeholder that will cause the firewall service to fail. Override `firewall_binary_path` with a DPDK-enabled build.
- `scripts/lifecycle-rollout.sh` starts a delayed HTTP server on the upstream VM (`:9000`, path `/delay/5`), runs sustained mixed traffic from a consumer VM (`dns_udp`, `dns_tcp`, `http`, `https`, `delayed_http`), executes a VMSS rolling update, and captures per-firewall metrics snapshots under `cloud-tests/azure/artifacts/`.
- `scripts/lifecycle-termination-drain.sh` runs delayed-flow traffic, triggers a lifecycle action on one selected VMSS instance (`terminate` via surge+delete or `reboot`), and asserts streamed max increases for `integration_termination_events_total` and `integration_termination_drain_start_seconds_count` so counter resets during reboot do not hide detections.
- Azure rejects chaining an internal Standard LB to a GWLB. We use a public Standard LB chained to the GWLB for upstream traffic, and only the required test ports are exposed (TCP 80/443/9000/5201, UDP 5201, and TCP/UDP 53).
- Azure load balancers do not forward ICMP; policy-smoke ICMP tests target the upstream VM private IP (still routed through the firewall by UDR) instead of the upstream ILB VIP.
- DNS service args now use repeated `--dns-target-ip` and `--dns-upstream`; Terraform inputs are `dns_target_ips` and `dns_upstreams` (both lists). Empty values default to management IP target and upstream VM `:53`.
- `scripts/run-tests.sh` now validates both UDP and TCP DNS queries and enforces strict TLS intercept allow/deny behavior (`/external-secrets/*` allowed, `/moolen` reset/refused).
- HTTP webhook perf scripts live under `scripts/http-perf-*.sh`, use k6 from consumer VMs, and store JSON artifacts under `cloud-tests/azure/artifacts/http-perf-*`.
- HTTP webhook perf setup now tunes consumer socket capacity for connection-heavy runs: wider ephemeral port range, `tcp_tw_reuse`, shorter `tcp_fin_timeout`, and higher `nofile` limits.
- Azure consumers now allocate `consumer_secondary_private_ip_count` additional private IPs per NIC by default for HTTP perf runs; the current default is `7`, giving one consumer VM `8` total source IPs for connection-heavy load generation.
- HTTP webhook perf runs now classify load-generator-limited cases as `status: "invalid"` in `result.json` and `matrix-summary.json` when k6 reports conditions such as `cannot assign requested address`, `Insufficient VUs`, or `too many open files`.
- `new_connection_heavy` fanout uses all resolved consumer VMs automatically and splits target RPS across them; single-consumer runs remain valid for debugging but are more likely to be generator-limited.
- HTTP perf artifacts now include consumer-side source-IP and socket diagnostics in `consumer-source-ips.json`, per-run `raw/pre.consumer-sockets.*.json` and `raw/post.consumer-sockets.*.json`, plus `consumer-socket-summary.json` with local-IP count and tuple-budget estimates.
- Raw IP throughput matrix wrapper lives at `scripts/throughput-matrix.sh` and uses the shared runner `cloud-tests/common/run-throughput-matrix.sh` to emit `context.json`, `workload.json`, `result.json`, and `matrix-summary.json` under `cloud-tests/azure/artifacts/throughput-matrix-*`.
- HTTP perf now supports explicit connection-mode and payload dimensions (`keep_alive` and `new_connection_heavy`; `1024` and `32768` bytes by default) via shared cross-cloud core scripts in `cloud-tests/common`.
