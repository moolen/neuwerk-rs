# Azure E2E Test Bench

This folder provisions the Azure test bench described in `ROADMAP/AZURE-E2E.md`.

## Requirements
- Terraform and Azure CLI.
- Logged in via `az login`.
- Built firewall binary with `--features dpdk` (use `make build.dpdk`).
- SSH keypair at `cloud-tests/.secrets/ssh/azure_e2e`.
- Default image is Ubuntu 24.04 (Noble). Override `image_offer`/`image_sku` if you switch regions or use a custom image.

## Quick Start
1. `cd cloud-tests/azure/terraform`
2. `terraform init`
3. `make build.dpdk`
4. `terraform apply -var 'firewall_binary_path=../../../target/release/firewall'`
5. Use scripts in `cloud-tests/azure/scripts`.
6. Run the cloud policy smoke suite with `make policy-smoke`.
7. Open a local tunnel to one firewall UI and mint a JWT with `make ui.port-forward` (override with `INDEX=<n>` and `UI_LOCAL_PORT=<port>`).
8. Run VMSS lifecycle rollout validation with `make lifecycle-rollout` (consumer-side sustained mixed traffic + strict zero-failure assertions).
9. Run termination drain-path validation with `make lifecycle-termination-drain` (targets one VMSS instance, triggers lifecycle action, and asserts termination/drain metrics via streamed max values). Use `TRIGGER_ACTION=terminate` (default) or `TRIGGER_ACTION=reboot`.

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
