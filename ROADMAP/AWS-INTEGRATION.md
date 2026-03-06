**Overview**
Build an AWS verification bench with **DPDK dataplane** and **GWLB/GENEVE** from the start, aligned with existing Azure/GCP cloud-test workflows and shared policy-smoke verification tooling.

**Decisions Locked In**
- Dataplane mode: `dpdk` (mandatory in Phase 1).
- Traffic steering: **AWS Gateway Load Balancer (GWLB) + GENEVE**, not route-table steering to instance ENIs.
- Initial scale: `desired=1` firewall instance.
- Region: `eu-central-1`.
- CPU/instance preference: Intel, 2 vCPU class, target up to 12.5 Gbps (start with `c6in.large`, fallback to equivalent if unavailable).

**Scope (Phase 1)**
- Provision AWS infra for `consumer -> GWLB/GWLBE -> firewall -> upstream` with symmetric return path.
- Keep strict NIC split:
- `mgmt0` for control plane only.
- `data0` for dataplane only.
- Reuse existing verification harness:
- `cloud-tests/common/run-policy-smoke.sh`
- `cloud-tests/runner` (`cloud-policy-smoke`).
- Add AWS-specific Terraform, cloud-init/user-data, scripts, and Make targets.

**Out Of Scope (Phase 1)**
- ASG lifecycle hook handling, termination-drain orchestration, and route reassignment.
- Multi-instance lifecycle correctness (rollout/surge/scale-in drain).
- Non-GWLB fallback datapath.

**Architecture (Phase 1)**
1. VPC/Subnets
- `mgmt`, `dataplane`, `consumer`, `upstream`, `jumpbox` subnets in `eu-central-1`.
2. Firewall Compute
- ASG/Launch Template with desired capacity `1`.
- Two ENIs per firewall instance:
- mgmt ENI in `mgmt` subnet.
- dataplane ENI in `dataplane` subnet (DPDK NIC).
3. GWLB Path
- GWLB in dataplane VPC path.
- GWLB target group protocol `GENEVE` / UDP `6081`.
- Register **dataplane IP targets** (not mgmt IP) to preserve NIC separation.
- Consumer/upstream subnets use GWLB endpoints (GWLBE) for steering.
4. Test Nodes
- Jumpbox for orchestration/SSH.
- Consumer VM for verification workload.
- Upstream VM (HTTP/HTTPS/DNS/iperf services).

**Firewall Runtime Requirements (Phase 1)**
1. Runtime flags
- `--management-interface <mgmt iface>`
- `--data-plane-interface <data iface or selector>`
- `--data-plane-mode dpdk`
- `--encap geneve`
- `--encap-udp-port 6081`
- `--snat none`
- repeated `--dns-target-ip` and `--dns-upstream`
- `--cloud-provider aws`
- `--integration none` (lifecycle deferred)
2. Overlay correctness
- Preserve GENEVE TLVs on forward/return path (required for GWLB flow stickiness metadata).
- Policy and NAT decisions remain on inner packet only.
3. NIC handling
- Deterministic mapping of mgmt vs dataplane interfaces from ENI metadata/tags + MAC matching.
- Hard-fail bootstrap if interfaces cannot be resolved cleanly.

**Implementation Workstreams**
**1) Terraform: `cloud-tests/aws/terraform`**
1. Add root files:
- `providers.tf`, `versions.tf`, `variables.tf`, `outputs.tf`, `main.tf`.
2. Networking:
- VPC, subnets, IGW/NAT where needed.
- Security groups for jumpbox, consumer, upstream, firewall.
3. GWLB/GWLBE:
- GWLB, GENEVE target group (`6081`), listeners.
- Endpoint/service attachments and route integration for consumer/upstream traffic through GWLBE.
4. Compute:
- Firewall LT + ASG (`desired=1`).
- Consumer, upstream, jumpbox instances.
5. Artifact distribution:
- S3 object for firewall binary and optional DPDK runtime bundle.
- IAM instance profile with S3 read.
6. Outputs:
- jumpbox public IP, consumer private IPs, upstream VIP/IP, firewall mgmt IP(s), firewall dataplane target IP(s), GWLB endpoint IDs.

**2) AWS Bootstrap + Systemd**
1. Add AWS cloud-init/user-data template:
- install required runtime tooling.
- fetch firewall binary/runtime from S3.
- setup hugepages / DPDK prerequisites.
2. Resolve ENIs and map interfaces:
- bind dataplane NIC for DPDK path as required by selected PMD path.
3. Install/start firewall service with required flags above.
4. Expose `/health` and `/ready` on mgmt plane only.

**3) AWS Scripts + Make Targets**
1. Add `cloud-tests/aws/Makefile` with:
- `ssh.jumpbox`, `ssh.consumer`, `ssh.upstream`, `ssh.firewall`, `health`, `policy-smoke`, `run-tests`.
2. Add scripts:
- `scripts/resolve-firewall-mgmt-ips.sh`
- `scripts/configure-policy.sh`
- `scripts/mint-api-token.sh`
- `scripts/health.sh`
- `scripts/run-tests.sh`
3. Hook root `Makefile`:
- add `aws.%: $(MAKE) -C cloud-tests/aws $*`.

**4) Verification Tests**
1. Health/readiness checks
- verify all firewall nodes (currently one) pass `/health` and `/ready`.
2. Policy smoke
- run shared cloud-policy-smoke suite end-to-end from consumer.
3. GWLB/GENEVE validation checks (must-pass)
- verify traffic flows only when GWLB path is active.
- verify bidirectional HTTP/HTTPS/DNS via GWLB.
- verify deny-path behavior still enforced under GENEVE encapsulation.
- verify no fallback route-table direct steering is used.
4. Throughput sanity
- short `iperf3` run from consumer to upstream through GWLB/firewall datapath.
5. Artifacts
- persist logs/metrics/results under `cloud-tests/aws/artifacts/<timestamp>/`.

**Acceptance Criteria**
- `terraform apply` brings up full AWS bench in `eu-central-1`.
- Firewall runs in DPDK mode with `encap geneve` and healthy readiness.
- `make aws.policy-smoke` passes using shared harness.
- `make aws.run-tests` passes baseline DNS/HTTP/HTTPS + throughput sanity over GWLB path.
- `terraform destroy` fully tears down resources.

**Milestones**
1. Scaffold AWS Terraform with GWLB + GWLBE + single firewall ASG.
2. Bring up nodes and validate basic reachability + GWLB path steering.
3. Add firewall bootstrap for DPDK + GENEVE runtime.
4. Integrate AWS scripts and Make targets with shared smoke runner.
5. Stabilize and capture reproducible artifacts in CI-like local runs.

**Risks And Mitigations**
- DPDK driver/PMD mismatches on selected instance family:
- Mitigation: pin supported instance family list and assert at bootstrap with explicit fail-fast logs.
- GWLB health checks vs strict NIC split:
- Mitigation: use dataplane target IPs in target group registration; do not target mgmt IP.
- GENEVE TLV handling regressions:
- Mitigation: add explicit verification checks and metrics assertions in AWS run tests.
- Instance type availability in `eu-central-1`:
- Mitigation: default `c6in.large`, allow override in Terraform vars (`firewall_instance_type`, `consumer_instance_type`, `upstream_instance_type`).

**Resolved Defaults**
1. Default instance type: `c6in.large` (overrideable via Terraform vars).
2. Parity sizing: firewall/consumer/upstream all default to `c6in.large`.
3. Topology scope: single-AZ for Phase 1 (`eu-central-1a` by default).
