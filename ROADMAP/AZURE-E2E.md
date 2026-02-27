**Goal**
Design and deploy an Azure test bench (via Terraform) that exercises firewall dataplane, control-plane policy, DNS forwarding, and VMSS lifecycle handling with both long-lived and short-lived traffic. Include a throughput benchmark with a 900 MiB/s minimum from consumers to upstream using multi-stream `iperf3`.

**Scope**
1. Region: Germany West Central, single-zone.
2. All resources created from scratch by Terraform.
3. Ubuntu 24.04 LTS for all VMs.
4. Firewall VMSS uses cloud-init on Ubuntu, pulls the firewall binary from private Azure Blob Storage using a managed identity.
5. Firewall runs in DPDK mode only, with VFIO binding and hugepages.
6. VMSS mode: Flexible, with termination notifications enabled.
7. Upstream VM runs HTTP, HTTPS (self-signed cert), DNS, and `iperf3` server.
8. Consumers are Ubuntu VMs; tests orchestrated from a local machine via SSH/CLI.
9. DPDK packages come from Ubuntu APT, which provides DPDK 23.11 LTS on Ubuntu 24.04 (accepted).

**Architecture**
1. VNet with 5 subnets.
2. `mgmt-subnet` for firewall `mgmt0` NICs.
3. `dataplane-subnet` for firewall `data0` NICs.
4. `consumer-subnet` for test clients.
5. `upstream-subnet` for upstream services VM.
6. `jumpbox-subnet` for a single SSH jumpbox with a public IP.
7. **Azure GWLB chain** for egress inspection:
   1. Gateway Load Balancer (GWLB) fronting the firewall VMSS as a backend pool.
   2. Internal Standard Load Balancer (ILB) chained to GWLB for **internal upstream** traffic.
   3. Standard Load Balancer outbound rule chained to GWLB for **internet egress** traffic.
8. Firewall VMSS with two NICs tagged `neuwerk.io/management` and `neuwerk.io/dataplane`.
9. Upstream VM uses a private DNS resolver that forwards to Azure DNS (168.63.129.16) plus custom zone for upstream hostname.

**Example Egress Path (Internal Upstream)**
1. Consumer resolves `upstream.test` to the **ILB VIP** (not the upstream VM IP).
2. Consumer sends traffic to ILB VIP.
3. ILB forwards to GWLB (chained frontend).
4. GWLB encapsulates in VXLAN and sends to firewall VMSS.
5. Firewall decapsulates, applies policy to inner packet, re‑encapsulates, sends back to GWLB.
6. GWLB forwards to ILB backend pool (upstream VM).
7. Return traffic follows the same chain back to consumer.

**Example Egress Path (Internet)**
1. Consumer sends traffic to any internet destination (for example `https://example.com`).
2. Subnet outbound uses a **Standard LB outbound rule** chained to GWLB.
3. GWLB encapsulates in VXLAN and sends to firewall VMSS.
4. Firewall decapsulates, applies policy to inner packet, re‑encapsulates, sends back to GWLB.
5. GWLB returns traffic to the outbound rule, which SNATs to public IP and sends to the internet.

**Terraform Layout**
1. `modules/network`:
   1. VNet, subnets, NSGs, route tables, and route associations.
2. `modules/storage`:
   1. Storage account + private container for firewall binaries.
   2. Role assignment for VMSS identity: `Storage Blob Data Reader`.
3. `modules/firewall_vmss`:
   1. Flexible VMSS with 2 NICs, IP forwarding on dataplane NIC, accelerated networking enabled.
   2. Termination notifications enabled (`terminateNotificationProfile.enable = true`).
   3. System-assigned identity for blob access.
   4. Cloud-init to install DPDK, configure hugepages and VFIO, bind the dataplane NIC, and run firewall with systemd.
4. `modules/upstream_vm`:
   1. Single Ubuntu VM with cloud-init that installs nginx, bind/unbound, iperf3, and generates self-signed TLS cert.
5. `modules/consumer_vms`:
   1. Ubuntu VMs with tools: curl, dig, iperf3, and wrk.
6. `modules/jumpbox`:
   1. Ubuntu VM with a public IP for SSH ProxyJump.
7. `modules/gwlb_chain`:
   1. GWLB with **tunnel interfaces** (VXLAN VNI/port).
   2. Internal Standard LB (ILB) chained to GWLB for upstream VIP.
   3. Standard LB outbound rule chained to GWLB for internet egress.
8. Root module wires outputs to a local test harness.

**Networking Plan**
1. Address plan (example, adjustable via variables):
   1. VNet `10.20.0.0/16`.
   2. `mgmt-subnet` `10.20.1.0/24`.
   3. `dataplane-subnet` `10.20.2.0/24`.
   4. `consumer-subnet` `10.20.3.0/24`.
   5. `upstream-subnet` `10.20.4.0/24`.
   6. `jumpbox-subnet` `10.20.5.0/24`.
2. UDRs:
   1. Keep UDRs minimal; Azure GWLB **does not** support UDRs that point to GWLB directly.
   2. Use GWLB chaining via Standard LB for both internal and outbound traffic instead of UDR steering.
3. Public internet access:
   1. Standard outbound via Azure default routes and SNAT.
   2. NSGs open for testing (not hardened yet).

**Firewall VMSS Bootstrap (Cloud-Init)**
1. Install packages: `dpdk`, `dpdk-dev`, `pciutils`, `linux-modules-extra`, `numactl`, `jq`, `unzip`.
2. Configure IOMMU and VFIO:
   1. Append `intel_iommu=on iommu=pt` or `amd_iommu=on iommu=pt` to GRUB.
   2. Load `vfio`, `vfio-pci`, `vfio_iommu_type1`.
3. Configure hugepages:
   1. Conservative default: 2048 x 2 MiB pages (4 GiB).
   2. Persist via `/etc/sysctl.d/` and GRUB, reboot once after setup.
4. Resolve NICs by Azure tags and map to Linux devices:
   1. Use managed identity to call ARM and list NICs attached to this VMSS instance.
   2. Identify the NICs tagged `neuwerk.io/management` and `neuwerk.io/dataplane`.
   3. Map NIC MAC to Linux interface name using IMDS network metadata.
   4. Record dataplane interface and its PCI address before binding.
5. Bind dataplane NIC to `vfio-pci` using `dpdk-devbind.py`.
6. Download firewall binary from blob storage using managed identity and `azcopy` or `azure-cli`.
7. Place binary under `/usr/local/bin/firewall`, set executable.
8. Create systemd unit:
   1. Flags:
      1. `--management-interface <mgmt-iface>`.
      2. `--data-plane-interface <data-iface-or-pci>`.
      3. `--data-plane-mode dpdk`.
      4. `--encap vxlan`.
      5. `--encap-vni <vni>`.
      6. `--encap-udp-port <port>`.
      7. `--dns-upstream <upstream-dns-ip:53>`.
      8. `--dns-listen <mgmt-ip:53>` or `0.0.0.0:53` on mgmt.
      9. `--http-bind <mgmt-ip:8443>`.
      10. `--metrics-bind <mgmt-ip:8080>`.
      11. `--default-policy allow` for initial non-blocking mode.
      12. `--snat none` (Azure GWLB requires re‑encap, not SNAT).
   2. Enable logging to journald.
9. Configure DHCP for dataplane NIC (mandatory in DPDK mode).
10. Ensure the firewall binary was built with `--features dpdk` and links against the installed DPDK shared libraries.
11. Recommendation: pass the PCI address for the dataplane NIC once it is bound to `vfio-pci`, and extend the firewall CLI/DPDK adapter to accept PCI IDs directly (avoids relying on a netdev name that disappears after binding).

**Upstream VM Bootstrap**
1. DNS:
   1. Run `unbound` or `bind` as a local DNS server.
   2. Forward to `168.63.129.16`.
   3. Add a local zone, for example `upstream.test.` with A records to the upstream VM.
2. HTTP/HTTPS:
   1. Install `nginx` with HTTP on 80 and HTTPS on 443.
   2. Generate self-signed cert for `upstream.test`.
3. Long-lived TCP service on 9000 using `socat` (simple, observable).
4. `iperf3` server on 5201 (and optional 5202).
5. Upstream VM sits behind an **internal Standard LB** (ILB) frontend; consumers target the ILB VIP so traffic is forced through GWLB.

**Consumer VM Bootstrap**
1. Install tools: `curl`, `dig`, `iperf3`, and `wrk`.
2. Optional: deploy a small agent that keeps long-lived connections open.

**Test Harness (Local)**
1. Terraform outputs:
   1. Firewall VMSS instance IPs (mgmt + dataplane).
   2. Upstream VM private IP.
   3. Consumer VM IPs.
   4. Jumpbox public IP.
   5. ILB VIP and GWLB tunnel params (VNI/port).
2. Local scripts:
   1. `scripts/azure-e2e/bootstrap.sh` to wait for VM readiness, SSH connectivity, and firewall health.
   2. `scripts/azure-e2e/configure-policy.sh` to push policies via `POST /api/v1/policies`.
   3. `scripts/azure-e2e/run-tests.sh` to execute traffic tests in parallel.
3. Readiness gating:
   1. Wait for `/ready` on each firewall VM before assigning traffic.
4. SSH usage:
   1. Use `ProxyJump` via the jumpbox to reach all private VMs.

**Traffic Tests**
1. DNS:
   1. `dig @<firewall-mgmt-ip> upstream.test`.
   2. Validate upstream DNS forwarding works.
2. HTTP:
   1. Short-lived `curl` loops to `http://upstream.test` (resolves to ILB VIP).
   2. Validate allow/deny policy changes.
3. HTTPS:
   1. `curl -k https://upstream.test` (resolves to ILB VIP).
   2. Validate TLS allow/deny when policy changes.
4. Long-lived connections:
   1. `socat - TCP:<upstream-ip>:9000` or `nc <upstream-ip> 9000` to keep sockets open for 10+ minutes.
   2. Keep these open across VMSS redeploy.
5. Short-lived connections:
   1. Repeated `curl` or `hey`/`wrk` bursts to verify new instance handles new flows post-cutover.

**Lifecycle (VMSS Redeploy) Tests**
1. Enable VMSS termination notifications and scheduled events in deployment.
2. Test flow:
   1. Start with 3 firewall instances.
   2. Start long-lived connections from consumers.
   3. Scale out to 6 instances (`az vmss scale --new-capacity 6`).
   4. Wait for `/ready` on the new instances.
   5. Verify short-lived traffic begins using new instances.
   6. Delete old instances by instance ID to trigger termination events and draining.
   7. Verify old connections remain until drain timeout (5 minutes) or completion.
   8. Verify routes update only when readiness checks pass.
3. Capture evidence:
   1. Firewall logs for drain start and completion.
   2. Route table changes (Terraform or `az network route-table route list`).
   3. Connection persistence stats on consumer and upstream.

**Benchmark**
1. `iperf3` multi-stream from consumer to upstream via firewall.
2. Targets:
   1. Minimum 900 MiB/s observed on consumer.
   2. Upstream VM size chosen to allow > 3 GiB/s.
3. Measure:
   1. CPU saturation on firewall and upstream.
   2. Packet drops or retransmits.
4. Record results in a local log and attach to the test run summary.
5. Use `wrk` to generate HTTP load in parallel with `iperf3` for latency sampling.

**Terraform Variables (Defaults to Decide)**
1. VM sizes:
   1. Firewall VMSS size (start with `Standard_D8s_v5`, downsize if throughput allows).
   2. Upstream VM size (start with `Standard_D16s_v5`).
   3. Consumer VM size (start with `Standard_D8s_v5`).
   4. Jumpbox size (start with `Standard_B2s`).
2. Instance counts:
   1. Firewall: 3 instances (initial).
   2. Consumers: 3 instances.
   3. Upstream: 1 instance.
   4. Jumpbox: 1 instance.
3. Resource names, tags, and SSH key inputs.
4. DNS zone name (example `upstream.test`).
5. DPDK hugepages count (default 2048 x 2 MiB).
6. DPDK version (Ubuntu package default on 24.04 is 23.11 LTS).
7. Data-plane interface identifier strategy: `netdev` or `pci` (recommended: `pci`).
8. GWLB tunnel settings:
   1. VXLAN VNI and UDP port (configurable; vendor defaults are VNI 800/801, port 2000/2001).

**Implementation Phases**
1. Phase 1: Network and base VMs.
2. Phase 2: Firewall VMSS + blob binary delivery.
3. Phase 3: Route tables + readiness gating.
4. Phase 4: Test harness scripts for traffic and lifecycle.
5. Phase 5: Benchmark + reporting outputs.

**Cost Estimate (Rough, Linux Pay-as-You-Go)**
1. `Standard_D4s_v5` is about $0.19/hr.
2. `Standard_D8s_v5` is about $0.38/hr.
3. `Standard_D16s_v5` is about $0.77/hr.
4. Monthly estimate at 730 hours:
   1. D4s_v5: ~$140/month.
   2. D8s_v5: ~$280/month.
   3. D16s_v5: ~$560/month.
5. Example steady-state cost (3x D8s_v5 consumers + 3x D8s_v5 firewall + 1x D16s_v5 upstream + 1x B2s jumpbox) is roughly $2,300 to $2,600/month before storage and bandwidth.

**Validation Checklist**
1. Terraform apply completes with no manual steps.
2. Firewall VMSS instances boot, register, and expose `/ready`.
3. DNS queries via firewall resolve upstream hostnames.
4. HTTP/HTTPS traffic through firewall follows policy.
5. VMSS redeploy triggers termination notice and drain.
6. Long-lived connections survive drain window or timeout.
7. Short-lived connections shift to new instance after readiness.
8. `iperf3` meets 900 MiB/s target on consumer.

**Open Decisions**
1. Confirm whether to implement PCI-address support for `--data-plane-interface` (recommended).
2. Final VM sizes once performance is observed.
