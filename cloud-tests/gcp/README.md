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
7. `cd terraform && terraform destroy`

## Notes
- Default project/region/zone are set in `terraform/variables.tf` and can be overridden via `-var`.
- Firewall VMs use gVNIC NIC type and bootstrap DPDK dataplane selection from the dataplane NIC PCI/MAC (targeting GCP gVNIC/net_gve PMD path).
- Firewall cloud-init installs hugepages/IOMMU settings and reboots once during first bootstrap.
- Policy management API checks use `https://<fw-mgmt-ip>:8443/{health,ready}` through the jumpbox.
- GCP does not allow overriding subnet-local routes with VPC static routes; steering is applied with per-host guest routes on consumer/upstream VMs that point to subnet-local dataplane ILB VIPs.
