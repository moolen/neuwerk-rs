# Cloud Tests

Layout is provider-scoped but consistent:
- `cloud-tests/azure/terraform`: Terraform modules and root configs.
- `cloud-tests/azure/scripts`: Local orchestration scripts.
- `cloud-tests/aws/terraform`: AWS Terraform root configs (GWLB/GENEVE bench).
- `cloud-tests/aws/scripts`: AWS local orchestration scripts.
- `cloud-tests/common`: Shared helper scripts.
- `cloud-tests/.secrets`: Local-only secrets (SSH keys, etc).
