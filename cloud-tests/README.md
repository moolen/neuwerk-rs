# Cloud Tests

Layout is provider-scoped but consistent:
- `cloud-tests/azure/terraform`: Terraform modules and root configs.
- `cloud-tests/azure/scripts`: Local orchestration scripts.
- `cloud-tests/common`: Shared helper scripts.
- `cloud-tests/.secrets`: Local-only secrets (SSH keys, etc).

Provider placeholders are present for AWS and GCP to keep layout consistent.
