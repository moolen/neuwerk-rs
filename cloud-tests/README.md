# Cloud Tests

Layout is provider-scoped but consistent:
- `cloud-tests/azure/terraform`: Terraform modules and root configs.
- `cloud-tests/azure/scripts`: Local orchestration scripts.
- `cloud-tests/aws/terraform`: AWS Terraform root configs (GWLB/GENEVE bench).
- `cloud-tests/aws/scripts`: AWS local orchestration scripts.
- `cloud-tests/common`: Shared helper scripts.
- `cloud-tests/common/run-throughput-matrix.sh`: Shared raw IP throughput matrix runner (cloud wrappers provide host discovery/context).
- `cloud-tests/common/http-perf-*.sh`: Shared HTTP/HTTPS/HTTPS+DPI setup/run/matrix scripts (provider wrappers pass cloud context).
- `cloud-tests/common/generate-scaling-recommendations.sh`: Median-based recommendation report generator for single-node and cluster tables.
- `cloud-tests/.secrets`: Local-only secrets (SSH keys, etc).
