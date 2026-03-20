# Cloud Tests

Cloud testing is split into two top-level scenarios:

- `policy-smoke`: cloud-agnostic functional verification of neuwerk behavior.
- `performance.scenario`: cloud-agnostic performance verification for both `consumer -> upstream` and `consumer -> neuwerk -> upstream`.

The performance scenario consolidates the existing benchmark families into one orchestrated run:

- Throughput: TCP and UDP link-saturation checks.
- CPS: completed-connection sweep using the Rust TCP client by default.
- NAT: connection-scale / churn exercise.
- TLS/DPI: HTTPS and TLS-intercept performance via the shared HTTP perf harness.

The lower-level matrix runners remain available as diagnostic building blocks, but they are no longer the primary documented workflow:

- `run-throughput-matrix.sh`
- `run-pps-matrix.sh`
- `run-cps-matrix.sh`
- `run-connscale-matrix.sh`
- `http-perf-*.sh`

TRex is no longer a supported cloud-test dependency. The supported CPS backends are the shared Python opener and the Rust TCP client, with `rust_tcp` as the default.

Layout is provider-scoped but consistent:

- `cloud-tests/azure/terraform`: Azure Terraform root configs and modules.
- `cloud-tests/azure/scripts`: Azure orchestration wrappers.
- `cloud-tests/aws/terraform`: AWS Terraform root configs.
- `cloud-tests/aws/scripts`: AWS orchestration wrappers.
- `cloud-tests/gcp/terraform`: GCP Terraform root configs.
- `cloud-tests/gcp/scripts`: GCP orchestration wrappers.
- `cloud-tests/common`: Shared scenario runners and helper scripts.
- `cloud-tests/common/run-performance-scenario.sh`: Shared cloud-agnostic performance scenario orchestrator.
- `cloud-tests/common/generate-scaling-recommendations.sh`: Post-processing helper for recommendation tables.
- `cloud-tests/.secrets`: Local-only SSH keys and related credentials.
