# Neuwerk

Most cloud environments accidentally allow outbound traffic to the entire internet.

Not because teams are careless — but because modern infrastructure makes it hard to do the right thing. SaaS endpoints sit behind CDNs, IPs change constantly, and traditional firewalls still operate on static CIDR lists.

Meanwhile, policy is written in hostnames:
`api.stripe.com`, `*.github.com`, `s3.amazonaws.com`.

This project bridges that gap.

It turns DNS context into enforceable network policy by binding resolution events to packet filters implemented in a **high-performance DPDK dataplane**. The result is an egress firewall that understands **names, services, and intent**, not just IPs.

No proxies. No application changes. No vendor lock-in.

---

## Why This Exists

Most egress controls today fall into one of three categories:

- **IP-based firewalls** — incompatible with modern SaaS infrastructure
- **HTTP proxies** — operationally painful and incomplete
- **cloud-provider firewalls** — expensive and inconsistent across providers

The result is predictable: many environments quietly allow `0.0.0.0/0` on port 443.

This project provides a **programmable, DNS-aware enforcement layer** designed for modern infrastructure.

---

## Architecture

The system follows a strict **control-plane / data-plane separation**.

The **dataplane** is implemented with **DPDK**, allowing high-throughput packet inspection and filtering without relying on kernel networking stacks.

The **control plane** exposes an API that allows policy to be managed programmatically. Policies can be defined through infrastructure pipelines and automatically translated into runtime firewall rules.

This architecture provides:

* high throughput
* deterministic performance
* programmable policy management
* operational separation between enforcement and configuration

---

## Key Features

### DNS-aware policy enforcement

DNS responses are translated into short-lived IP sets and enforced in the DPDK dataplane.

### TLS metadata filtering

Policies can match TLS metadata such as **SNI and certificate attributes** without terminating TLS.

### Optional TLS deep packet inspection

For environments that require deeper inspection, encrypted flows can be analyzed while maintaining a transparent network path.

### Kubernetes integration

Designed to integrate with Kubernetes networking and container workloads while enforcing policy outside the node trust boundary.

### Infrastructure-as-Code control plane

Policy configuration integrates naturally with **Terraform and other IaC workflows**.

### Cloud and vendor agnostic

Runs anywhere Linux runs:

- AWS
- GCP
- Azure
- on-premises
- hybrid environments

No dependency on proprietary cloud firewall products.

---

## What This Is (and Isn't)

This is not another heavyweight NGFW appliance.

It’s a **programmable, API-driven egress firewall** designed for modern infrastructure:

- DNS-aware policy
- high-performance DPDK dataplane
- strict control-plane separation
- cloud-agnostic deployment

The goal is simple:

**make default-deny egress practical again.**

---

## Documentation

Start with the operator and deployment material in this repository:

- `docs/operations/` for appliance, runtime configuration reference, observability, backup, upgrade, and local demo workflows
- packaged appliance runtime configuration is documented around `/etc/neuwerk/config.yaml`
- `demo/vagrant/README.md` for the fastest local evaluation path
- `terraform-provider-neuwerk/README.md` for Terraform automation coverage
- `www/src/content/docs/` for the broader structured docs set that backs the project site

For API integrations, Neuwerk also exposes a generated OpenAPI document at runtime and ships a
static docs copy under `www/public/openapi/`.

To refresh or verify the checked-in static OpenAPI artifact, use:

- `make openapi.sync`
- `make openapi.check`

---

## License

Neuwerk is licensed under Apache License 2.0. See `LICENSE`.

---

## Local Benchmarking

For dataplane microbenchmarks, use the repo runner instead of ad hoc `cargo bench` commands:

```bash
make bench.dataplane
NEUWERK_BENCH_CORE=2 NEUWERK_BENCH_SAVE_BASELINE=before make bench.dataplane
NEUWERK_BENCH_CORE=2 NEUWERK_BENCH_COMPARE_BASELINE=before make bench.dataplane
```

The runner lives at `scripts/bench-dataplane.sh` and standardizes sample size, warm-up time, optional CPU affinity, optional nice level, and log capture under `target/criterion-runs/`.

For the feature-gated Rust surface, use:

```bash
make test.all-features
```

## Project Status

- Release readiness: `docs/operations/release-readiness.md`
- Security contact: `security@neuwerk.io`
