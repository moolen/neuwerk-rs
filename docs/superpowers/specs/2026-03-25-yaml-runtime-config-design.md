# YAML Runtime Configuration Design

## Summary

Neuwerk currently exposes operator configuration through a large set of environment variables spread across three layers:

- appliance bootstrap shell scripts
- a launcher that translates env vars into CLI flags
- Rust subsystems that read `std::env` directly for advanced behavior

This design replaces that model with one strict, canonical YAML configuration file at `/etc/neuwerk/config.yaml`.

The YAML file becomes the only supported operator-facing configuration interface.

Key decisions:

- one canonical config file: `/etc/neuwerk/config.yaml`
- YAML is the primary and only supported operator interface
- no env-var compatibility layer for operators
- no migration release; this is an intentional breaking change
- strict parsing and strict validation; unknown keys fail startup
- the implementation is native end to end rather than YAML translated back into env vars

## Goals

- Replace the operator-facing env-var surface with a coherent YAML configuration model
- Make Neuwerk startup read configuration natively in Rust from `/etc/neuwerk/config.yaml`
- Eliminate generated operator config artifacts such as `/etc/neuwerk/neuwerk.env`
- Remove shell-based env-to-CLI translation as the appliance startup path
- Represent the full supported operator settings surface, including advanced DPDK and TLS tuning, in the YAML schema
- Centralize defaults, validation, and derived runtime settings in typed Rust code
- Rewrite the new runtime knob documentation page into the canonical YAML config reference

## Non-Goals

- Preserve backwards compatibility with `appliance.env`, `neuwerk.env`, or supported `NEUWERK_*` operator knobs
- Ship an automatic config migration tool in the first version
- Keep environment variables as an officially supported emergency override channel
- Redesign Neuwerk policy format or control-plane APIs
- Change dataplane or control-plane behavior beyond the configuration surface and startup plumbing needed for the rewrite

## Breaking Change Contract

This is a deliberate configuration-surface break.

After this design is implemented:

- published appliance images should ship `/etc/neuwerk/config.yaml`
- `appliance.env` and `neuwerk.env` should no longer be part of the supported operator workflow
- operator-facing `NEUWERK_*` runtime variables should no longer be documented as the supported interface
- systemd should launch Neuwerk directly rather than through an env translation wrapper

Internal derived runtime state may still exist, but it should not be represented as a supported persistent operator config file.

## Operator Experience

### Canonical File

Operators manage one file:

- `/etc/neuwerk/config.yaml`

That file contains both:

- declarative operator intent
- advanced subsystem tuning when explicitly needed

There should not be a second supported file for bootstrap-only settings versus runtime-only settings. The split between bootstrap and runtime remains an implementation concern, not an operator concern.

### Strictness

Config loading is strict by default.

Required behavior:

- unknown YAML keys fail startup
- wrong types fail startup
- invalid enum values fail startup
- semantically invalid field combinations fail startup

Examples of semantic failures:

- static DPDK IP configured without prefix, gateway, or MAC
- cloud integration mode selected without its required provider fields
- invalid listener bind and exposure combinations
- unsupported SNAT combinations for the selected dataplane mode

This is intentionally not a forward-compatible “ignore unknown keys” model. The operator should learn immediately that the file does not match the binary they are running.

## Config Shape

The YAML should be organized by subsystem rather than by legacy env-var names.

Illustrative shape:

```yaml
version: 1

bootstrap:
  cloud_provider: aws
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
  data_plane_selector: mac:aa:bb:cc:dd:ee:ff

dns:
  target_ips:
    - 10.0.1.4
  upstreams:
    - 10.0.0.2:53
    - 10.0.0.3:53

policy:
  default: deny
  internal_cidr: 10.0.0.0/16

http:
  bind: 10.0.1.4:8443
  advertise: 10.0.1.4:8443
  external_url: https://fw.example.com

metrics:
  bind: 10.0.1.4:8080
  allow_public_bind: false

integration:
  mode: aws-asg
  route_name: neuwerk-default
  cluster_name: neuwerk
  aws:
    region: eu-central-1
    vpc_id: vpc-0123456789abcdef0
    asg_name: neuwerk-asg

tls_intercept:
  upstream_verify: strict
  io_timeout_secs: 3
  h2:
    body_timeout_secs: 10
    max_concurrent_streams: 64

dataplane:
  flow_table_capacity: 32768
  nat_table_capacity: 32768

dpdk:
  workers: auto
  rx_ring_size: 1024
  tx_ring_size: 1024
  service_lane:
    interface: svc0
    intercept_service_ip: 169.254.255.1
    intercept_service_port: 15443
```

Design rules for the schema:

- `version` is mandatory from day one
- cloud-specific integration settings live in nested provider blocks, not as flat global keys
- advanced settings remain first-class and typed; they are not hidden in an untyped `advanced` map
- field names should be normalized for product clarity instead of mechanically mirroring existing env names
- the schema should remain readable even though it covers the full supported settings surface

## Architecture

### High-Level Flow

Neuwerk startup becomes:

1. systemd starts `neuwerk` directly
2. Neuwerk loads `/etc/neuwerk/config.yaml`
3. YAML parsing runs with strict schema rules
4. semantic validation runs on the parsed config
5. derived runtime state is computed in Rust from validated config plus runtime discovery
6. typed subsystem config is passed into dataplane, control-plane, DPDK, and TLS components
7. Neuwerk starts with no operator-facing env translation path

### Config Layers

The implementation should distinguish three concepts:

#### 1. Schema Config

The operator-facing YAML model as parsed from disk.

Responsibilities:

- serde decode
- field-level defaults where appropriate
- strict unknown-field rejection

#### 2. Validated Config

The schema config after cross-field validation.

Responsibilities:

- reject invalid combinations
- enforce required fields based on mode selection
- normalize values that need semantic interpretation

#### 3. Derived Runtime Config

The internal config used to boot subsystems.

Responsibilities:

- attach machine/cloud-derived values
- compute resolved bind addresses and dataplane selectors
- provide typed subsystem views without further env lookups

This preserves the useful concept of bootstrap-derived state without exposing bootstrap plumbing as the operator interface.

## Component Boundaries

Recommended new Rust modules:

- `src/runtime/config/schema.rs`
- `src/runtime/config/validate.rs`
- `src/runtime/config/load.rs`
- `src/runtime/config/derived.rs`
- `src/runtime/config/types.rs`
- `src/runtime/config/mod.rs`

Responsibilities:

- `schema.rs`: serde-facing YAML schema types
- `validate.rs`: semantic validation and cross-field checks
- `load.rs`: file IO, parse, validation, and error shaping
- `derived.rs`: runtime discovery and derived config construction
- `types.rs`: internal config structs passed to runtime subsystems

### Existing Runtime Boundaries That Need Refactoring

Current config sources are fragmented across:

- `src/runtime/cli/*`
- `src/main.rs`
- `src/runtime/bootstrap/*`
- `src/runtime/dpdk/*`
- `src/runtime/startup/*`
- `src/controlplane/trafficd*`
- `src/controlplane/http_api.rs`
- `src/dataplane/*` DPDK helpers and debug flag paths
- `packaging/runtime/neuwerk-bootstrap.sh`
- `packaging/runtime/neuwerk-launch.sh`

These need to converge on typed config instead of:

- CLI parsing for appliance runtime settings
- `std::env::var(...)` lookups scattered throughout runtime code
- shell scripts that rewrite runtime config into env files

### CLI Surface After The Rewrite

The CLI should remain for explicit commands such as:

- `neuwerk auth ...`
- `neuwerk sysdump ...`

The main runtime path should not require the current large CLI configuration surface for appliance boot.

That implies significant simplification of:

- `src/runtime/cli/args.rs`
- `src/runtime/cli/types.rs`
- `src/runtime/cli/usage.rs`

The implementation can preserve narrowly scoped runtime CLI flags if they are intentionally retained as direct invocation tools, but the supported appliance/operator surface should be YAML only.

## Startup And Packaging Changes

### Remove Shell Config Translation

The current appliance startup path:

- sources `appliance.env`
- derives `neuwerk.env`
- sources `neuwerk.env`
- translates env into CLI flags

should be removed as the supported path.

Target end state:

- systemd starts the binary directly
- the binary knows the default config path `/etc/neuwerk/config.yaml`
- packaging ships an example or default `config.yaml`
- any runtime discovery needed for cloud/bootstrap behavior happens inside Rust

### Packaging Files Expected To Change

Likely touched or removed:

- `packaging/runtime/neuwerk-bootstrap.sh`
- `packaging/runtime/neuwerk-launch.sh`
- `packaging/runtime/appliance.env`
- appliance systemd unit and related packaging templates

Likely added:

- a packaged `/etc/neuwerk/config.yaml`
- maybe a packaged commented example config or schema example in docs/assets

### Derived Runtime State

Derived state still exists, but it becomes internal and ephemeral.

Examples:

- detected cloud provider when configured as auto
- resolved dataplane selector based on machine/cloud facts
- management IP used to derive default listener addresses

This state should live in typed Rust objects and logs, not in a generated supported operator file.

## Subsystem Refactoring Requirements

### DPDK And Advanced Runtime Knobs

DPDK currently consumes many settings via `std::env::var(...)`.

That pattern should be removed in favor of typed config structs passed to:

- worker planning
- EAL selection and initialization
- service lane configuration
- queue/ring sizing
- platform compatibility flags
- gateway and DHCP trust pins
- overlay and GWLB compatibility

The same refactoring principle applies to:

- TLS intercept tuning
- metrics bind guardrails
- control-plane runtime thread settings
- dataplane admission and table sizing

### Avoid A Global Config Registry

Do not replace env lookups with a global “config singleton”.

Preferred pattern:

- load once at startup
- validate once
- pass focused config structs into the components that need them

This keeps config ownership explicit and testable.

## Documentation Changes

The newly added operator config page should remain canonical, but it should stop being an env-var catalog.

Target doc behavior:

- `docs/operations/runtime-knobs.md` becomes the canonical YAML config reference
- the top-of-page quick-reference table remains
- entries are grouped by subsystem
- each row references a YAML path rather than an env-var name
- the table keeps a default column and deeper links where extra guidance is needed

Other docs that must change:

- `docs/operations/appliance-image-usage.md`
- `docs/operations/image-build.md`
- any other operator docs that currently point users at `/etc/neuwerk/appliance.env`
- `AGENTS.md` guidance so config schema/default changes update the canonical YAML config reference

The design should preserve the documentation maintenance discipline introduced by the runtime-knobs work while changing the user-facing surface from env vars to YAML.

## Testing

### Config Parsing Tests

Add tests for:

- strict rejection of unknown keys
- strict rejection of wrong types
- enum parsing errors
- version field enforcement
- fixture loading of realistic configs

### Semantic Validation Tests

Add tests for:

- required cloud provider fields by integration mode
- all-or-nothing static DPDK addressing
- unsupported SNAT and dataplane combinations
- metrics/public bind guardrails
- invalid conflicting overlay settings

### Startup Tests

Add tests for:

- startup with a valid YAML config
- startup failure when required config is missing
- resolved bind behavior from YAML plus runtime discovery
- packaging/systemd path assumptions pointing at `/etc/neuwerk/config.yaml`

### Regression Tests

Existing behavior-sensitive tests should continue to cover:

- DPDK worker planning
- service lane behavior
- TLS intercept defaults
- dataplane admission caps
- cloud integration bootstrap behavior

Where those tests currently depend on env mutation, they should move toward typed config setup.

## Implementation Risks

- The current runtime has many hidden config reads; missing even one will leave a partially migrated system
- DPDK startup and platform-compatibility flags are numerous and easy to regress if typed config boundaries are not carefully designed
- A naive schema can become a direct copy of env names rather than a coherent product surface
- Removing shell bootstrap too early without replacing all derived-state behavior in Rust can break appliance boot on cloud platforms
- Documentation can drift if the YAML schema and canonical operator reference are not updated together

## Recommendation

Implement a first-class typed runtime configuration system in Rust centered on `/etc/neuwerk/config.yaml`, and delete the operator-facing env-based appliance path rather than wrapping it.

That means:

- no env compatibility layer for operators
- no shell translation path as the primary runtime flow
- typed config passed directly into runtime subsystems
- the canonical operator documentation rewritten around YAML paths and defaults

This is a larger refactor than adding a YAML front-end on top of env vars, but it is the only approach that matches the desired product boundary cleanly and prevents Neuwerk from carrying two competing operator configuration models indefinitely.
