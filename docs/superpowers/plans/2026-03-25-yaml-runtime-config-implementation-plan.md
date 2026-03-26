# YAML Runtime Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Neuwerk's operator-facing env-var configuration model with one strict native YAML config file at `/etc/neuwerk/config.yaml`, remove the env-based startup path, and rewrite the operator docs around the YAML schema.

**Architecture:** Add a typed Rust config subsystem that loads, validates, and derives runtime settings from YAML, then thread focused config structs into startup, control-plane, dataplane, DPDK, and packaging. Remove shell bootstrap and launcher config translation, simplify the runtime CLI surface, and rewrite the canonical config reference page to document YAML paths and defaults instead of env vars.

**Tech Stack:** Rust, serde/serde_yaml, systemd packaging templates, shell packaging assets, existing inline Rust test modules, Markdown operator docs

---

### Task 1: Add The Config Module Skeleton And Strict YAML Loader

**Files:**
- Create: `src/runtime/config/mod.rs`
- Create: `src/runtime/config/schema.rs`
- Create: `src/runtime/config/load.rs`
- Create: `src/runtime/config/validate.rs`
- Create: `src/runtime/config/types.rs`
- Modify: `src/runtime/mod.rs`
- Test: `src/runtime/config/load.rs`
- Test: `src/runtime/config/validate.rs`

- [ ] **Step 1: Write the failing parsing and validation tests**

Add inline tests that prove:

- unknown YAML keys are rejected
- wrong scalar types are rejected
- `version` is required and must match `1`
- a minimal valid config fixture parses successfully

Suggested fixture pattern:

```rust
const MINIMAL_CONFIG: &str = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams:
    - 10.0.0.2:53
"#;

#[test]
fn load_config_rejects_unknown_fields() {
    let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
  mystery: true
dns:
  upstreams:
    - 10.0.0.2:53
"#;
    let err = load_config_str(raw).unwrap_err();
    assert!(err.contains("unknown field"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin neuwerk runtime::config::load`
Run: `cargo test --bin neuwerk runtime::config::validate`
Expected: FAIL because the `runtime::config` module and loader APIs do not exist yet.

- [ ] **Step 3: Add the typed schema and loader**

Implement:

- a root config struct with `#[serde(deny_unknown_fields)]`
- nested subsystem structs for bootstrap, dns, policy, http, metrics, integration, tls_intercept, dataplane, and dpdk
- `load_config(path: &Path) -> Result<LoadedConfig, String>`
- `load_config_str(raw: &str) -> Result<LoadedConfig, String>` for tests

Keep schema-facing types separate from runtime-facing types:

```rust
pub fn load_config_str(raw: &str) -> Result<LoadedConfig, String> {
    let parsed: RuntimeConfigFile =
        serde_yaml::from_str(raw).map_err(|err| format!("config parse error: {err}"))?;
    validate_config(parsed)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --bin neuwerk runtime::config::load`
Run: `cargo test --bin neuwerk runtime::config::validate`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/runtime/config src/runtime/mod.rs
git commit -m "feat: add strict yaml runtime config loader"
```

### Task 2: Define Semantic Validation And Derived Runtime Config

**Files:**
- Modify: `src/runtime/config/validate.rs`
- Create: `src/runtime/config/derived.rs`
- Modify: `src/runtime/config/types.rs`
- Modify: `src/runtime/config/mod.rs`
- Test: `src/runtime/config/validate.rs`
- Test: `src/runtime/config/derived.rs`

- [ ] **Step 1: Write the failing semantic validation tests**

Cover at least:

- static DPDK IP without prefix/gateway/MAC fails
- integration mode `aws-asg` without region/vpc/asg fails
- metrics public bind without allow flag fails
- static SNAT with DPDK dataplane fails

Suggested pattern:

```rust
#[test]
fn validate_rejects_partial_static_dpdk_addressing() {
    let err = load_config_str(r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams: [10.0.0.2:53]
dpdk:
  static_ip: 10.0.2.5
"#).unwrap_err();
    assert!(err.contains("static"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin neuwerk runtime::config::validate`
Run: `cargo test --bin neuwerk runtime::config::derived`
Expected: FAIL because semantic validation and derived config APIs are incomplete.

- [ ] **Step 3: Implement validation and derived config construction**

Add:

- a validated root config type
- cross-field validation helpers
- a derived runtime config type that computes resolved values needed later by startup

Suggested boundary:

```rust
pub struct DerivedRuntimeConfig {
    pub operator: ValidatedConfig,
    pub runtime: RuntimeSettings,
}

pub fn derive_runtime_config(cfg: ValidatedConfig) -> Result<DerivedRuntimeConfig, String> {
    // preserve unresolved machine/cloud-dependent values for later resolution
    Ok(DerivedRuntimeConfig { operator: cfg, runtime })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --bin neuwerk runtime::config::validate`
Run: `cargo test --bin neuwerk runtime::config::derived`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/runtime/config
git commit -m "feat: validate yaml config semantics"
```

### Task 3: Switch Main Startup To YAML Config Loading

**Files:**
- Modify: `src/main.rs`
- Modify: `src/runtime/mod.rs`
- Modify: `src/runtime/bootstrap/startup.rs`
- Modify: `src/runtime/bootstrap/network.rs`
- Modify: `src/runtime/bootstrap/integration.rs`
- Modify: `src/runtime/bootstrap/dataplane_config.rs`
- Modify: `src/runtime/bootstrap/dataplane_warmup.rs`
- Test: `src/main.rs`
- Test: `src/runtime/bootstrap/startup.rs`

- [ ] **Step 1: Write the failing startup tests**

Add focused tests that prove:

- runtime startup can load config from a YAML fixture path
- missing config file produces a startup error
- resolved binds use YAML values or derived defaults from management IP

Suggested helper shape:

```rust
fn parse_test_config(raw: &str) -> DerivedRuntimeConfig {
    derive_runtime_config(load_config_str(raw).unwrap()).unwrap()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin neuwerk runtime::bootstrap::startup`
Expected: FAIL because startup still depends on CLI/env-driven `CliConfig`.

- [ ] **Step 3: Replace the main runtime config entrypoint**

Implement:

- direct load of `/etc/neuwerk/config.yaml` in `main`
- replacement of `CliConfig`-centric startup flow with the derived YAML config model
- preservation of `auth` and `sysdump` subcommands as explicit CLI commands

Target shape:

```rust
let runtime_cfg = runtime::config::load_default_config()?;
let derived_cfg = runtime::config::derive_runtime_config(runtime_cfg)?;
run_runtime(derived_cfg).await?;
```

Keep `auth` and `sysdump` command dispatch ahead of config loading if they do not require appliance runtime config.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --bin neuwerk runtime::bootstrap::startup`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/runtime/mod.rs src/runtime/bootstrap
git commit -m "feat: load appliance runtime from yaml config"
```

### Task 4: Simplify The Runtime CLI Surface

**Files:**
- Modify: `src/runtime/cli/args.rs`
- Modify: `src/runtime/cli/types.rs`
- Modify: `src/runtime/cli/usage.rs`
- Modify: `src/runtime/cli/mod.rs`
- Test: `src/runtime/cli/args.rs`

- [ ] **Step 1: Write the failing CLI regression tests**

Add tests that prove:

- `auth` and `sysdump` flows still parse correctly
- the main runtime no longer accepts the old operator flag set
- help output reflects the new YAML-based startup contract

Suggested assertions:

```rust
#[test]
fn runtime_usage_points_to_config_yaml() {
    let text = usage("neuwerk");
    assert!(text.contains("/etc/neuwerk/config.yaml"));
    assert!(!text.contains("--management-interface"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin neuwerk runtime::cli`
Expected: FAIL because the old runtime CLI still exposes the flag-based appliance configuration surface.

- [ ] **Step 3: Remove the appliance-runtime CLI surface**

Refactor:

- keep only intentional non-runtime commands and helpers
- delete or reduce `CliConfig`
- remove usage text and parsing logic for the old main runtime flags

If a minimal direct-runtime CLI path remains, keep it explicitly unsupported for appliance/operator docs.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --bin neuwerk runtime::cli`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/runtime/cli
git commit -m "refactor: remove flag-based appliance runtime cli"
```

### Task 5: Thread Typed Config Into Control-Plane And Admission Paths

**Files:**
- Modify: `src/runtime/startup/controlplane_runtime.rs`
- Modify: `src/runtime/startup/controlplane_threads.rs`
- Modify: `src/controlplane/http_api.rs`
- Modify: `src/controlplane/trafficd.rs`
- Modify: `src/controlplane/trafficd/upstream_tls.rs`
- Modify: `src/dataplane/flow.rs`
- Modify: `src/dataplane/nat.rs`
- Modify: `src/dataplane/engine.rs`
- Test: `src/controlplane/http_api.rs`
- Test: `src/controlplane/trafficd.rs`
- Test: `src/dataplane/engine.rs`

- [ ] **Step 1: Write the failing subsystem-config tests**

Cover:

- metrics bind guardrail now reads typed config instead of env
- TLS intercept upstream verification reads typed config instead of env
- dataplane admission defaults and overrides come from typed config

Suggested pattern:

```rust
let cfg = TestRuntimeConfig::builder()
    .metrics_bind("0.0.0.0:8080")
    .allow_public_metrics_bind(false)
    .build();
assert!(validate_metrics_bind(&cfg).is_err());
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test controlplane::http_api --lib`
Run: `cargo test controlplane::trafficd --lib`
Run: `cargo test dataplane::engine --lib`
Expected: FAIL because the code still reads `std::env` directly.

- [ ] **Step 3: Replace env lookups with focused config structs**

Introduce subsystem config inputs such as:

```rust
pub struct MetricsConfig {
    pub bind: SocketAddr,
    pub allow_public_bind: bool,
}

pub struct TlsInterceptConfig {
    pub upstream_verify: UpstreamVerifyMode,
    pub io_timeout_secs: u64,
    pub h2: H2Config,
}
```

Pass these explicitly through startup instead of looking up env in place.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test controlplane::http_api --lib`
Run: `cargo test controlplane::trafficd --lib`
Run: `cargo test dataplane::engine --lib`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/runtime/startup src/controlplane src/dataplane/flow.rs src/dataplane/nat.rs src/dataplane/engine.rs
git commit -m "refactor: pass typed runtime config to controlplane and dataplane"
```

### Task 6: Thread Typed Config Into DPDK Runtime And Remove Env Reads

**Files:**
- Modify: `src/runtime/dpdk/run.rs`
- Modify: `src/runtime/dpdk/worker_plan.rs`
- Modify: `src/dataplane/dpdk_adapter.rs`
- Modify: `src/dataplane/dpdk_adapter/debug_flags.rs`
- Modify: `src/dataplane/dpdk_adapter/io.rs`
- Modify: `src/dataplane/dpdk_adapter/io/init_port.rs`
- Modify: `src/dataplane/dpdk_adapter/io/eal_port_select.rs`
- Modify: `src/dataplane/dpdk_adapter/service_lane.rs`
- Modify: `src/dataplane/dpdk_adapter/service_lane_runtime.rs`
- Test: `src/runtime/dpdk/worker_plan.rs`
- Test: `src/dataplane/dpdk_adapter/tests.rs`
- Test: `src/dataplane/dpdk_adapter/tests/intercept_overlay_cases.rs`

- [ ] **Step 1: Write the failing DPDK config tests**

Add tests that prove:

- worker selection is driven by typed config
- service lane defaults and overrides are driven by typed config
- overlay/GWLB compatibility flags are driven by typed config
- static DPDK trust pins and queue settings are driven by typed config

Suggested pattern:

```rust
let cfg = DpdkConfig {
    workers: WorkerCount::Explicit(4),
    single_queue_mode: DpdkSingleQueueMode::Demux,
    allow_azure_multiworker: false,
    ..Default::default()
};
let plan = choose_dpdk_worker_plan(&cfg, &caps);
assert_eq!(plan.worker_count, 1);
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin neuwerk runtime::dpdk`
Run: `cargo test dataplane::dpdk_adapter --lib`
Expected: FAIL because the DPDK path still depends on `std::env`.

- [ ] **Step 3: Refactor the DPDK runtime to accept typed config**

Create focused config structs for:

- worker planning
- EAL selection
- service lane
- platform compatibility and discovery
- gateway and DHCP trust pins
- overlay debug and compatibility flags

Remove in-place env lookups and env mutation from production code. Tests may still use builders or fixtures, but production code should no longer depend on `std::env`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --bin neuwerk runtime::dpdk`
Run: `cargo test dataplane::dpdk_adapter --lib`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/runtime/dpdk src/dataplane/dpdk_adapter*
git commit -m "refactor: remove env-based dpdk runtime configuration"
```

### Task 7: Replace Packaging And Appliance Startup Assets

**Files:**
- Modify: `packaging/runtime/neuwerk.service.in`
- Delete: `packaging/runtime/neuwerk-bootstrap.sh`
- Delete: `packaging/runtime/neuwerk-launch.sh`
- Delete: `packaging/runtime/appliance.env`
- Create: `packaging/runtime/config.yaml`
- Test: `packaging/runtime/neuwerk.service.in`
- Test: `packaging/runtime/config.yaml`

- [ ] **Step 1: Write the failing packaging assertions**

Add or script assertions that prove:

- service startup no longer uses `ExecStartPre=...neuwerk-bootstrap`
- service startup no longer uses `neuwerk-launch`
- packaged runtime assets include `config.yaml`

Suggested shell assertion:

```bash
test "$(grep -c 'neuwerk-bootstrap' packaging/runtime/neuwerk.service.in)" -eq 0
test "$(grep -c 'neuwerk-launch' packaging/runtime/neuwerk.service.in)" -eq 0
test -f packaging/runtime/config.yaml
```

- [ ] **Step 2: Run checks to verify they fail**

Run: `rg -n "neuwerk-bootstrap|neuwerk-launch|appliance.env" packaging/runtime`
Expected: output still shows the old env-based runtime path.

- [ ] **Step 3: Replace the packaged startup contract**

Update the service template to start the binary directly, for example:

```ini
[Service]
Type=simple
ExecStart=__RUNTIME_BINARY_DIR__/neuwerk
Restart=on-failure
```

Add a packaged `config.yaml` example with comments that match the new schema and remove the old env assets.

- [ ] **Step 4: Run checks to verify they pass**

Run: `rg -n "neuwerk-bootstrap|neuwerk-launch|appliance.env" packaging/runtime`
Expected: no matches for supported runtime packaging assets.

- [ ] **Step 5: Commit**

```bash
git add packaging/runtime
git commit -m "packaging: switch appliance runtime to yaml config"
```

### Task 8: Rewrite Operator Docs Around YAML Paths And Defaults

**Files:**
- Modify: `docs/operations/runtime-knobs.md`
- Modify: `docs/operations/appliance-image-usage.md`
- Modify: `docs/operations/image-build.md`
- Modify: `docs/operations/logging.md`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Test: `docs/operations/runtime-knobs.md`

- [ ] **Step 1: Write the failing doc consistency checks**

Add or run checks that prove:

- operator docs no longer instruct users to edit `appliance.env`
- the canonical config page documents YAML paths rather than env-var names for the supported surface

Suggested checks:

```bash
rg -n "/etc/neuwerk/appliance.env|NEUWERK_BOOTSTRAP_|NEUWERK_" docs/operations README.md AGENTS.md
```

Expected initial result: matches still exist in operator-facing docs.

- [ ] **Step 2: Rewrite the canonical config reference**

Convert `docs/operations/runtime-knobs.md` into the YAML config reference while preserving:

- grouped subsystem tables
- default column
- deeper note sections where context is needed

Rows should use YAML paths like:

- `bootstrap.cloud_provider`
- `metrics.allow_public_bind`
- `tls_intercept.upstream_verify`
- `dpdk.service_lane.intercept_service_ip`

- [ ] **Step 3: Update appliance and build docs**

Replace env-based operator instructions with `/etc/neuwerk/config.yaml` examples and update the AGENTS rule to make the YAML reference canonical.

- [ ] **Step 4: Run doc consistency checks**

Run: `rg -n "/etc/neuwerk/appliance.env|NEUWERK_BOOTSTRAP_|NEUWERK_" docs/operations README.md AGENTS.md`
Expected: only deliberate historical or internal references remain, not active operator instructions.

- [ ] **Step 5: Commit**

```bash
git add docs/operations README.md AGENTS.md
git commit -m "docs: rewrite operator config reference for yaml"
```

### Task 9: Remove Residual Production Env Reads And Verify End-To-End

**Files:**
- Modify: any remaining production files found by search
- Test: `src/**`
- Test: `packaging/runtime/**`
- Test: `docs/operations/**`

- [ ] **Step 1: Find remaining production env lookups**

Run:

```bash
rg -n 'std::env::var\\(|NEUWERK_[A-Z0-9_]+' src packaging/runtime | rg -v 'tests?'
```

Expected initial result: any leftover production env-based config paths still show up.

- [ ] **Step 2: Remove or justify each residual production lookup**

Allowed remaining env usage should be limited to:

- explicit non-runtime tooling
- test-only scaffolding
- intentionally retained process-level behavior not part of operator config

Everything else should move to typed YAML config inputs.

- [ ] **Step 3: Run full verification**

Run:

```bash
cargo test --lib
git diff --check
rg -n "/etc/neuwerk/appliance.env|/etc/neuwerk/neuwerk.env" .
rg -n 'std::env::var\\(|NEUWERK_[A-Z0-9_]+' src packaging/runtime | rg -v 'tests?'
```

Expected:

- tests pass
- no whitespace errors
- no active operator docs or packaging references to the env-based appliance path
- no unintended production env-driven config reads remain

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: complete yaml-only runtime configuration"
```
