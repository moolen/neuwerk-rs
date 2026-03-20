use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use neuwerk::controlplane::api_auth;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa};
use serde_json::Value;
use tempfile::TempDir;

const PROVIDER_VERSION: &str = "0.0.0";

fn next_addr(ip: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("timed out waiting for {}", path.display()))
}

fn http_client(tls_dir: &Path) -> Result<reqwest::Client, String> {
    let ca_pem =
        fs::read(tls_dir.join("ca.crt")).map_err(|err| format!("read ca cert failed: {err}"))?;
    let ca = reqwest::Certificate::from_pem(&ca_pem)
        .map_err(|err| format!("parse ca cert failed: {err}"))?;
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|err| format!("build client failed: {err}"))
}

async fn wait_for_ready(
    client: &reqwest::Client,
    addr: SocketAddr,
    expected: bool,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(format!("https://{addr}/ready")).send().await {
            let status_ok = resp.status().is_success();
            if let Ok(body) = resp.json::<Value>().await {
                let ready = body.get("ready").and_then(|value| value.as_bool());
                if ready == Some(expected) && status_ok == expected {
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("timed out waiting for ready={expected} at {addr}"))
}

async fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait().map_err(|err| err.to_string())?.is_some() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("timed out waiting for neuwerk exit".to_string())
}

fn cleanup_interface(name: &str) {
    let _ = Command::new("ip")
        .args(["link", "delete", "dev", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn create_tun_interface(name: &str, cidr: &str) -> Result<(), String> {
    cleanup_interface(name);
    let output = Command::new("ip")
        .args(["tuntap", "add", "dev", name, "mode", "tun"])
        .output()
        .map_err(|err| format!("create tuntap {name} failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "create tuntap {name} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let output = Command::new("ip")
        .args(["addr", "add", cidr, "dev", name])
        .output()
        .map_err(|err| format!("assign addr {cidr} to {name} failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "assign addr {cidr} to {name} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let output = Command::new("ip")
        .args(["link", "set", "dev", name, "up"])
        .output()
        .map_err(|err| format!("set link {name} up failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "set link {name} up exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn cleanup_service_lane_state() {
    cleanup_interface("svc0");
    for pref in ["10940", "10941", "10942"] {
        let _ = Command::new("ip")
            .args(["-4", "rule", "del", "pref", pref])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    for table in ["190", "191"] {
        let _ = Command::new("ip")
            .args(["-4", "route", "flush", "table", table])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct NetworkCleanup {
    dataplane_iface: String,
}

impl Drop for NetworkCleanup {
    fn drop(&mut self) {
        cleanup_interface(&self.dataplane_iface);
        cleanup_service_lane_state();
    }
}

fn spawn_neuwerk(
    tls_dir: &Path,
    local_root: &Path,
    http_bind: SocketAddr,
    metrics_bind: SocketAddr,
    dataplane_iface: &str,
) -> Result<Child, String> {
    Command::new(env!("CARGO_BIN_EXE_neuwerk"))
        .args([
            "--management-interface",
            "lo",
            "--data-plane-interface",
            dataplane_iface,
            "--dns-target-ip",
            "1.1.1.1",
            "--dns-upstream",
            "1.1.1.1:53",
            "--data-plane-mode",
            "tun",
            "--internal-cidr",
            "10.0.0.0/24",
            "--snat",
            "none",
            "--http-bind",
            &http_bind.to_string(),
            "--http-advertise",
            &http_bind.to_string(),
            "--http-external-url",
            &format!("https://{http_bind}"),
            "--http-tls-dir",
            tls_dir
                .to_str()
                .ok_or_else(|| "tls dir not utf8".to_string())?,
            "--metrics-bind",
            &metrics_bind.to_string(),
        ])
        .env("NEUWERK_LOCAL_DATA_DIR", local_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("spawn neuwerk failed: {err}"))
}

struct NeuwerkHarness {
    _dir: TempDir,
    _network_cleanup: NetworkCleanup,
    child: Child,
    tls_dir: PathBuf,
    http_bind: SocketAddr,
    client: reqwest::Client,
    token: String,
}

impl NeuwerkHarness {
    async fn start(label: &str) -> Result<Self, String> {
        let dir = TempDir::new().map_err(|err| err.to_string())?;
        let tls_dir = dir.path().join("http-tls");
        let local_root = dir.path().join("var-lib");
        let http_bind = next_addr(Ipv4Addr::LOCALHOST);
        let metrics_bind = next_addr(Ipv4Addr::LOCALHOST);
        let dataplane_iface = format!("nwtf{}{}", std::process::id(), sanitize_label(label));
        let network_cleanup = NetworkCleanup {
            dataplane_iface: dataplane_iface.clone(),
        };

        cleanup_service_lane_state();
        create_tun_interface(&dataplane_iface, "10.19.0.2/24")?;

        let child = spawn_neuwerk(
            &tls_dir,
            &local_root,
            http_bind,
            metrics_bind,
            &dataplane_iface,
        )?;

        wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(10)).await?;
        let client = http_client(&tls_dir)?;
        wait_for_ready(&client, http_bind, true, Duration::from_secs(10)).await?;

        let auth_path = api_auth::local_keyset_path(&tls_dir);
        wait_for_file(&auth_path, Duration::from_secs(10)).await?;
        let keyset = api_auth::load_keyset_from_file(&auth_path)
            .map_err(|err| err.to_string())?
            .ok_or_else(|| "missing api keyset".to_string())?;
        let token = api_auth::mint_token(&keyset, "terraform-contract", None, None)
            .map_err(|err| err.to_string())?
            .token;

        Ok(Self {
            _dir: dir,
            _network_cleanup: network_cleanup,
            child,
            tls_dir,
            http_bind,
            client,
            token,
        })
    }

    fn endpoint(&self) -> String {
        format!("https://{}", self.http_bind)
    }

    async fn get_json(&self, path: &str) -> Result<Value, String> {
        let resp = self
            .client
            .get(format!("https://{}{}", self.http_bind, path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|err| format!("get {path} failed: {err}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("get {path} status {status}: {body}"));
        }
        resp.json::<Value>()
            .await
            .map_err(|err| format!("decode {path} failed: {err}"))
    }

    async fn get_status(&self, path: &str) -> Result<reqwest::StatusCode, String> {
        self.client
            .get(format!("https://{}{}", self.http_bind, path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map(|resp| resp.status())
            .map_err(|err| format!("status {path} failed: {err}"))
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        kill(Pid::from_raw(self.child.id() as i32), Signal::SIGTERM)
            .map_err(|err| err.to_string())?;
        wait_for_child_exit(&mut self.child, Duration::from_secs(10)).await
    }
}

impl Drop for NeuwerkHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

struct ProviderInstall {
    _dir: TempDir,
    cli_config_path: PathBuf,
}

impl ProviderInstall {
    fn build() -> Result<Self, String> {
        let dir = TempDir::new().map_err(|err| err.to_string())?;
        let mirror_dir = dir.path().join("plugins");
        let host_dir = mirror_dir
            .join("registry.terraform.io")
            .join("moolen")
            .join("neuwerk")
            .join(PROVIDER_VERSION)
            .join(terraform_platform_dir()?);
        fs::create_dir_all(&host_dir).map_err(|err| err.to_string())?;

        let binary_name = format!("terraform-provider-neuwerk_v{}", PROVIDER_VERSION);
        let output_path = host_dir.join(binary_name);
        let provider_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("terraform-provider-neuwerk");
        let output = Command::new("go")
            .arg("build")
            .arg("-trimpath")
            .arg("-ldflags")
            .arg(format!("-X main.version=v{}", PROVIDER_VERSION))
            .arg("-o")
            .arg(&output_path)
            .arg(".")
            .current_dir(&provider_dir)
            .output()
            .map_err(|err| format!("go build provider failed: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "go build provider failed: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let cli_config_path = dir.path().join("terraform.rc");
        let cli_config = format!(
            r#"
provider_installation {{
  filesystem_mirror {{
    path    = "{mirror}"
    include = ["registry.terraform.io/moolen/neuwerk"]
  }}
  direct {{
    exclude = ["registry.terraform.io/moolen/neuwerk"]
  }}
}}
"#,
            mirror = mirror_dir.display()
        );
        fs::write(&cli_config_path, cli_config).map_err(|err| err.to_string())?;

        Ok(Self {
            _dir: dir,
            cli_config_path,
        })
    }
}

fn terraform_platform_dir() -> Result<String, String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(format!("unsupported terraform test arch {other}")),
    };
    Ok(format!("{}_{}", std::env::consts::OS, arch))
}

struct TerraformWorkspace {
    _dir: TempDir,
    root: PathBuf,
    cli_config_path: PathBuf,
}

impl TerraformWorkspace {
    fn new(
        provider: &ProviderInstall,
        fixture: &str,
        replacements: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let dir = TempDir::new().map_err(|err| err.to_string())?;
        let root = dir.path().to_path_buf();
        render_fixture(fixture, &root, replacements)?;
        Ok(Self {
            _dir: dir,
            root,
            cli_config_path: provider.cli_config_path.clone(),
        })
    }

    fn run(&self, args: &[&str]) -> Result<Output, String> {
        let output = Command::new("terraform")
            .args(args)
            .arg("-no-color")
            .current_dir(&self.root)
            .env("TF_CLI_CONFIG_FILE", &self.cli_config_path)
            .env("TF_IN_AUTOMATION", "1")
            .output()
            .map_err(|err| format!("terraform {:?} failed: {err}", args))?;
        Ok(output)
    }

    fn init(&self) -> Result<(), String> {
        expect_success(self.run(&["init", "-input=false"])?, "terraform init")
    }

    fn apply(&self) -> Result<(), String> {
        expect_success(
            self.run(&["apply", "-input=false", "-auto-approve"])?,
            "terraform apply",
        )
    }

    fn destroy(&self) -> Result<(), String> {
        expect_success(
            self.run(&["destroy", "-input=false", "-auto-approve"])?,
            "terraform destroy",
        )
    }

    fn import(&self, address: &str, id: &str) -> Result<(), String> {
        expect_success(
            self.run(&["import", "-input=false", address, id])?,
            &format!("terraform import {address}"),
        )
    }

    fn expect_plan_clean(&self) -> Result<(), String> {
        let output = self.run(&["plan", "-input=false", "-detailed-exitcode"])?;
        match output.status.code() {
            Some(0) => Ok(()),
            Some(2) => Err(format!(
                "terraform plan reported drift\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )),
            _ => Err(format!(
                "terraform plan failed with {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )),
        }
    }
}

fn expect_success(output: Output, command: &str) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{command} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn render_fixture(
    fixture: &str,
    destination: &Path,
    replacements: &BTreeMap<String, String>,
) -> Result<(), String> {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("terraform_provider_golden")
        .join(fixture);
    for entry in fs::read_dir(&fixture_dir).map_err(|err| err.to_string())? {
        let entry = entry.map_err(|err| err.to_string())?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| format!("fixture filename not utf8: {}", path.display()))?;
        if !name.ends_with(".tmpl") {
            continue;
        }
        let target_name = name.trim_end_matches(".tmpl");
        let raw = fs::read_to_string(&path).map_err(|err| err.to_string())?;
        let rendered = render_template(&raw, replacements);
        fs::write(destination.join(target_name), rendered).map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn render_template(template: &str, replacements: &BTreeMap<String, String>) -> String {
    let mut rendered = template.to_string();
    for (key, value) in replacements {
        rendered = rendered.replace(&format!("{{{{{key}}}}}"), value);
    }
    rendered
}

fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(6)
        .collect()
}

fn read_expected_json(fixture: &str, file: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("terraform_provider_golden")
        .join(fixture)
        .join(file);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn fixture_replacements(
    harness: &NeuwerkHarness,
    extra: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut replacements = BTreeMap::new();
    replacements.insert("PROVIDER_VERSION".to_string(), PROVIDER_VERSION.to_string());
    replacements.insert("ENDPOINT".to_string(), harness.endpoint());
    replacements.insert("TOKEN".to_string(), harness.token.clone());
    replacements.insert(
        "CA_CERT_FILE".to_string(),
        harness.tls_dir.join("ca.crt").display().to_string(),
    );
    replacements.insert(
        "K8S_SERVICE_ACCOUNT_TOKEN".to_string(),
        "k8s-test-token".to_string(),
    );
    for (key, value) in extra {
        replacements.insert(key, value);
    }
    replacements
}

fn generate_uploaded_ca_pair() -> (String, String) {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Neuwerk Terraform Uploaded CA");
    let cert = Certificate::from_params(params).unwrap();
    (
        cert.serialize_pem().unwrap(),
        cert.serialize_private_key_pem(),
    )
}

async fn verify_policy_exact(
    harness: &NeuwerkHarness,
    name: &str,
    expected_policy: Value,
) -> Result<(), String> {
    let policy = harness
        .get_json(&format!("/api/v1/policies/by-name/{name}"))
        .await?;
    let actual = policy
        .get("policy")
        .cloned()
        .ok_or_else(|| "policy response missing policy".to_string())?;
    if actual != expected_policy {
        return Err(format!(
            "policy mismatch for {name}\nexpected:\n{}\nactual:\n{}",
            serde_json::to_string_pretty(&expected_policy).unwrap(),
            serde_json::to_string_pretty(&actual).unwrap()
        ));
    }
    Ok(())
}

async fn verify_integration_exists(harness: &NeuwerkHarness, name: &str) -> Result<(), String> {
    let integration = harness
        .get_json(&format!("/api/v1/integrations/{name}"))
        .await?;
    if integration.get("name").and_then(|value| value.as_str()) != Some(name) {
        return Err(format!("unexpected integration response: {integration}"));
    }
    Ok(())
}

async fn verify_policy_missing(harness: &NeuwerkHarness, name: &str) -> Result<(), String> {
    let status = harness
        .get_status(&format!("/api/v1/policies/by-name/{name}"))
        .await?;
    if status != reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "expected policy {name} to be missing, got {status}"
        ));
    }
    Ok(())
}

async fn verify_integration_missing(harness: &NeuwerkHarness, name: &str) -> Result<(), String> {
    let status = harness
        .get_status(&format!("/api/v1/integrations/{name}"))
        .await?;
    if status != reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "expected integration {name} to be missing, got {status}"
        ));
    }
    Ok(())
}

async fn verify_tls_ca_configured(harness: &NeuwerkHarness) -> Result<Value, String> {
    let status = harness
        .get_json("/api/v1/settings/tls-intercept-ca")
        .await?;
    if status.get("configured").and_then(|value| value.as_bool()) != Some(true) {
        return Err(format!(
            "expected tls intercept ca configured, got {status}"
        ));
    }
    Ok(status)
}

async fn verify_tls_ca_missing(harness: &NeuwerkHarness) -> Result<(), String> {
    let status = harness
        .get_json("/api/v1/settings/tls-intercept-ca")
        .await?;
    if status.get("configured").and_then(|value| value.as_bool()) != Some(false) {
        return Err(format!("expected tls intercept ca removed, got {status}"));
    }
    Ok(())
}

async fn run_foundation_import_case(
    harness: &NeuwerkHarness,
    provider: &ProviderInstall,
) -> Result<(), String> {
    let workspace = TerraformWorkspace::new(
        provider,
        "foundation_importable",
        &fixture_replacements(harness, BTreeMap::new()),
    )?;
    workspace.init()?;
    workspace.apply()?;
    workspace.expect_plan_clean()?;
    verify_integration_exists(harness, "prod-k8s").await?;
    verify_policy_exact(
        harness,
        "terraform-contract-raw",
        read_expected_json("foundation_importable", "expected_policy.json"),
    )
    .await?;

    let import_workspace = TerraformWorkspace::new(
        provider,
        "foundation_importable",
        &fixture_replacements(harness, BTreeMap::new()),
    )?;
    import_workspace.init()?;
    import_workspace.import("neuwerk_kubernetes_integration.prod", "prod-k8s")?;
    import_workspace.import("neuwerk_policy.main", "terraform-contract-raw")?;
    import_workspace.apply()?;
    import_workspace.expect_plan_clean()?;
    import_workspace.destroy()?;

    verify_integration_missing(harness, "prod-k8s").await?;
    verify_policy_missing(harness, "terraform-contract-raw").await?;
    Ok(())
}

async fn run_uploaded_ca_import_case(
    harness: &NeuwerkHarness,
    provider: &ProviderInstall,
) -> Result<(), String> {
    let (cert_pem, key_pem) = generate_uploaded_ca_pair();
    let workspace = TerraformWorkspace::new(
        provider,
        "uploaded_ca_importable",
        &fixture_replacements(
            harness,
            BTreeMap::from([
                ("UPLOADED_CA_CERT_PEM".to_string(), cert_pem.clone()),
                ("UPLOADED_CA_KEY_PEM".to_string(), key_pem.clone()),
            ]),
        ),
    )?;
    workspace.init()?;
    workspace.apply()?;
    workspace.expect_plan_clean()?;
    let initial_status = verify_tls_ca_configured(harness).await?;
    let initial_fp = initial_status
        .get("fingerprint_sha256")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing initial tls ca fingerprint".to_string())?
        .to_string();

    let import_workspace = TerraformWorkspace::new(
        provider,
        "uploaded_ca_importable",
        &fixture_replacements(
            harness,
            BTreeMap::from([
                ("UPLOADED_CA_CERT_PEM".to_string(), cert_pem),
                ("UPLOADED_CA_KEY_PEM".to_string(), key_pem),
            ]),
        ),
    )?;
    import_workspace.init()?;
    import_workspace.import("neuwerk_tls_intercept_ca.main", "singleton")?;
    import_workspace.apply()?;
    import_workspace.expect_plan_clean()?;
    let imported_status = verify_tls_ca_configured(harness).await?;
    let imported_fp = imported_status
        .get("fingerprint_sha256")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing imported tls ca fingerprint".to_string())?;
    if imported_fp != initial_fp {
        return Err(format!(
            "tls ca fingerprint changed across import/apply: {initial_fp} != {imported_fp}"
        ));
    }

    import_workspace.destroy()?;
    verify_tls_ca_missing(harness).await?;
    Ok(())
}

async fn run_generated_ca_case(
    harness: &NeuwerkHarness,
    provider: &ProviderInstall,
) -> Result<(), String> {
    let workspace = TerraformWorkspace::new(
        provider,
        "generated_ca",
        &fixture_replacements(harness, BTreeMap::new()),
    )?;
    workspace.init()?;
    workspace.apply()?;
    workspace.expect_plan_clean()?;
    verify_tls_ca_configured(harness).await?;
    workspace.destroy()?;
    verify_tls_ca_missing(harness).await?;
    Ok(())
}

async fn run_policy_dns_sugar_case(
    harness: &NeuwerkHarness,
    provider: &ProviderInstall,
) -> Result<(), String> {
    let workspace = TerraformWorkspace::new(
        provider,
        "policy_dns_sugar",
        &fixture_replacements(harness, BTreeMap::new()),
    )?;
    workspace.init()?;
    workspace.apply()?;
    workspace.expect_plan_clean()?;
    verify_policy_exact(
        harness,
        "terraform-dns-sugar",
        read_expected_json("policy_dns_sugar", "expected_policy.json"),
    )
    .await?;
    workspace.destroy()?;
    verify_policy_missing(harness, "terraform-dns-sugar").await?;
    Ok(())
}

async fn run_policy_kubernetes_sugar_import_case(
    harness: &NeuwerkHarness,
    provider: &ProviderInstall,
) -> Result<(), String> {
    let workspace = TerraformWorkspace::new(
        provider,
        "policy_kubernetes_sugar_importable",
        &fixture_replacements(harness, BTreeMap::new()),
    )?;
    workspace.init()?;
    workspace.apply()?;
    workspace.expect_plan_clean()?;
    verify_integration_exists(harness, "prod-k8s").await?;
    verify_policy_exact(
        harness,
        "terraform-k8s-sugar",
        read_expected_json("policy_kubernetes_sugar_importable", "expected_policy.json"),
    )
    .await?;

    let import_workspace = TerraformWorkspace::new(
        provider,
        "policy_kubernetes_sugar_importable",
        &fixture_replacements(harness, BTreeMap::new()),
    )?;
    import_workspace.init()?;
    import_workspace.import("neuwerk_kubernetes_integration.prod", "prod-k8s")?;
    import_workspace.import("neuwerk_policy.main", "terraform-k8s-sugar")?;
    import_workspace.apply()?;
    import_workspace.expect_plan_clean()?;
    verify_policy_exact(
        harness,
        "terraform-k8s-sugar",
        read_expected_json("policy_kubernetes_sugar_importable", "expected_policy.json"),
    )
    .await?;
    import_workspace.destroy()?;

    verify_integration_missing(harness, "prod-k8s").await?;
    verify_policy_missing(harness, "terraform-k8s-sugar").await?;
    Ok(())
}

async fn run_policy_tls_targets_case(
    harness: &NeuwerkHarness,
    provider: &ProviderInstall,
) -> Result<(), String> {
    let workspace = TerraformWorkspace::new(
        provider,
        "policy_tls_targets_sugar",
        &fixture_replacements(harness, BTreeMap::new()),
    )?;
    workspace.init()?;
    workspace.apply()?;
    workspace.expect_plan_clean()?;
    verify_policy_exact(
        harness,
        "terraform-tls-targets",
        read_expected_json("policy_tls_targets_sugar", "expected_policy.json"),
    )
    .await?;
    workspace.destroy()?;
    verify_policy_missing(harness, "terraform-tls-targets").await?;
    Ok(())
}

#[tokio::test]
async fn terraform_provider_golden_contract_suite() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping terraform provider contract suite: requires root");
        return;
    }

    for bin in ["go", "terraform", "ip"] {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {bin} >/dev/null 2>&1"))
            .status()
            .unwrap();
        if !status.success() {
            eprintln!("skipping terraform provider contract suite: missing dependency {bin}");
            return;
        }
    }

    let provider = ProviderInstall::build().expect("build provider");

    let mut harness = match NeuwerkHarness::start("tfe2e").await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping terraform provider contract suite: {err}");
            return;
        }
    };

    run_foundation_import_case(&harness, &provider)
        .await
        .expect("foundation importable case");
    run_uploaded_ca_import_case(&harness, &provider)
        .await
        .expect("uploaded ca importable case");
    run_generated_ca_case(&harness, &provider)
        .await
        .expect("generated ca case");
    run_policy_dns_sugar_case(&harness, &provider)
        .await
        .expect("policy dns sugar case");
    run_policy_kubernetes_sugar_import_case(&harness, &provider)
        .await
        .expect("policy kubernetes sugar import case");
    run_policy_tls_targets_case(&harness, &provider)
        .await
        .expect("policy tls targets case");

    harness.shutdown().await.expect("shutdown neuwerk");
}
