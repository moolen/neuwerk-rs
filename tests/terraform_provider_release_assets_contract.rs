use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn generate_test_signing_env() -> Vec<(String, String)> {
    let gnupg_home = TempDir::new().expect("create gnupg home");
    let passphrase = "neuwerk-provider-ci-passphrase";
    fs::set_permissions(
        gnupg_home.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("chmod gnupg home");
    let config_path = gnupg_home.path().join("key.conf");
    fs::write(
        &config_path,
        "\
Key-Type: RSA
Key-Length: 3072
Name-Real: Neuwerk Provider CI
Name-Email: ci-provider@neuwerk.invalid
Expire-Date: 0
Passphrase: neuwerk-provider-ci-passphrase
%commit
",
    )
    .expect("write gpg key config");

    let status = Command::new("gpg")
        .env("GNUPGHOME", gnupg_home.path())
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            passphrase,
        ])
        .arg("--generate-key")
        .arg(&config_path)
        .status()
        .expect("generate ephemeral gpg key");
    assert!(status.success(), "generate-key failed: {status}");

    let key_id_output = Command::new("gpg")
        .env("GNUPGHOME", gnupg_home.path())
        .args([
            "--batch",
            "--list-secret-keys",
            "--with-colons",
            "ci-provider@neuwerk.invalid",
        ])
        .output()
        .expect("list secret keys");
    assert!(
        key_id_output.status.success(),
        "list-secret-keys failed: {}",
        String::from_utf8_lossy(&key_id_output.stderr)
    );
    let key_id = String::from_utf8_lossy(&key_id_output.stdout)
        .lines()
        .find_map(|line| {
            let parts = line.split(':').collect::<Vec<_>>();
            if parts.first() == Some(&"sec") {
                parts.get(4).map(|value| value.to_string())
            } else {
                None
            }
        })
        .expect("extract gpg key id");

    let private_key_output = Command::new("gpg")
        .env("GNUPGHOME", gnupg_home.path())
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            passphrase,
            "--armor",
            "--export-secret-keys",
            &key_id,
        ])
        .output()
        .expect("export secret key");
    assert!(
        private_key_output.status.success(),
        "export-secret-keys failed: {}",
        String::from_utf8_lossy(&private_key_output.stderr)
    );

    vec![
        (
            "GPG_PRIVATE_KEY".to_string(),
            String::from_utf8(private_key_output.stdout).expect("secret key utf8"),
        ),
        ("GPG_PASSPHRASE".to_string(), passphrase.to_string()),
        ("GPG_KEY_ID".to_string(), key_id),
    ]
}

#[test]
fn build_provider_release_assets_emits_registry_compatible_checksums() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output_dir = TempDir::new().expect("create output tempdir");
    let checksum_path = output_dir
        .path()
        .join("terraform-provider-neuwerk_0.0.0-test_SHA256SUMS");

    let mut command = Command::new("bash");
    command
        .current_dir(repo_root)
        .arg("packaging/scripts/build_terraform_provider_release_assets.sh")
        .arg("--release-version")
        .arg("v0.0.0-test")
        .arg("--output-dir")
        .arg(output_dir.path());
    for (name, value) in generate_test_signing_env() {
        command.env(name, value);
    }

    let status = command
        .status()
        .expect("run provider release asset builder");
    assert!(
        status.success(),
        "provider release asset builder failed: {status}"
    );

    let checksums = fs::read_to_string(&checksum_path).expect("read checksum file");
    for expected_name in [
        "terraform-provider-neuwerk_0.0.0-test_linux_amd64.zip",
        "terraform-provider-neuwerk_0.0.0-test_linux_arm64.zip",
        "terraform-provider-neuwerk_0.0.0-test_darwin_amd64.zip",
        "terraform-provider-neuwerk_0.0.0-test_darwin_arm64.zip",
        "terraform-provider-neuwerk_0.0.0-test_windows_amd64.zip",
    ] {
        assert!(
            checksums.contains(&format!("  {expected_name}")),
            "expected checksum file to contain bare asset name {expected_name}\n{checksums}"
        );
    }
    assert!(
        !checksums.contains("./terraform-provider-neuwerk_0.0.0-test_"),
        "expected checksum file not to prefix asset names with ./\n{checksums}"
    );
}
