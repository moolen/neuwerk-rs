use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn assert_exists(path: &Path) {
    assert!(path.exists(), "expected {} to exist", path.display());
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    fs::write(path, contents).expect("write file");
}

fn stage_release_fixture(root: &Path, target: &str, include_image_sbom: bool, include_source_bundle: bool) -> Vec<u8> {
    let release_dir = root.join("release").join(target);
    let qemu_dir = root.join("qemu").join(target);

    write_file(
        &release_dir.join("linkage.json"),
        br#"{"runtime":"vendored"}"#,
    );
    if include_image_sbom {
        write_file(
            &release_dir.join(format!("{target}-image.spdx.json")),
            br#"{"spdxVersion":"SPDX-2.3"}"#,
        );
    }
    write_file(
        &release_dir.join(format!("{target}-image.cyclonedx.json")),
        br#"{"bomFormat":"CycloneDX"}"#,
    );
    write_file(
        &release_dir.join(format!("{target}-rootfs.spdx.json")),
        br#"{"spdxVersion":"SPDX-2.3"}"#,
    );
    write_file(
        &release_dir.join(format!("{target}-rootfs.cyclonedx.json")),
        br#"{"bomFormat":"CycloneDX"}"#,
    );
    write_file(
        &release_dir.join("rootfs/etc/neuwerk/appliance.env"),
        b"NEUWERK_BOOTSTRAP_DEFAULT_POLICY=deny\n",
    );
    write_file(&root.join("packer-manifest.json"), br#"{"builds":[]}"#);
    if include_source_bundle {
        write_file(
            &root.join("source").join(format!("{target}.tar.gz")),
            b"fake-source-bundle",
        );
    }

    let qcow2_path = qemu_dir.join(format!("neuwerk-{target}.qcow2"));
    let qcow2_bytes = (0..32_768u32)
        .map(|value| (value % 251) as u8)
        .collect::<Vec<_>>();
    write_file(&qcow2_path, &qcow2_bytes);
    qcow2_bytes
}

fn generate_test_signing_env(public_key_output: &Path) -> Vec<(String, String)> {
    let gnupg_home = TempDir::new().expect("create gnupg home");
    let passphrase = "neuwerk-ci-passphrase";
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
Name-Real: Neuwerk Appliance CI
Name-Email: ci-appliance@neuwerk.invalid
Expire-Date: 0
Passphrase: neuwerk-ci-passphrase
%commit
",
    )
    .expect("write gpg key config");

    let status = Command::new("gpg")
        .env("GNUPGHOME", gnupg_home.path())
        .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", passphrase])
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
            "ci-appliance@neuwerk.invalid",
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

    let public_key_export = Command::new("gpg")
        .env("GNUPGHOME", gnupg_home.path())
        .args(["--batch", "--armor", "--export", &key_id])
        .output()
        .expect("export public key");
    assert!(
        public_key_export.status.success(),
        "export public key failed: {}",
        String::from_utf8_lossy(&public_key_export.stderr)
    );
    fs::write(public_key_output, public_key_export.stdout).expect("write public key output");

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
#[ignore = "requires release packaging toolchain"]
fn prepare_github_release_emits_verified_appliance_contract() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let artifact_dir = TempDir::new().expect("create artifact tempdir");
    let output_dir = TempDir::new().expect("create output tempdir");
    let target = "ubuntu-24.04-minimal-amd64";
    let qcow2_bytes = stage_release_fixture(artifact_dir.path(), target, true, true);

    let status = Command::new("bash")
        .current_dir(repo_root)
        .arg("packaging/scripts/prepare_github_release.sh")
        .arg("--target")
        .arg(target)
        .arg("--artifact-dir")
        .arg(artifact_dir.path())
        .arg("--release-version")
        .arg("v0.0.0-test")
        .arg("--git-revision")
        .arg("deadbeefcafe")
        .arg("--split-size")
        .arg("100")
        .arg("--output-dir")
        .arg(output_dir.path())
        .status()
        .expect("run prepare_github_release.sh");

    assert!(status.success(), "prepare_github_release.sh failed: {status}");

    let output_root = output_dir.path();
    assert_exists(&output_root.join("manifest.json"));
    assert_exists(&output_root.join("release-notes.md"));
    assert_exists(&output_root.join("SHA256SUMS"));
    assert_exists(&output_root.join("restore-qcow2.sh"));
    assert_exists(&output_root.join("packer-manifest.json"));
    assert_exists(&output_root.join("neuwerk-ubuntu-24.04-minimal-amd64-rootfs.tar.zst"));
    assert_exists(&output_root.join("neuwerk-ubuntu-24.04-minimal-amd64-source.tar.gz"));

    let qcow2_parts = fs::read_dir(output_root)
        .expect("read output directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("neuwerk-ubuntu-24.04-minimal-amd64.qcow2.zst.part-"))
        .collect::<Vec<_>>();
    assert!(
        qcow2_parts.len() >= 2,
        "expected split qcow2 archive to produce multiple parts, got {:?}",
        qcow2_parts
    );

    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(output_root.join("manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    assert_eq!(manifest["release_version"], "v0.0.0-test");
    assert_eq!(manifest["git_revision"], "deadbeefcafe");
    assert_eq!(manifest["provider"], "qemu");
    assert_eq!(manifest["distribution"]["channel"], "github-release");
    assert_eq!(manifest["distribution"]["artifact_type"], "appliance-image");
    assert_eq!(manifest["distribution"]["support_model"], "manual-import");
    assert_eq!(
        manifest["distribution"]["supported_platforms"],
        serde_json::json!(["aws", "azure", "gcp"])
    );
    assert_eq!(manifest["distribution"]["supported_os"]["family"], "ubuntu");
    assert_eq!(manifest["distribution"]["supported_os"]["version"], "24.04");
    assert_eq!(
        manifest["distribution"]["runtime_contract"]["dpdk_mode"],
        "vendored"
    );

    let artifact_paths = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts array")
        .iter()
        .map(|entry| {
            entry["path"]
                .as_str()
                .expect("artifact path")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert!(
        artifact_paths.iter().any(|path| path == "release-notes.md"),
        "expected manifest to contain release notes artifact"
    );
    assert!(
        artifact_paths.iter().any(|path| path == "restore-qcow2.sh"),
        "expected manifest to contain restore helper"
    );
    assert!(
        artifact_paths.iter().any(|path| path == "SHA256SUMS"),
        "expected manifest to contain SHA256SUMS"
    );
    assert!(
        artifact_paths
            .iter()
            .any(|path| path == "neuwerk-ubuntu-24.04-minimal-amd64-source.tar.gz"),
        "expected manifest to contain the source bundle"
    );
    assert!(
        artifact_paths
            .iter()
            .any(|path| path.starts_with("neuwerk-ubuntu-24.04-minimal-amd64.qcow2.zst.part-")),
        "expected manifest to contain split qcow2 archive parts"
    );

    let release_notes =
        fs::read_to_string(output_root.join("release-notes.md")).expect("read release notes");
    assert!(
        release_notes.contains("## Supported Appliance Contract"),
        "expected release notes to describe the supported appliance contract"
    );
    assert!(
        release_notes.contains("Ubuntu 24.04 is the supported appliance base"),
        "expected release notes to mention the supported appliance base"
    );
    assert!(
        release_notes.contains("AWS, Azure, and GCP are supported as manual import targets."),
        "expected release notes to mention manual import targets"
    );
    assert!(
        release_notes.contains("docs/operations/appliance-image-usage.md"),
        "expected release notes to reference the operator appliance guide"
    );

    let checksum_status = Command::new("sha256sum")
        .current_dir(output_root)
        .arg("-c")
        .arg("SHA256SUMS")
        .status()
        .expect("run sha256sum -c");
    assert!(
        checksum_status.success(),
        "expected generated SHA256SUMS verification to pass"
    );

    let restore_status = Command::new("bash")
        .current_dir(output_root)
        .arg("./restore-qcow2.sh")
        .status()
        .expect("run restore-qcow2.sh");
    assert!(restore_status.success(), "restore-qcow2.sh failed: {restore_status}");

    let restored_qcow2 =
        fs::read(output_root.join(format!("neuwerk-{target}.qcow2"))).expect("read restored qcow2");
    assert_eq!(
        restored_qcow2, qcow2_bytes,
        "expected restored qcow2 to match the original staged artifact"
    );
}

#[test]
#[ignore = "requires release packaging toolchain"]
fn prepare_github_release_fails_when_required_provenance_artifacts_are_missing() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let artifact_dir = TempDir::new().expect("create artifact tempdir");
    let output_dir = TempDir::new().expect("create output tempdir");
    let target = "ubuntu-24.04-minimal-amd64";
    let _ = stage_release_fixture(artifact_dir.path(), target, false, false);

    let output = Command::new("bash")
        .current_dir(repo_root)
        .arg("packaging/scripts/prepare_github_release.sh")
        .arg("--target")
        .arg(target)
        .arg("--artifact-dir")
        .arg(artifact_dir.path())
        .arg("--release-version")
        .arg("v0.0.0-test")
        .arg("--git-revision")
        .arg("deadbeefcafe")
        .arg("--output-dir")
        .arg(output_dir.path())
        .output()
        .expect("run prepare_github_release.sh");

    assert!(
        !output.status.success(),
        "expected prepare_github_release.sh to fail when provenance artifacts are missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing required release artifact:"),
        "expected explicit missing-artifact failure, got stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("{target}-image.spdx.json"))
            || stderr.contains(&format!("source/{target}.tar.gz")),
        "expected stderr to identify the missing provenance artifact, got stderr: {stderr}"
    );
}

#[test]
#[ignore = "requires release packaging toolchain"]
fn sign_appliance_release_checksums_emits_signature_and_public_key() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let artifact_dir = TempDir::new().expect("create artifact tempdir");
    let output_dir = TempDir::new().expect("create output tempdir");
    let verify_home = TempDir::new().expect("create verify gnupg home");
    fs::set_permissions(
        verify_home.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("chmod verify gnupg home");
    let target = "ubuntu-24.04-minimal-amd64";
    let _ = stage_release_fixture(artifact_dir.path(), target, true, true);
    let signing_key_path = artifact_dir.path().join("neuwerk-release-signing-key.asc");

    assert_exists(&repo_root.join("packaging/release-signing/neuwerk-release-signing-key.asc"));

    let prepare_status = Command::new("bash")
        .current_dir(repo_root)
        .arg("packaging/scripts/prepare_github_release.sh")
        .arg("--target")
        .arg(target)
        .arg("--artifact-dir")
        .arg(artifact_dir.path())
        .arg("--release-version")
        .arg("v0.0.0-test")
        .arg("--git-revision")
        .arg("deadbeefcafe")
        .arg("--output-dir")
        .arg(output_dir.path())
        .status()
        .expect("prepare release assets");
    assert!(prepare_status.success(), "prepare_github_release.sh failed: {prepare_status}");

    let mut command = Command::new("bash");
    command
        .current_dir(repo_root)
        .arg("packaging/scripts/sign_github_release_checksums.sh")
        .arg("--artifact-dir")
        .arg(output_dir.path())
        .arg("--signing-key")
        .arg(&signing_key_path);
    for (name, value) in generate_test_signing_env(&signing_key_path) {
        command.env(name, value);
    }
    let sign_output = command.output().expect("run signing helper");
    assert!(
        sign_output.status.success(),
        "expected signing helper to succeed, stderr: {}",
        String::from_utf8_lossy(&sign_output.stderr)
    );

    let signature_path = output_dir.path().join("SHA256SUMS.sig");
    let public_key_path = output_dir.path().join("neuwerk-release-signing-key.asc");
    assert_exists(&signature_path);
    assert_exists(&public_key_path);

    let import_status = Command::new("gpg")
        .env("GNUPGHOME", verify_home.path())
        .args(["--batch", "--import"])
        .arg(&public_key_path)
        .status()
        .expect("import public key");
    assert!(import_status.success(), "gpg import failed: {import_status}");

    let verify_output = Command::new("gpg")
        .env("GNUPGHOME", verify_home.path())
        .args(["--batch", "--verify"])
        .arg(&signature_path)
        .arg(output_dir.path().join("SHA256SUMS"))
        .output()
        .expect("verify signature");
    assert!(
        verify_output.status.success(),
        "expected signature verification to succeed, stderr: {}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
}
