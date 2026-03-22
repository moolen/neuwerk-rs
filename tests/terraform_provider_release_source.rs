use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn assert_exists(path: &Path) {
    assert!(path.exists(), "expected {} to exist", path.display());
}

fn assert_missing(path: &Path) {
    assert!(!path.exists(), "expected {} to be absent", path.display());
}

#[test]
fn export_creates_flat_provider_release_source_tree() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output_dir = TempDir::new().expect("create tempdir");

    let status = Command::new("make")
        .current_dir(repo_root)
        .arg("package.terraform-provider.release-source")
        .arg(format!("OUTPUT_DIR={}", output_dir.path().display()))
        .status()
        .expect("run make export target");

    assert!(status.success(), "make export target failed: {status}");

    let exported_root = output_dir.path();
    assert_exists(&exported_root.join("main.go"));
    assert_exists(&exported_root.join("go.mod"));
    assert_exists(&exported_root.join("internal/provider/provider.go"));
    assert_exists(&exported_root.join("docs/index.md"));
    assert_exists(&exported_root.join("examples/basic/main.tf"));
    assert_exists(&exported_root.join("README.md"));
    assert_exists(&exported_root.join(".gitignore"));
    assert_exists(&exported_root.join(".github/workflows/ci.yml"));
    assert_exists(&exported_root.join(".github/workflows/release.yml"));

    assert_missing(&exported_root.join("src"));
    assert_missing(&exported_root.join("ui"));
    assert_missing(&exported_root.join("packer"));
    assert_missing(&exported_root.join("terraform-provider-neuwerk"));
}
