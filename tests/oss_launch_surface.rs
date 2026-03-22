use std::path::Path;
use std::process::Command;

#[test]
fn check_oss_launch_surface_reports_success() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let status = Command::new("bash")
        .current_dir(repo_root)
        .arg("packaging/scripts/check_oss_launch_surface.sh")
        .status()
        .expect("run OSS launch surface preflight");

    assert!(status.success(), "OSS launch surface preflight failed: {status}");
}
