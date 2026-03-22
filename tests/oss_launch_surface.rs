use std::fs;
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

#[test]
fn ci_workflow_enforces_oss_launch_surface_on_pull_requests() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ci_workflow =
        fs::read_to_string(repo_root.join(".github/workflows/ci.yml")).expect("read ci workflow");

    assert!(
        ci_workflow.contains("oss-launch-surface:"),
        "expected ci workflow to define an oss-launch-surface job"
    );
    assert!(
        ci_workflow.contains("bash packaging/scripts/check_oss_launch_surface.sh"),
        "expected ci workflow to run the OSS launch surface preflight script"
    );
    assert!(
        ci_workflow.contains("npm --prefix www ci"),
        "expected ci workflow to install the docs site dependencies"
    );
    assert!(
        ci_workflow.contains("node --test www/tests/*.test.mjs"),
        "expected ci workflow to run the docs navigation tests"
    );
    assert!(
        ci_workflow.contains("npm --prefix www run build"),
        "expected ci workflow to build the docs site"
    );
}

#[test]
fn release_readiness_docs_call_out_oss_launch_surface_ci() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let release_readiness = fs::read_to_string(repo_root.join("docs/operations/release-readiness.md"))
        .expect("read release readiness doc");
    let community_release_readiness =
        fs::read_to_string(repo_root.join("www/src/content/docs/community/release-process.mdx"))
            .expect("read community release process doc");

    assert!(
        release_readiness.contains("OSS launch surface preflight"),
        "expected release readiness doc to mention the OSS launch surface preflight"
    );
    assert!(
        community_release_readiness.contains("OSS launch surface preflight"),
        "expected community release readiness doc to mention the OSS launch surface preflight"
    );
}
