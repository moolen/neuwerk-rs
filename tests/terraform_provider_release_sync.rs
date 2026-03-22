use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn run(command: &mut Command) {
    let output = command.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn sync_script_bootstraps_and_pushes_public_release_repo() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp_root = TempDir::new().expect("create tempdir");
    let bare_remote = temp_root.path().join("terraform-provider-neuwerk.git");
    let local_clone = temp_root.path().join("public-repo");
    let verify_clone = temp_root.path().join("verify-clone");

    run(Command::new("git").arg("init").arg("--bare").arg(&bare_remote));

    let mut sync = Command::new("bash");
    sync.current_dir(repo_root)
        .arg("packaging/scripts/sync_terraform_provider_release_source.sh")
        .arg("--repo-dir")
        .arg(&local_clone)
        .arg("--remote-url")
        .arg(&bare_remote)
        .arg("--push")
        .env("GIT_AUTHOR_NAME", "Neuwerk Test")
        .env("GIT_AUTHOR_EMAIL", "test@neuwerk.invalid")
        .env("GIT_COMMITTER_NAME", "Neuwerk Test")
        .env("GIT_COMMITTER_EMAIL", "test@neuwerk.invalid");
    run(&mut sync);

    run(
        Command::new("git")
            .arg("clone")
            .arg("--branch")
            .arg("main")
            .arg(&bare_remote)
            .arg(&verify_clone),
    );

    assert!(verify_clone.join("main.go").exists());
    assert!(verify_clone.join("LICENSE").exists());
    assert!(verify_clone.join(".github/workflows/release.yml").exists());

    let readme = fs::read_to_string(verify_clone.join("README.md")).expect("read exported readme");
    assert!(readme.contains("moolen/neuwerk"));
}
