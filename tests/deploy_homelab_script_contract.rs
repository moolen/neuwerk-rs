use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn homelab_deploy_script_exists_and_documents_usage() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script_path = repo_root.join("hack/deploy-homelab.sh");

    assert!(
        script_path.exists(),
        "expected homelab deploy script at {}",
        script_path.display()
    );

    let syntax_status = Command::new("bash")
        .arg("-n")
        .arg(&script_path)
        .status()
        .expect("check deploy script syntax");
    assert!(
        syntax_status.success(),
        "deploy script failed bash syntax check: {syntax_status}"
    );

    let help_output = Command::new("bash")
        .current_dir(repo_root)
        .arg(&script_path)
        .arg("--help")
        .output()
        .expect("run deploy script --help");
    assert!(
        help_output.status.success(),
        "deploy script --help failed: {}",
        help_output.status
    );

    let help_stdout = String::from_utf8_lossy(&help_output.stdout);
    assert!(
        help_stdout.contains("192.168.178.76,192.168.178.83,192.168.178.84"),
        "expected help output to mention default homelab hosts, got:\n{help_stdout}"
    );
    assert!(
        help_stdout.contains("23.11.2"),
        "expected help output to mention the vendored DPDK version, got:\n{help_stdout}"
    );
    assert!(
        help_stdout.contains("firewall"),
        "expected help output to mention the firewall systemd unit, got:\n{help_stdout}"
    );

    let script_body = fs::read_to_string(&script_path).expect("read deploy script");
    assert!(
        script_body.contains("neuwerk-firewall-start.sh"),
        "expected deploy script to manage the homelab wrapper"
    );
    assert!(
        script_body.contains("\"${USER_NAME}@${host}\" bash <<EOF"),
        "expected deploy script to force bash for remote ssh commands so pipefail and [[ ]] work on homelab guests"
    );
    assert!(
        script_body.contains("wait_for_https_health \"${host}\""),
        "expected deploy script to poll health from the rollout controller instead of relying on guest self-connectivity during restart"
    );
    assert!(
        !script_body.contains("\\\"\\${actual_bin_sha}\\\""),
        "expected deploy script ssh heredocs to avoid leftover escaped quotes from the old string-based remote command"
    );
    assert!(
        script_body.contains("\\${actual_bin_sha}"),
        "expected deploy script ssh heredocs to preserve remote variable expansion instead of letting the local shell expand it first"
    );
}
