use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use firewall::controlplane::integrations::IntegrationStore;
use firewall::controlplane::kubernetes::run_kubernetes_resolver;
use firewall::controlplane::policy_config::PolicyConfig;
use firewall::controlplane::PolicyStore;
use firewall::dataplane::config::DataplaneConfig;
use firewall::dataplane::policy::{DefaultPolicy, PolicySnapshot};
use firewall::dataplane::{handle_packet, Action, EngineState, Packet};

const TEST_NAMESPACE: &str = "neuwerk-e2e";
const TEST_SERVICE_ACCOUNT: &str = "resolver";
const TEST_INTEGRATION_NAME: &str = "kind-e2e";
const TEST_SECONDARY_NAMESPACE: &str = "default";
const POD_IMAGE: &str = "registry.k8s.io/pause:3.9";
const STALE_GRACE: Duration = Duration::from_secs(6);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

const LABEL_POD_BASE_KEY: &str = "neuwerk-e2e-pod";
const LABEL_NODE_BASE_KEY: &str = "neuwerk-e2e-node";
const LABEL_STALE_KEY: &str = "neuwerk-stale";
const LABEL_NAMESPACE_KEY: &str = "neuwerk-namespace";
const LABEL_UNION_KEY: &str = "neuwerk-union";
const LABEL_UNION_EXTRA_KEY: &str = "neuwerk-union-extra";
const LABEL_UNION_NODE_KEY: &str = "neuwerk-union-node";
const LABEL_PRIORITY_KEY: &str = "neuwerk-priority";
const LABEL_CHURN_POD_KEY: &str = "neuwerk-churn-pod";
const LABEL_CHURN_NODE_KEY: &str = "neuwerk-churn-node";
const LABEL_TRUE: &str = "true";

#[derive(Debug, Clone)]
struct KindApiConfig {
    context: String,
    server: String,
    ca_pem: String,
    token: String,
}

struct KindClusterGuard {
    name: String,
}

impl Drop for KindClusterGuard {
    fn drop(&mut self) {
        let _ = Command::new("kind")
            .args(["delete", "cluster", "--name", &self.name])
            .output();
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cluster_name = format!(
        "nwk-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    );
    println!("kind e2e: creating cluster {cluster_name}");
    run_cmd(
        "kind",
        &[
            "create",
            "cluster",
            "--name",
            &cluster_name,
            "--wait",
            "180s",
        ],
    )?;
    let _cluster_guard = KindClusterGuard {
        name: cluster_name.clone(),
    };

    let kind = discover_kind_api(&cluster_name)?;
    let node_name = first_node_name(&kind.context)?;
    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pod_primary = format!("nwk-pod-a-{suffix}");
    let pod_secondary = format!("nwk-pod-b-{suffix}");

    create_pod(&kind.context, TEST_NAMESPACE, &pod_primary, &[])?;
    create_pod(&kind.context, TEST_SECONDARY_NAMESPACE, &pod_secondary, &[])?;

    let pod_primary_ip = wait_for_pod_ip(
        &kind.context,
        TEST_NAMESPACE,
        &pod_primary,
        Duration::from_secs(90),
    )
    .await?;
    let pod_secondary_ip = wait_for_pod_ip(
        &kind.context,
        TEST_SECONDARY_NAMESPACE,
        &pod_secondary,
        Duration::from_secs(90),
    )
    .await?;

    println!("kind e2e: selected node {node_name}");
    println!("kind e2e: selected pod {pod_primary} ({pod_primary_ip})");
    println!("kind e2e: selected pod {pod_secondary} ({pod_secondary_ip})");

    let integration_root = std::env::temp_dir().join(format!(
        "neuwerk-kind-e2e-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir_all(&integration_root)?;
    let integration_store = IntegrationStore::local(integration_root.join("integrations"));
    integration_store
        .create_kubernetes(
            TEST_INTEGRATION_NAME.to_string(),
            kind.server.clone(),
            kind.ca_pem.clone(),
            kind.token.clone(),
        )
        .await?;

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let resolver_task = tokio::spawn(run_kubernetes_resolver(
        policy_store.clone(),
        integration_store.clone(),
        STALE_GRACE,
        RECONCILE_INTERVAL,
    ));

    let run_result = async {
        scenario_pod_selector_applies(&kind, &policy_store, &pod_primary, pod_primary_ip).await?;
        scenario_node_selector_applies(&kind, &policy_store, &node_name).await?;
        scenario_stale_grace_and_integration_update(
            &kind,
            &policy_store,
            &integration_store,
            &pod_primary,
            pod_primary_ip,
        )
        .await?;
        scenario_namespace_correctness(
            &kind,
            &policy_store,
            &pod_primary,
            pod_primary_ip,
            &pod_secondary,
            pod_secondary_ip,
        )
        .await?;
        scenario_union_and_dedupe(
            &kind,
            &policy_store,
            &pod_primary,
            pod_primary_ip,
            &node_name,
        )
        .await?;
        scenario_priority_precedence(&kind, &policy_store, &pod_primary, pod_primary_ip).await?;
        scenario_pod_node_churn(
            &kind,
            &policy_store,
            &pod_primary,
            pod_primary_ip,
            &node_name,
            suffix,
        )
        .await?;
        Ok::<(), String>(())
    }
    .await;

    resolver_task.abort();
    cleanup_labels(&kind.context, TEST_NAMESPACE, &pod_primary, &node_name);
    cleanup_labels(
        &kind.context,
        TEST_SECONDARY_NAMESPACE,
        &pod_secondary,
        &node_name,
    );
    let _ = delete_pod(&kind.context, TEST_NAMESPACE, &pod_primary);
    let _ = delete_pod(&kind.context, TEST_SECONDARY_NAMESPACE, &pod_secondary);
    let _ = fs::remove_dir_all(&integration_root);

    if let Err(err) = run_result {
        return Err(err.into());
    }

    println!("kind e2e: passed");
    Ok(())
}

async fn scenario_pod_selector_applies(
    kind: &KindApiConfig,
    policy_store: &PolicyStore,
    pod_name: &str,
    pod_ip: Ipv4Addr,
) -> Result<(), String> {
    println!("kind e2e: scenario pod selector apply");
    let policy = policy_with_pod_selector(
        TEST_INTEGRATION_NAME,
        TEST_NAMESPACE,
        LABEL_POD_BASE_KEY,
        LABEL_TRUE,
    )?;
    policy_store.rebuild_from_config(policy)?;
    wait_for_binding_count(policy_store, 1, Duration::from_secs(20)).await?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(30)).await?;

    label_pod(
        &kind.context,
        TEST_NAMESPACE,
        pod_name,
        LABEL_POD_BASE_KEY,
        LABEL_TRUE,
    )?;
    wait_for_dynamic_ips_exact(
        policy_store,
        BTreeSet::from([pod_ip]),
        Duration::from_secs(60),
    )
    .await?;

    assert_action(
        "pod selector allow",
        evaluate_packet(&policy_store.snapshot(), pod_ip, 50000),
        Action::Forward { out_port: 0 },
    )?;

    remove_pod_label(&kind.context, TEST_NAMESPACE, pod_name, LABEL_POD_BASE_KEY)?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(60)).await?;

    assert_action(
        "pod selector drop",
        evaluate_packet(&policy_store.snapshot(), pod_ip, 50001),
        Action::Drop,
    )?;
    Ok(())
}

async fn scenario_node_selector_applies(
    kind: &KindApiConfig,
    policy_store: &PolicyStore,
    node_name: &str,
) -> Result<(), String> {
    println!("kind e2e: scenario node selector apply");
    let policy = policy_with_node_selector(TEST_INTEGRATION_NAME, LABEL_NODE_BASE_KEY, LABEL_TRUE)?;
    policy_store.rebuild_from_config(policy)?;
    wait_for_binding_count(policy_store, 1, Duration::from_secs(20)).await?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(30)).await?;

    label_node(&kind.context, node_name, LABEL_NODE_BASE_KEY, LABEL_TRUE)?;
    let selected_node_ip = wait_for_any_dynamic_ip(policy_store, Duration::from_secs(60)).await?;

    assert_action(
        "node selector allow",
        evaluate_packet(&policy_store.snapshot(), selected_node_ip, 50002),
        Action::Forward { out_port: 0 },
    )?;

    remove_node_label(&kind.context, node_name, LABEL_NODE_BASE_KEY)?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(60)).await?;

    assert_action(
        "node selector drop",
        evaluate_packet(&policy_store.snapshot(), selected_node_ip, 50003),
        Action::Drop,
    )?;
    Ok(())
}

async fn scenario_stale_grace_and_integration_update(
    kind: &KindApiConfig,
    policy_store: &PolicyStore,
    integration_store: &IntegrationStore,
    pod_name: &str,
    pod_ip: Ipv4Addr,
) -> Result<(), String> {
    println!("kind e2e: scenario stale grace and integration update");
    let policy = policy_with_pod_selector(
        TEST_INTEGRATION_NAME,
        TEST_NAMESPACE,
        LABEL_STALE_KEY,
        LABEL_TRUE,
    )?;
    policy_store.rebuild_from_config(policy)?;
    wait_for_binding_count(policy_store, 1, Duration::from_secs(20)).await?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(30)).await?;

    label_pod(
        &kind.context,
        TEST_NAMESPACE,
        pod_name,
        LABEL_STALE_KEY,
        LABEL_TRUE,
    )?;
    wait_for_dynamic_ips_exact(
        policy_store,
        BTreeSet::from([pod_ip]),
        Duration::from_secs(60),
    )
    .await?;

    integration_store
        .update_kubernetes(
            TEST_INTEGRATION_NAME,
            "https://127.0.0.1:1".to_string(),
            kind.ca_pem.clone(),
            kind.token.clone(),
        )
        .await?;

    tokio::time::sleep(Duration::from_secs(2)).await;
    let during_grace = current_dynamic_ips(policy_store);
    if !during_grace.contains(&pod_ip) {
        return Err(format!(
            "expected stale ip {pod_ip} during grace period, current={during_grace:?}"
        ));
    }

    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(40)).await?;
    assert_action(
        "stale grace expiry drop",
        evaluate_packet(&policy_store.snapshot(), pod_ip, 50004),
        Action::Drop,
    )?;

    integration_store
        .update_kubernetes(
            TEST_INTEGRATION_NAME,
            kind.server.clone(),
            kind.ca_pem.clone(),
            kind.token.clone(),
        )
        .await?;
    wait_for_dynamic_ips_exact(
        policy_store,
        BTreeSet::from([pod_ip]),
        Duration::from_secs(60),
    )
    .await?;
    assert_action(
        "integration update reconnect allow",
        evaluate_packet(&policy_store.snapshot(), pod_ip, 50005),
        Action::Forward { out_port: 0 },
    )?;

    remove_pod_label(&kind.context, TEST_NAMESPACE, pod_name, LABEL_STALE_KEY)?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(60)).await?;
    Ok(())
}

async fn scenario_namespace_correctness(
    kind: &KindApiConfig,
    policy_store: &PolicyStore,
    pod_primary: &str,
    pod_primary_ip: Ipv4Addr,
    pod_secondary: &str,
    pod_secondary_ip: Ipv4Addr,
) -> Result<(), String> {
    println!("kind e2e: scenario namespace correctness");
    label_pod(
        &kind.context,
        TEST_NAMESPACE,
        pod_primary,
        LABEL_NAMESPACE_KEY,
        LABEL_TRUE,
    )?;
    label_pod(
        &kind.context,
        TEST_SECONDARY_NAMESPACE,
        pod_secondary,
        LABEL_NAMESPACE_KEY,
        LABEL_TRUE,
    )?;

    let policy = policy_with_pod_selector(
        TEST_INTEGRATION_NAME,
        TEST_NAMESPACE,
        LABEL_NAMESPACE_KEY,
        LABEL_TRUE,
    )?;
    policy_store.rebuild_from_config(policy)?;
    wait_for_binding_count(policy_store, 1, Duration::from_secs(20)).await?;
    wait_for_dynamic_ips_exact(
        policy_store,
        BTreeSet::from([pod_primary_ip]),
        Duration::from_secs(60),
    )
    .await?;

    assert_action(
        "namespace selected pod allow",
        evaluate_packet(&policy_store.snapshot(), pod_primary_ip, 50006),
        Action::Forward { out_port: 0 },
    )?;
    assert_action(
        "namespace unselected pod drop",
        evaluate_packet(&policy_store.snapshot(), pod_secondary_ip, 50007),
        Action::Drop,
    )?;

    remove_pod_label(
        &kind.context,
        TEST_NAMESPACE,
        pod_primary,
        LABEL_NAMESPACE_KEY,
    )?;
    remove_pod_label(
        &kind.context,
        TEST_SECONDARY_NAMESPACE,
        pod_secondary,
        LABEL_NAMESPACE_KEY,
    )?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(60)).await?;
    Ok(())
}

async fn scenario_union_and_dedupe(
    kind: &KindApiConfig,
    policy_store: &PolicyStore,
    pod_name: &str,
    pod_ip: Ipv4Addr,
    node_name: &str,
) -> Result<(), String> {
    println!("kind e2e: scenario union and dedupe");
    label_pod(
        &kind.context,
        TEST_NAMESPACE,
        pod_name,
        LABEL_UNION_KEY,
        LABEL_TRUE,
    )?;
    label_pod(
        &kind.context,
        TEST_NAMESPACE,
        pod_name,
        LABEL_UNION_EXTRA_KEY,
        LABEL_TRUE,
    )?;
    label_node(&kind.context, node_name, LABEL_UNION_NODE_KEY, LABEL_TRUE)?;

    let policy = policy_union_and_dedupe(TEST_INTEGRATION_NAME)?;
    policy_store.rebuild_from_config(policy)?;
    wait_for_binding_count(policy_store, 3, Duration::from_secs(20)).await?;

    let node_ip = wait_for_dynamic_ip_count(policy_store, 2, Duration::from_secs(60))
        .await
        .and_then(|_| {
            let ips = current_dynamic_ips(policy_store);
            ips.into_iter()
                .find(|ip| *ip != pod_ip)
                .ok_or_else(|| "failed to identify selected node ip".to_string())
        })?;

    wait_for_dynamic_ips_exact(
        policy_store,
        BTreeSet::from([pod_ip, node_ip]),
        Duration::from_secs(60),
    )
    .await?;

    assert_action(
        "union pod allow",
        evaluate_packet(&policy_store.snapshot(), pod_ip, 50008),
        Action::Forward { out_port: 0 },
    )?;
    assert_action(
        "union node allow",
        evaluate_packet(&policy_store.snapshot(), node_ip, 50009),
        Action::Forward { out_port: 0 },
    )?;

    remove_pod_label(&kind.context, TEST_NAMESPACE, pod_name, LABEL_UNION_KEY)?;
    remove_pod_label(
        &kind.context,
        TEST_NAMESPACE,
        pod_name,
        LABEL_UNION_EXTRA_KEY,
    )?;
    remove_node_label(&kind.context, node_name, LABEL_UNION_NODE_KEY)?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(60)).await?;
    Ok(())
}

async fn scenario_priority_precedence(
    kind: &KindApiConfig,
    policy_store: &PolicyStore,
    pod_name: &str,
    pod_ip: Ipv4Addr,
) -> Result<(), String> {
    println!("kind e2e: scenario priority precedence");
    label_pod(
        &kind.context,
        TEST_NAMESPACE,
        pod_name,
        LABEL_PRIORITY_KEY,
        LABEL_TRUE,
    )?;

    let policy = policy_priority_dynamic_deny_static_allow(
        TEST_INTEGRATION_NAME,
        TEST_NAMESPACE,
        LABEL_PRIORITY_KEY,
        LABEL_TRUE,
        pod_ip,
    )?;
    policy_store.rebuild_from_config(policy)?;
    wait_for_binding_count(policy_store, 1, Duration::from_secs(20)).await?;
    wait_for_dynamic_ips_exact(
        policy_store,
        BTreeSet::from([pod_ip]),
        Duration::from_secs(60),
    )
    .await?;

    assert_action(
        "priority dynamic deny wins",
        evaluate_packet(&policy_store.snapshot(), pod_ip, 50010),
        Action::Drop,
    )?;

    remove_pod_label(&kind.context, TEST_NAMESPACE, pod_name, LABEL_PRIORITY_KEY)?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(60)).await?;
    assert_action(
        "priority fallback static allow",
        evaluate_packet(&policy_store.snapshot(), pod_ip, 50011),
        Action::Forward { out_port: 0 },
    )?;
    Ok(())
}

async fn scenario_pod_node_churn(
    kind: &KindApiConfig,
    policy_store: &PolicyStore,
    pod_name: &str,
    pod_ip: Ipv4Addr,
    node_name: &str,
    suffix: u128,
) -> Result<(), String> {
    println!("kind e2e: scenario pod/node churn");
    label_pod(
        &kind.context,
        TEST_NAMESPACE,
        pod_name,
        LABEL_CHURN_POD_KEY,
        LABEL_TRUE,
    )?;
    label_node(&kind.context, node_name, LABEL_CHURN_NODE_KEY, LABEL_TRUE)?;

    let policy = policy_pod_node_churn(TEST_INTEGRATION_NAME)?;
    policy_store.rebuild_from_config(policy)?;
    wait_for_binding_count(policy_store, 2, Duration::from_secs(20)).await?;

    let node_ip = wait_for_dynamic_ip_count(policy_store, 2, Duration::from_secs(60))
        .await
        .and_then(|_| {
            let ips = current_dynamic_ips(policy_store);
            ips.into_iter()
                .find(|ip| *ip != pod_ip)
                .ok_or_else(|| "failed to identify selected node ip".to_string())
        })?;

    wait_for_dynamic_ips_exact(
        policy_store,
        BTreeSet::from([pod_ip, node_ip]),
        Duration::from_secs(60),
    )
    .await?;

    for _ in 0..2 {
        remove_pod_label(&kind.context, TEST_NAMESPACE, pod_name, LABEL_CHURN_POD_KEY)?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        label_pod(
            &kind.context,
            TEST_NAMESPACE,
            pod_name,
            LABEL_CHURN_POD_KEY,
            LABEL_TRUE,
        )?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    wait_for_dynamic_ips_contains(policy_store, pod_ip, Duration::from_secs(60)).await?;

    let replacement_pod = format!("nwk-pod-repl-{suffix}");
    delete_pod(&kind.context, TEST_NAMESPACE, pod_name)?;
    create_pod(
        &kind.context,
        TEST_NAMESPACE,
        &replacement_pod,
        &[(LABEL_CHURN_POD_KEY, LABEL_TRUE)],
    )?;
    let replacement_ip = wait_for_pod_ip(
        &kind.context,
        TEST_NAMESPACE,
        &replacement_pod,
        Duration::from_secs(90),
    )
    .await?;

    wait_for_dynamic_ips_contains(policy_store, replacement_ip, Duration::from_secs(60)).await?;
    let current = current_dynamic_ips(policy_store);
    if replacement_ip != pod_ip && current.contains(&pod_ip) {
        return Err(format!(
            "old pod ip {pod_ip} still present after replacement: {current:?}"
        ));
    }

    remove_node_label(&kind.context, node_name, LABEL_CHURN_NODE_KEY)?;
    wait_for_dynamic_ip_count(policy_store, 1, Duration::from_secs(60)).await?;
    label_node(&kind.context, node_name, LABEL_CHURN_NODE_KEY, LABEL_TRUE)?;
    wait_for_dynamic_ips_contains(policy_store, node_ip, Duration::from_secs(60)).await?;

    assert_action(
        "churn replacement pod allow",
        evaluate_packet(&policy_store.snapshot(), replacement_ip, 50012),
        Action::Forward { out_port: 0 },
    )?;

    remove_pod_label(
        &kind.context,
        TEST_NAMESPACE,
        &replacement_pod,
        LABEL_CHURN_POD_KEY,
    )?;
    remove_node_label(&kind.context, node_name, LABEL_CHURN_NODE_KEY)?;
    wait_for_dynamic_ip_count(policy_store, 0, Duration::from_secs(60)).await?;
    delete_pod(&kind.context, TEST_NAMESPACE, &replacement_pod)?;
    Ok(())
}

fn policy_with_pod_selector(
    integration_name: &str,
    namespace: &str,
    label_key: &str,
    label_value: &str,
) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: kind-pods
    sources:
      kubernetes:
        - integration: "{integration_name}"
          pod_selector:
            namespace: {namespace}
            match_labels:
              "{label_key}": "{label_value}"
    rules:
      - id: allow-udp-8080
        action: allow
        match:
          proto: udp
          dst_ports: [8080]
"#
    );
    serde_yaml::from_str::<PolicyConfig>(&yaml).map_err(|err| format!("policy yaml error: {err}"))
}

fn policy_with_node_selector(
    integration_name: &str,
    label_key: &str,
    label_value: &str,
) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: kind-nodes
    sources:
      kubernetes:
        - integration: "{integration_name}"
          node_selector:
            match_labels:
              "{label_key}": "{label_value}"
    rules:
      - id: allow-udp-8080
        action: allow
        match:
          proto: udp
          dst_ports: [8080]
"#
    );
    serde_yaml::from_str::<PolicyConfig>(&yaml).map_err(|err| format!("policy yaml error: {err}"))
}

fn policy_union_and_dedupe(integration_name: &str) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: kind-union
    sources:
      kubernetes:
        - integration: "{integration_name}"
          pod_selector:
            namespace: {TEST_NAMESPACE}
            match_labels:
              "{LABEL_UNION_KEY}": "{LABEL_TRUE}"
        - integration: "{integration_name}"
          pod_selector:
            namespace: {TEST_NAMESPACE}
            match_labels:
              "{LABEL_UNION_KEY}": "{LABEL_TRUE}"
              "{LABEL_UNION_EXTRA_KEY}": "{LABEL_TRUE}"
        - integration: "{integration_name}"
          node_selector:
            match_labels:
              "{LABEL_UNION_NODE_KEY}": "{LABEL_TRUE}"
    rules:
      - id: allow-udp-8080
        action: allow
        match:
          proto: udp
          dst_ports: [8080]
"#
    );
    serde_yaml::from_str::<PolicyConfig>(&yaml).map_err(|err| format!("policy yaml error: {err}"))
}

fn policy_priority_dynamic_deny_static_allow(
    integration_name: &str,
    namespace: &str,
    label_key: &str,
    label_value: &str,
    static_ip: Ipv4Addr,
) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: dynamic-deny
    priority: 0
    sources:
      kubernetes:
        - integration: "{integration_name}"
          pod_selector:
            namespace: {namespace}
            match_labels:
              "{label_key}": "{label_value}"
    rules:
      - id: deny-udp-8080
        priority: 0
        action: deny
        match:
          proto: udp
          dst_ports: [8080]
  - id: static-allow
    priority: 1
    sources:
      ips: ["{static_ip}"]
    rules:
      - id: allow-udp-8080
        priority: 0
        action: allow
        match:
          proto: udp
          dst_ports: [8080]
"#
    );
    serde_yaml::from_str::<PolicyConfig>(&yaml).map_err(|err| format!("policy yaml error: {err}"))
}

fn policy_pod_node_churn(integration_name: &str) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: churn
    sources:
      kubernetes:
        - integration: "{integration_name}"
          pod_selector:
            namespace: {TEST_NAMESPACE}
            match_labels:
              "{LABEL_CHURN_POD_KEY}": "{LABEL_TRUE}"
        - integration: "{integration_name}"
          node_selector:
            match_labels:
              "{LABEL_CHURN_NODE_KEY}": "{LABEL_TRUE}"
    rules:
      - id: allow-udp-8080
        action: allow
        match:
          proto: udp
          dst_ports: [8080]
"#
    );
    serde_yaml::from_str::<PolicyConfig>(&yaml).map_err(|err| format!("policy yaml error: {err}"))
}

fn discover_kind_api(cluster_name: &str) -> Result<KindApiConfig, String> {
    let context = format!("kind-{cluster_name}");
    run_kubectl(&context, &["create", "namespace", TEST_NAMESPACE]).or_else(|err| {
        if err.contains("AlreadyExists") {
            Ok(String::new())
        } else {
            Err(err)
        }
    })?;
    run_kubectl(
        &context,
        &[
            "-n",
            TEST_NAMESPACE,
            "create",
            "serviceaccount",
            TEST_SERVICE_ACCOUNT,
        ],
    )
    .or_else(|err| {
        if err.contains("AlreadyExists") {
            Ok(String::new())
        } else {
            Err(err)
        }
    })?;
    run_kubectl(
        &context,
        &[
            "create",
            "clusterrolebinding",
            "neuwerk-e2e-resolver-binding",
            "--clusterrole=cluster-admin",
            &format!(
                "--serviceaccount={}:{}",
                TEST_NAMESPACE, TEST_SERVICE_ACCOUNT
            ),
        ],
    )
    .or_else(|err| {
        if err.contains("AlreadyExists") {
            Ok(String::new())
        } else {
            Err(err)
        }
    })?;
    let token = run_kubectl(
        &context,
        &[
            "-n",
            TEST_NAMESPACE,
            "create",
            "token",
            TEST_SERVICE_ACCOUNT,
            "--duration=2h",
        ],
    )?;

    let kubeconfig = run_cmd("kind", &["get", "kubeconfig", "--name", cluster_name])?;
    let value: serde_yaml::Value = serde_yaml::from_str(&kubeconfig)
        .map_err(|err| format!("invalid kubeconfig yaml: {err}"))?;
    let cluster = value
        .get("clusters")
        .and_then(|clusters| clusters.as_sequence())
        .and_then(|clusters| clusters.first())
        .and_then(|entry| entry.get("cluster"))
        .ok_or_else(|| "kubeconfig missing clusters[0].cluster".to_string())?;
    let server = cluster
        .get("server")
        .and_then(|server| server.as_str())
        .ok_or_else(|| "kubeconfig missing server".to_string())?
        .to_string();
    let ca_data = cluster
        .get("certificate-authority-data")
        .and_then(|ca| ca.as_str())
        .ok_or_else(|| "kubeconfig missing certificate-authority-data".to_string())?;
    let ca_pem = BASE64_STANDARD
        .decode(ca_data.trim())
        .map_err(|err| format!("invalid certificate-authority-data: {err}"))?;
    let ca_pem = String::from_utf8(ca_pem).map_err(|err| format!("invalid ca pem utf8: {err}"))?;

    Ok(KindApiConfig {
        context,
        server,
        ca_pem,
        token: token.trim().to_string(),
    })
}

fn first_node_name(context: &str) -> Result<String, String> {
    let output = run_kubectl(context, &["get", "nodes", "-o", "json"])?;
    let value: serde_json::Value =
        serde_json::from_str(&output).map_err(|err| format!("invalid nodes json: {err}"))?;
    let name = value
        .get("items")
        .and_then(|items| items.as_array())
        .and_then(|items| items.first())
        .and_then(|item| item.get("metadata"))
        .and_then(|meta| meta.get("name"))
        .and_then(|name| name.as_str())
        .ok_or_else(|| "no nodes found".to_string())?;
    Ok(name.to_string())
}

fn create_pod(
    context: &str,
    namespace: &str,
    pod_name: &str,
    labels: &[(&str, &str)],
) -> Result<(), String> {
    let mut args = vec![
        "-n",
        namespace,
        "run",
        pod_name,
        "--image",
        POD_IMAGE,
        "--restart=Never",
    ];
    let labels_arg = labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    if !labels_arg.is_empty() {
        args.push("--labels");
        args.push(labels_arg.as_str());
    }
    run_kubectl(context, &args)?;
    Ok(())
}

fn delete_pod(context: &str, namespace: &str, pod_name: &str) -> Result<(), String> {
    run_kubectl(
        context,
        &[
            "-n",
            namespace,
            "delete",
            "pod",
            pod_name,
            "--ignore-not-found=true",
            "--wait=true",
            "--timeout=60s",
        ],
    )?;
    Ok(())
}

fn label_pod(
    context: &str,
    namespace: &str,
    pod_name: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    run_kubectl(
        context,
        &[
            "-n",
            namespace,
            "label",
            "pod",
            pod_name,
            &format!("{key}={value}"),
            "--overwrite",
        ],
    )?;
    Ok(())
}

fn remove_pod_label(
    context: &str,
    namespace: &str,
    pod_name: &str,
    key: &str,
) -> Result<(), String> {
    run_kubectl(
        context,
        &[
            "-n",
            namespace,
            "label",
            "pod",
            pod_name,
            &format!("{key}-"),
        ],
    )?;
    Ok(())
}

fn label_node(context: &str, node_name: &str, key: &str, value: &str) -> Result<(), String> {
    run_kubectl(
        context,
        &[
            "label",
            "node",
            node_name,
            &format!("{key}={value}"),
            "--overwrite",
        ],
    )?;
    Ok(())
}

fn remove_node_label(context: &str, node_name: &str, key: &str) -> Result<(), String> {
    run_kubectl(context, &["label", "node", node_name, &format!("{key}-")])?;
    Ok(())
}

fn cleanup_labels(context: &str, namespace: &str, pod_name: &str, node_name: &str) {
    let labels = [
        LABEL_POD_BASE_KEY,
        LABEL_STALE_KEY,
        LABEL_NAMESPACE_KEY,
        LABEL_UNION_KEY,
        LABEL_UNION_EXTRA_KEY,
        LABEL_PRIORITY_KEY,
        LABEL_CHURN_POD_KEY,
    ];
    for key in labels {
        let _ = remove_pod_label(context, namespace, pod_name, key);
    }
    let node_labels = [
        LABEL_NODE_BASE_KEY,
        LABEL_UNION_NODE_KEY,
        LABEL_CHURN_NODE_KEY,
    ];
    for key in node_labels {
        let _ = remove_node_label(context, node_name, key);
    }
}

fn current_dynamic_ips(policy_store: &PolicyStore) -> BTreeSet<Ipv4Addr> {
    policy_store
        .kubernetes_bindings()
        .into_iter()
        .next()
        .map(|binding| {
            binding
                .dynamic_set
                .ips()
                .into_iter()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default()
}

async fn wait_for_binding_count(
    policy_store: &PolicyStore,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if policy_store.kubernetes_bindings().len() == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for {expected} kubernetes bindings (current={})",
                policy_store.kubernetes_bindings().len()
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_dynamic_ip_count(
    policy_store: &PolicyStore,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let count = current_dynamic_ips(policy_store).len();
        if count == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for dynamic ip count {expected} (current={count})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_any_dynamic_ip(
    policy_store: &PolicyStore,
    timeout: Duration,
) -> Result<Ipv4Addr, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(ip) = current_dynamic_ips(policy_store).into_iter().next() {
            return Ok(ip);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for any dynamic ip".to_string());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_dynamic_ips_exact(
    policy_store: &PolicyStore,
    expected: BTreeSet<Ipv4Addr>,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let ips = current_dynamic_ips(policy_store);
        if ips == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for dynamic ips {expected:?} (current={ips:?})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_dynamic_ips_contains(
    policy_store: &PolicyStore,
    expected_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let ips = current_dynamic_ips(policy_store);
        if ips.contains(&expected_ip) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for dynamic ip {expected_ip} (current={ips:?})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_pod_ip(
    context: &str,
    namespace: &str,
    pod_name: &str,
    timeout: Duration,
) -> Result<Ipv4Addr, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let output = run_kubectl(
            context,
            &["-n", namespace, "get", "pod", pod_name, "-o", "json"],
        )?;
        let value: serde_json::Value = serde_json::from_str(&output)
            .map_err(|err| format!("invalid pod json for {pod_name}: {err}"))?;
        if let Some(ip) = value
            .get("status")
            .and_then(|status| status.get("podIP"))
            .and_then(|ip| ip.as_str())
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        {
            return Ok(ip);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for pod ip: {namespace}/{pod_name}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn assert_action(label: &str, got: Action, expected: Action) -> Result<(), String> {
    if got == expected {
        Ok(())
    } else {
        Err(format!(
            "{} mismatch: expected {:?}, got {:?}",
            label, expected, got
        ))
    }
}

fn evaluate_packet(
    policy: &Arc<RwLock<PolicySnapshot>>,
    src_ip: Ipv4Addr,
    src_port: u16,
) -> Action {
    let mut state = EngineState::new(policy.clone(), src_ip, 32, Ipv4Addr::new(203, 0, 113, 1), 0);
    set_dataplane_ip(&mut state, src_ip);
    let mut packet = build_ipv4_udp(
        src_ip,
        Ipv4Addr::new(198, 51, 100, 10),
        src_port,
        8080,
        b"kind-e2e",
    );
    handle_packet(&mut packet, &mut state)
}

fn set_dataplane_ip(state: &mut EngineState, ip: Ipv4Addr) {
    state.dataplane_config.set(DataplaneConfig {
        ip,
        prefix: 32,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: [0; 6],
        lease_expiry: None,
    });
}

fn build_ipv4_udp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Packet {
    let total_len = 20 + 8 + payload.len();
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = 17;
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let l4_off = 20;
    buf[l4_off..l4_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[l4_off + 2..l4_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf[l4_off + 4..l4_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[l4_off + 6..l4_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[l4_off + 8..].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    pkt.recalc_checksums();
    pkt
}

fn run_kubectl(context: &str, args: &[&str]) -> Result<String, String> {
    let mut full_args = Vec::with_capacity(args.len() + 2);
    full_args.push("--context");
    full_args.push(context);
    full_args.extend_from_slice(args);
    run_cmd("kubectl", &full_args)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| format!("{cmd} execution failed: {err}"))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{cmd} {:?} failed with status {}:\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
