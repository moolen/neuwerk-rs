use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use neuwerk::controlplane::integrations::IntegrationStore;
use neuwerk::controlplane::kubernetes::run_kubernetes_resolver;
use neuwerk::controlplane::policy_config::PolicyConfig;
use neuwerk::controlplane::PolicyStore;
use neuwerk::dataplane::config::DataplaneConfig;
use neuwerk::dataplane::policy::{DefaultPolicy, PolicySnapshot};
use neuwerk::dataplane::{handle_packet, Action, EngineState, Packet};

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

include!("e2e_kind_harness/k8s_helpers.rs");
