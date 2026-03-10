use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use futures::StreamExt;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::Value;

use crate::controlplane::integrations::{IntegrationKind, IntegrationStore};
use crate::controlplane::policy_config::KubernetesSourceSelector;
use crate::controlplane::PolicyStore;
use crate::dataplane::policy::DynamicIpSetV4;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BindingKey {
    source_group_id: String,
    integration: String,
    selector: KubernetesSourceSelector,
}

#[derive(Clone)]
struct BindingRuntime {
    dynamic_set: DynamicIpSetV4,
}

#[derive(Debug)]
enum WorkerEvent {
    Update {
        key: BindingKey,
        ips: BTreeSet<Ipv4Addr>,
        observed_at: Instant,
    },
    Error {
        key: BindingKey,
        error: String,
    },
}

#[derive(Debug)]
struct BindingState {
    ips: BTreeSet<Ipv4Addr>,
    last_success: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchOutcome {
    Continue,
    Relist,
}

#[derive(Debug, Default)]
struct SelectorState {
    object_ips: HashMap<String, Ipv4Addr>,
    resource_version: Option<String>,
}

pub async fn run_kubernetes_resolver(
    policy_store: PolicyStore,
    integration_store: IntegrationStore,
    stale_grace: Duration,
    reconcile_interval: Duration,
) {
    let mut generation = 0u64;
    let mut workers: HashMap<BindingKey, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut runtimes: HashMap<BindingKey, BindingRuntime> = HashMap::new();
    let mut states: HashMap<BindingKey, BindingState> = HashMap::new();
    let mut source_groups: HashMap<String, Vec<BindingKey>> = HashMap::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<WorkerEvent>(1024);
    let mut ticker = tokio::time::interval(reconcile_interval.max(Duration::from_millis(200)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let current = policy_store.policy_generation();
                if current != generation {
                    generation = current;
                    for (_, handle) in workers.drain() {
                        handle.abort();
                    }
                    runtimes.clear();
                    states.clear();
                    source_groups.clear();

                    let mut seen = HashSet::new();
                    for binding in policy_store.kubernetes_bindings() {
                        let key = BindingKey {
                            source_group_id: binding.source_group_id.clone(),
                            integration: binding.integration.clone(),
                            selector: binding.selector.clone(),
                        };
                        let inserted = seen.insert(key.clone());
                        if !inserted {
                            continue;
                        }
                        source_groups
                            .entry(key.source_group_id.clone())
                            .or_default()
                            .push(key.clone());
                        runtimes.insert(
                            key.clone(),
                            BindingRuntime {
                                dynamic_set: binding.dynamic_set.clone(),
                            },
                        );
                        let tx_clone = tx.clone();
                        let integrations = integration_store.clone();
                        let worker_key = key.clone();
                        let handle = tokio::spawn(async move {
                            run_binding_worker(worker_key, integrations, tx_clone).await;
                        });
                        workers.insert(key, handle);
                    }
                    recompute_all_groups(&runtimes, &source_groups, &states);
                }

                let now = Instant::now();
                let mut changed_groups = HashSet::new();
                for (key, state) in &mut states {
                    if now.duration_since(state.last_success) > stale_grace && !state.ips.is_empty() {
                        state.ips.clear();
                        changed_groups.insert(key.source_group_id.clone());
                    }
                }
                for group in changed_groups {
                    recompute_group(&group, &runtimes, &source_groups, &states);
                }
            }
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    continue;
                };
                match event {
                    WorkerEvent::Update { key, ips, observed_at } => {
                        if !runtimes.contains_key(&key) {
                            continue;
                        }
                        let entry = states.entry(key.clone()).or_insert_with(|| BindingState {
                            ips: BTreeSet::new(),
                            last_success: observed_at,
                        });
                        let changed = entry.ips != ips;
                        entry.ips = ips;
                        entry.last_success = observed_at;
                        if changed {
                            recompute_group(&key.source_group_id, &runtimes, &source_groups, &states);
                        }
                    }
                    WorkerEvent::Error { key, error } => {
                        if !runtimes.contains_key(&key) {
                            continue;
                        }
                        tracing::warn!(
                            source_group_id = %key.source_group_id,
                            integration = %key.integration,
                            error = %error,
                            "kubernetes resolver refresh failed"
                        );
                    }
                }
            }
        }
    }
}

fn recompute_all_groups(
    runtimes: &HashMap<BindingKey, BindingRuntime>,
    source_groups: &HashMap<String, Vec<BindingKey>>,
    states: &HashMap<BindingKey, BindingState>,
) {
    for group in source_groups.keys() {
        recompute_group(group, runtimes, source_groups, states);
    }
}

fn recompute_group(
    source_group_id: &str,
    runtimes: &HashMap<BindingKey, BindingRuntime>,
    source_groups: &HashMap<String, Vec<BindingKey>>,
    states: &HashMap<BindingKey, BindingState>,
) {
    let Some(keys) = source_groups.get(source_group_id) else {
        return;
    };
    let mut union = BTreeSet::new();
    let mut target_set: Option<DynamicIpSetV4> = None;
    for key in keys {
        if let Some(runtime) = runtimes.get(key) {
            if target_set.is_none() {
                target_set = Some(runtime.dynamic_set.clone());
            }
        }
        if let Some(state) = states.get(key) {
            union.extend(state.ips.iter().copied());
        }
    }
    if let Some(dynamic_set) = target_set {
        dynamic_set.clear();
        dynamic_set.insert_many(union);
    }
}

async fn run_binding_worker(
    key: BindingKey,
    integration_store: IntegrationStore,
    tx: tokio::sync::mpsc::Sender<WorkerEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let record = match integration_store
            .get_by_name_kind(&key.integration, IntegrationKind::Kubernetes)
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => {
                let _ = tx
                    .send(WorkerEvent::Error {
                        key: key.clone(),
                        error: "integration not found".to_string(),
                    })
                    .await;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(15));
                continue;
            }
            Err(err) => {
                let _ = tx
                    .send(WorkerEvent::Error {
                        key: key.clone(),
                        error: err,
                    })
                    .await;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(15));
                continue;
            }
        };

        let ca = match reqwest::Certificate::from_pem(record.ca_cert_pem.as_bytes()) {
            Ok(ca) => ca,
            Err(err) => {
                let _ = tx
                    .send(WorkerEvent::Error {
                        key: key.clone(),
                        error: format!("invalid ca pem: {err}"),
                    })
                    .await;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(15));
                continue;
            }
        };
        let client = match reqwest::Client::builder()
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(20))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                let _ = tx
                    .send(WorkerEvent::Error {
                        key: key.clone(),
                        error: format!("client build failed: {err}"),
                    })
                    .await;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(15));
                continue;
            }
        };

        match list_and_watch_forever(
            &client,
            &record.api_server_url,
            &record.service_account_token,
            &key.selector,
            &key,
            &tx,
        )
        .await
        {
            Ok(()) => {
                backoff = Duration::from_secs(1);
            }
            Err(err) => {
                let _ = tx
                    .send(WorkerEvent::Error {
                        key: key.clone(),
                        error: err,
                    })
                    .await;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        }
    }
}

async fn list_and_watch_forever(
    client: &reqwest::Client,
    api_server_url: &str,
    token: &str,
    selector: &KubernetesSourceSelector,
    key: &BindingKey,
    tx: &tokio::sync::mpsc::Sender<WorkerEvent>,
) -> Result<(), String> {
    let (path, query) = selector_request(selector);
    let list_url = format!("{}/{}", api_server_url.trim_end_matches('/'), path);
    let list = request_json(client, &list_url, token, &query).await?;
    let mut state = list_to_state(selector, &list)?;
    let ips = current_ips(&state.object_ips);
    let observed_at = Instant::now();
    tx.send(WorkerEvent::Update {
        key: key.clone(),
        ips,
        observed_at,
    })
    .await
    .map_err(|_| "resolver event channel closed".to_string())?;
    loop {
        let outcome = watch_once(
            client, &list_url, token, &query, selector, key, tx, &mut state,
        )
        .await?;
        match outcome {
            WatchOutcome::Continue => {
                tx.send(WorkerEvent::Update {
                    key: key.clone(),
                    ips: current_ips(&state.object_ips),
                    observed_at: Instant::now(),
                })
                .await
                .map_err(|_| "resolver event channel closed".to_string())?;
            }
            WatchOutcome::Relist => return Ok(()),
        }
    }
}

async fn watch_once(
    client: &reqwest::Client,
    list_url: &str,
    token: &str,
    base_query: &[(String, String)],
    selector: &KubernetesSourceSelector,
    key: &BindingKey,
    tx: &tokio::sync::mpsc::Sender<WorkerEvent>,
    state: &mut SelectorState,
) -> Result<WatchOutcome, String> {
    let mut query = base_query.to_vec();
    query.push(("watch".to_string(), "true".to_string()));
    query.push(("timeoutSeconds".to_string(), "30".to_string()));
    query.push(("allowWatchBookmarks".to_string(), "true".to_string()));
    if let Some(resource_version) = state.resource_version.as_ref() {
        if !resource_version.is_empty() {
            query.push(("resourceVersion".to_string(), resource_version.clone()));
        }
    }

    let response = client
        .get(list_url)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", token.trim()))
        .query(&query)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.status() == StatusCode::GONE {
        return Ok(WatchOutcome::Relist);
    }
    if !response.status().is_success() {
        return Err(format!("watch request failed: {}", response.status()));
    }

    let mut stream = response.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| err.to_string())?;
        buf.extend_from_slice(&chunk);
        while let Some(line) = take_next_line(&mut buf) {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let event: Value = serde_json::from_slice(&line)
                .map_err(|err| format!("watch event parse failed: {err}"))?;
            let event_type = event
                .get("type")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let object = event.get("object").unwrap_or(&Value::Null);

            if event_type.eq_ignore_ascii_case("BOOKMARK") {
                state.resource_version = extract_resource_version(object);
                continue;
            }

            if event_type.eq_ignore_ascii_case("ERROR") {
                let code = object
                    .get("code")
                    .and_then(|value| value.as_u64())
                    .unwrap_or_default();
                if code == 410 {
                    return Ok(WatchOutcome::Relist);
                }
                let message = object
                    .get("message")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown watch error");
                return Err(format!("watch returned error event: {message}"));
            }

            let changed = if matches!(event_type, "ADDED" | "MODIFIED") {
                apply_upsert(selector, &mut state.object_ips, object)
            } else if event_type == "DELETED" {
                apply_delete(&mut state.object_ips, object)
            } else {
                false
            };

            if matches!(event_type, "ADDED" | "MODIFIED" | "DELETED") {
                state.resource_version = extract_resource_version(object);
                if changed {
                    tx.send(WorkerEvent::Update {
                        key: key.clone(),
                        ips: current_ips(&state.object_ips),
                        observed_at: Instant::now(),
                    })
                    .await
                    .map_err(|_| "resolver event channel closed".to_string())?;
                }
            }
        }
    }
    Ok(WatchOutcome::Continue)
}

fn list_to_state(
    selector: &KubernetesSourceSelector,
    list: &Value,
) -> Result<SelectorState, String> {
    let items = list
        .get("items")
        .and_then(|items| items.as_array())
        .ok_or_else(|| "kubernetes list missing items array".to_string())?;
    let mut object_ips = HashMap::new();
    for item in items {
        let Some(uid) = extract_uid(item) else {
            continue;
        };
        let Some(ip) = extract_selected_ipv4(selector, item) else {
            continue;
        };
        object_ips.insert(uid, ip);
    }
    Ok(SelectorState {
        object_ips,
        resource_version: extract_resource_version(list),
    })
}

fn current_ips(object_ips: &HashMap<String, Ipv4Addr>) -> BTreeSet<Ipv4Addr> {
    object_ips.values().copied().collect::<BTreeSet<_>>()
}

fn apply_upsert(
    selector: &KubernetesSourceSelector,
    object_ips: &mut HashMap<String, Ipv4Addr>,
    object: &Value,
) -> bool {
    let Some(uid) = extract_uid(object) else {
        return false;
    };
    if let Some(ip) = extract_selected_ipv4(selector, object) {
        return object_ips.insert(uid, ip) != Some(ip);
    }
    object_ips.remove(&uid).is_some()
}

fn apply_delete(object_ips: &mut HashMap<String, Ipv4Addr>, object: &Value) -> bool {
    let Some(uid) = extract_uid(object) else {
        return false;
    };
    object_ips.remove(&uid).is_some()
}

fn extract_uid(object: &Value) -> Option<String> {
    let uid = object
        .get("metadata")
        .and_then(|meta| meta.get("uid"))
        .and_then(|uid| uid.as_str())?;
    let uid = uid.trim();
    if uid.is_empty() {
        None
    } else {
        Some(uid.to_string())
    }
}

fn extract_resource_version(object: &Value) -> Option<String> {
    let rv = object
        .get("metadata")
        .and_then(|meta| meta.get("resourceVersion"))
        .and_then(|rv| rv.as_str())?;
    let rv = rv.trim();
    if rv.is_empty() {
        None
    } else {
        Some(rv.to_string())
    }
}

fn selector_request(selector: &KubernetesSourceSelector) -> (String, Vec<(String, String)>) {
    match selector {
        KubernetesSourceSelector::Pod {
            namespace,
            match_labels,
        } => {
            let mut query = Vec::new();
            let selector = label_selector(match_labels);
            if !selector.is_empty() {
                query.push(("labelSelector".to_string(), selector));
            }
            (format!("api/v1/namespaces/{namespace}/pods"), query)
        }
        KubernetesSourceSelector::Node { match_labels } => {
            let mut query = Vec::new();
            let selector = label_selector(match_labels);
            if !selector.is_empty() {
                query.push(("labelSelector".to_string(), selector));
            }
            ("api/v1/nodes".to_string(), query)
        }
    }
}

fn label_selector(labels: &BTreeMap<String, String>) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

async fn request_json(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    query: &[(String, String)],
) -> Result<Value, String> {
    let response = client
        .get(url)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", token.trim()))
        .query(query)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("list request failed: {}", response.status()));
    }
    response
        .json::<Value>()
        .await
        .map_err(|err| err.to_string())
}

fn extract_selected_ipv4(selector: &KubernetesSourceSelector, object: &Value) -> Option<Ipv4Addr> {
    match selector {
        KubernetesSourceSelector::Pod { .. } => object
            .get("status")
            .and_then(|status| status.get("podIP"))
            .and_then(|ip| ip.as_str())
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok()),
        KubernetesSourceSelector::Node { .. } => object
            .get("status")
            .and_then(|status| status.get("addresses"))
            .and_then(|addresses| addresses.as_array())
            .and_then(|addresses| {
                addresses.iter().find_map(|address| {
                    let kind = address.get("type").and_then(|kind| kind.as_str());
                    let value = address.get("address").and_then(|value| value.as_str());
                    if kind == Some("InternalIP") {
                        value.and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                    } else {
                        None
                    }
                })
            }),
    }
}

fn take_next_line(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let idx = buf.iter().position(|byte| *byte == b'\n')?;
    let mut line = buf.drain(..=idx).collect::<Vec<_>>();
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_selector_renders_stably() {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "frontend".to_string());
        labels.insert("tier".to_string(), "web".to_string());
        assert_eq!(label_selector(&labels), "app=frontend,tier=web");
    }

    #[test]
    fn extract_pod_ips_ignores_missing_and_ipv6() {
        let selector = KubernetesSourceSelector::Pod {
            namespace: "default".to_string(),
            match_labels: BTreeMap::new(),
        };
        let value: Value = serde_json::from_str(
            r#"{
                "items": [
                    {
                        "metadata": {"uid": "pod-1"},
                        "status": {"podIP": "10.1.0.2"}
                    },
                    {
                        "metadata": {"uid": "pod-2"},
                        "status": {"podIP": "fd00::1"}
                    },
                    {
                        "metadata": {"uid": "pod-3"},
                        "status": {}
                    }
                ],
                "metadata": {"resourceVersion": "123"}
            }"#,
        )
        .unwrap();
        let state = list_to_state(&selector, &value).unwrap();
        let ips = current_ips(&state.object_ips);
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&Ipv4Addr::new(10, 1, 0, 2)));
        assert_eq!(state.resource_version.as_deref(), Some("123"));
    }

    #[test]
    fn extract_node_internal_ips() {
        let selector = KubernetesSourceSelector::Node {
            match_labels: BTreeMap::new(),
        };
        let value: Value = serde_json::from_str(
            r#"{
                "items": [
                    {
                        "metadata": {"uid": "node-1"},
                        "status": {
                            "addresses": [
                                {"type": "Hostname", "address": "node-a"},
                                {"type": "InternalIP", "address": "10.0.0.10"},
                                {"type": "ExternalIP", "address": "34.1.2.3"}
                            ]
                        }
                    }
                ]
            }"#,
        )
        .unwrap();
        let state = list_to_state(&selector, &value).unwrap();
        let ips = current_ips(&state.object_ips);
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&Ipv4Addr::new(10, 0, 0, 10)));
    }

    #[test]
    fn upsert_and_delete_update_state() {
        let selector = KubernetesSourceSelector::Pod {
            namespace: "default".to_string(),
            match_labels: BTreeMap::new(),
        };
        let mut object_ips = HashMap::new();
        let added: Value = serde_json::from_str(
            r#"{
                "metadata": {"uid": "pod-1"},
                "status": {"podIP": "10.2.0.3"}
            }"#,
        )
        .unwrap();
        assert!(apply_upsert(&selector, &mut object_ips, &added));
        assert_eq!(
            current_ips(&object_ips),
            BTreeSet::from([Ipv4Addr::new(10, 2, 0, 3)])
        );

        let modified: Value = serde_json::from_str(
            r#"{
                "metadata": {"uid": "pod-1"},
                "status": {"podIP": "10.2.0.4"}
            }"#,
        )
        .unwrap();
        assert!(apply_upsert(&selector, &mut object_ips, &modified));
        assert_eq!(
            current_ips(&object_ips),
            BTreeSet::from([Ipv4Addr::new(10, 2, 0, 4)])
        );

        let deleted: Value = serde_json::from_str(r#"{"metadata": {"uid": "pod-1"}}"#).unwrap();
        assert!(apply_delete(&mut object_ips, &deleted));
        assert!(object_ips.is_empty());
    }
}
