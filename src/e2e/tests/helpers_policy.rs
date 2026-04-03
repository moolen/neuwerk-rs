#![allow(clippy::format_in_format_args)]

use super::*;

pub(in crate::e2e::tests) fn policy_allow_cluster_deny_foo() -> &'static str {
    r#"default_policy: deny
source_groups:
  - id: "client-primary"
    priority: 0
    mode: enforce
    sources:
      ips: ["192.0.2.2"]
      cidrs: ["10.0.0.0/24"]
    rules:
      - id: "allow-cluster"
        priority: 0
        action: allow
        match:
          dns_hostname: '^cluster\.allowed$'
      - id: "deny-foo"
        priority: 1
        action: deny
        match:
          dns_hostname: '^foo\.allowed$'
  - id: "client-secondary"
    priority: 1
    mode: enforce
    sources:
      ips: ["192.0.2.3"]
    rules:
      - id: "allow-bar"
        action: allow
        match:
          dns_hostname: '^bar\.allowed$'
"#
}

pub(in crate::e2e::tests) fn policy_allow_spoof() -> &'static str {
    r#"default_policy: deny
source_groups:
  - id: "client-primary"
    priority: 0
    mode: enforce
    sources:
      ips: ["192.0.2.2"]
      cidrs: ["10.0.0.0/24"]
    rules:
      - id: "allow-spoof"
        priority: 0
        action: allow
        match:
          dns_hostname: '^spoof(-fail)?\.allowed$'
"#
}

pub(in crate::e2e::tests) fn policy_allow_foo_deny_cluster() -> &'static str {
    r#"default_policy: deny
source_groups:
  - id: "client-primary"
    priority: 0
    mode: enforce
    sources:
      ips: ["192.0.2.2"]
      cidrs: ["10.0.0.0/24"]
    rules:
      - id: "allow-foo"
        priority: 0
        action: allow
        match:
          dns_hostname: '^foo\.allowed$'
      - id: "deny-cluster"
        priority: 1
        action: deny
        match:
          dns_hostname: '^cluster\.allowed$'
  - id: "client-secondary"
    priority: 1
    mode: enforce
    sources:
      ips: ["192.0.2.3"]
    rules:
      - id: "allow-bar"
        action: allow
        match:
          dns_hostname: '^bar\.allowed$'
"#
}

pub(in crate::e2e::tests) fn parse_policy(yaml: &str) -> Result<PolicyConfig, String> {
    serde_yaml::from_str(yaml).map_err(|e| format!("policy yaml error: {e}"))
}

pub(in crate::e2e::tests) fn wait_for_path(
    path: &std::path::Path,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(format!("timed out waiting for {}", path.display()))
}

#[allow(dead_code)]
pub(in crate::e2e::tests) fn read_active_id(path: &std::path::Path) -> Result<uuid::Uuid, String> {
    let payload = std::fs::read(path).map_err(|e| format!("read active policy failed: {e}"))?;
    let active: PolicyActive =
        serde_json::from_slice(&payload).map_err(|e| format!("active json error: {e}"))?;
    Ok(active.id)
}

#[allow(dead_code)]
pub(in crate::e2e::tests) fn wait_for_active_id(
    path: &std::path::Path,
    expected: uuid::Uuid,
    timeout: Duration,
) -> Result<uuid::Uuid, String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(active) = read_active_id(path) {
            if active == expected {
                return Ok(active);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for active policy {}; path={}",
                expected,
                path.display()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

pub(in crate::e2e::tests) fn read_stored_policy(
    path: &std::path::Path,
) -> Result<crate::controlplane::policy_repository::StoredPolicy, String> {
    let payload = std::fs::read(path).map_err(|e| format!("read stored policy failed: {e}"))?;
    serde_json::from_slice(&payload).map_err(|e| format!("stored policy json error: {e}"))
}

pub(in crate::e2e::tests) fn policies_equal(
    left: &PolicyConfig,
    right: &PolicyConfig,
) -> Result<bool, String> {
    let left = serde_json::to_value(left).map_err(|e| format!("policy json encode failed: {e}"))?;
    let right =
        serde_json::to_value(right).map_err(|e| format!("policy json encode failed: {e}"))?;
    Ok(left == right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_for_active_id_observes_updated_active_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("active.json");
        let initial = PolicyActive {
            id: uuid::Uuid::new_v4(),
        };
        let expected = uuid::Uuid::new_v4();
        std::fs::write(
            &path,
            serde_json::to_vec(&initial).expect("serialize active"),
        )
        .expect("write initial active");

        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let updated = PolicyActive { id: expected };
            std::fs::write(
                &writer_path,
                serde_json::to_vec(&updated).expect("serialize updated active"),
            )
            .expect("write updated active");
        });

        let observed = wait_for_active_id(&path, expected, Duration::from_secs(1))
            .expect("wait for active id");
        writer.join().expect("join writer");
        assert_eq!(observed, expected);
    }

    #[test]
    fn wait_for_active_id_times_out_when_expected_id_never_arrives() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("active.json");
        let current = PolicyActive {
            id: uuid::Uuid::new_v4(),
        };
        let expected = uuid::Uuid::new_v4();
        std::fs::write(
            &path,
            serde_json::to_vec(&current).expect("serialize active"),
        )
        .expect("write active");

        let err = wait_for_active_id(&path, expected, Duration::from_millis(100))
            .expect_err("expected timeout");
        assert!(err.contains("timed out waiting for active policy"));
        assert!(err.contains(&expected.to_string()));
    }
}

#[allow(dead_code)]
pub(in crate::e2e::tests) fn parse_created_at(
    record: &PolicyRecord,
) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(&record.created_at, &Rfc3339)
        .map_err(|e| format!("invalid created_at {}: {e}", record.created_at))
}

pub(in crate::e2e::tests) fn metric_value(
    body: &str,
    path: &str,
    method: &str,
    status: &str,
) -> Option<f64> {
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with("http_requests_total{") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let labels = parts.next()?;
        let value = parts.next()?;
        let labels = labels
            .strip_prefix("http_requests_total{")?
            .strip_suffix('}')?;

        if !label_matches(labels, "path", path) {
            continue;
        }
        if !label_matches(labels, "method", method) {
            continue;
        }
        if !label_matches(labels, "status", status) {
            continue;
        }

        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

pub(in crate::e2e::tests) fn metric_value_with_labels(
    body: &str,
    metric: &str,
    labels: &[(&str, &str)],
) -> Option<f64> {
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with(metric) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let labels_raw = parts.next()?;
        let value = parts.next()?;
        let labels_raw = labels_raw
            .strip_prefix(&format!("{metric}{{"))?
            .strip_suffix('}')?;

        let mut matches = true;
        for (key, expected) in labels {
            if !label_matches(labels_raw, key, expected) {
                matches = false;
                break;
            }
        }
        if !matches {
            continue;
        }
        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

pub(in crate::e2e::tests) fn metric_plain_value(body: &str, metric: &str) -> Option<f64> {
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with(metric) {
            continue;
        }
        let rest = &line[metric.len()..];
        if rest.starts_with('{') {
            continue;
        }
        if !rest.starts_with(' ') && !rest.starts_with('\t') {
            continue;
        }
        let value = rest.split_whitespace().next()?;
        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

pub(in crate::e2e::tests) fn label_matches(labels: &str, key: &str, expected: &str) -> bool {
    for label in labels.split(',') {
        let mut iter = label.splitn(2, '=');
        let k = match iter.next() {
            Some(value) => value.trim(),
            None => continue,
        };
        let v = match iter.next() {
            Some(value) => value.trim(),
            None => continue,
        };
        if k == key {
            return v.trim_matches('"') == expected;
        }
    }
    false
}

pub(in crate::e2e::tests) fn http_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

pub(in crate::e2e::tests) async fn http_get_path_bound(
    addr: SocketAddr,
    host: &str,
    path: &str,
    bind_ip: Ipv4Addr,
) -> Result<String, String> {
    let socket = TcpSocket::new_v4().map_err(|e| format!("socket error: {e}"))?;
    socket
        .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .map_err(|e| format!("bind error: {e}"))?;
    let mut stream = tokio::time::timeout(Duration::from_secs(1), socket.connect(addr))
        .await
        .map_err(|_| "http connect timed out".to_string())?
        .map_err(|e| format!("http connect failed: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("http write failed: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("http read failed: {e}"))?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

pub(in crate::e2e::tests) fn read_cert_sans(path: &std::path::Path) -> Result<Vec<IpAddr>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("read cert failed: {e}"))?;
    let (_, pem) = parse_x509_pem(&pem).map_err(|e| format!("parse pem failed: {e}"))?;
    let (_, cert) = parse_x509_certificate(&pem.contents).map_err(|e| format!("{e}"))?;
    let mut ips = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in san.general_names.iter() {
                if let GeneralName::IPAddress(raw) = name {
                    if raw.len() == 4 {
                        let ip = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
                        ips.push(ip);
                    }
                }
            }
        }
    }
    Ok(ips)
}

pub(in crate::e2e::tests) fn allowlist_gc_delay(cfg: &TopologyConfig) -> Duration {
    let secs = cfg
        .dns_allowlist_idle_secs
        .saturating_add(cfg.dns_allowlist_gc_interval_secs)
        .saturating_add(1);
    Duration::from_secs(secs.max(1))
}

pub(in crate::e2e::tests) fn tls_sni_policy(
    cfg: &TopologyConfig,
    sni: &str,
) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "tls"
    priority: 0
    mode: enforce
    sources:
      ips: ["{client_ip}"]
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-tls-sni"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [443]
          tls:
            sni:
              exact: ["{sni}"]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        client_ip = cfg.client_mgmt_ip,
        dst_ip = cfg.up_dp_ip,
        sni = sni
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

pub(in crate::e2e::tests) fn tls_cert_policy(cfg: &TopologyConfig) -> Result<PolicyConfig, String> {
    tls_cert_policy_with(cfg, "foo.allowed", "deny")
}

pub(in crate::e2e::tests) fn tls_cert_policy_with(
    cfg: &TopologyConfig,
    san: &str,
    tls13_uninspectable: &str,
) -> Result<PolicyConfig, String> {
    let ca_pem = std::fs::read_to_string(&cfg.upstream_tls_ca_path)
        .map_err(|e| format!("read upstream ca failed: {e}"))?;
    let ca_block = indent_lines(&ca_pem, 16);
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "tls"
    priority: 0
    mode: enforce
    sources:
      ips: ["{client_ip}"]
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-tls-cert"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [443]
          tls:
            server_san:
              exact: ["{san}"]
            trust_anchors_pem:
              - |
{ca_block}
            tls13_uninspectable: {tls13_uninspectable}
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        client_ip = cfg.client_mgmt_ip,
        dst_ip = cfg.up_dp_ip,
        san = san,
        ca_block = ca_block,
        tls13_uninspectable = tls13_uninspectable
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

pub(in crate::e2e::tests) fn tls_intercept_policy(
    cfg: &TopologyConfig,
) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "tls-intercept"
    mode: enforce
    sources:
      ips: ["{client_ip}"]
      cidrs: ["{internal}/24"]
    rules:
      - id: "intercept-http"
        action: allow
        match:
          proto: tcp
          dst_ports: [443]
          tls:
            mode: intercept
            http:
              request:
                host:
                  exact: ["foo.allowed"]
                methods: ["GET"]
                path:
                  prefix: ["/external-secrets/"]
"#,
        internal = cfg.client_dp_ip,
        client_ip = cfg.client_mgmt_ip
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

pub(in crate::e2e::tests) fn tls_intercept_policy_with_response_deny(
    cfg: &TopologyConfig,
) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "tls-intercept"
    mode: enforce
    sources:
      ips: ["{client_ip}"]
      cidrs: ["{internal}/24"]
    rules:
      - id: "intercept-http"
        action: allow
        match:
          proto: tcp
          dst_ports: [443]
          tls:
            mode: intercept
            http:
              request:
                host:
                  exact: ["foo.allowed"]
                methods: ["GET"]
                path:
                  prefix: ["/external-secrets/"]
              response:
                headers:
                  deny_present: ["x-forbidden"]
"#,
        internal = cfg.client_dp_ip,
        client_ip = cfg.client_mgmt_ip
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

pub(in crate::e2e::tests) fn first_line(msg: &str) -> &str {
    msg.split("\r\n").next().unwrap_or(msg)
}

pub(in crate::e2e::tests) fn looks_like_reset(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("reset")
        || lower.contains("broken pipe")
        || lower.contains("refused")
        || lower.contains("closed")
        || lower.contains("timed out")
}

pub(in crate::e2e::tests) fn indent_lines(value: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    value
        .lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(in crate::e2e::tests) fn build_audit_query(
    policy_id: Option<uuid::Uuid>,
    finding_type: Option<&str>,
    source_group: Option<&str>,
    limit: Option<usize>,
) -> Result<String, String> {
    build_audit_query_with_since(policy_id, finding_type, source_group, None, limit)
}

pub(in crate::e2e::tests) fn build_audit_query_with_since(
    policy_id: Option<uuid::Uuid>,
    finding_type: Option<&str>,
    source_group: Option<&str>,
    since: Option<u64>,
    limit: Option<usize>,
) -> Result<String, String> {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(id) = policy_id {
        params.push(("policy_id".to_string(), id.to_string()));
    }
    if let Some(value) = finding_type {
        params.push(("finding_type".to_string(), value.to_string()));
    }
    if let Some(value) = source_group {
        params.push(("source_group".to_string(), value.to_string()));
    }
    if let Some(value) = since {
        params.push(("since".to_string(), value.to_string()));
    }
    if let Some(value) = limit {
        params.push(("limit".to_string(), value.to_string()));
    }
    serde_urlencoded::to_string(params).map_err(|err| err.to_string())
}

pub(in crate::e2e::tests) async fn wait_for_audit_findings(
    api_addr: SocketAddr,
    tls_dir: &std::path::Path,
    token: &str,
    query: &str,
    timeout: Duration,
) -> Result<AuditQueryResponse, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match http_get_audit_findings(api_addr, tls_dir, Some(query), Some(token)).await {
            Ok(resp) if !resp.items.is_empty() => return Ok(resp),
            Ok(_) => {}
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(err);
                }
            }
        }
        if Instant::now() >= deadline {
            let broad = http_get_audit_findings(api_addr, tls_dir, Some("limit=50"), Some(token))
                .await
                .map(|resp| resp.items)
                .unwrap_or_default();
            let typed = http_get_audit_findings(
                api_addr,
                tls_dir,
                Some("finding_type=tls_deny&limit=50"),
                Some(token),
            )
            .await
            .map(|resp| resp.items)
            .unwrap_or_default();
            return Err(format!(
                "timed out waiting for audit findings with query={query}; tls_deny_items={typed:?}; all_items={broad:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(in crate::e2e::tests) fn has_audit_finding(
    items: &[AuditFinding],
    finding_type: AuditFindingType,
    source_group: &str,
) -> bool {
    items
        .iter()
        .any(|item| item.finding_type == finding_type && item.source_group == source_group)
}
