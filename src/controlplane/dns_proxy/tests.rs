use super::*;
use crate::controlplane::metrics::Metrics;
use crate::controlplane::policy_config::{DnsRule, DnsSourceGroup};
use crate::controlplane::PolicyStore;
use crate::dataplane::policy::{
    DefaultPolicy, EnforcementMode, IpSetV4, RuleAction, RuleMode as DataplaneRuleMode,
};
use regex::Regex;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamMode {
    Valid(Ipv4Addr),
    TxIdMismatch(Ipv4Addr),
    QuestionMismatch(Ipv4Addr),
}

async fn spawn_test_upstream(mode: UpstreamMode) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let req = &buf[..len];
        let response = match mode {
            UpstreamMode::Valid(ip) => {
                let q = parse_dns_question(req).unwrap();
                build_dns_response(&q.name, ip)
            }
            UpstreamMode::TxIdMismatch(ip) => {
                let q = parse_dns_question(req).unwrap();
                let mut resp = build_dns_response(&q.name, ip);
                resp[0] = 0x33;
                resp[1] = 0x44;
                resp
            }
            UpstreamMode::QuestionMismatch(ip) => build_dns_response("other.allowed", ip),
        };
        let _ = socket.send_to(&response, peer).await;
    });
    (addr, handle)
}

fn build_dns_query(name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x12, 0x34]); // id
    msg.extend_from_slice(&[0x01, 0x00]); // flags
    msg.extend_from_slice(&[0x00, 0x01]); // qdcount
    msg.extend_from_slice(&[0x00, 0x00]); // ancount
    msg.extend_from_slice(&[0x00, 0x00]); // nscount
    msg.extend_from_slice(&[0x00, 0x00]); // arcount
    for label in name.trim_end_matches('.').split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x01]); // qtype A
    msg.extend_from_slice(&[0x00, 0x01]); // qclass IN
    msg
}

fn build_dns_response(name: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x12, 0x34]); // id
    msg.extend_from_slice(&[0x81, 0x80]); // flags
    msg.extend_from_slice(&[0x00, 0x01]); // qdcount
    msg.extend_from_slice(&[0x00, 0x01]); // ancount
    msg.extend_from_slice(&[0x00, 0x00]); // nscount
    msg.extend_from_slice(&[0x00, 0x00]); // arcount
    for label in name.trim_end_matches('.').split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x01]); // qtype A
    msg.extend_from_slice(&[0x00, 0x01]); // qclass IN

    msg.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
    msg.extend_from_slice(&[0x00, 0x01]); // type A
    msg.extend_from_slice(&[0x00, 0x01]); // class IN
    msg.extend_from_slice(&60u32.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x04]); // rdlen
    msg.extend_from_slice(&ip.octets());
    msg
}

fn single_group_policy(rules: Vec<DnsRule>) -> DnsPolicy {
    let mut sources = IpSetV4::new();
    sources.add_ip(Ipv4Addr::new(192, 0, 2, 2));
    DnsPolicy::new(vec![DnsSourceGroup {
        id: "client-primary".to_string(),
        priority: 0,
        sources,
        rules,
    }])
}

fn dns_rule(
    id: &str,
    priority: u32,
    action: RuleAction,
    mode: DataplaneRuleMode,
    host_re: &str,
) -> DnsRule {
    DnsRule {
        id: id.to_string(),
        priority,
        action,
        mode,
        hostname: Regex::new(host_re).unwrap(),
    }
}

#[test]
fn skip_name_handles_root() {
    let msg = [0u8, 0u8];
    assert_eq!(skip_name(&msg, 0), Some(1));
}

#[test]
fn parse_dns_query_name_handles_long_labels() {
    let name = format!("{}.{}.example.com", "a".repeat(63), "b".repeat(63));
    let query = build_dns_query(&name);
    let parsed = parse_dns_question(&query).unwrap();
    assert_eq!(parsed.name, name);
}

#[test]
fn build_nxdomain_preserves_id_and_question() {
    let query = build_dns_query("foo.allowed");
    let response = build_nxdomain(&query);
    assert!(response.len() >= 12);
    assert_eq!(&response[0..2], &query[0..2]);
    assert_eq!(response[3] & 0x0f, 3);
    let qdcount = read_u16(&response, 4).unwrap();
    assert_eq!(qdcount, 1);
}

#[test]
fn extract_ips_populates_dns_map() {
    let ip = Ipv4Addr::new(93, 184, 216, 34);
    let response = build_dns_response("Example.COM.", ip);
    let ips = extract_ips_from_dns_response(&response);
    assert_eq!(ips, vec![IpAddr::V4(ip)]);

    let map = DnsMap::new();
    let v4s: Vec<Ipv4Addr> = ips
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();
    map.insert_many("Example.COM.", &v4s, 42);
    assert_eq!(map.lookup(ip), Some("example.com".to_string()));
}

#[test]
fn dns_rcode_detects_nxdomain() {
    let query = build_dns_query("foo.allowed");
    let response = build_nxdomain(&query);
    assert_eq!(dns_rcode(&response), Some(3));
    assert!(is_nxdomain(&response));
}

#[test]
fn dns_rcode_handles_success() {
    let ip = Ipv4Addr::new(203, 0, 113, 1);
    let response = build_dns_response("example.com.", ip);
    assert_eq!(dns_rcode(&response), Some(0));
    assert!(!is_nxdomain(&response));
}

#[test]
fn evaluate_dns_policy_decision_enforce_mode_denies() {
    let policy = std::sync::Arc::new(std::sync::RwLock::new(DnsPolicy::new(Vec::new())));
    let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let (allowed, would_deny, source_group) = evaluate_dns_policy_decision(
        &policy,
        Some(&store),
        Ipv4Addr::new(192, 0, 2, 2),
        "foo.allowed",
    );
    assert!(!allowed);
    assert!(would_deny);
    assert_eq!(source_group, "default");
}

#[test]
fn evaluate_dns_policy_decision_audit_mode_passthroughs_raw_deny() {
    let policy = std::sync::Arc::new(std::sync::RwLock::new(DnsPolicy::new(Vec::new())));
    let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    store
        .rebuild(
            Vec::new(),
            DnsPolicy::new(Vec::new()),
            None,
            EnforcementMode::Audit,
        )
        .unwrap();
    let (allowed, would_deny, source_group) = evaluate_dns_policy_decision(
        &policy,
        Some(&store),
        Ipv4Addr::new(192, 0, 2, 2),
        "foo.allowed",
    );
    assert!(allowed);
    assert!(would_deny);
    assert_eq!(source_group, "default");
}

#[test]
fn evaluate_dns_policy_decision_marks_audit_rule_deny_without_blocking() {
    let policy = std::sync::Arc::new(std::sync::RwLock::new(single_group_policy(vec![
        dns_rule(
            "allow-enforce",
            0,
            RuleAction::Allow,
            DataplaneRuleMode::Enforce,
            r"^foo\.allowed$",
        ),
        dns_rule(
            "deny-audit",
            1,
            RuleAction::Deny,
            DataplaneRuleMode::Audit,
            r"^foo\.allowed$",
        ),
    ])));
    let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let (allowed, would_deny, source_group) = evaluate_dns_policy_decision(
        &policy,
        Some(&store),
        Ipv4Addr::new(192, 0, 2, 2),
        "foo.allowed",
    );
    assert!(allowed);
    assert!(would_deny);
    assert_eq!(source_group, "client-primary");
}

#[tokio::test(flavor = "current_thread")]
async fn udp_upstream_failover_recovers_after_mismatch() {
    let request = build_dns_query("spoof.allowed");
    let question = parse_dns_question(&request).unwrap();
    let metrics = Metrics::new().unwrap();

    let (bad_addr, bad_task) =
        spawn_test_upstream(UpstreamMode::TxIdMismatch(Ipv4Addr::new(203, 0, 113, 10))).await;
    let expected = Ipv4Addr::new(203, 0, 113, 11);
    let (good_addr, good_task) = spawn_test_upstream(UpstreamMode::Valid(expected)).await;

    let response = forward_dns_query_udp(
        &request,
        &question,
        &[bad_addr, good_addr],
        "unit",
        &metrics,
    )
    .await
    .expect("query should succeed via fallback upstream");
    assert_eq!(
        extract_ips_from_dns_response(&response),
        vec![IpAddr::V4(expected)]
    );

    let _ = bad_task.await;
    let _ = good_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn udp_upstream_failover_returns_mismatch_when_all_invalid() {
    let request = build_dns_query("spoof.allowed");
    let question = parse_dns_question(&request).unwrap();
    let metrics = Metrics::new().unwrap();

    let (bad_txid_addr, bad_txid_task) =
        spawn_test_upstream(UpstreamMode::TxIdMismatch(Ipv4Addr::new(203, 0, 113, 12))).await;
    let (bad_question_addr, bad_question_task) = spawn_test_upstream(
        UpstreamMode::QuestionMismatch(Ipv4Addr::new(203, 0, 113, 13)),
    )
    .await;

    let result = forward_dns_query_udp(
        &request,
        &question,
        &[bad_txid_addr, bad_question_addr],
        "unit",
        &metrics,
    )
    .await;
    assert_eq!(result, Err(UpstreamQueryError::Mismatch));

    let _ = bad_txid_task.await;
    let _ = bad_question_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn startup_status_reports_empty_upstream_error() {
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (startup_tx, startup_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();

    let result = run_dns_proxy(
        bind_addr,
        Vec::new(),
        DynamicIpSetV4::new(),
        std::sync::Arc::new(std::sync::RwLock::new(DnsPolicy::new(Vec::new()))),
        DnsMap::new(),
        Metrics::new().unwrap(),
        None,
        None,
        "node-test".to_string(),
        Some(startup_tx),
    )
    .await;
    assert!(result.is_err());

    let startup = startup_rx
        .await
        .expect("startup channel should be reported");
    assert!(startup.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn startup_status_reports_bind_error() {
    let occupied = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let bind_addr = occupied.local_addr().unwrap();
    let (startup_tx, startup_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();

    let result = run_dns_proxy(
        bind_addr,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
        DynamicIpSetV4::new(),
        std::sync::Arc::new(std::sync::RwLock::new(DnsPolicy::new(Vec::new()))),
        DnsMap::new(),
        Metrics::new().unwrap(),
        None,
        None,
        "node-test".to_string(),
        Some(startup_tx),
    )
    .await;
    assert!(result.is_err());

    let startup = startup_rx
        .await
        .expect("startup channel should be reported");
    assert!(startup.is_err());
}
