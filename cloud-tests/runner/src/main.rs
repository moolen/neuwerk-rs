use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Config {
    api_endpoints: Vec<ApiEndpoint>,
    api_insecure: bool,
    upstream_vip: Ipv4Addr,
    upstream_ip: Ipv4Addr,
    dns_server: SocketAddr,
    dns_zone: String,
    timeout: Duration,
}

#[derive(Debug, Clone)]
struct ApiEndpoint {
    base: String,
    token: String,
}

#[derive(Clone)]
struct ApiClient {
    base: String,
    token: String,
    client: reqwest::blocking::Client,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyRecord {
    id: String,
    created_at: String,
    mode: String,
    policy: Value,
}

#[derive(Debug, Serialize)]
struct PolicyCreateRequest {
    mode: String,
    policy: Value,
}

#[derive(Debug, Serialize)]
struct TestResult {
    name: String,
    status: String,
    duration_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Summary {
    ok: bool,
    duration_ms: u128,
    tests: Vec<TestResult>,
    restore_error: Option<String>,
}

struct Context {
    cfg: Config,
    apis: Vec<ApiClient>,
    originals: Vec<Option<PolicyRecord>>,
    created_ids: Vec<Vec<String>>,
    consumer_ip: Ipv4Addr,
    deadline: Instant,
}

struct TestCase {
    name: &'static str,
    func: fn(&mut Context) -> Result<(), String>,
}

fn main() {
    let mut json_output: Option<String> = None;
    let mut test_filter: Option<String> = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json-output" => {
                json_output = args.next();
                if json_output.is_none() {
                    eprintln!("missing value for --json-output");
                    std::process::exit(2);
                }
            }
            "--tests" => {
                test_filter = args.next();
                if test_filter.is_none() {
                    eprintln!("missing value for --tests");
                    std::process::exit(2);
                }
            }
            "--help" | "-h" => {
                println!(
                    "usage: cloud-policy-smoke [--json-output <path>] [--tests <name1,name2,...>]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let start = Instant::now();
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("config error: {err}");
            std::process::exit(2);
        }
    };

    if let Err(err) = require_bin("dig") {
        eprintln!("missing dependency: {err}");
        std::process::exit(2);
    }
    if let Err(err) = require_bin("curl") {
        eprintln!("missing dependency: {err}");
        std::process::exit(2);
    }
    if let Err(err) = require_bin("iperf3") {
        eprintln!("missing dependency: {err}");
        std::process::exit(2);
    }
    if let Err(err) = require_bin("ping") {
        eprintln!("missing dependency: {err}");
        std::process::exit(2);
    }

    let apis = match cfg
        .api_endpoints
        .iter()
        .map(|endpoint| ApiClient::new(&endpoint.base, &endpoint.token, cfg.api_insecure))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(apis) if !apis.is_empty() => apis,
        Ok(_) => {
            eprintln!("api client error: no policy api base configured");
            std::process::exit(2);
        }
        Err(err) => {
            eprintln!("api client error: {err}");
            std::process::exit(2);
        }
    };

    let consumer_ip = match local_ipv4_for(cfg.upstream_vip) {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("failed to determine consumer ip: {err}");
            std::process::exit(2);
        }
    };

    let originals = match apis
        .iter()
        .map(|api| {
            let mut policies = api.list_policies()?;
            policies.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            Ok::<Option<PolicyRecord>, String>(policies.pop())
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(originals) => originals,
        Err(err) => {
            eprintln!("failed to list policies: {err}");
            std::process::exit(2);
        }
    };

    let deadline = Instant::now() + cfg.timeout;
    let api_count = originals.len();
    let mut ctx = Context {
        cfg,
        apis,
        originals,
        created_ids: vec![Vec::new(); api_count],
        consumer_ip,
        deadline,
    };

    let tests = vec![
        TestCase {
            name: "cidr_port_allow",
            func: test_cidr_port_allow,
        },
        TestCase {
            name: "cidr_port_deny",
            func: test_cidr_port_deny,
        },
        TestCase {
            name: "tls_sni_allow",
            func: test_tls_sni_allow,
        },
        TestCase {
            name: "tls_sni_deny",
            func: test_tls_sni_deny,
        },
        TestCase {
            name: "tls13_uninspectable_deny",
            func: test_tls13_uninspectable_deny,
        },
        TestCase {
            name: "policy_recheck_existing_flow",
            func: test_policy_recheck_existing_flow,
        },
        TestCase {
            name: "metrics_allow_deny_counters",
            func: test_metrics_allow_deny,
        },
        TestCase {
            name: "udp_allow_5201",
            func: test_udp_allow_5201,
        },
        TestCase {
            name: "udp_deny_5201",
            func: test_udp_deny_5201,
        },
        TestCase {
            name: "tcp_allow_udp_deny_same_port",
            func: test_tcp_allow_udp_deny_same_port,
        },
        TestCase {
            name: "udp_policy_swap_allow_to_deny",
            func: test_udp_policy_swap_allow_to_deny,
        },
        TestCase {
            name: "icmp_echo_allow",
            func: test_icmp_echo_allow,
        },
        TestCase {
            name: "icmp_echo_deny",
            func: test_icmp_echo_deny,
        },
        TestCase {
            name: "policy_consistency_all_firewalls",
            func: test_policy_consistency_all_firewalls,
        },
        TestCase {
            name: "metrics_protocol_specific_validation",
            func: test_metrics_protocol_specific_validation,
        },
        TestCase {
            name: "dns_allowlist_allow",
            func: test_dns_allowlist_allow,
        },
        TestCase {
            name: "dns_allowlist_deny",
            func: test_dns_allowlist_deny,
        },
        TestCase {
            name: "dns_allowlist_reset_on_rebuild",
            func: test_dns_allowlist_reset,
        },
    ];

    let mut results = Vec::with_capacity(tests.len());

    let selected_names = parse_test_filter(test_filter.as_deref());
    for test in tests {
        if !selected_names.is_empty() && !selected_names.contains(test.name) {
            continue;
        }
        if Instant::now() > ctx.deadline {
            results.push(TestResult {
                name: test.name.to_string(),
                status: "fail".to_string(),
                duration_ms: 0,
                error: Some("timeout budget exceeded before test start".to_string()),
            });
            continue;
        }
        eprintln!("running test: {}", test.name);
        let test_start = Instant::now();
        let result = (test.func)(&mut ctx);
        let duration_ms = test_start.elapsed().as_millis();
        match result {
            Ok(()) => results.push(TestResult {
                name: test.name.to_string(),
                status: "pass".to_string(),
                duration_ms,
                error: None,
            }),
            Err(err) => results.push(TestResult {
                name: test.name.to_string(),
                status: "fail".to_string(),
                duration_ms,
                error: Some(err),
            }),
        }
    }

    let restore_error = match ctx.restore() {
        Ok(()) => None,
        Err(err) => {
            eprintln!("restore failed: {err}");
            Some(err)
        }
    };

    let ok = restore_error.is_none() && results.iter().all(|r| r.status != "fail");
    let summary = Summary {
        ok,
        duration_ms: start.elapsed().as_millis(),
        tests: results,
        restore_error,
    };

    let json_output_str = match serde_json::to_string_pretty(&summary) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("failed to serialize summary: {err}");
            std::process::exit(2);
        }
    };

    println!("{json_output_str}");
    if let Some(path) = json_output {
        if let Err(err) = std::fs::write(&path, json_output_str.as_bytes()) {
            eprintln!("failed to write json output to {path}: {err}");
            std::process::exit(2);
        }
    }

    if ok {
        std::process::exit(0);
    }
    std::process::exit(1);
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let api_endpoints = parse_api_endpoints()?;
        let api_insecure = env_bool("NEUWERK_POLICY_API_INSECURE").unwrap_or(false);
        let upstream_vip = require_ipv4("NEUWERK_UPSTREAM_VIP")?;
        let upstream_ip = optional_ipv4("NEUWERK_UPSTREAM_IP")?.unwrap_or(upstream_vip);
        let dns_server = require_socket_addr("NEUWERK_DNS_SERVER", 53)?;
        let dns_zone = require_env("NEUWERK_DNS_ZONE")?;
        let timeout_secs = env::var("NEUWERK_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(300);
        Ok(Self {
            api_endpoints,
            api_insecure,
            upstream_vip,
            upstream_ip,
            dns_server,
            dns_zone,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

impl ApiClient {
    fn new(base: &str, token: &str, insecure: bool) -> Result<Self, String> {
        let client = reqwest::blocking::ClientBuilder::new()
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|err| format!("reqwest client build: {err}"))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
            client,
        })
    }

    fn list_policies(&self) -> Result<Vec<PolicyRecord>, String> {
        let url = format!("{}/api/v1/policies", self.base);
        let resp = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .map_err(|err| format!("list policies request failed: {err}"))?;
        if !resp.status().is_success() {
            return Err(format!("list policies status {}", resp.status()));
        }
        resp.json::<Vec<PolicyRecord>>()
            .map_err(|err| format!("list policies decode failed: {err}"))
    }

    fn create_policy(&self, policy: Value) -> Result<PolicyRecord, String> {
        let url = format!("{}/api/v1/policies", self.base);
        let req = PolicyCreateRequest {
            mode: "enforce".to_string(),
            policy,
        };
        let resp = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .json(&req)
            .send()
            .map_err(|err| format!("create policy request failed: {err}"))?;
        if !resp.status().is_success() {
            return Err(format!("create policy status {}", resp.status()));
        }
        resp.json::<PolicyRecord>()
            .map_err(|err| format!("create policy decode failed: {err}"))
    }

    fn update_policy(&self, id: &str, mode: &str, policy: Value) -> Result<PolicyRecord, String> {
        let url = format!("{}/api/v1/policies/{id}", self.base);
        let req = PolicyCreateRequest {
            mode: mode.to_string(),
            policy,
        };
        let resp = self
            .client
            .put(url)
            .bearer_auth(&self.token)
            .json(&req)
            .send()
            .map_err(|err| format!("update policy request failed: {err}"))?;
        if !resp.status().is_success() {
            return Err(format!("update policy status {}", resp.status()));
        }
        resp.json::<PolicyRecord>()
            .map_err(|err| format!("update policy decode failed: {err}"))
    }

    fn delete_policy(&self, id: &str) -> Result<(), String> {
        let url = format!("{}/api/v1/policies/{id}", self.base);
        let resp = self
            .client
            .delete(url)
            .bearer_auth(&self.token)
            .send()
            .map_err(|err| format!("delete policy request failed: {err}"))?;
        if !resp.status().is_success() {
            return Err(format!("delete policy status {}", resp.status()));
        }
        Ok(())
    }

    fn get_metrics(&self) -> Result<String, String> {
        let url = self.metrics_url()?;
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|err| format!("metrics request failed: {err}"))?;
        if !resp.status().is_success() {
            return Err(format!("metrics status {}", resp.status()));
        }
        resp.text()
            .map_err(|err| format!("metrics read failed: {err}"))
    }

    fn metrics_url(&self) -> Result<String, String> {
        let base =
            reqwest::Url::parse(&self.base).map_err(|err| format!("invalid api base: {err}"))?;
        let host = base
            .host_str()
            .ok_or_else(|| "api base missing host".to_string())?;
        Ok(format!("http://{host}:8080/metrics"))
    }
}

impl Context {
    fn apply_policy(&mut self, policy: Value) -> Result<PolicyRecord, String> {
        let mut first_record: Option<PolicyRecord> = None;
        for (idx, api) in self.apis.iter().enumerate() {
            let record = api.create_policy(policy.clone())?;
            self.created_ids[idx].push(record.id.clone());
            if first_record.is_none() {
                first_record = Some(record);
            }
        }
        first_record.ok_or_else(|| "no api clients available".to_string())
    }

    fn restore(&mut self) -> Result<(), String> {
        for (idx, api) in self.apis.iter().enumerate() {
            if let Some(original) = &self.originals[idx] {
                let _ = api.update_policy(&original.id, &original.mode, original.policy.clone())?;
            }
        }
        for (idx, api) in self.apis.iter().enumerate() {
            for id in &self.created_ids[idx] {
                if let Err(err) = api.delete_policy(id) {
                    eprintln!("warning: failed to delete policy {id}: {err}");
                }
            }
        }
        Ok(())
    }

    fn get_metrics(&self) -> Result<String, String> {
        let mut merged = String::new();
        for api in &self.apis {
            let body = api.get_metrics()?;
            merged.push_str(&body);
            merged.push('\n');
        }
        Ok(merged)
    }
}

fn test_dns_allowlist_allow(ctx: &mut Context) -> Result<(), String> {
    let host_regex = hostname_regex(&ctx.cfg.dns_zone);
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_dns("dns-allow", "allow", &host_regex)],
    );
    ctx.apply_policy(policy)?;

    let result = dig_query(&ctx.cfg, &ctx.cfg.dns_zone)?;
    if result.status != "NOERROR" {
        return Err(format!("dns status {}, expected NOERROR", result.status));
    }
    if !result.answers.contains(&ctx.cfg.upstream_vip) {
        return Err(format!(
            "dns answers {:?} missing vip {}",
            result.answers, ctx.cfg.upstream_vip
        ));
    }

    wait_for(
        Duration::from_secs(20),
        Duration::from_millis(400),
        || {
            // Fan queries across mgmt LB backends so each firewall can learn allowlist entries.
            let probe = dig_query(&ctx.cfg, &ctx.cfg.dns_zone)?;
            if probe.status != "NOERROR" {
                return Ok(false);
            }
            let out = run_curl(
                &ctx.cfg,
                &ctx.cfg.dns_zone,
                ctx.cfg.upstream_vip,
                80,
                false,
                None,
                true,
            )?;
            Ok(out.status == 0)
        },
        "dns allowlist did not permit upstream http after repeated dns queries",
    )
}

fn test_dns_allowlist_deny(ctx: &mut Context) -> Result<(), String> {
    let blocked = format!("blocked.{}", ctx.cfg.dns_zone);
    let host_regex = hostname_regex(&blocked);
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_dns("dns-deny", "deny", &host_regex)],
    );
    ctx.apply_policy(policy)?;

    let result = dig_query(&ctx.cfg, &blocked)?;
    if result.status != "NXDOMAIN" {
        return Err(format!("dns status {}, expected NXDOMAIN", result.status));
    }
    Ok(())
}

fn test_dns_allowlist_reset(ctx: &mut Context) -> Result<(), String> {
    let host_regex = hostname_regex(&ctx.cfg.dns_zone);
    let policy_allow = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_dns("dns-allow", "allow", &host_regex)],
    );
    ctx.apply_policy(policy_allow)?;
    let result = dig_query(&ctx.cfg, &ctx.cfg.dns_zone)?;
    if result.status != "NOERROR" {
        return Err(format!("dns status {}, expected NOERROR", result.status));
    }

    let policy_deny = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_dns("dns-deny", "deny", &host_regex)],
    );
    ctx.apply_policy(policy_deny)?;
    wait_for(
        Duration::from_secs(5),
        Duration::from_millis(200),
        || {
            let result = dig_query(&ctx.cfg, &ctx.cfg.dns_zone)?;
            if result.status == "NXDOMAIN" {
                Ok(true)
            } else {
                Ok(false)
            }
        },
        "dns status stayed non-NXDOMAIN after deny policy",
    )
}

fn test_cidr_port_allow(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_tcp("allow-http", "allow", ctx.cfg.upstream_vip, &[80])],
    );
    ctx.apply_policy(policy)?;
    curl_expect_success(
        &ctx.cfg,
        &ctx.cfg.dns_zone,
        ctx.cfg.upstream_vip,
        80,
        false,
        None,
    )
}

fn test_cidr_port_deny(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![
            rule_tcp("allow-http", "allow", ctx.cfg.upstream_vip, &[80]),
            rule_tcp("deny-https", "deny", ctx.cfg.upstream_vip, &[443]),
        ],
    );
    ctx.apply_policy(policy)?;
    curl_expect_failure(
        &ctx.cfg,
        &ctx.cfg.dns_zone,
        ctx.cfg.upstream_vip,
        443,
        true,
        None,
    )
}

fn test_tls_sni_allow(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_tls_sni(
            "tls-allow",
            "allow",
            ctx.cfg.upstream_vip,
            &ctx.cfg.dns_zone,
            None,
            None,
        )],
    );
    ctx.apply_policy(policy)?;
    curl_expect_success(
        &ctx.cfg,
        &ctx.cfg.dns_zone,
        ctx.cfg.upstream_vip,
        443,
        true,
        Some("1.2"),
    )
}

fn test_tls_sni_deny(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_tls_sni(
            "tls-allow",
            "allow",
            ctx.cfg.upstream_vip,
            &ctx.cfg.dns_zone,
            None,
            None,
        )],
    );
    ctx.apply_policy(policy)?;
    let blocked = format!("blocked.{}", ctx.cfg.dns_zone);
    curl_expect_failure(
        &ctx.cfg,
        &blocked,
        ctx.cfg.upstream_vip,
        443,
        true,
        Some("1.2"),
    )
}

fn test_tls13_uninspectable_deny(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_tls_sni(
            "tls13-deny",
            "allow",
            ctx.cfg.upstream_vip,
            &ctx.cfg.dns_zone,
            Some("deny"),
            Some(&ctx.cfg.dns_zone),
        )],
    );
    ctx.apply_policy(policy)?;
    curl_expect_failure(
        &ctx.cfg,
        &ctx.cfg.dns_zone,
        ctx.cfg.upstream_vip,
        443,
        true,
        Some("1.3"),
    )
}

fn test_policy_recheck_existing_flow(ctx: &mut Context) -> Result<(), String> {
    let policy_allow = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_tcp(
            "allow-long",
            "allow",
            ctx.cfg.upstream_vip,
            &[9000],
        )],
    );
    ctx.apply_policy(policy_allow)?;

    let mut stream = std::net::TcpStream::connect((ctx.cfg.upstream_vip, 9000))
        .map_err(|err| format!("connect failed: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("set write timeout failed: {err}"))?;

    stream
        .write_all(b"hello")
        .map_err(|err| format!("initial write failed: {err}"))?;

    let policy_deny = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_tcp("deny-long", "deny", ctx.cfg.upstream_vip, &[9000])],
    );
    ctx.apply_policy(policy_deny)?;

    let payload = vec![0u8; 32 * 1024 * 1024];
    let write_result = stream.write_all(&payload);
    match write_result {
        Ok(()) => Err("write unexpectedly succeeded after deny".to_string()),
        Err(_) => Ok(()),
    }
}

fn test_metrics_allow_deny(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![
            rule_tcp("allow-http", "allow", ctx.cfg.upstream_vip, &[80]),
            rule_tcp("deny-https", "deny", ctx.cfg.upstream_vip, &[443]),
        ],
    );
    ctx.apply_policy(policy)?;

    let before = ctx.get_metrics()?;
    let allow_before = metric_sum(&before, "dp_packets_total", &[("decision", "allow")])?;
    let deny_before = metric_sum(&before, "dp_packets_total", &[("decision", "deny")])?;

    let _ = curl_expect_success(
        &ctx.cfg,
        &ctx.cfg.dns_zone,
        ctx.cfg.upstream_vip,
        80,
        false,
        None,
    )?;

    let mid = ctx.get_metrics()?;
    let allow_mid = metric_sum(&mid, "dp_packets_total", &[("decision", "allow")])?;

    let _ = curl_expect_failure(
        &ctx.cfg,
        &ctx.cfg.dns_zone,
        ctx.cfg.upstream_vip,
        443,
        true,
        None,
    )?;

    let after = ctx.get_metrics()?;
    let deny_after = metric_sum(&after, "dp_packets_total", &[("decision", "deny")])?;

    if allow_mid <= allow_before {
        return Err("allow counter did not increase".to_string());
    }
    if deny_after <= deny_before {
        return Err("deny counter did not increase".to_string());
    }
    Ok(())
}

fn test_udp_allow_5201(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![
            rule_tcp(
                "allow-iperf-control",
                "allow",
                ctx.cfg.upstream_vip,
                &[5201],
            ),
            rule_udp("allow-iperf-udp", "allow", ctx.cfg.upstream_vip, &[5201]),
        ],
    );
    ctx.apply_policy(policy)?;
    iperf3_udp_expect_success(ctx.cfg.upstream_vip, 5201)
}

fn test_udp_deny_5201(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![
            rule_tcp(
                "allow-iperf-control",
                "allow",
                ctx.cfg.upstream_vip,
                &[5201],
            ),
            rule_udp("deny-iperf-udp", "deny", ctx.cfg.upstream_vip, &[5201]),
        ],
    );
    ctx.apply_policy(policy)?;
    iperf3_udp_expect_deny(ctx.cfg.upstream_vip, 5201)
}

fn test_tcp_allow_udp_deny_same_port(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![
            rule_tcp("allow-iperf-tcp", "allow", ctx.cfg.upstream_vip, &[5201]),
            rule_udp("deny-iperf-udp", "deny", ctx.cfg.upstream_vip, &[5201]),
        ],
    );
    ctx.apply_policy(policy)?;
    iperf3_tcp_expect_success(ctx.cfg.upstream_vip, 5201)?;
    iperf3_udp_expect_deny(ctx.cfg.upstream_vip, 5201)
}

fn test_udp_policy_swap_allow_to_deny(ctx: &mut Context) -> Result<(), String> {
    let allow_policy = policy_with_rules(
        ctx.consumer_ip,
        vec![
            rule_tcp(
                "allow-iperf-control",
                "allow",
                ctx.cfg.upstream_vip,
                &[5201],
            ),
            rule_udp("allow-iperf-udp", "allow", ctx.cfg.upstream_vip, &[5201]),
        ],
    );
    ctx.apply_policy(allow_policy)?;
    iperf3_udp_expect_success(ctx.cfg.upstream_vip, 5201)?;

    let deny_policy = policy_with_rules(
        ctx.consumer_ip,
        vec![
            rule_tcp(
                "allow-iperf-control",
                "allow",
                ctx.cfg.upstream_vip,
                &[5201],
            ),
            rule_udp("deny-iperf-udp", "deny", ctx.cfg.upstream_vip, &[5201]),
        ],
    );
    ctx.apply_policy(deny_policy)?;
    iperf3_udp_expect_deny(ctx.cfg.upstream_vip, 5201)
}

fn test_icmp_echo_allow(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_icmp(
            "allow-icmp-echo",
            "allow",
            ctx.cfg.upstream_ip,
            &[8],
            &[],
        )],
    );
    ctx.apply_policy(policy)?;
    ping_expect_success(ctx.cfg.upstream_ip)
}

fn test_icmp_echo_deny(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_icmp(
            "deny-icmp-echo",
            "deny",
            ctx.cfg.upstream_ip,
            &[8],
            &[],
        )],
    );
    ctx.apply_policy(policy)?;
    ping_expect_failure(ctx.cfg.upstream_ip)
}

fn test_policy_consistency_all_firewalls(ctx: &mut Context) -> Result<(), String> {
    let marker = "consistency-rule";
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![rule_tcp(marker, "allow", ctx.cfg.upstream_vip, &[80])],
    );
    ctx.apply_policy(policy)?;

    for api in &ctx.apis {
        let mut records = api.list_policies()?;
        records.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        let latest = records
            .last()
            .ok_or_else(|| "policy list empty while checking consistency".to_string())?;
        if latest.mode != "enforce" {
            return Err(format!(
                "latest policy on {} is mode {}, expected enforce",
                api.base, latest.mode
            ));
        }
        if !policy_contains_rule_id(&latest.policy, marker) {
            return Err(format!(
                "latest policy on {} missing marker rule {}",
                api.base, marker
            ));
        }
    }
    Ok(())
}

fn test_metrics_protocol_specific_validation(ctx: &mut Context) -> Result<(), String> {
    let policy = policy_with_rules(
        ctx.consumer_ip,
        vec![
            rule_tcp("allow-iperf-tcp", "allow", ctx.cfg.upstream_vip, &[5201]),
            rule_udp("deny-iperf-udp", "deny", ctx.cfg.upstream_vip, &[5201]),
        ],
    );
    ctx.apply_policy(policy)?;

    let before = ctx.get_metrics()?;
    let tcp_allow_before = metric_sum(
        &before,
        "dp_packets_total",
        &[("decision", "allow"), ("proto", "tcp")],
    )?;
    let udp_deny_before = metric_sum(
        &before,
        "dp_packets_total",
        &[("decision", "deny"), ("proto", "udp")],
    )?;

    iperf3_tcp_expect_success(ctx.cfg.upstream_vip, 5201)?;
    iperf3_udp_expect_deny(ctx.cfg.upstream_vip, 5201)?;

    let after = ctx.get_metrics()?;
    let tcp_allow_after = metric_sum(
        &after,
        "dp_packets_total",
        &[("decision", "allow"), ("proto", "tcp")],
    )?;
    let udp_deny_after = metric_sum(
        &after,
        "dp_packets_total",
        &[("decision", "deny"), ("proto", "udp")],
    )?;

    if tcp_allow_after <= tcp_allow_before {
        return Err("tcp allow counter did not increase".to_string());
    }
    if udp_deny_after <= udp_deny_before {
        return Err("udp deny counter did not increase".to_string());
    }
    Ok(())
}

fn policy_with_rules(consumer_ip: Ipv4Addr, rules: Vec<Value>) -> Value {
    json!({
        "default_policy": "deny",
        "source_groups": [
            {
                "id": "consumers",
                "priority": 1,
                "sources": {"ips": [consumer_ip.to_string()]},
                "default_action": "deny",
                "rules": rules
            }
        ]
    })
}

fn rule_dns(id: &str, action: &str, hostname: &str) -> Value {
    json!({
        "id": id,
        "action": action,
        "match": {
            "proto": "udp",
            "dst_ports": [53],
            "dns_hostname": hostname
        }
    })
}

fn rule_tcp(id: &str, action: &str, vip: Ipv4Addr, ports: &[u16]) -> Value {
    let ports_json: Vec<Value> = ports.iter().map(|p| json!(p)).collect();
    json!({
        "id": id,
        "action": action,
        "match": {
            "proto": "tcp",
            "dst_ports": ports_json,
            "dst_ips": [vip.to_string()]
        }
    })
}

fn rule_udp(id: &str, action: &str, vip: Ipv4Addr, ports: &[u16]) -> Value {
    let ports_json: Vec<Value> = ports.iter().map(|p| json!(p)).collect();
    json!({
        "id": id,
        "action": action,
        "match": {
            "proto": "udp",
            "dst_ports": ports_json,
            "dst_ips": [vip.to_string()]
        }
    })
}

fn rule_icmp(id: &str, action: &str, vip: Ipv4Addr, types: &[u8], codes: &[u8]) -> Value {
    let types_json: Vec<Value> = types.iter().map(|v| json!(v)).collect();
    let codes_json: Vec<Value> = codes.iter().map(|v| json!(v)).collect();
    json!({
        "id": id,
        "action": action,
        "match": {
            "proto": "icmp",
            "dst_ips": [vip.to_string()],
            "icmp_types": types_json,
            "icmp_codes": codes_json
        }
    })
}

fn rule_tls_sni(
    id: &str,
    action: &str,
    vip: Ipv4Addr,
    sni: &str,
    tls13_uninspectable: Option<&str>,
    server_cn: Option<&str>,
) -> Value {
    let mut tls = serde_json::Map::new();
    tls.insert("sni".to_string(), json!({ "exact": [sni] }));
    if let Some(value) = tls13_uninspectable {
        tls.insert("tls13_uninspectable".to_string(), json!(value));
    }
    if let Some(value) = server_cn {
        tls.insert("server_cn".to_string(), json!({ "exact": [value] }));
    }
    json!({
        "id": id,
        "action": action,
        "match": {
            "proto": "tcp",
            "dst_ports": [443],
            "dst_ips": [vip.to_string()],
            "tls": Value::Object(tls)
        }
    })
}

fn hostname_regex(hostname: &str) -> String {
    let mut out = String::from("^");
    for ch in hostname.chars() {
        if matches!(
            ch,
            '.' | '^' | '$' | '|' | '?' | '*' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('$');
    out
}

struct DigResult {
    status: String,
    answers: Vec<Ipv4Addr>,
}

fn dig_query(cfg: &Config, name: &str) -> Result<DigResult, String> {
    let mut args = Vec::new();
    args.push("+time=2".to_string());
    args.push("+tries=1".to_string());
    args.push("+noall".to_string());
    args.push("+answer".to_string());
    args.push("+comments".to_string());
    if cfg.dns_server.port() != 53 {
        args.push("-p".to_string());
        args.push(cfg.dns_server.port().to_string());
    }
    args.push(format!("@{}", cfg.dns_server.ip()));
    args.push(name.to_string());

    let output = run_cmd("dig", &args)?;
    let stdout = output.stdout;

    let mut status = None;
    let mut answers = Vec::new();
    for line in stdout.lines() {
        if line.starts_with(";; ->>HEADER<<-") {
            if let Some(pos) = line.find("status:") {
                let rest = &line[pos + 7..];
                if let Some(end) = rest.find(',') {
                    status = Some(rest[..end].trim().to_string());
                }
            }
            continue;
        }
        if line.starts_with(';') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[3] == "A" {
            if let Ok(ip) = parts[4].parse::<Ipv4Addr>() {
                answers.push(ip);
            }
        }
    }

    let status = status.ok_or_else(|| "missing DNS status".to_string())?;
    Ok(DigResult { status, answers })
}

fn curl_expect_success(
    cfg: &Config,
    host: &str,
    vip: Ipv4Addr,
    port: u16,
    https: bool,
    tls_version: Option<&str>,
) -> Result<(), String> {
    let output = run_curl(cfg, host, vip, port, https, tls_version, false)?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(format!(
            "curl failed (exit {}) stdout={} stderr={}",
            output.status, output.stdout, output.stderr
        ))
    }
}

fn curl_expect_failure(
    cfg: &Config,
    host: &str,
    vip: Ipv4Addr,
    port: u16,
    https: bool,
    tls_version: Option<&str>,
) -> Result<(), String> {
    let output = run_curl(cfg, host, vip, port, https, tls_version, true)?;
    if output.status == 0 {
        Err("curl unexpectedly succeeded".to_string())
    } else {
        Ok(())
    }
}

struct CmdOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_curl(
    _cfg: &Config,
    host: &str,
    vip: Ipv4Addr,
    port: u16,
    https: bool,
    tls_version: Option<&str>,
    fast_fail: bool,
) -> Result<CmdOutput, String> {
    let mut args = vec!["-fsS".to_string()];
    if fast_fail {
        args.push("--max-time".to_string());
        args.push("8".to_string());
        args.push("--connect-timeout".to_string());
        args.push("3".to_string());
    } else {
        args.push("--max-time".to_string());
        args.push("20".to_string());
        args.push("--connect-timeout".to_string());
        args.push("10".to_string());
        args.push("--retry".to_string());
        args.push("2".to_string());
        args.push("--retry-delay".to_string());
        args.push("1".to_string());
        args.push("--retry-all-errors".to_string());
    }
    if https {
        args.push("-k".to_string());
        // Force TCP transport for policy tests; HTTP/3 over UDP/443 would bypass tcp/443 rules.
        args.push("--http1.1".to_string());
        if let Some(version) = tls_version {
            match version {
                "1.2" => {
                    args.push("--tlsv1.2".to_string());
                    args.push("--tls-max".to_string());
                    args.push("1.2".to_string());
                }
                "1.3" => {
                    args.push("--tlsv1.3".to_string());
                    args.push("--tls-max".to_string());
                    args.push("1.3".to_string());
                }
                other => return Err(format!("unsupported tls version {other}")),
            }
        }
    }
    args.push("--resolve".to_string());
    args.push(format!("{host}:{port}:{vip}"));

    let scheme = if https { "https" } else { "http" };
    let url = if (https && port == 443) || (!https && port == 80) {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    };
    args.push(url);

    run_cmd("curl", &args)
}

fn run_cmd(cmd: &str, args: &[String]) -> Result<CmdOutput, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| format!("failed to run {cmd}: {err}"))?;

    let status = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok(CmdOutput {
        status,
        stdout,
        stderr,
    })
}

fn iperf3_tcp_expect_success(vip: Ipv4Addr, port: u16) -> Result<(), String> {
    let args = vec![
        "-c".to_string(),
        vip.to_string(),
        "-p".to_string(),
        port.to_string(),
        "-t".to_string(),
        "4".to_string(),
        "--connect-timeout".to_string(),
        "5000".to_string(),
    ];
    let out = run_cmd("iperf3", &args)?;
    if out.status == 0 {
        Ok(())
    } else {
        Err(format!(
            "iperf3 tcp failed (exit {}) stdout={} stderr={}",
            out.status, out.stdout, out.stderr
        ))
    }
}

fn iperf3_udp_expect_success(vip: Ipv4Addr, port: u16) -> Result<(), String> {
    let out = iperf3_udp_run(vip, port)?;
    if out.status != 0 {
        return Err(format!(
            "iperf3 udp failed (exit {}) stdout={} stderr={}",
            out.status, out.stdout, out.stderr
        ));
    }
    let bps = parse_iperf3_udp_bps(&out.stdout)
        .ok_or_else(|| "iperf3 udp output missing bits_per_second".to_string())?;
    if bps < 1000.0 {
        return Err(format!(
            "iperf3 udp throughput too low for allow case: {} bps",
            bps
        ));
    }
    Ok(())
}

fn iperf3_udp_expect_deny(vip: Ipv4Addr, port: u16) -> Result<(), String> {
    let out = iperf3_udp_run(vip, port)?;
    if out.status != 0 {
        return Ok(());
    }
    let bps = parse_iperf3_udp_bps(&out.stdout).unwrap_or(0.0);
    if bps < 1000.0 {
        Ok(())
    } else {
        Err(format!(
            "iperf3 udp unexpectedly succeeded with {} bps",
            bps
        ))
    }
}

fn iperf3_udp_run(vip: Ipv4Addr, port: u16) -> Result<CmdOutput, String> {
    let args = vec![
        "-c".to_string(),
        vip.to_string(),
        "-p".to_string(),
        port.to_string(),
        "-u".to_string(),
        "-b".to_string(),
        "5M".to_string(),
        "-t".to_string(),
        "4".to_string(),
        "-J".to_string(),
        "--connect-timeout".to_string(),
        "5000".to_string(),
    ];
    run_cmd("iperf3", &args)
}

fn parse_iperf3_udp_bps(stdout: &str) -> Option<f64> {
    let value: Value = serde_json::from_str(stdout).ok()?;
    let candidates = [
        value
            .pointer("/end/sum/bits_per_second")
            .and_then(Value::as_f64),
        value
            .pointer("/end/sum_received/bits_per_second")
            .and_then(Value::as_f64),
        value
            .pointer("/end/streams/0/udp/bits_per_second")
            .and_then(Value::as_f64),
    ];
    candidates.into_iter().flatten().next()
}

fn ping_expect_success(vip: Ipv4Addr) -> Result<(), String> {
    let args = vec![
        "-c".to_string(),
        "3".to_string(),
        "-W".to_string(),
        "2".to_string(),
        vip.to_string(),
    ];
    let out = run_cmd("ping", &args)?;
    if out.status == 0 {
        Ok(())
    } else {
        Err(format!(
            "ping failed (exit {}) stdout={} stderr={}",
            out.status, out.stdout, out.stderr
        ))
    }
}

fn ping_expect_failure(vip: Ipv4Addr) -> Result<(), String> {
    let args = vec![
        "-c".to_string(),
        "3".to_string(),
        "-W".to_string(),
        "2".to_string(),
        vip.to_string(),
    ];
    let out = run_cmd("ping", &args)?;
    if out.status == 0 {
        Err("ping unexpectedly succeeded".to_string())
    } else {
        Ok(())
    }
}

fn policy_contains_rule_id(policy: &Value, rule_id: &str) -> bool {
    let Some(groups) = policy.get("source_groups").and_then(Value::as_array) else {
        return false;
    };
    for group in groups {
        let Some(rules) = group.get("rules").and_then(Value::as_array) else {
            continue;
        };
        for rule in rules {
            if rule.get("id").and_then(Value::as_str) == Some(rule_id) {
                return true;
            }
        }
    }
    false
}

fn metric_sum(body: &str, name: &str, labels: &[(&str, &str)]) -> Result<f64, String> {
    let mut sum = 0.0;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(name) {
            continue;
        }
        let (metric_part, value_part) = match line.split_once(' ') {
            Some(parts) => parts,
            None => continue,
        };
        let value: f64 = match value_part.trim().parse() {
            Ok(value) => value,
            Err(_) => continue,
        };

        if let Some(start) = metric_part.find('{') {
            let end = metric_part.rfind('}').unwrap_or(metric_part.len());
            let labels_str = &metric_part[start + 1..end];
            let mut matched = true;
            for (k, v) in labels {
                if !labels_str.contains(&format!("{k}=\"{v}\"")) {
                    matched = false;
                    break;
                }
            }
            if matched {
                sum += value;
            }
        } else if labels.is_empty() {
            sum += value;
        }
    }
    Ok(sum)
}

fn parse_api_endpoints() -> Result<Vec<ApiEndpoint>, String> {
    if let Ok(value) = env::var("NEUWERK_POLICY_API_ENDPOINTS") {
        let mut endpoints = Vec::new();
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (base, token) = item.split_once('|').ok_or_else(|| {
                format!("invalid endpoint entry '{item}', expected <base>|<token>")
            })?;
            let base = base.trim().trim_end_matches('/').to_string();
            let token = token.trim().to_string();
            if base.is_empty() || token.is_empty() {
                return Err(format!(
                    "invalid endpoint entry '{item}', base/token cannot be empty"
                ));
            }
            endpoints.push(ApiEndpoint { base, token });
        }
        if !endpoints.is_empty() {
            return Ok(endpoints);
        }
        return Err("NEUWERK_POLICY_API_ENDPOINTS is set but empty".to_string());
    }

    let token = require_env("NEUWERK_POLICY_API_TOKEN")?;
    let bases = parse_api_bases()?;
    Ok(bases
        .into_iter()
        .map(|base| ApiEndpoint {
            base,
            token: token.clone(),
        })
        .collect())
}

fn parse_api_bases() -> Result<Vec<String>, String> {
    if let Ok(value) = env::var("NEUWERK_POLICY_API_BASES") {
        let values: Vec<String> = value
            .split(',')
            .map(|item| item.trim().trim_end_matches('/').to_string())
            .filter(|item| !item.is_empty())
            .collect();
        if !values.is_empty() {
            return Ok(values);
        }
        return Err("NEUWERK_POLICY_API_BASES is set but empty".to_string());
    }
    let value = require_env("NEUWERK_POLICY_API_BASE")?;
    Ok(vec![value.trim_end_matches('/').to_string()])
}

fn require_env(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("missing {key}"))
}

fn env_bool(key: &str) -> Option<bool> {
    let value = env::var(key).ok()?;
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    match value.as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn require_ipv4(key: &str) -> Result<Ipv4Addr, String> {
    let value = require_env(key)?;
    value
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("invalid {key}: {err}"))
}

fn optional_ipv4(key: &str) -> Result<Option<Ipv4Addr>, String> {
    let Some(value) = env::var(key).ok() else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    value
        .parse::<Ipv4Addr>()
        .map(Some)
        .map_err(|err| format!("invalid {key}: {err}"))
}

fn require_socket_addr(key: &str, default_port: u16) -> Result<SocketAddr, String> {
    let value = require_env(key)?;
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    Err(format!("invalid {key}: {value}"))
}

fn require_bin(bin: &str) -> Result<(), String> {
    let status = Command::new("sh")
        .args(["-c", &format!("command -v {bin} >/dev/null 2>&1")])
        .status()
        .map_err(|err| format!("failed to run shell: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(bin.to_string())
    }
}

fn local_ipv4_for(target: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| err.to_string())?;
    socket
        .connect(SocketAddr::new(IpAddr::V4(target), 9))
        .map_err(|err| format!("udp connect failed: {err}"))?;
    match socket.local_addr().map_err(|err| err.to_string())?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err("unexpected ipv6 local address".to_string()),
    }
}

fn parse_test_filter(filter: Option<&str>) -> std::collections::HashSet<&'static str> {
    let Some(filter) = filter else {
        return std::collections::HashSet::new();
    };
    filter
        .split(',')
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .filter_map(|name| match name {
            "cidr_port_allow" => Some("cidr_port_allow"),
            "cidr_port_deny" => Some("cidr_port_deny"),
            "tls_sni_allow" => Some("tls_sni_allow"),
            "tls_sni_deny" => Some("tls_sni_deny"),
            "tls13_uninspectable_deny" => Some("tls13_uninspectable_deny"),
            "policy_recheck_existing_flow" => Some("policy_recheck_existing_flow"),
            "metrics_allow_deny_counters" => Some("metrics_allow_deny_counters"),
            "udp_allow_5201" => Some("udp_allow_5201"),
            "udp_deny_5201" => Some("udp_deny_5201"),
            "tcp_allow_udp_deny_same_port" => Some("tcp_allow_udp_deny_same_port"),
            "udp_policy_swap_allow_to_deny" => Some("udp_policy_swap_allow_to_deny"),
            "icmp_echo_allow" => Some("icmp_echo_allow"),
            "icmp_echo_deny" => Some("icmp_echo_deny"),
            "policy_consistency_all_firewalls" => Some("policy_consistency_all_firewalls"),
            "metrics_protocol_specific_validation" => Some("metrics_protocol_specific_validation"),
            "dns_allowlist_allow" => Some("dns_allowlist_allow"),
            "dns_allowlist_deny" => Some("dns_allowlist_deny"),
            "dns_allowlist_reset_on_rebuild" => Some("dns_allowlist_reset_on_rebuild"),
            _ => None,
        })
        .collect()
}

fn wait_for<F>(
    timeout: Duration,
    interval: Duration,
    mut check: F,
    timeout_msg: &str,
) -> Result<(), String>
where
    F: FnMut() -> Result<bool, String>,
{
    let start = Instant::now();
    loop {
        if check()? {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(timeout_msg.to_string());
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_regex_matches_exact_name() {
        let pattern = hostname_regex("api.example.com");
        let re = regex::Regex::new(&pattern).expect("regex compiles");
        assert!(re.is_match("api.example.com"));
        assert!(!re.is_match("xapi.example.com"));
        assert!(!re.is_match("api.example.com.evil"));
    }

    #[test]
    fn metric_sum_filters_by_labels() {
        let body = r#"
# HELP dp_packets_total Dataplane packets
dp_packets_total{direction="outbound",proto="tcp",decision="allow",source_group="consumers"} 10
dp_packets_total{direction="outbound",proto="tcp",decision="deny",source_group="consumers"} 3
dp_packets_total{direction="inbound",proto="tcp",decision="allow",source_group="consumers"} 2
"#;
        let allow = metric_sum(body, "dp_packets_total", &[("decision", "allow")]).unwrap();
        let deny = metric_sum(body, "dp_packets_total", &[("decision", "deny")]).unwrap();
        assert_eq!(allow, 12.0);
        assert_eq!(deny, 3.0);
    }

    #[test]
    fn metric_sum_returns_zero_when_metric_missing() {
        let body = r#"
dns_queries_total{result="allow"} 7
"#;
        let value = metric_sum(body, "dp_packets_total", &[("decision", "allow")]).unwrap();
        assert_eq!(value, 0.0);
    }

    #[test]
    fn socket_addr_parsing_accepts_ip_or_socket_addr() {
        env::set_var("NEUWERK_DNS_SERVER", "10.0.0.10");
        let with_default = require_socket_addr("NEUWERK_DNS_SERVER", 53).unwrap();
        assert_eq!(with_default, "10.0.0.10:53".parse::<SocketAddr>().unwrap());

        env::set_var("NEUWERK_DNS_SERVER", "10.0.0.10:1053");
        let with_port = require_socket_addr("NEUWERK_DNS_SERVER", 53).unwrap();
        assert_eq!(with_port, "10.0.0.10:1053".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn env_bool_parses_expected_values() {
        env::set_var("BOOL_TEST", "true");
        assert_eq!(env_bool("BOOL_TEST"), Some(true));
        env::set_var("BOOL_TEST", "0");
        assert_eq!(env_bool("BOOL_TEST"), Some(false));
        env::set_var("BOOL_TEST", "wat");
        assert_eq!(env_bool("BOOL_TEST"), None);
        env::remove_var("BOOL_TEST");
        assert_eq!(env_bool("BOOL_TEST"), None);
    }

    #[test]
    fn tls_rule_uses_exact_match_shape() {
        let rule = rule_tls_sni(
            "tls",
            "allow",
            "10.20.4.10".parse().unwrap(),
            "upstream.test",
            Some("deny"),
            Some("upstream.test"),
        );
        let tls = rule
            .get("match")
            .and_then(Value::as_object)
            .and_then(|m| m.get("tls"))
            .and_then(Value::as_object)
            .expect("tls object");
        assert_eq!(tls.get("tls13_uninspectable"), Some(&json!("deny")));
        assert_eq!(tls.get("sni"), Some(&json!({"exact": ["upstream.test"]})));
        assert_eq!(
            tls.get("server_cn"),
            Some(&json!({"exact": ["upstream.test"]}))
        );
    }

    #[test]
    fn parse_test_filter_selects_known_names_only() {
        let selected = parse_test_filter(Some(
            "cidr_port_allow,unknown,dns_allowlist_allow,,metrics_allow_deny_counters,udp_allow_5201",
        ));
        assert!(selected.contains("cidr_port_allow"));
        assert!(selected.contains("dns_allowlist_allow"));
        assert!(selected.contains("metrics_allow_deny_counters"));
        assert!(selected.contains("udp_allow_5201"));
        assert!(!selected.contains("unknown"));
    }

    #[test]
    fn parse_api_bases_prefers_multi_value_env() {
        env::remove_var("NEUWERK_POLICY_API_ENDPOINTS");
        env::set_var(
            "NEUWERK_POLICY_API_BASES",
            "https://10.0.0.1:8443, https://10.0.0.2:8443",
        );
        env::set_var("NEUWERK_POLICY_API_BASE", "https://10.0.0.9:8443");
        let values = parse_api_bases().unwrap();
        assert_eq!(
            values,
            vec![
                "https://10.0.0.1:8443".to_string(),
                "https://10.0.0.2:8443".to_string()
            ]
        );
        env::remove_var("NEUWERK_POLICY_API_BASES");
        env::remove_var("NEUWERK_POLICY_API_BASE");
    }

    #[test]
    fn parse_api_endpoints_supports_per_endpoint_tokens() {
        env::set_var(
            "NEUWERK_POLICY_API_ENDPOINTS",
            "https://10.0.0.1:8443|tok1,https://10.0.0.2:8443|tok2",
        );
        let values = parse_api_endpoints().unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].base, "https://10.0.0.1:8443");
        assert_eq!(values[0].token, "tok1");
        assert_eq!(values[1].base, "https://10.0.0.2:8443");
        assert_eq!(values[1].token, "tok2");
        env::remove_var("NEUWERK_POLICY_API_ENDPOINTS");
    }

    #[test]
    fn parse_iperf3_udp_bps_reads_json() {
        let body = r#"{"end":{"sum":{"bits_per_second":12345.0}}}"#;
        assert_eq!(parse_iperf3_udp_bps(body), Some(12345.0));
    }

    #[test]
    fn policy_contains_rule_id_matches_nested_rules() {
        let policy = json!({
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "consumers",
                    "rules": [
                        {"id": "rule-a"},
                        {"id": "rule-b"}
                    ]
                }
            ]
        });
        assert!(policy_contains_rule_id(&policy, "rule-b"));
        assert!(!policy_contains_rule_id(&policy, "missing"));
    }
}
