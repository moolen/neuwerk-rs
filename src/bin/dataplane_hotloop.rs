use std::env;
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use neuwerk::dataplane::config::DataplaneConfig;
use neuwerk::dataplane::policy::{
    CidrV4, DefaultPolicy, DynamicIpSetV4, IpSetV4, PolicySnapshot, Proto, Rule, RuleAction,
    RuleMatch, RuleMode, SourceGroup,
};
use neuwerk::dataplane::{handle_packet, Action, EngineState, Packet, SnatMode};
use neuwerk::metrics::Metrics;

const BENCH_NOW_SECS: u64 = 1;
const SOURCE_PORT_BASE: usize = 10_000;
const MAX_UNIQUE_TCP_PORTS: usize = (u16::MAX as usize) - SOURCE_PORT_BASE + 1;
const DEFAULT_POOL_SIZE: usize = 4_096;
const DEFAULT_ITERATIONS: u64 = 5_000_000;

#[derive(Clone, Copy)]
enum Scenario {
    UniqueSourceNoSnat,
    SharedSourceNoSnat,
    SnatNoMetrics,
    SnatMetrics,
}

impl Scenario {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "unique-source-no-snat" => Some(Self::UniqueSourceNoSnat),
            "shared-source-no-snat" => Some(Self::SharedSourceNoSnat),
            "snat-no-metrics" => Some(Self::SnatNoMetrics),
            "snat-metrics" => Some(Self::SnatMetrics),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::UniqueSourceNoSnat => "unique-source-no-snat",
            Self::SharedSourceNoSnat => "shared-source-no-snat",
            Self::SnatNoMetrics => "snat-no-metrics",
            Self::SnatMetrics => "snat-metrics",
        }
    }
}

struct Args {
    scenario: Scenario,
    iterations: u64,
    pool_size: usize,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut scenario = None;
        let mut iterations = DEFAULT_ITERATIONS;
        let mut pool_size = DEFAULT_POOL_SIZE;

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => {
                    return Err(String::new());
                }
                "--iterations" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "missing value for --iterations".to_string())?;
                    iterations = value
                        .parse()
                        .map_err(|_| format!("invalid iterations value: {value}"))?;
                }
                "--pool-size" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "missing value for --pool-size".to_string())?;
                    pool_size = value
                        .parse()
                        .map_err(|_| format!("invalid pool size value: {value}"))?;
                }
                value if !value.starts_with('-') && scenario.is_none() => {
                    scenario = Scenario::parse(value);
                    if scenario.is_none() {
                        return Err(format!("unknown scenario: {value}"));
                    }
                }
                _ => return Err(format!("unknown argument: {arg}")),
            }
        }

        let scenario = scenario.ok_or_else(|| "missing scenario".to_string())?;
        if pool_size == 0 {
            return Err("pool size must be greater than zero".to_string());
        }
        if pool_size > MAX_UNIQUE_TCP_PORTS {
            return Err(format!(
                "pool size must be <= {MAX_UNIQUE_TCP_PORTS} to avoid TCP source-port wrap"
            ));
        }

        Ok(Self {
            scenario,
            iterations,
            pool_size,
        })
    }
}

fn print_usage() {
    eprintln!(
        "Usage: dataplane_hotloop <scenario> [--iterations N] [--pool-size N]\n\
         \n\
         Scenarios:\n\
         \tunique-source-no-snat\n\
            \tshared-source-no-snat\n\
            \tsnat-no-metrics\n\
            \tsnat-metrics\n\
         \n\
         Defaults:\n\
            \titerations={DEFAULT_ITERATIONS}\n\
            \tpool-size={DEFAULT_POOL_SIZE}"
    );
}

fn main() {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(err) if err.is_empty() => {
            print_usage();
            return;
        }
        Err(err) => {
            eprintln!("{err}");
            print_usage();
            std::process::exit(2);
        }
    };

    let mut harness = ScenarioHarness::new(args.scenario, args.pool_size);
    let mut action_accumulator = 0u64;
    let start = Instant::now();

    for _ in 0..args.iterations {
        action_accumulator ^= harness.step();
    }

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let ns_per_packet = (secs * 1_000_000_000.0) / args.iterations as f64;
    let mpps = (args.iterations as f64 / secs) / 1_000_000.0;

    println!("scenario={}", args.scenario.as_str());
    println!("iterations={}", args.iterations);
    println!("pool_size={}", args.pool_size);
    println!("elapsed_secs={secs:.6}");
    println!("ns_per_packet={ns_per_packet:.3}");
    println!("mpps={mpps:.3}");
    println!("action_accumulator={action_accumulator}");
    println!("flows_len={}", harness.state.flows.len());
    println!("nat_len={}", harness.state.nat.len());
}

struct ScenarioHarness {
    state: EngineState,
    packet_templates: Vec<Vec<u8>>,
    packet_working: Vec<Vec<u8>>,
    next_index: usize,
}

impl ScenarioHarness {
    fn new(scenario: Scenario, pool_size: usize) -> Self {
        let (template_state, packet_templates) = match scenario {
            Scenario::UniqueSourceNoSnat => {
                let (policy, src_ip) = policy_with_many_groups_unique_sources(1024);
                let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
                (
                    new_engine_state_with_policy(policy, SnatMode::None),
                    build_tcp_frame_pool(src_ip, dst_ip, 443, pool_size),
                )
            }
            Scenario::SharedSourceNoSnat => {
                let src_ip = Ipv4Addr::new(10, 0, 0, 42);
                let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
                (
                    new_engine_state_with_policy(
                        policy_with_many_rules_for_source(src_ip, 16, 64),
                        SnatMode::None,
                    ),
                    build_tcp_frame_pool(src_ip, dst_ip, 443, pool_size),
                )
            }
            Scenario::SnatMetrics => {
                let src_ip = Ipv4Addr::new(10, 0, 0, 42);
                let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
                let mut state = new_engine_state(SnatMode::Auto);
                attach_metrics(&mut state);
                (state, build_tcp_frame_pool(src_ip, dst_ip, 443, pool_size))
            }
            Scenario::SnatNoMetrics => {
                let src_ip = Ipv4Addr::new(10, 0, 0, 42);
                let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
                (
                    new_engine_state(SnatMode::Auto),
                    build_tcp_frame_pool(src_ip, dst_ip, 443, pool_size),
                )
            }
        };
        let state = clone_hotloop_state(&template_state);
        let packet_working = packet_templates.clone();
        Self {
            state,
            packet_templates,
            packet_working,
            next_index: 0,
        }
    }

    fn step(&mut self) -> u64 {
        let buf = &mut self.packet_working[self.next_index];
        let len = buf.len();
        let action = unsafe {
            let mut packet =
                Packet::from_borrowed_mut(buf.as_mut_ptr(), len).expect("borrowed packet");
            handle_packet(black_box(&mut packet), black_box(&mut self.state))
        };

        self.next_index += 1;
        if self.next_index == self.packet_working.len() {
            self.reset_cycle();
        }

        action_to_u64(action)
    }

    fn reset_cycle(&mut self) {
        self.state.flows.clear();
        self.state.syn_only.clear();
        self.state.nat.clear();
        self.state.evict_expired_now();
        for (dst, src) in self
            .packet_working
            .iter_mut()
            .zip(self.packet_templates.iter())
        {
            dst.copy_from_slice(src);
        }
        self.next_index = 0;
    }
}

fn action_to_u64(action: Action) -> u64 {
    match action {
        Action::Drop => 0,
        Action::Forward { out_port } => (out_port as u64) + 1,
        Action::ToHost => u16::MAX as u64 + 1,
    }
}

fn clone_hotloop_state(template: &EngineState) -> EngineState {
    let mut state = template.clone_for_shard();
    state.evict_expired_now();
    state
}

fn new_engine_state(snat_mode: SnatMode) -> EngineState {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(198, 51, 100, 10));
    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist,
    );

    let public_ip = match snat_mode {
        SnatMode::None => Ipv4Addr::UNSPECIFIED,
        _ => Ipv4Addr::new(203, 0, 113, 1),
    };
    let mut state = EngineState::new(policy, Ipv4Addr::new(10, 0, 0, 0), 24, public_ip, 0);
    initialize_engine_state(&mut state, snat_mode);
    state
}

fn new_engine_state_with_policy(policy: PolicySnapshot, snat_mode: SnatMode) -> EngineState {
    let public_ip = match snat_mode {
        SnatMode::None => Ipv4Addr::UNSPECIFIED,
        _ => Ipv4Addr::new(203, 0, 113, 1),
    };
    let mut state = EngineState::new(
        Arc::new(RwLock::new(policy)),
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        public_ip,
        0,
    );
    initialize_engine_state(&mut state, snat_mode);
    state
}

fn initialize_engine_state(state: &mut EngineState, snat_mode: SnatMode) {
    state.set_snat_mode(snat_mode);
    state.dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: [0; 6],
        lease_expiry: None,
    });
    state.set_policy_applied_generation(Arc::new(AtomicU64::new(1)));
    state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
    state.set_time_override(Some(BENCH_NOW_SECS));
}

fn attach_metrics(state: &mut EngineState) {
    state.set_metrics_handle(Arc::new(Metrics::new().expect("metrics")));
}

fn policy_with_allowlist(
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    default_policy: DefaultPolicy,
    allowlist: DynamicIpSetV4,
) -> Arc<RwLock<PolicySnapshot>> {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(internal_net, internal_prefix));

    let rule = Rule {
        id: "allowlist".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: Some(IpSetV4::with_dynamic(allowlist)),
            proto: Proto::Any,
            src_ports: Vec::new(),
            dst_ports: Vec::new(),
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: None,
        },
        action: RuleAction::Allow,
        mode: RuleMode::Enforce,
    };

    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![rule],
        default_action: None,
    };

    Arc::new(RwLock::new(PolicySnapshot::new(
        default_policy,
        vec![group],
    )))
}

fn policy_with_many_rules_for_source(
    src_ip: Ipv4Addr,
    group_count: usize,
    rules_per_group: usize,
) -> PolicySnapshot {
    let target_dst = Ipv4Addr::new(198, 51, 100, 10);
    let mut groups = Vec::with_capacity(group_count);

    for group_idx in 0..group_count {
        let mut sources = IpSetV4::new();
        sources.add_ip(src_ip);

        let mut rules = Vec::with_capacity(rules_per_group);
        for rule_idx in 0..rules_per_group {
            let dst_ip = if group_idx + 1 == group_count && rule_idx + 1 == rules_per_group {
                target_dst
            } else {
                Ipv4Addr::new(
                    203,
                    (group_idx % 200) as u8,
                    ((rule_idx / 200) % 200) as u8,
                    (rule_idx % 200) as u8,
                )
            };
            let mut rule = build_allow_rule(&format!("rule-{group_idx}-{rule_idx}"), dst_ip);
            rule.priority = rule_idx as u32;
            rules.push(rule);
        }

        groups.push(SourceGroup {
            id: format!("group-{group_idx}"),
            priority: group_idx as u32,
            sources,
            rules,
            default_action: None,
        });
    }

    PolicySnapshot::new(DefaultPolicy::Deny, groups)
}

fn policy_with_many_groups_unique_sources(group_count: usize) -> (PolicySnapshot, Ipv4Addr) {
    let target_dst = Ipv4Addr::new(198, 51, 100, 10);
    let mut groups = Vec::with_capacity(group_count);
    let mut matched_src_ip = Ipv4Addr::UNSPECIFIED;

    for group_idx in 0..group_count {
        let src_ip = Ipv4Addr::new(
            172,
            16,
            ((group_idx / 250) % 250) as u8,
            (group_idx % 250) as u8 + 1,
        );
        let mut sources = IpSetV4::new();
        sources.add_ip(src_ip);
        let dst_ip = if group_idx + 1 == group_count {
            matched_src_ip = src_ip;
            target_dst
        } else {
            Ipv4Addr::new(
                203,
                1,
                ((group_idx / 200) % 200) as u8,
                (group_idx % 200) as u8,
            )
        };
        let rule = build_allow_rule(&format!("unique-group-rule-{group_idx}"), dst_ip);
        groups.push(SourceGroup {
            id: format!("unique-group-{group_idx}"),
            priority: group_idx as u32,
            sources,
            rules: vec![rule],
            default_action: None,
        });
    }

    (
        PolicySnapshot::new(DefaultPolicy::Deny, groups),
        matched_src_ip,
    )
}

fn build_allow_rule(id: &str, dst_ip: Ipv4Addr) -> Rule {
    let mut dst_ips = IpSetV4::new();
    dst_ips.add_ip(dst_ip);
    Rule {
        id: id.to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: Some(dst_ips),
            proto: Proto::Tcp,
            src_ports: Vec::new(),
            dst_ports: Vec::new(),
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: None,
        },
        action: RuleAction::Allow,
        mode: RuleMode::Enforce,
    }
}

fn build_tcp_frame_pool(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    pool_size: usize,
) -> Vec<Vec<u8>> {
    (0..pool_size)
        .map(|index| {
            build_eth_ipv4_tcp(
                [0; 6],
                [0; 6],
                src_ip,
                dst_ip,
                (SOURCE_PORT_BASE + index) as u16,
                dst_port,
                b"hello",
            )
            .into_vec()
        })
        .collect()
}

fn build_eth_ipv4_tcp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Packet {
    let inner = build_ipv4_tcp(src_ip, dst_ip, src_port, dst_port, payload).into_vec();
    let mut frame = Vec::with_capacity(14 + inner.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&inner);
    Packet::new(frame)
}

fn build_ipv4_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Packet {
    let total_len = 20 + 20 + payload.len();
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = 6;
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let l4_off = 20;
    buf[l4_off..l4_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[l4_off + 2..l4_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[l4_off + 12] = 0x50;
    buf[l4_off + 13] = 0x10;
    buf[l4_off + 16..l4_off + 18].copy_from_slice(&1024u16.to_be_bytes());
    buf[l4_off + 18..l4_off + 20].copy_from_slice(&0u16.to_be_bytes());
    buf[l4_off + 20..].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    assert!(pkt.recalc_checksums());
    pkt
}
