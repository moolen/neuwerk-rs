use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use openraft::RaftMetrics;
use reqwest::{Certificate as ReqwestCertificate, Client};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use crate::controlplane::cluster::bootstrap;
use crate::controlplane::cluster::config::ClusterConfig;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterCommand;
use crate::controlplane::cluster::types::ClusterTypeConfig;
use crate::controlplane::api_auth;
use crate::controlplane::http_api::{run_http_api, HttpApiCluster, HttpApiConfig};
use crate::controlplane::metrics::Metrics;
use crate::controlplane::http_tls::{ensure_http_tls, HttpTlsConfig};
use crate::controlplane::policy_config::{PolicyConfig, PolicyMode};
use crate::controlplane::policy_repository::{policy_item_key, PolicyCreateRequest, PolicyDiskStore};
use crate::controlplane::PolicyStore;
use crate::dataplane::policy::DefaultPolicy;
use crate::e2e::topology::Topology;

struct ClusterCase {
    name: &'static str,
    func: fn() -> Result<(), String>,
}

pub fn run(topology: &Topology) -> Result<(), String> {
    for case in cases() {
        println!("running cluster case: {}", case.name);
        topology
            .fw()
            .run(|_| (case.func)())
            .map_err(|e| format!("{e}"))??;
    }
    Ok(())
}

fn cases() -> Vec<ClusterCase> {
    vec![
        ClusterCase {
            name: "cluster_mtls_enforced",
            func: cluster_mtls_enforced,
        },
        ClusterCase {
            name: "http_tls_ca_replication_joiner",
            func: http_tls_ca_replication_joiner,
        },
        ClusterCase {
            name: "http_tls_ca_persists_restart",
            func: http_tls_ca_persists_restart,
        },
        ClusterCase {
            name: "http_api_proxy_to_leader",
            func: http_api_proxy_to_leader,
        },
        ClusterCase {
            name: "http_api_leader_loss",
            func: http_api_leader_loss,
        },
        ClusterCase {
            name: "cluster_replication_put",
            func: cluster_replication_put,
        },
        ClusterCase {
            name: "cluster_gc_deterministic",
            func: cluster_gc_deterministic,
        },
        ClusterCase {
            name: "cluster_leader_failover_can_join",
            func: cluster_leader_failover_can_join,
        },
    ]
}

fn cluster_mtls_enforced() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-mtls")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    let seed_addr = next_addr();
    let seed_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let tls_dir = seed_dir.join("tls");
        let ca =
            fs::read(tls_dir.join("ca.crt")).map_err(|e| format!("read ca cert failed: {e}"))?;
        let cert = fs::read(tls_dir.join("node.crt"))
            .map_err(|e| format!("read node cert failed: {e}"))?;
        let key =
            fs::read(tls_dir.join("node.key")).map_err(|e| format!("read node key failed: {e}"))?;

        let endpoint = Endpoint::from_shared(format!("https://{seed_addr}"))
            .map_err(|e| format!("invalid endpoint: {e}"))?
            .connect_timeout(Duration::from_secs(2));

        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca.clone()));
        let channel = endpoint
            .clone()
            .tls_config(tls)
            .map_err(|e| format!("tls config failed: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("connect without identity failed: {e}"))?;
        let mut client =
            crate::controlplane::cluster::rpc::proto::raft_service_client::RaftServiceClient::new(
                channel,
            );
        let resp = client
            .vote(crate::controlplane::cluster::rpc::proto::RaftRequest {
                payload: Vec::new(),
            })
            .await;
        match resp {
            Err(status) if status.code() == tonic::Code::InvalidArgument => {
                let _ = seed.shutdown().await;
                return Err(
                    "mTLS not enforced: request reached service without client cert".to_string(),
                );
            }
            Err(_) => {}
            Ok(_) => {
                let _ = seed.shutdown().await;
                return Err("mTLS not enforced: unexpected success without client cert".to_string());
            }
        }

        let identity = Identity::from_pem(cert, key);
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(identity);
        let channel = endpoint
            .tls_config(tls)
            .map_err(|e| format!("tls config failed: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("connect with identity failed: {e}"))?;
        let mut client =
            crate::controlplane::cluster::rpc::proto::raft_service_client::RaftServiceClient::new(
                channel,
            );
        let resp = client
            .vote(crate::controlplane::cluster::rpc::proto::RaftRequest {
                payload: Vec::new(),
            })
            .await;
        match resp {
            Err(status) if status.code() == tonic::Code::InvalidArgument => {}
            Err(status) => {
                let _ = seed.shutdown().await;
                return Err(format!("unexpected mTLS response: {status:?}"));
            }
            Ok(_) => {
                let _ = seed.shutdown().await;
                return Err("unexpected success with empty payload".to_string());
            }
        }

        seed.shutdown().await;
        Ok(())
    })
}

fn http_tls_ca_replication_joiner() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("http-tls-repl")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_dir = base_dir.join("joiner");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_dir).map_err(|e| format!("joiner dir create failed: {e}"))?;

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let joiner_ip = Ipv4Addr::new(127, 0, 0, 2);
    let seed_addr = next_addr_on(seed_ip);
    let seed_join_addr = next_addr_on(seed_ip);
    let joiner_addr = next_addr_on(joiner_ip);
    let joiner_join_addr = next_addr_on(joiner_ip);

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let mut joiner_cfg = base_config(&joiner_dir, &token_path);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_join_addr);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;
        let joiner = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner cluster start failed: {err}"))?;

        let joiner_id = load_node_id(&joiner_dir)?;
        wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5)).await?;

        let seed_tls_dir = seed_dir.join("http-tls");
        let joiner_tls_dir = joiner_dir.join("http-tls");

        let seed_tls = HttpTlsConfig {
            tls_dir: seed_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(seed.raft.clone()),
            store: Some(seed.store.clone()),
        };
        ensure_http_tls(seed_tls).await?;
        wait_for_state_present(&joiner.store, b"http/ca/cert", Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, b"http/ca/envelope", Duration::from_secs(5)).await?;

        let joiner_tls = HttpTlsConfig {
            tls_dir: joiner_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            san_entries: Vec::new(),
            advertise_addr: joiner_addr,
            management_ip: joiner_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(joiner.raft.clone()),
            store: Some(joiner.store.clone()),
        };
        ensure_http_tls(joiner_tls).await?;

        let seed_ca =
            fs::read(seed_tls_dir.join("ca.crt")).map_err(|e| format!("read ca: {e}"))?;
        let joiner_ca =
            fs::read(joiner_tls_dir.join("ca.crt")).map_err(|e| format!("read ca: {e}"))?;
        if seed_ca != joiner_ca {
            return Err("joiner CA does not match seed CA".to_string());
        }

        seed.shutdown().await;
        joiner.shutdown().await;
        Ok(())
    })
}

fn http_tls_ca_persists_restart() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("http-tls-restart")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;
    let seed_dir = base_dir.join("seed");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let tls_dir = seed_dir.join("http-tls");
        let tls_cfg = HttpTlsConfig {
            tls_dir: tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(seed.raft.clone()),
            store: Some(seed.store.clone()),
        };

        ensure_http_tls(tls_cfg.clone()).await?;
        let ca_first =
            fs::read(tls_dir.join("ca.crt")).map_err(|e| format!("read ca: {e}"))?;
        let stored = seed
            .store
            .get_state_value(b"http/ca/cert")?
            .ok_or_else(|| "missing http ca in store".to_string())?;
        if stored != ca_first {
            return Err("stored CA does not match local CA".to_string());
        }

        if tls_dir.exists() {
            fs::remove_dir_all(&tls_dir).map_err(|e| format!("remove tls dir failed: {e}"))?;
        }
        ensure_http_tls(tls_cfg).await?;
        let ca_second =
            fs::read(tls_dir.join("ca.crt")).map_err(|e| format!("read ca: {e}"))?;
        if ca_second != ca_first {
            return Err("CA changed after restart".to_string());
        }

        seed.shutdown().await;
        Ok(())
    })
}

fn http_api_proxy_to_leader() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("http-api-proxy")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_dir = base_dir.join("joiner");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_dir).map_err(|e| format!("joiner dir create failed: {e}"))?;

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let joiner_ip = Ipv4Addr::new(127, 0, 0, 2);
    let http_port = next_port_on(seed_ip);
    let mut metrics_port = next_port_on(seed_ip);
    while metrics_port == http_port {
        metrics_port = next_port_on(seed_ip);
    }

    let seed_addr = next_addr_on(seed_ip);
    let seed_join_addr = next_addr_on(seed_ip);
    let joiner_addr = next_addr_on(joiner_ip);
    let joiner_join_addr = next_addr_on(joiner_ip);

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let mut joiner_cfg = base_config(&joiner_dir, &token_path);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_join_addr);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;
        let joiner = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner cluster start failed: {err}"))?;

        let joiner_id = load_node_id(&joiner_dir)?;
        wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5)).await?;
        let leader_id = wait_for_leader(&seed.raft, Duration::from_secs(5)).await?;

        let seed_api_addr = SocketAddr::new(seed_ip.into(), http_port);
        let joiner_api_addr = SocketAddr::new(joiner_ip.into(), http_port);
        let seed_metrics_addr = SocketAddr::new(seed_ip.into(), metrics_port);
        let joiner_metrics_addr = SocketAddr::new(joiner_ip.into(), metrics_port);

        let seed_tls_dir = seed_dir.join("http-tls");
        let joiner_tls_dir = joiner_dir.join("http-tls");
        let seed_policy_dir = seed_dir.join("policy-store");
        let joiner_policy_dir = joiner_dir.join("policy-store");

        ensure_http_tls(HttpTlsConfig {
            tls_dir: seed_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(seed.raft.clone()),
            store: Some(seed.store.clone()),
        })
        .await?;

        wait_for_state_present(&joiner.store, b"http/ca/cert", Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, b"http/ca/envelope", Duration::from_secs(5)).await?;

        ensure_http_tls(HttpTlsConfig {
            tls_dir: joiner_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            san_entries: Vec::new(),
            advertise_addr: joiner_addr,
            management_ip: joiner_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(joiner.raft.clone()),
            store: Some(joiner.store.clone()),
        })
        .await?;

        let seed_http = spawn_http_api(
            seed_api_addr,
            seed_metrics_addr,
            seed_tls_dir.clone(),
            seed_policy_dir.clone(),
            token_path.clone(),
            Some(HttpApiCluster {
                raft: seed.raft.clone(),
                store: seed.store.clone(),
            }),
        )?;
        let joiner_http = spawn_http_api(
            joiner_api_addr,
            joiner_metrics_addr,
            joiner_tls_dir.clone(),
            joiner_policy_dir.clone(),
            token_path.clone(),
            Some(HttpApiCluster {
                raft: joiner.raft.clone(),
                store: joiner.store.clone(),
            }),
        )?;

        http_wait_for_health(seed_api_addr, &seed_tls_dir, Duration::from_secs(5)).await?;
        http_wait_for_health(joiner_api_addr, &joiner_tls_dir, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, api_auth::API_KEYS_KEY, Duration::from_secs(5)).await?;
        let token = mint_auth_token(&seed.store)?;

        let seed_id = load_node_id(&seed_dir)?;
        let (leader_addr, leader_tls, follower_addr, follower_tls, follower_policy_dir) =
            if leader_id == seed_id {
                (
                    seed_api_addr,
                    seed_tls_dir.clone(),
                    joiner_api_addr,
                    joiner_tls_dir.clone(),
                    joiner_policy_dir.clone(),
                )
            } else {
                (
                    joiner_api_addr,
                    joiner_tls_dir.clone(),
                    seed_api_addr,
                    seed_tls_dir.clone(),
                    seed_policy_dir.clone(),
                )
            };

        let policy = sample_policy("proxy-policy")?;
        let record = http_set_policy(
            follower_addr,
            &follower_tls,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let leader_list = http_list_policies(leader_addr, &leader_tls, Some(&token)).await?;
        if !leader_list.iter().any(|item| item.id == record.id) {
            return Err("leader list missing proxied policy".to_string());
        }
        let follower_list = http_list_policies(follower_addr, &follower_tls, Some(&token)).await?;
        if !follower_list.iter().any(|item| item.id == record.id) {
            return Err("follower list missing proxied policy".to_string());
        }

        if follower_policy_dir.join("policies").exists() {
            return Err("follower local policy store was mutated".to_string());
        }

        let key = policy_item_key(record.id);
        wait_for_state_present(&seed.store, &key, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, &key, Duration::from_secs(5)).await?;

        seed_http.abort();
        joiner_http.abort();
        seed.shutdown().await;
        joiner.shutdown().await;
        Ok(())
    })
}

fn http_api_leader_loss() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("http-api-leader-loss")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_dir = base_dir.join("joiner");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_dir).map_err(|e| format!("joiner dir create failed: {e}"))?;

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let joiner_ip = Ipv4Addr::new(127, 0, 0, 2);
    let http_port = next_port_on(seed_ip);
    let mut metrics_port = next_port_on(seed_ip);
    while metrics_port == http_port {
        metrics_port = next_port_on(seed_ip);
    }

    let seed_addr = next_addr_on(seed_ip);
    let seed_join_addr = next_addr_on(seed_ip);
    let joiner_addr = next_addr_on(joiner_ip);
    let joiner_join_addr = next_addr_on(joiner_ip);

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let mut joiner_cfg = base_config(&joiner_dir, &token_path);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_join_addr);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;
        let joiner = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner cluster start failed: {err}"))?;
        let mut seed = Some(seed);
        let mut joiner = Some(joiner);

        let joiner_id = load_node_id(&joiner_dir)?;
        wait_for_voter(
            &seed.as_ref().unwrap().raft,
            joiner_id,
            Duration::from_secs(5),
        )
        .await?;
        let leader_id = wait_for_leader(&seed.as_ref().unwrap().raft, Duration::from_secs(5)).await?;
        let seed_id = load_node_id(&seed_dir)?;

        let seed_api_addr = SocketAddr::new(seed_ip.into(), http_port);
        let joiner_api_addr = SocketAddr::new(joiner_ip.into(), http_port);
        let seed_metrics_addr = SocketAddr::new(seed_ip.into(), metrics_port);
        let joiner_metrics_addr = SocketAddr::new(joiner_ip.into(), metrics_port);

        let seed_tls_dir = seed_dir.join("http-tls");
        let joiner_tls_dir = joiner_dir.join("http-tls");
        let seed_policy_dir = seed_dir.join("policy-store");
        let joiner_policy_dir = joiner_dir.join("policy-store");

        ensure_http_tls(HttpTlsConfig {
            tls_dir: seed_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(seed.as_ref().unwrap().raft.clone()),
            store: Some(seed.as_ref().unwrap().store.clone()),
        })
        .await?;

        wait_for_state_present(
            &joiner.as_ref().unwrap().store,
            b"http/ca/cert",
            Duration::from_secs(5),
        )
        .await?;
        wait_for_state_present(
            &joiner.as_ref().unwrap().store,
            b"http/ca/envelope",
            Duration::from_secs(5),
        )
        .await?;

        ensure_http_tls(HttpTlsConfig {
            tls_dir: joiner_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            san_entries: Vec::new(),
            advertise_addr: joiner_addr,
            management_ip: joiner_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(joiner.as_ref().unwrap().raft.clone()),
            store: Some(joiner.as_ref().unwrap().store.clone()),
        })
        .await?;

        let seed_http = spawn_http_api(
            seed_api_addr,
            seed_metrics_addr,
            seed_tls_dir.clone(),
            seed_policy_dir,
            token_path.clone(),
            Some(HttpApiCluster {
                raft: seed.as_ref().unwrap().raft.clone(),
                store: seed.as_ref().unwrap().store.clone(),
            }),
        )?;
        let joiner_http = spawn_http_api(
            joiner_api_addr,
            joiner_metrics_addr,
            joiner_tls_dir.clone(),
            joiner_policy_dir,
            token_path.clone(),
            Some(HttpApiCluster {
                raft: joiner.as_ref().unwrap().raft.clone(),
                store: joiner.as_ref().unwrap().store.clone(),
            }),
        )?;

        http_wait_for_health(seed_api_addr, &seed_tls_dir, Duration::from_secs(5)).await?;
        http_wait_for_health(joiner_api_addr, &joiner_tls_dir, Duration::from_secs(5)).await?;
        wait_for_state_present(
            &seed.as_ref().unwrap().store,
            api_auth::API_KEYS_KEY,
            Duration::from_secs(5),
        )
        .await?;
        let token = mint_auth_token(&seed.as_ref().unwrap().store)?;

        let (leader_is_seed, follower_addr, follower_tls, follower_raft) = if leader_id == seed_id
        {
            (
                true,
                joiner_api_addr,
                joiner_tls_dir.clone(),
                joiner.as_ref().unwrap().raft.clone(),
            )
        } else {
            (
                false,
                seed_api_addr,
                seed_tls_dir.clone(),
                seed.as_ref().unwrap().raft.clone(),
            )
        };

        if leader_is_seed {
            seed.take().unwrap().shutdown().await;
            seed_http.abort();
        } else {
            joiner.take().unwrap().shutdown().await;
            joiner_http.abort();
        }

        wait_for_no_leader(&follower_raft, Duration::from_secs(5)).await?;

        let health = http_api_status(follower_addr, &follower_tls, "/health", None).await?;
        if !health.is_success() {
            return Err(format!("health status unexpected: {health}"));
        }

        let policies =
            http_api_status(follower_addr, &follower_tls, "/api/v1/policies", Some(&token)).await?;
        if policies != reqwest::StatusCode::SERVICE_UNAVAILABLE
            && policies != reqwest::StatusCode::BAD_GATEWAY
        {
            return Err(format!("unexpected policy status after leader loss: {policies}"));
        }

        if leader_is_seed {
            joiner_http.abort();
            joiner.take().unwrap().shutdown().await;
        } else {
            seed_http.abort();
            seed.take().unwrap().shutdown().await;
        }
        Ok(())
    })
}

fn cluster_leader_failover_can_join() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-failover")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_a_dir = base_dir.join("joiner-a");
    let joiner_b_dir = base_dir.join("joiner-b");
    let joiner_c_dir = base_dir.join("joiner-c");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_a_dir).map_err(|e| format!("joiner-a dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_b_dir).map_err(|e| format!("joiner-b dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_c_dir).map_err(|e| format!("joiner-c dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();
    let joiner_b_addr = next_addr();
    let joiner_b_join_addr = next_addr();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let mut seed_cfg = base_config(&seed_dir, &token_path);
        seed_cfg.bind_addr = seed_addr;
        seed_cfg.advertise_addr = seed_addr;
        seed_cfg.join_bind_addr = seed_join_addr;
        let mut seed = Some(
            bootstrap::run_cluster(seed_cfg.clone(), None, None)
                .await
                .map_err(|err| format!("seed cluster start failed: {err}"))?,
        );

        let mut joiner_cfg = base_config(&joiner_a_dir, &token_path);
        joiner_cfg.bind_addr = joiner_a_addr;
        joiner_cfg.advertise_addr = joiner_a_addr;
        joiner_cfg.join_bind_addr = joiner_a_join_addr;
        joiner_cfg.join_seed = Some(seed_join_addr);
        let mut joiner_a = Some(
            bootstrap::run_cluster(joiner_cfg.clone(), None, None)
                .await
                .map_err(|err| format!("joiner-a start failed: {err}"))?,
        );

        let mut joiner_cfg = base_config(&joiner_b_dir, &token_path);
        joiner_cfg.bind_addr = joiner_b_addr;
        joiner_cfg.advertise_addr = joiner_b_addr;
        joiner_cfg.join_bind_addr = joiner_b_join_addr;
        joiner_cfg.join_seed = Some(seed_join_addr);
        let mut joiner_b = Some(
            bootstrap::run_cluster(joiner_cfg.clone(), None, None)
                .await
                .map_err(|err| format!("joiner-b start failed: {err}"))?,
        );

        let seed_id = load_node_id(&seed_dir)?;
        let joiner_a_id = load_node_id(&joiner_a_dir)?;
        let joiner_b_id = load_node_id(&joiner_b_dir)?;

        let seed_ref = seed.as_ref().unwrap();
        wait_for_voter(&seed_ref.raft, joiner_a_id, Duration::from_secs(5)).await?;
        wait_for_voter(&seed_ref.raft, joiner_b_id, Duration::from_secs(5)).await?;
        wait_for_stable_membership(&seed_ref.raft, Duration::from_secs(5)).await?;

        wait_for_envelope(&seed_ref.store, seed_id, Duration::from_secs(5)).await?;
        wait_for_envelope(
            &joiner_a.as_ref().unwrap().store,
            joiner_a_id,
            Duration::from_secs(5),
        )
        .await?;
        wait_for_envelope(
            &joiner_b.as_ref().unwrap().store,
            joiner_b_id,
            Duration::from_secs(5),
        )
        .await?;

        let leader_id = wait_for_leader(&seed_ref.raft, Duration::from_secs(5)).await?;
        let (remaining_a, remaining_b) = if leader_id == seed_id {
            seed.take().unwrap().shutdown().await;
            (joiner_a.as_ref().unwrap(), joiner_b.as_ref().unwrap())
        } else if leader_id == joiner_a_id {
            joiner_a.take().unwrap().shutdown().await;
            (seed.as_ref().unwrap(), joiner_b.as_ref().unwrap())
        } else {
            joiner_b.take().unwrap().shutdown().await;
            (seed.as_ref().unwrap(), joiner_a.as_ref().unwrap())
        };

        let new_leader_id = wait_for_new_leader(
            [&remaining_a.raft, &remaining_b.raft],
            leader_id,
            Duration::from_secs(10),
        )
        .await?;
        let new_leader_join_addr = if new_leader_id == seed_id {
            seed_join_addr
        } else if new_leader_id == joiner_a_id {
            joiner_a_join_addr
        } else {
            joiner_b_join_addr
        };

        let joiner_c_addr = next_addr();
        let joiner_c_join_addr = next_addr();
        let mut joiner_cfg = base_config(&joiner_c_dir, &token_path);
        joiner_cfg.bind_addr = joiner_c_addr;
        joiner_cfg.advertise_addr = joiner_c_addr;
        joiner_cfg.join_bind_addr = joiner_c_join_addr;
        joiner_cfg.join_seed = Some(new_leader_join_addr);
        let joiner_c = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner-c start failed: {err}"))?;

        let joiner_c_id = load_node_id(&joiner_c_dir)?;
        wait_for_voter(&remaining_a.raft, joiner_c_id, Duration::from_secs(5)).await?;

        if let Some(seed) = seed.take() {
            seed.shutdown().await;
        }
        if let Some(joiner_a) = joiner_a.take() {
            joiner_a.shutdown().await;
        }
        if let Some(joiner_b) = joiner_b.take() {
            joiner_b.shutdown().await;
        }
        joiner_c.shutdown().await;
        Ok(())
    })
}

fn cluster_replication_put() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-repl")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_a_dir = base_dir.join("joiner-a");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_a_dir).map_err(|e| format!("joiner-a dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let mut seed_cfg = base_config(&seed_dir, &token_path);
        seed_cfg.bind_addr = seed_addr;
        seed_cfg.advertise_addr = seed_addr;
        seed_cfg.join_bind_addr = seed_join_addr;
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let mut joiner_cfg = base_config(&joiner_a_dir, &token_path);
        joiner_cfg.bind_addr = joiner_a_addr;
        joiner_cfg.advertise_addr = joiner_a_addr;
        joiner_cfg.join_bind_addr = joiner_a_join_addr;
        joiner_cfg.join_seed = Some(seed_join_addr);
        let joiner_a = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner-a start failed: {err}"))?;

        let seed_id = load_node_id(&seed_dir)?;
        let joiner_a_id = load_node_id(&joiner_a_dir)?;
        wait_for_voter(&seed.raft, joiner_a_id, Duration::from_secs(5)).await?;

        let leader_id = wait_for_leader(&seed.raft, Duration::from_secs(5)).await?;
        let leader = if leader_id == seed_id { &seed } else { &joiner_a };

        let key = b"rules/active".to_vec();
        let value = b"v1".to_vec();
        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: key.clone(),
                value: value.clone(),
            })
            .await
            .map_err(|err| format!("client_write put failed: {err:?}"))?;

        wait_for_state_value(&seed.store, &key, &value, Duration::from_secs(5)).await?;
        wait_for_state_value(&joiner_a.store, &key, &value, Duration::from_secs(5)).await?;

        if leader_id == seed_id {
            joiner_a.shutdown().await;
            seed.shutdown().await;
        } else {
            seed.shutdown().await;
            joiner_a.shutdown().await;
        }
        Ok(())
    })
}

fn cluster_gc_deterministic() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-gc")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_a_dir = base_dir.join("joiner-a");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_a_dir).map_err(|e| format!("joiner-a dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let mut seed_cfg = base_config(&seed_dir, &token_path);
        seed_cfg.bind_addr = seed_addr;
        seed_cfg.advertise_addr = seed_addr;
        seed_cfg.join_bind_addr = seed_join_addr;
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let mut joiner_cfg = base_config(&joiner_a_dir, &token_path);
        joiner_cfg.bind_addr = joiner_a_addr;
        joiner_cfg.advertise_addr = joiner_a_addr;
        joiner_cfg.join_bind_addr = joiner_a_join_addr;
        joiner_cfg.join_seed = Some(seed_join_addr);
        let joiner_a = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner-a start failed: {err}"))?;

        let seed_id = load_node_id(&seed_dir)?;
        let joiner_a_id = load_node_id(&joiner_a_dir)?;
        wait_for_voter(&seed.raft, joiner_a_id, Duration::from_secs(5)).await?;

        let leader_id = wait_for_leader(&seed.raft, Duration::from_secs(5)).await?;
        let leader = if leader_id == seed_id { &seed } else { &joiner_a };

        let stale_key = b"dns/last_seen/foo.allowed/203.0.113.10".to_vec();
        let stale_ts =
            bincode::serialize(&10i64).map_err(|e| format!("encode stale ts failed: {e}"))?;
        let stale_map_key = b"dns/map/foo.allowed/203.0.113.10".to_vec();
        let stale_map_val = b"stale".to_vec();

        let fresh_key = b"dns/last_seen/foo.allowed/203.0.113.20".to_vec();
        let fresh_ts =
            bincode::serialize(&200i64).map_err(|e| format!("encode fresh ts failed: {e}"))?;
        let fresh_map_key = b"dns/map/foo.allowed/203.0.113.20".to_vec();
        let fresh_map_val = b"fresh".to_vec();

        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: stale_key.clone(),
                value: stale_ts,
            })
            .await
            .map_err(|err| format!("put stale last_seen failed: {err:?}"))?;
        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: stale_map_key.clone(),
                value: stale_map_val.clone(),
            })
            .await
            .map_err(|err| format!("put stale map failed: {err:?}"))?;
        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: fresh_key.clone(),
                value: fresh_ts,
            })
            .await
            .map_err(|err| format!("put fresh last_seen failed: {err:?}"))?;
        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: fresh_map_key.clone(),
                value: fresh_map_val.clone(),
            })
            .await
            .map_err(|err| format!("put fresh map failed: {err:?}"))?;

        wait_for_state_present(&seed.store, &stale_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner_a.store, &stale_key, Duration::from_secs(5)).await?;

        leader
            .raft
            .client_write(ClusterCommand::Gc { cutoff_unix: 100 })
            .await
            .map_err(|err| format!("gc command failed: {err:?}"))?;

        wait_for_state_absent(&seed.store, &stale_key, Duration::from_secs(5)).await?;
        wait_for_state_absent(&seed.store, &stale_map_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, &fresh_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, &fresh_map_key, Duration::from_secs(5)).await?;

        wait_for_state_absent(&joiner_a.store, &stale_key, Duration::from_secs(5)).await?;
        wait_for_state_absent(&joiner_a.store, &stale_map_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner_a.store, &fresh_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner_a.store, &fresh_map_key, Duration::from_secs(5)).await?;

        if leader_id == seed_id {
            joiner_a.shutdown().await;
            seed.shutdown().await;
        } else {
            seed.shutdown().await;
            joiner_a.shutdown().await;
        }
        Ok(())
    })
}

fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn create_temp_dir(label: &str) -> Result<PathBuf, String> {
    let base = std::env::temp_dir().join(format!("neuwerk-e2e-{}-{}", label, uuid::Uuid::new_v4()));
    fs::create_dir_all(&base).map_err(|e| format!("temp dir create failed: {e}"))?;
    Ok(base)
}

fn write_token_file(path: &Path) -> Result<(), String> {
    let json = r#"{
  "tokens": [
    { "kid": "test", "token": "b64:dGVzdC1zZWNyZXQ=", "valid_until": "2027-01-01T00:00:00Z" }
  ]
}"#;
    fs::write(path, json).map_err(|e| format!("write token file failed: {e}"))?;
    Ok(())
}

fn next_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

fn base_config(data_dir: &Path, token_path: &Path) -> ClusterConfig {
    let mut cfg = ClusterConfig::disabled();
    cfg.enabled = true;
    cfg.data_dir = data_dir.to_path_buf();
    cfg.token_path = token_path.to_path_buf();
    cfg.node_id_path = data_dir.join("node_id");
    cfg
}

fn next_addr_on(ip: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind((ip, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

fn next_port_on(ip: Ipv4Addr) -> u16 {
    let listener = TcpListener::bind((ip, 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

fn load_node_id(dir: &Path) -> Result<u128, String> {
    let raw =
        fs::read_to_string(dir.join("node_id")).map_err(|e| format!("read node id failed: {e}"))?;
    let id = uuid::Uuid::parse_str(raw.trim()).map_err(|e| format!("parse node id failed: {e}"))?;
    Ok(id.as_u128())
}

async fn wait_for_voter(
    raft: &openraft::Raft<ClusterTypeConfig>,
    node_id: u128,
    timeout: Duration,
) -> Result<(), String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if m.membership_config
            .membership()
            .voter_ids()
            .any(|id| id == node_id)
        {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for voter membership".to_string());
        }
        let remaining = deadline - now;
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .map_err(|_| "metrics wait timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

async fn wait_for_no_leader(
    raft: &openraft::Raft<ClusterTypeConfig>,
    timeout: Duration,
) -> Result<(), String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if m.current_leader.is_none() {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for leader loss".to_string());
        }
        let remaining = deadline - now;
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .map_err(|_| "metrics wait timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

async fn wait_for_stable_membership(
    raft: &openraft::Raft<ClusterTypeConfig>,
    timeout: Duration,
) -> Result<(), String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if m.membership_config.membership().get_joint_config().len() == 1 {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for stable membership".to_string());
        }
        let remaining = deadline - now;
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .map_err(|_| "metrics wait timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

async fn wait_for_leader(
    raft: &openraft::Raft<ClusterTypeConfig>,
    timeout: Duration,
) -> Result<u128, String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if let Some(leader) = m.current_leader {
            return Ok(leader);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for leader".to_string());
        }
        let remaining = deadline - now;
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .map_err(|_| "metrics wait timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

async fn wait_for_new_leader(
    rafts: [&openraft::Raft<ClusterTypeConfig>; 2],
    old_leader: u128,
    timeout: Duration,
) -> Result<u128, String> {
    let deadline = Instant::now() + timeout;
    loop {
        for raft in rafts {
            let m = raft.metrics().borrow().clone();
            if let Some(leader) = m.current_leader {
                if leader != old_leader {
                    return Ok(leader);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for new leader".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_envelope(
    store: &ClusterStore,
    node_id: u128,
    timeout: Duration,
) -> Result<(), String> {
    let key = format!("ca/envelope/{node_id}").into_bytes();
    let deadline = Instant::now() + timeout;
    loop {
        if store.get_state_value(&key)?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for ca envelope".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_state_value(
    store: &ClusterStore,
    key: &[u8],
    expected: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = store.get_state_value(key)? {
            if value == expected {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for state value".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_state_present(
    store: &ClusterStore,
    key: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if store.get_state_value(key)?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for state key".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn mint_auth_token(store: &ClusterStore) -> Result<String, String> {
    let keyset = api_auth::load_keyset_from_store(store)?
        .ok_or_else(|| "missing api auth keyset".to_string())?;
    let token = api_auth::mint_token(&keyset, "e2e-cluster", None, None)?;
    Ok(token.token)
}

async fn wait_for_state_absent(
    store: &ClusterStore,
    key: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if store.get_state_value(key)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for state key removal".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn sample_policy(rule_id: &str) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"default_policy: deny
source_groups:
  - id: "client-primary"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "{rule_id}"
        action: allow
        match:
          dns_hostname: '^foo\.allowed$'
"#
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

fn spawn_http_api(
    bind_addr: SocketAddr,
    metrics_bind: SocketAddr,
    tls_dir: PathBuf,
    local_policy_dir: PathBuf,
    token_path: PathBuf,
    cluster: Option<HttpApiCluster>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let policy_store = PolicyStore::new(
        DefaultPolicy::Deny,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
    );
    let local_store = PolicyDiskStore::new(local_policy_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind,
        tls_dir,
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: bind_addr.ip(),
        token_path,
        cluster_tls_dir: None,
    };
    let metrics = Metrics::new().map_err(|err| format!("metrics init failed: {err}"))?;
    Ok(tokio::spawn(async move {
        let _ = run_http_api(cfg, policy_store, local_store, cluster, None, None, metrics).await;
    }))
}

fn http_api_client(tls_dir: &Path) -> Result<Client, String> {
    let ca = fs::read(tls_dir.join("ca.crt"))
        .map_err(|e| format!("read http ca cert failed: {e}"))?;
    let ca = ReqwestCertificate::from_pem(&ca)
        .map_err(|e| format!("invalid http ca cert: {e}"))?;
    Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|e| format!("http client build failed: {e}"))
}

async fn http_wait_for_health(
    addr: SocketAddr,
    tls_dir: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match http_api_status(addr, tls_dir, "/health", None).await {
            Ok(status) if status.is_success() => return Ok(()),
            Ok(_) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for http api health".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn http_api_status(
    addr: SocketAddr,
    tls_dir: &Path,
    path: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut req = client.get(format!("https://{addr}{path}"));
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("http request failed: {e}"))?;
    Ok(resp.status())
}

async fn http_set_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy: PolicyConfig,
    mode: PolicyMode,
    auth_token: Option<&str>,
) -> Result<crate::controlplane::policy_repository::PolicyRecord, String> {
    let client = http_api_client(tls_dir)?;
    let req = PolicyCreateRequest { mode, policy };
    let mut builder = client
        .post(format!("https://{addr}/api/v1/policies"))
        .json(&req);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy post failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy post status {}", resp.status()));
    }
    resp.json::<crate::controlplane::policy_repository::PolicyRecord>()
        .await
        .map_err(|e| format!("policy decode failed: {e}"))
}

async fn http_list_policies(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<Vec<crate::controlplane::policy_repository::PolicyRecord>, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/policies"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy list failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy list status {}", resp.status()));
    }
    resp.json::<Vec<crate::controlplane::policy_repository::PolicyRecord>>()
        .await
        .map_err(|e| format!("policy list decode failed: {e}"))
}
