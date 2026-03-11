use super::*;

#[derive(Debug)]
pub struct UpstreamServices {
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    pub dns_addr: SocketAddr,
    pub dns_addr_secondary: SocketAddr,
    pub http_addr: SocketAddr,
    pub https_addr: SocketAddr,
    pub udp_echo_addr: SocketAddr,
    pub answer_ip: Ipv4Addr,
    pub answer_ip_alt: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct UpstreamTlsMaterial {
    pub ca_pem: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
}

pub fn generate_upstream_tls_material() -> Result<UpstreamTlsMaterial, String> {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Upstream Test CA");
    let ca_cert = Certificate::from_params(ca_params).map_err(|e| format!("ca gen failed: {e}"))?;
    let ca_pem = ca_cert
        .serialize_pem()
        .map_err(|e| format!("ca pem failed: {e}"))?
        .into_bytes();
    let ca_der = ca_cert
        .serialize_der()
        .map_err(|e| format!("ca der failed: {e}"))?;

    let mut leaf_params = CertificateParams::new(vec!["foo.allowed".to_string()]);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "foo.allowed");
    let leaf_cert =
        Certificate::from_params(leaf_params).map_err(|e| format!("leaf gen failed: {e}"))?;
    let leaf_der = leaf_cert
        .serialize_der_with_signer(&ca_cert)
        .map_err(|e| format!("leaf der failed: {e}"))?;
    let key_der = leaf_cert.serialize_private_key_der();

    Ok(UpstreamTlsMaterial {
        ca_pem,
        cert_chain: vec![leaf_der, ca_der],
        key_der,
    })
}

impl UpstreamServices {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        ns: netns_rs::NetNs,
        dns_addr: SocketAddr,
        dns_addr_secondary: SocketAddr,
        http_addr: SocketAddr,
        https_addr: SocketAddr,
        udp_echo_addr: SocketAddr,
        answer_ip: Ipv4Addr,
        answer_ip_alt: Ipv4Addr,
        tls: UpstreamTlsMaterial,
    ) -> Result<Self, String> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let _ = ns.run(|_| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime error: {e}"))?;
                rt.block_on(async move {
                    let dns_task = tokio::spawn(crate::e2e::services::dns::run_dns_server(
                        dns_addr,
                        answer_ip,
                        answer_ip_alt,
                        crate::e2e::services::dns::DnsServerBehavior::Primary,
                    ));
                    let dns_task_secondary =
                        tokio::spawn(crate::e2e::services::dns::run_dns_server(
                            dns_addr_secondary,
                            answer_ip,
                            answer_ip_alt,
                            crate::e2e::services::dns::DnsServerBehavior::Secondary,
                        ));
                    let http_task = tokio::spawn(
                        crate::e2e::services::server_runtime::run_http_server(http_addr),
                    );
                    let http_task_alt =
                        tokio::spawn(crate::e2e::services::server_runtime::run_http_server(
                            (answer_ip_alt, http_addr.port()).into(),
                        ));
                    let https_task =
                        tokio::spawn(crate::e2e::services::server_runtime::run_https_server(
                            https_addr,
                            tls.clone(),
                        ));
                    let https_task_alt =
                        tokio::spawn(crate::e2e::services::server_runtime::run_https_server(
                            (answer_ip_alt, https_addr.port()).into(),
                            tls.clone(),
                        ));
                    let udp_task = tokio::spawn(
                        crate::e2e::services::server_runtime::run_udp_echo_server(udp_echo_addr),
                    );
                    let udp_task_alt =
                        tokio::spawn(crate::e2e::services::server_runtime::run_udp_echo_server(
                            (answer_ip_alt, udp_echo_addr.port()).into(),
                        ));

                    let _ = shutdown_rx.await;
                    dns_task.abort();
                    dns_task_secondary.abort();
                    http_task.abort();
                    http_task_alt.abort();
                    https_task.abort();
                    https_task_alt.abort();
                    udp_task.abort();
                    udp_task_alt.abort();
                    Ok::<(), String>(())
                })
            });
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
            dns_addr,
            dns_addr_secondary,
            http_addr,
            https_addr,
            udp_echo_addr,
            answer_ip,
            answer_ip_alt,
        })
    }
}

impl Drop for UpstreamServices {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
