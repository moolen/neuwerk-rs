impl AzureProvider {
    fn extract_nic_ips(nic: &NicResource) -> Vec<Ipv4Addr> {
        let mut ips = Vec::new();
        if let Some(configs) = nic
            .properties
            .as_ref()
            .and_then(|props| props.ip_configurations.as_ref())
        {
            for cfg in configs {
                if let Some(ip) = cfg
                    .properties
                    .as_ref()
                    .and_then(|props| props.private_ip_address.clone())
                    .and_then(|addr| addr.parse::<Ipv4Addr>().ok())
                {
                    ips.push(ip);
                }
            }
        }
        ips
    }

    fn nic_has_tag(nic: &NicResource, tags: &[&str]) -> bool {
        nic.tags
            .as_ref()
            .is_some_and(|map| tags.iter().any(|tag| map.contains_key(*tag)))
    }

    fn select_tagged_ips(nics: &[NicResource]) -> Result<(Ipv4Addr, Ipv4Addr), CloudError> {
        let mut mgmt_ip = None;
        let mut dataplane_ip = None;
        for nic in nics {
            let ips = AzureProvider::extract_nic_ips(nic);
            if ips.is_empty() {
                continue;
            }
            if mgmt_ip.is_none() && AzureProvider::nic_has_tag(nic, TAG_NIC_MANAGEMENT) {
                mgmt_ip = ips.first().copied();
            }
            if dataplane_ip.is_none() && AzureProvider::nic_has_tag(nic, TAG_NIC_DATAPLANE) {
                dataplane_ip = ips.first().copied();
            }
        }
        match (mgmt_ip, dataplane_ip) {
            (Some(mgmt_ip), Some(dataplane_ip)) => Ok((mgmt_ip, dataplane_ip)),
            _ => Err(CloudError::InvalidResponse(
                "missing tagged nic (neuwerk.io/management or neuwerk.io.management, neuwerk.io/dataplane or neuwerk.io.dataplane)".to_string(),
            )),
        }
    }

    fn select_named_ips(nics: &[NicResource]) -> Result<(Ipv4Addr, Ipv4Addr), CloudError> {
        let mut mgmt_ip = None;
        let mut dataplane_ip = None;
        for nic in nics {
            let nic_name = nic.name.as_deref().unwrap_or_default();
            let configs = nic
                .properties
                .as_ref()
                .and_then(|props| props.ip_configurations.as_ref());
            if let Some(configs) = configs {
                for cfg in configs {
                    let cfg_name = cfg.name.as_deref().unwrap_or_default();
                    let ip = cfg
                        .properties
                        .as_ref()
                        .and_then(|props| props.private_ip_address.clone())
                        .or_else(|| cfg.private_ip_address.clone())
                        .and_then(|addr| addr.parse::<Ipv4Addr>().ok());
                    let Some(ip) = ip else { continue };
                    if mgmt_ip.is_none() && (cfg_name == "mgmt-ipcfg" || nic_name.contains("mgmt0"))
                    {
                        mgmt_ip = Some(ip);
                    }
                    if dataplane_ip.is_none()
                        && (cfg_name == "data-ipcfg" || nic_name.contains("data0"))
                    {
                        dataplane_ip = Some(ip);
                    }
                }
            }
        }
        match (mgmt_ip, dataplane_ip) {
            (Some(mgmt_ip), Some(dataplane_ip)) => Ok((mgmt_ip, dataplane_ip)),
            _ => {
                for nic in nics {
                    let nic_name = nic.name.as_deref().unwrap_or("<unknown>");
                    let cfgs = nic
                        .properties
                        .as_ref()
                        .and_then(|props| props.ip_configurations.as_ref())
                        .map(|cfgs| {
                            cfgs.iter()
                                .map(|cfg| cfg.name.as_deref().unwrap_or("<no-name>"))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    tracing::debug!("azure integration: nic name={nic_name}, ipcfgs={:?}", cfgs);
                }
                Err(CloudError::InvalidResponse(
                    "missing mgmt/data nic by name (mgmt-ipcfg/data-ipcfg or mgmt0/data0)"
                        .to_string(),
                ))
            }
        }
    }

    fn select_mgmt_dataplane_ips(nics: &[NicResource]) -> Result<(Ipv4Addr, Ipv4Addr), CloudError> {
        match AzureProvider::select_tagged_ips(nics) {
            Ok(pair) => Ok(pair),
            Err(err) => {
                tracing::warn!(
                    "azure integration: {err}; falling back to name-based NIC selection"
                );
                AzureProvider::select_named_ips(nics)
            }
        }
    }
}
