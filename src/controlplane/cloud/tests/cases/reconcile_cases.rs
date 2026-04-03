#[tokio::test]
async fn reconcile_updates_routes_and_protection() {
    let tags = tagged(&[
        ("neuwerk.io/cluster", "demo"),
        ("neuwerk.io/role", "dataplane"),
    ]);
    let instance_a = tagged_instance(
        "i-a",
        "zone-1",
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 0, 1),
        tags.clone(),
    );
    let instance_b = tagged_instance(
        "i-b",
        "zone-1",
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 1, 0, 2),
        tags.clone(),
    );
    let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());
    let expected_assignments = compute_assignments(
        std::slice::from_ref(&subnet),
        &[instance_a.clone(), instance_b.clone()],
    );
    let local_id = expected_assignments.values().next().cloned().unwrap();

    let provider = MockProvider::new(
        vec![instance_a.clone(), instance_b.clone()],
        vec![subnet.clone()],
        IntegrationCapabilities {
            instance_protection: true,
            termination_notice: false,
            lifecycle_hook: false,
        },
        &local_id,
    );
    let mut readiness = HashMap::new();
    readiness.insert(instance_a.mgmt_ip, true);
    readiness.insert(instance_b.mgmt_ip, true);
    let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
        tag_filter: DiscoveryFilter { tags: tags.clone() },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        Arc::new(provider.clone()),
        None,
        None,
        metrics.clone(),
        drain_control.clone(),
        ready,
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();

    let routes = provider.routes.lock().await;
    let assigned_id = expected_assignments.get("subnet-1").unwrap();
    let assigned_ip = if assigned_id == "i-a" {
        instance_a.dataplane_ip
    } else {
        instance_b.dataplane_ip
    };
    let route_key = "subnet-1:neuwerk-default".to_string();
    assert_eq!(routes.get(&route_key), Some(&assigned_ip));

    let protections = provider.protections.lock().await;
    let mut latest = HashMap::new();
    for (id, enabled) in protections.iter().cloned() {
        latest.insert(id, enabled);
    }
    let expected_a = assigned_id == "i-a";
    let expected_b = assigned_id == "i-b";
    assert_eq!(latest.get("i-a"), Some(&expected_a));
    assert_eq!(latest.get("i-b"), Some(&expected_b));

    assert!(!drain_control.is_draining());
    assert_eq!(
        manager.local_cache.assignments.get("subnet-1"),
        expected_assignments.get("subnet-1")
    );
}

#[tokio::test]
async fn reconcile_uses_only_ready_instances() {
    let tags = tagged(&[
        ("neuwerk.io/cluster", "demo"),
        ("neuwerk.io/role", "dataplane"),
    ]);
    let instance_a = tagged_instance(
        "i-a",
        "zone-1",
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 0, 1),
        tags.clone(),
    );
    let instance_b = tagged_instance(
        "i-b",
        "zone-1",
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 1, 0, 2),
        tags.clone(),
    );
    let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());

    let provider = MockProvider::new(
        vec![instance_a.clone(), instance_b.clone()],
        vec![subnet.clone()],
        IntegrationCapabilities::default(),
        "i-a",
    );
    let mut readiness = HashMap::new();
    readiness.insert(instance_a.mgmt_ip, true);
    readiness.insert(instance_b.mgmt_ip, false);
    let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
        tag_filter: DiscoveryFilter { tags: tags.clone() },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        Arc::new(provider.clone()),
        None,
        None,
        metrics,
        drain_control,
        ready,
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();

    let routes = provider.routes.lock().await;
    let route_key = "subnet-1:neuwerk-default".to_string();
    assert_eq!(routes.get(&route_key), Some(&instance_a.dataplane_ip));
}

#[tokio::test]
async fn reconcile_skips_instances_without_tags() {
    let tags = tagged(&[
        ("neuwerk.io/cluster", "demo"),
        ("neuwerk.io/role", "dataplane"),
    ]);
    let instance = tagged_instance(
        "i-a",
        "zone-1",
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 0, 1),
        HashMap::new(),
    );
    let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());

    let provider = MockProvider::new(
        vec![instance],
        vec![subnet.clone()],
        IntegrationCapabilities::default(),
        "i-a",
    );
    let mut readiness = HashMap::new();
    readiness.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), true);
    let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
        tag_filter: DiscoveryFilter { tags },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        Arc::new(provider.clone()),
        None,
        None,
        metrics,
        drain_control,
        ready,
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();

    let routes = provider.routes.lock().await;
    assert!(routes.is_empty());
}

#[tokio::test]
async fn reconcile_preserves_routes_when_no_ready_instances() {
    let tags = tagged(&[
        ("neuwerk.io/cluster", "demo"),
        ("neuwerk.io/role", "dataplane"),
    ]);
    let instance = tagged_instance(
        "i-a",
        "zone-1",
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 0, 1),
        tags.clone(),
    );
    let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());

    let provider = MockProvider::new(
        vec![instance.clone()],
        vec![subnet.clone()],
        IntegrationCapabilities::default(),
        "i-a",
    );
    {
        let mut routes = provider.routes.lock().await;
        routes.insert(
            format!("{}:neuwerk-default", subnet.id),
            instance.dataplane_ip,
        );
    }

    let ready = Arc::new(MockReady {
        readiness: vec![(instance.mgmt_ip, false)].into_iter().collect(),
    }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
        tag_filter: DiscoveryFilter { tags },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        Arc::new(provider.clone()),
        None,
        None,
        metrics,
        drain_control,
        ready,
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();

    let routes = provider.routes.lock().await;
    let route_key = format!("{}:neuwerk-default", subnet.id);
    assert_eq!(routes.get(&route_key), Some(&instance.dataplane_ip));
}

#[tokio::test]
async fn reconcile_lifecycle_only_mode_keeps_ready_nodes_active() {
    let tags = tagged(&[
        ("neuwerk.io/cluster", "demo"),
        ("neuwerk.io/role", "dataplane"),
    ]);
    let instance_a = tagged_instance(
        "i-a",
        "zone-1",
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 0, 1),
        tags.clone(),
    );
    let instance_b = tagged_instance(
        "i-b",
        "zone-1",
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 1, 0, 2),
        tags.clone(),
    );

    let provider = MockProvider::new(
        vec![instance_a.clone(), instance_b.clone()],
        Vec::new(),
        IntegrationCapabilities {
            instance_protection: true,
            termination_notice: false,
            lifecycle_hook: true,
        },
        "i-a",
    );
    let ready = Arc::new(MockReady {
        readiness: vec![(instance_a.mgmt_ip, true), (instance_b.mgmt_ip, true)]
            .into_iter()
            .collect(),
    }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
        tag_filter: DiscoveryFilter { tags },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        Arc::new(provider.clone()),
        None,
        None,
        metrics,
        drain_control.clone(),
        ready,
    )
    .await
    .expect("manager");

    manager.local_cache.terminations.insert(
        "i-b".to_string(),
        TerminationEvent {
            id: "t-1".to_string(),
            instance_id: "i-b".to_string(),
            deadline_epoch: unix_now() + 120,
        },
    );

    manager.reconcile_once().await.unwrap();

    let routes = provider.routes.lock().await;
    assert!(routes.is_empty());

    let protections = provider.protections.lock().await;
    let mut latest = HashMap::new();
    for (id, enabled) in protections.iter().cloned() {
        latest.insert(id, enabled);
    }
    assert_eq!(latest.get("i-a"), Some(&false));
    assert_eq!(latest.get("i-b"), None);

    assert!(!drain_control.is_draining());
    let local_state = manager
        .local_cache
        .drains
        .get("i-a")
        .expect("local drain state");
    assert_eq!(local_state.state, DrainStatus::Active);
    let terminating_state = manager
        .local_cache
        .drains
        .get("i-b")
        .expect("terminating drain state");
    assert_eq!(terminating_state.state, DrainStatus::Draining);
}
