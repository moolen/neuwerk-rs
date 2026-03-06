#[tokio::test]
async fn termination_event_completes_after_drain() {
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
    let provider = MockProvider::new(
        vec![instance.clone()],
        Vec::new(),
        IntegrationCapabilities {
            instance_protection: false,
            termination_notice: true,
            lifecycle_hook: false,
        },
        "i-a",
    );
    *provider.termination_event.lock().await = Some(TerminationEvent {
        id: "event-1".to_string(),
        instance_id: "i-a".to_string(),
        deadline_epoch: 0,
    });

    let ready = Arc::new(MockReady {
        readiness: vec![(instance.mgmt_ip, true)].into_iter().collect(),
    }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
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

    manager.local_cache.drains.insert(
        "i-a".to_string(),
        DrainState {
            state: DrainStatus::Drained,
            since_epoch: 0,
            deadline_epoch: 0,
        },
    );

    manager.reconcile_once().await.unwrap();

    let completed = provider.completed.lock().await;
    assert_eq!(*completed, 1);
}

#[tokio::test]
async fn termination_event_persists_and_clears_locally() {
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
    let provider = MockProvider::new(
        vec![instance.clone()],
        Vec::new(),
        IntegrationCapabilities {
            instance_protection: false,
            termination_notice: true,
            lifecycle_hook: false,
        },
        "i-a",
    );
    *provider.termination_event.lock().await = Some(TerminationEvent {
        id: "event-1".to_string(),
        instance_id: "i-a".to_string(),
        deadline_epoch: 0,
    });

    let ready = Arc::new(MockReady {
        readiness: vec![(instance.mgmt_ip, true)].into_iter().collect(),
    }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
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
    assert!(manager.local_cache.terminations.contains_key("i-a"));

    manager.local_cache.drains.insert(
        "i-a".to_string(),
        DrainState {
            state: DrainStatus::Drained,
            since_epoch: 0,
            deadline_epoch: 0,
        },
    );
    manager.reconcile_once().await.unwrap();

    let completed = provider.completed.lock().await;
    assert_eq!(*completed, 1);
    assert!(manager.local_cache.terminations.get("i-a").is_none());
}

#[tokio::test]
async fn termination_event_completes_after_timeout_when_draining() {
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
    let provider = MockProvider::new(
        vec![instance.clone()],
        Vec::new(),
        IntegrationCapabilities {
            instance_protection: false,
            termination_notice: true,
            lifecycle_hook: false,
        },
        "i-a",
    );
    *provider.termination_event.lock().await = Some(TerminationEvent {
        id: "event-1".to_string(),
        instance_id: "i-a".to_string(),
        deadline_epoch: 0,
    });

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

    manager.local_cache.drains.insert(
        "i-a".to_string(),
        DrainState {
            state: DrainStatus::Draining,
            since_epoch: 0,
            deadline_epoch: 0,
        },
    );

    manager.reconcile_once().await.unwrap();

    let completed = provider.completed.lock().await;
    assert_eq!(*completed, 1);
    assert!(manager.local_cache.terminations.get("i-a").is_none());
}

#[tokio::test]
async fn termination_event_is_not_republished_on_duplicate_notice() {
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
    let event = TerminationEvent {
        id: "event-1".to_string(),
        instance_id: "i-a".to_string(),
        deadline_epoch: 0,
    };
    let provider = RepeatTerminationProvider::new(
        vec![instance.clone()],
        Vec::new(),
        IntegrationCapabilities {
            instance_protection: false,
            termination_notice: true,
            lifecycle_hook: false,
        },
        "i-a",
        2,
        event.clone(),
    );

    let ready = Arc::new(MockReady {
        readiness: vec![(instance.mgmt_ip, true)].into_iter().collect(),
    }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
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
    manager.reconcile_once().await.unwrap();

    assert_eq!(
        manager.local_termination_published_id.as_deref(),
        Some("event-1")
    );
    assert_eq!(manager.local_cache.terminations.len(), 1);
    assert!(manager.local_cache.terminations.get("i-a").is_some());
    assert_eq!(provider.completed_count().await, 0);
}

#[tokio::test]
async fn termination_event_ack_is_safe_to_repeat() {
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
    let event = TerminationEvent {
        id: "event-1".to_string(),
        instance_id: "i-a".to_string(),
        deadline_epoch: 0,
    };
    let provider = RepeatTerminationProvider::new(
        vec![instance.clone()],
        Vec::new(),
        IntegrationCapabilities {
            instance_protection: false,
            termination_notice: true,
            lifecycle_hook: false,
        },
        "i-a",
        2,
        event,
    );

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

    manager.local_cache.drains.insert(
        "i-a".to_string(),
        DrainState {
            state: DrainStatus::Drained,
            since_epoch: 0,
            deadline_epoch: 0,
        },
    );

    manager.reconcile_once().await.unwrap();
    manager.reconcile_once().await.unwrap();

    assert_eq!(provider.completed_count().await, 2);
}


#[tokio::test]
async fn remote_unknown_flow_count_drains_after_timeout() {
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
    let assignments =
        compute_assignments(&[subnet.clone()], &[instance_a.clone(), instance_b.clone()]);
    let local_id = assignments
        .get("subnet-1")
        .cloned()
        .expect("initial assignment");
    let remote_id = if local_id == "i-a" { "i-b" } else { "i-a" }.to_string();

    let provider = MockProvider::new(
        vec![instance_a.clone(), instance_b.clone()],
        vec![subnet],
        IntegrationCapabilities::default(),
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
        drain_timeout_secs: 1,
        reconcile_interval_secs: 1,
        tag_filter: DiscoveryFilter { tags },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        Arc::new(provider),
        None,
        None,
        metrics,
        drain_control,
        ready,
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();
    let first_state = manager
        .local_cache
        .drains
        .get(&remote_id)
        .cloned()
        .expect("remote drain state on first reconcile");
    assert_eq!(first_state.state, DrainStatus::Draining);

    tokio::time::sleep(Duration::from_secs(2)).await;
    manager.reconcile_once().await.unwrap();
    let second_state = manager
        .local_cache
        .drains
        .get(&remote_id)
        .cloned()
        .expect("remote drain state after timeout");
    assert_eq!(second_state.state, DrainStatus::Drained);
}

