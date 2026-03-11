#[test]
fn assignments_respect_zone_affinity() {
    let instances = vec![instance("a", "1"), instance("b", "2")];
    let subnets = vec![subnet("s1", "1"), subnet("s2", "2")];
    let assignments = compute_assignments(&subnets, &instances);
    assert_eq!(assignments.get("s1"), Some(&"a".to_string()));
    assert_eq!(assignments.get("s2"), Some(&"b".to_string()));
}

#[test]
fn assignments_with_fallback_prefers_primary_set() {
    let subnet = subnet("s1", "1");
    let instance_a = instance("a", "1");
    let instance_b = instance("b", "1");
    let preferred = vec![instance_b.clone()];
    let fallback = vec![instance_a.clone(), instance_b.clone()];
    let assignments =
        compute_assignments_with_fallback(std::slice::from_ref(&subnet), &preferred, &fallback);
    assert_eq!(assignments.get("s1"), Some(&"b".to_string()));

    let empty: Vec<InstanceRef> = Vec::new();
    let assignments = compute_assignments_with_fallback(&[subnet], &empty, &fallback);
    assert!(assignments.contains_key("s1"));
}

#[test]
fn assignments_with_fallback_uses_zone_match_when_preferred_missing() {
    let subnet_a = subnet("s1", "zone-a");
    let subnet_b = subnet("s2", "zone-b");
    let preferred = vec![instance("i1", "zone-a")];
    let fallback = vec![instance("i2", "zone-b")];
    let assignments = compute_assignments_with_fallback(
        &[subnet_a.clone(), subnet_b.clone()],
        &preferred,
        &fallback,
    );
    assert_eq!(assignments.get("s1"), Some(&"i1".to_string()));
    assert_eq!(assignments.get("s2"), Some(&"i2".to_string()));
}

#[test]
fn drain_state_transitions() {
    let now = 100;
    let timeout = 10;
    let state = compute_drain_state(None, false, 5, now, timeout);
    assert_eq!(state.state, DrainStatus::Draining);
    let later = compute_drain_state(Some(state.clone()), false, 0, now + 5, timeout);
    assert_eq!(later.state, DrainStatus::Drained);
    let active = compute_drain_state(Some(later), true, 0, now + 6, timeout);
    assert_eq!(active.state, DrainStatus::Active);
}

#[test]
fn drain_state_requires_timeout_for_remote_flow_count() {
    let now = 100;
    let timeout = 10;
    let state = compute_drain_state(None, false, -1, now, timeout);
    assert_eq!(state.state, DrainStatus::Draining);
    let still = compute_drain_state(Some(state.clone()), false, -1, now + 5, timeout);
    assert_eq!(still.state, DrainStatus::Draining);
    let drained = compute_drain_state(Some(state), false, -1, now + 11, timeout);
    assert_eq!(drained.state, DrainStatus::Drained);
}

#[test]
fn transitioned_into_draining_treats_missing_previous_as_transition() {
    let next = DrainState {
        state: DrainStatus::Draining,
        since_epoch: 0,
        deadline_epoch: 1,
    };
    assert!(transitioned_into_draining(None, &next));

    let prev_active = DrainState {
        state: DrainStatus::Active,
        since_epoch: 0,
        deadline_epoch: 0,
    };
    assert!(transitioned_into_draining(Some(&prev_active), &next));

    let prev_draining = DrainState {
        state: DrainStatus::Draining,
        since_epoch: 0,
        deadline_epoch: 1,
    };
    assert!(!transitioned_into_draining(Some(&prev_draining), &next));
}

#[test]
fn seed_selection_picks_oldest_then_id() {
    let mut a = instance("a", "1");
    a.created_at_epoch = 10;
    let mut b = instance("b", "1");
    b.created_at_epoch = 5;
    let mut c = instance("c", "1");
    c.created_at_epoch = 5;
    let seed = select_seed_instance(&[a.clone(), b.clone(), c.clone()]).unwrap();
    assert_eq!(seed.id, "b");
}


#[tokio::test]
async fn assignments_avoid_terminating_instance_when_possible() {
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
    readiness.insert(instance_b.mgmt_ip, true);
    let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
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
    manager.local_cache.terminations.insert(
        "i-a".to_string(),
        TerminationEvent {
            id: "event-1".to_string(),
            instance_id: "i-a".to_string(),
            deadline_epoch: 0,
        },
    );

    manager.reconcile_once().await.unwrap();
    let routes = provider.routes.lock().await;
    let route_key = "subnet-1:neuwerk-default".to_string();
    assert_eq!(routes.get(&route_key), Some(&instance_b.dataplane_ip));
}

#[tokio::test]
async fn assignments_fall_back_to_terminating_instance_when_needed() {
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
    manager.local_cache.terminations.insert(
        "i-a".to_string(),
        TerminationEvent {
            id: "event-1".to_string(),
            instance_id: "i-a".to_string(),
            deadline_epoch: 0,
        },
    );

    manager.reconcile_once().await.unwrap();
    let routes = provider.routes.lock().await;
    let route_key = "subnet-1:neuwerk-default".to_string();
    assert_eq!(routes.get(&route_key), Some(&instance_a.dataplane_ip));
}

#[test]
fn assignment_change_count_detects_changes() {
    let mut prev = HashMap::new();
    prev.insert("s1".to_string(), "i1".to_string());
    let mut next = HashMap::new();
    next.insert("s1".to_string(), "i2".to_string());
    next.insert("s2".to_string(), "i3".to_string());
    let changes = assignment_change_count(&prev, &next);
    assert_eq!(changes, 2);
}

fn zone_strategy() -> impl Strategy<Value = String> {
    prop_oneof![Just("zone-a"), Just("zone-b"), Just("zone-c")].prop_map(|value| value.to_string())
}

fn subnet_strategy() -> impl Strategy<Value = Vec<SubnetRef>> {
    prop::collection::hash_set(".{1,8}", 1..8)
        .prop_flat_map(|ids| {
            let ids: Vec<String> = ids.into_iter().collect();
            let len = ids.len();
            (Just(ids), prop::collection::vec(zone_strategy(), len))
        })
        .prop_map(|(ids, zones)| {
            ids.into_iter()
                .zip(zones)
                .map(|(id, zone)| SubnetRef {
                    id: id.clone(),
                    name: id,
                    zone,
                    cidr: "10.0.0.0/24".to_string(),
                    route_table_id: "rt".to_string(),
                    tags: HashMap::new(),
                })
                .collect()
        })
}

proptest! {
    #[test]
    fn assignments_only_choose_matching_zone(
        instance_zones in prop::collection::vec((zone_strategy(), any::<u8>()), 1..8),
        subnets in subnet_strategy(),
    ) {
        let instances: Vec<InstanceRef> = instance_zones
            .into_iter()
            .enumerate()
            .map(|(idx, (zone, octet))| InstanceRef {
                id: format!("i{idx}"),
                name: format!("i{idx}"),
                zone,
                created_at_epoch: 0,
                mgmt_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
                dataplane_ip: Ipv4Addr::new(10, 1, 0, octet),
                tags: HashMap::new(),
                active: true,
            })
            .collect();
        let assignments = compute_assignments(&subnets, &instances);
        for subnet in &subnets {
            if let Some(instance_id) = assignments.get(&subnet.id) {
                let instance = instances
                    .iter()
                    .find(|instance| &instance.id == instance_id)
                    .expect("assigned instance exists");
                prop_assert_eq!(&instance.zone, &subnet.zone);
            }
        }
    }
}

#[test]
fn assignments_only_change_for_removed_instance() {
    let subnets = vec![
        subnet("s1", "zone-a"),
        subnet("s2", "zone-a"),
        subnet("s3", "zone-a"),
    ];
    let instances = vec![
        instance("i1", "zone-a"),
        instance("i2", "zone-a"),
        instance("i3", "zone-a"),
    ];
    let assignments_before = compute_assignments(&subnets, &instances);
    let removed = "i2".to_string();
    let remaining: Vec<_> = instances
        .into_iter()
        .filter(|instance| instance.id != removed)
        .collect();
    let assignments_after = compute_assignments(&subnets, &remaining);
    for subnet in &subnets {
        let before = assignments_before.get(&subnet.id).expect("assignment");
        let after = assignments_after.get(&subnet.id).expect("assignment");
        if before != &removed {
            assert_eq!(before, after);
        }
    }
}
