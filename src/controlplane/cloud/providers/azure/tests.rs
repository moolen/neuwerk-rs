use super::*;
use std::collections::HashMap;

fn nic_with_tags(tags: &[&str], ip: &str) -> NicResource {
    let mut map = HashMap::new();
    for tag in tags {
        map.insert((*tag).to_string(), "true".to_string());
    }
    NicResource {
        name: Some("nic-test".to_string()),
        tags: Some(map),
        virtual_machine: None,
        properties: Some(NicProperties {
            virtual_machine: None,
            ip_configurations: Some(vec![NicIpConfiguration {
                name: Some("ipcfg-test".to_string()),
                private_ip_address: None,
                properties: Some(NicIpProperties {
                    private_ip_address: Some(ip.to_string()),
                }),
            }]),
        }),
    }
}

#[test]
fn nic_tag_enforcement_requires_both_tags() {
    let mgmt_only = vec![nic_with_tags(TAG_NIC_MANAGEMENT, "10.0.0.1")];
    assert!(AzureProvider::select_tagged_ips(&mgmt_only).is_err());

    let dataplane_only = vec![nic_with_tags(TAG_NIC_DATAPLANE, "10.0.1.1")];
    assert!(AzureProvider::select_tagged_ips(&dataplane_only).is_err());

    let both = vec![
        nic_with_tags(TAG_NIC_MANAGEMENT, "10.0.0.1"),
        nic_with_tags(TAG_NIC_DATAPLANE, "10.0.1.1"),
    ];
    let ips = AzureProvider::select_tagged_ips(&both).expect("tagged ips");
    assert_eq!(ips.0, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(ips.1, Ipv4Addr::new(10, 0, 1, 1));
}

#[test]
fn management_subnet_detection_uses_name_and_tags() {
    let mut role_tags = HashMap::new();
    role_tags.insert("neuwerk.io.role".to_string(), "management".to_string());
    assert!(AzureProvider::is_management_subnet(
        "app-subnet",
        &role_tags
    ));

    let mut mgmt_tags = HashMap::new();
    mgmt_tags.insert("neuwerk.io.management".to_string(), "true".to_string());
    assert!(AzureProvider::is_management_subnet(
        "consumer-subnet",
        &mgmt_tags
    ));

    let mut data_tags = HashMap::new();
    data_tags.insert("neuwerk.io.role".to_string(), "dataplane".to_string());
    assert!(!AzureProvider::is_management_subnet(
        "consumer-subnet",
        &data_tags
    ));
    assert!(AzureProvider::is_management_subnet(
        "mgmt-subnet",
        &data_tags
    ));
}

#[test]
fn scheduled_events_parse_and_match_instance() {
    let json = r#"{
        "DocumentIncarnation": 2,
        "Events": [
            {
                "EventId": "C7061BAC-AFDC-4513-B24B-AA5F13A16123",
                "EventStatus": "Scheduled",
                "EventType": "Freeze",
                "ResourceType": "VirtualMachine",
                "Resources": ["WestNO_0", "WestNO_1"],
                "NotBefore": "Mon, 11 Apr 2022 22:26:58 GMT",
                "Description": "Virtual machine is being paused because of a memory-preserving Live Migration operation.",
                "EventSource": "Platform",
                "DurationInSeconds": 5
            }
        ]
    }"#;
    let payload: ScheduledEventsResponse =
        serde_json::from_str(json).expect("scheduled events parse");
    assert_eq!(payload.events.len(), 1);
    let event = &payload.events[0];
    assert_eq!(event.event_id, "C7061BAC-AFDC-4513-B24B-AA5F13A16123");
    assert!(event.is_termination());

    let instance = InstanceRef {
        id: "0".to_string(),
        name: "WestNO_0".to_string(),
        zone: "zone-1".to_string(),
        created_at_epoch: 0,
        mgmt_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dataplane_ip: Ipv4Addr::new(10, 0, 1, 1),
        tags: HashMap::new(),
        active: true,
    };
    assert!(event.applies_to(&instance));
    let path_resource = ScheduledEvent {
        event_id: "event-path".to_string(),
        event_type: "Reboot".to_string(),
        event_status: Some("Scheduled".to_string()),
        resources: Some(vec![format!(
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{}",
            instance.name
        )]),
        not_before: None,
        duration_in_seconds: None,
    };
    assert!(path_resource.applies_to(&instance));
    let suffix_resource = ScheduledEvent {
        event_id: "event-suffix".to_string(),
        event_type: "Reboot".to_string(),
        event_status: Some("Scheduled".to_string()),
        resources: Some(vec!["vmss_0".to_string()]),
        not_before: None,
        duration_in_seconds: None,
    };
    assert!(suffix_resource.applies_to(&instance));

    let canceled = ScheduledEvent {
        event_id: "event-cancel".to_string(),
        event_type: "Freeze".to_string(),
        event_status: Some("Canceled".to_string()),
        resources: Some(vec!["WestNO_0".to_string()]),
        not_before: None,
        duration_in_seconds: None,
    };
    assert!(!canceled.is_termination());
}

#[test]
fn scheduled_event_ack_serializes_start_requests() {
    let ack = ScheduledEventAck {
        start_requests: vec![ScheduledEventStartRequest {
            event_id: "event-1".to_string(),
        }],
    };
    let value = serde_json::to_value(&ack).expect("serialize ack");
    let start_requests = value
        .get("StartRequests")
        .and_then(|value| value.as_array())
        .expect("start requests");
    assert_eq!(start_requests.len(), 1);
    let event_id = start_requests[0]
        .get("EventId")
        .and_then(|value| value.as_str())
        .expect("event id");
    assert_eq!(event_id, "event-1");
}
