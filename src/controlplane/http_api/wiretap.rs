use super::*;

pub(super) async fn wiretap_stream(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let raw_query = request.uri().query().unwrap_or("");
    let query: WiretapQuery = match serde_urlencoded::from_str(raw_query) {
        Ok(query) => query,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };
    let filter = match WiretapFilter::from_query(query.clone()) {
        Ok(filter) => filter,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };

    if let Some(cluster) = &state.cluster {
        match proxy::leader_state(cluster, state.http_port).await {
            proxy::LeaderState::Leader => return wiretap_leader_stream(&state, query).await,
            proxy::LeaderState::Unknown => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "leader unknown".to_string(),
                );
            }
            proxy::LeaderState::Follower(addr) => {
                let path = if raw_query.is_empty() {
                    "/api/v1/wiretap/stream".to_string()
                } else {
                    format!("/api/v1/wiretap/stream?{raw_query}")
                };
                return match proxy::proxy_stream_request(&state, addr, &headers, &path).await {
                    Ok(response) => response,
                    Err(err) => error_response(StatusCode::BAD_GATEWAY, err),
                };
            }
        }
    }

    wiretap_local_stream(&state, filter)
}

fn wiretap_local_stream(state: &ApiState, filter: WiretapFilter) -> Response {
    let Some(hub) = &state.wiretap_hub else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "wiretap unavailable".to_string(),
        );
    };

    let subscriber = hub.subscribe(filter);
    let stream = subscriber.into_stream().map(|event| {
        let event_name = match event.event_type {
            crate::dataplane::wiretap::WiretapEventType::Flow => "flow",
            crate::dataplane::wiretap::WiretapEventType::FlowEnd => "flow_end",
        };
        let payload = event.payload();
        let data = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        Ok::<Event, Infallible>(Event::default().event(event_name).data(data))
    });

    Sse::new(stream).into_response()
}

async fn wiretap_leader_stream(state: &ApiState, query: WiretapQuery) -> Response {
    let Some(cluster) = &state.cluster else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster unavailable".to_string(),
        );
    };
    let Some(tls_dir) = &state.cluster_tls_dir else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cluster tls dir missing".to_string(),
        );
    };
    let tls = match RaftTlsConfig::load(tls_dir.clone()) {
        Ok(tls) => tls,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    let request = crate::controlplane::cluster::rpc::proto::WiretapSubscribeRequest {
        src_cidr: query.src_cidr.clone(),
        dst_cidr: query.dst_cidr.clone(),
        hostname: query.hostname.clone(),
        proto: query.proto.clone(),
        src_port: query.src_port.clone(),
        dst_port: query.dst_port.clone(),
    };

    let metrics = cluster.raft.metrics().borrow().clone();
    let mut streams: SelectAll<
        Pin<
            Box<
                dyn futures::Stream<Item = crate::controlplane::cluster::rpc::proto::WiretapEvent>
                    + Send,
            >,
        >,
    > = SelectAll::new();
    let mut stream_count = 0usize;
    for (_, node) in metrics.membership_config.membership().nodes() {
        let Ok(addr) = node.addr.parse::<SocketAddr>() else {
            continue;
        };
        let mut client = match WiretapClient::connect(addr, tls.clone()).await {
            Ok(client) => client,
            Err(_) => continue,
        };
        let stream = match client.subscribe(request.clone()).await {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let stream = stream.filter_map(|event| async move { event.ok() });
        streams.push(Box::pin(stream));
        stream_count += 1;
    }

    if stream_count == 0 {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "no wiretap subscribers available".to_string(),
        );
    }

    let stream = streams.map(|event| Ok::<Event, Infallible>(wiretap_event_from_proto(event)));
    Sse::new(stream).into_response()
}

fn wiretap_event_from_proto(
    event: crate::controlplane::cluster::rpc::proto::WiretapEvent,
) -> Event {
    let crate::controlplane::cluster::rpc::proto::WiretapEvent {
        event_type,
        flow_id,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        packets_in,
        packets_out,
        last_seen,
        hostname,
        node_id,
    } = event;
    let event_name = if event_type == "flow_end" {
        "flow_end"
    } else {
        "flow"
    };
    let hostname = if hostname.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(hostname)
    };
    let payload = json!({
        "flow_id": flow_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "packets_in": packets_in,
        "packets_out": packets_out,
        "last_seen": last_seen,
        "hostname": hostname,
        "node_id": node_id,
    });
    Event::default().event(event_name).data(payload.to_string())
}
