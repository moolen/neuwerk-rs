use super::*;

use std::net::Ipv4Addr;
use std::net::TcpListener;
use std::time::Duration;

use crate::dataplane::policy::DefaultPolicy;
use axum::http::{header::AUTHORIZATION, header::COOKIE, HeaderValue};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, SanType};
use tempfile::TempDir;
use tower::ServiceExt;

#[tokio::test]
async fn proxy_stream_forwards_auth_header() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = TempDir::new().unwrap();
    let cert_path = dir.path().join("node.crt");
    let key_path = dir.path().join("node.key");

    let mut ca_params = CertificateParams::new(Vec::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    let ca_pem = ca_cert.serialize_pem().unwrap();

    let mut leaf_params = CertificateParams::new(Vec::new());
    leaf_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let leaf_cert = Certificate::from_params(leaf_params).unwrap();
    let leaf_pem = leaf_cert.serialize_pem_with_signer(&ca_cert).unwrap();
    let leaf_key = leaf_cert.serialize_private_key_pem();

    std::fs::write(&cert_path, leaf_pem).unwrap();
    std::fs::write(&key_path, leaf_key).unwrap();

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let app = Router::new().route(
        "/api/v1/wiretap/stream",
        get(|headers: HeaderMap| async move {
            match headers.get(AUTHORIZATION) {
                Some(value) if value == "Bearer testtoken" => Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("ok"))
                    .unwrap(),
                _ => Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("unauthorized"))
                    .unwrap(),
            }
        }),
    );

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .unwrap();
    let server = tokio::spawn(async move {
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .ok();
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .unwrap();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(dir.path().join("policies"));
    let service_accounts = ServiceAccountStore::local(dir.path().join("service-accounts"));
    let integrations = IntegrationStore::local(dir.path().join("integrations"));
    let metrics = Metrics::new().unwrap();
    let state = ApiState {
        policy_store,
        local_store,
        service_accounts,
        integrations,
        audit_store: None,
        cluster: None,
        metrics,
        proxy_client: Some(client),
        http_port: addr.port(),
        auth_source: ApiAuthSource::Local(dir.path().join("auth.json")),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        tls_dir: dir.path().join("http-tls"),
        token_path: dir.path().join("bootstrap-token"),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        dns_map: None,
        readiness: None,
    };

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer testtoken"));
    let response = proxy::proxy_stream_request(&state, addr, &headers, "/api/v1/wiretap/stream")
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, "ok");

    server.abort();
}

#[tokio::test]
async fn auth_metrics_record_failures() {
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    api_auth::ensure_local_keyset(&tls_dir).unwrap();
    let keyset_path = api_auth::local_keyset_path(&tls_dir);
    let keyset = api_auth::load_keyset_from_file(&keyset_path)
        .unwrap()
        .expect("missing keyset");
    let token = api_auth::mint_token(&keyset, "auth-test", None, None).unwrap();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(dir.path().join("policies"));
    let service_accounts = ServiceAccountStore::local(dir.path().join("service-accounts"));
    let integrations = IntegrationStore::local(dir.path().join("integrations"));
    let metrics = Metrics::new().unwrap();
    let state = ApiState {
        policy_store,
        local_store,
        service_accounts,
        integrations,
        audit_store: None,
        cluster: None,
        metrics: metrics.clone(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path.clone()),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        tls_dir: tls_dir.clone(),
        token_path: dir.path().join("bootstrap-token"),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        dns_map: None,
        readiness: None,
    };

    let app = Router::new()
        .route("/api/v1/policies", get(|| async { StatusCode::OK }))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies")
                .header(AUTHORIZATION, "Basic test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies")
                .header(AUTHORIZATION, "Bearer invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies")
                .header(AUTHORIZATION, format!("Bearer {}", token.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies")
                .header(COOKIE, format!("{AUTH_COOKIE_NAME}={}", token.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let missing_keyset_state = ApiState {
        auth_source: ApiAuthSource::Local(dir.path().join("missing.json")),
        ..state
    };
    let missing_app = Router::new()
        .route("/api/v1/policies", get(|| async { StatusCode::OK }))
        .with_state(missing_keyset_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            missing_keyset_state,
            auth::auth_middleware,
        ));
    let resp = missing_app
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies")
                .header(AUTHORIZATION, "Bearer test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let rendered = metrics.render().unwrap();
    assert!(rendered.contains("http_auth_total{outcome=\"deny\",reason=\"missing_token\"}"));
    assert!(rendered.contains("http_auth_total{outcome=\"deny\",reason=\"invalid_scheme\"}"));
    assert!(rendered.contains("http_auth_total{outcome=\"deny\",reason=\"invalid_token\"}"));
    assert!(rendered.contains("http_auth_total{outcome=\"deny\",reason=\"keyset_error\"}"));
    assert!(rendered.contains("http_auth_total{outcome=\"allow\",reason=\"valid_token\"}"));
}

#[tokio::test]
async fn wiretap_query_token_is_rejected_and_cookie_auth_works() {
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    api_auth::ensure_local_keyset(&tls_dir).unwrap();
    let keyset_path = api_auth::local_keyset_path(&tls_dir);
    let keyset = api_auth::load_keyset_from_file(&keyset_path)
        .unwrap()
        .expect("missing keyset");
    let token = api_auth::mint_token(&keyset, "wiretap-auth-test", None, None).unwrap();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(dir.path().join("policies"));
    let service_accounts = ServiceAccountStore::local(dir.path().join("service-accounts"));
    let integrations = IntegrationStore::local(dir.path().join("integrations"));
    let metrics = Metrics::new().unwrap();
    let state = ApiState {
        policy_store,
        local_store,
        service_accounts,
        integrations,
        audit_store: None,
        cluster: None,
        metrics,
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        tls_dir: tls_dir.clone(),
        token_path: dir.path().join("bootstrap-token"),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        dns_map: None,
        readiness: None,
    };

    let app = Router::new()
        .route("/api/v1/wiretap/stream", get(|| async { StatusCode::OK }))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/wiretap/stream?access_token={}",
                    token.token
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "query-token auth should not be accepted"
    );

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/wiretap/stream")
                .header(COOKIE, format!("{AUTH_COOKIE_NAME}={}", token.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn security_headers_are_attached() {
    let app = Router::new()
        .route("/", get(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn(
            security::security_headers_middleware,
        ));

    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        HeaderValue::from_static("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").unwrap(),
        HeaderValue::from_static("DENY")
    );
    assert_eq!(
        headers.get("referrer-policy").unwrap(),
        HeaderValue::from_static("no-referrer")
    );
    assert!(headers.contains_key("permissions-policy"));
    assert!(headers.contains_key("content-security-policy"));
    assert_eq!(
        headers.get("strict-transport-security").unwrap(),
        HeaderValue::from_static("max-age=31536000; includeSubDomains")
    );
}

#[tokio::test]
async fn auth_routes_set_no_store_cache_control() {
    let app = Router::new()
        .route(
            "/api/v1/auth/token-login",
            post(|| async { StatusCode::OK }),
        )
        .layer(axum::middleware::from_fn(
            security::security_headers_middleware,
        ));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/token-login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        HeaderValue::from_static("no-store")
    );
}

#[test]
fn proxy_header_filter_drops_hop_by_hop_headers() {
    assert!(!proxy::should_proxy_header("connection"));
    assert!(!proxy::should_proxy_header("keep-alive"));
    assert!(!proxy::should_proxy_header("transfer-encoding"));
    assert!(!proxy::should_proxy_header("te"));
    assert!(!proxy::should_proxy_header("upgrade"));
    assert!(!proxy::should_proxy_header("trailer"));
    assert!(!proxy::should_proxy_header("proxy-authenticate"));
    assert!(!proxy::should_proxy_header("proxy-authorization"));
    assert!(!proxy::should_proxy_header("host"));
    assert!(!proxy::should_proxy_header("content-length"));
    assert!(proxy::should_proxy_header("authorization"));
    assert!(proxy::should_proxy_header("x-custom"));
}

#[tokio::test]
async fn read_body_limited_rejects_large_payload() {
    let body = Body::from(vec![b'a'; MAX_BODY_BYTES + 1]);
    let response = read_body_limited(body)
        .await
        .expect_err("expected payload limit error");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn auth_token_login_rate_limits_repeated_failures() {
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    api_auth::ensure_local_keyset(&tls_dir).unwrap();
    let keyset_path = api_auth::local_keyset_path(&tls_dir);

    let state = ApiState {
        policy_store: PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24),
        local_store: PolicyDiskStore::new(dir.path().join("policies")),
        service_accounts: ServiceAccountStore::local(dir.path().join("service-accounts")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        tls_dir,
        token_path: dir.path().join("bootstrap-token"),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        dns_map: None,
        readiness: None,
    };

    let app = Router::new()
        .route("/api/v1/auth/token-login", post(auth_token_login))
        .with_state(state);

    for _ in 0..AUTH_LOGIN_MAX_FAILURES {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/token-login")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"token":"invalid-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    let blocked = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/token-login")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"token":"invalid-token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_token_login_rate_limit_is_scoped_by_client_and_token() {
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    api_auth::ensure_local_keyset(&tls_dir).unwrap();
    let keyset_path = api_auth::local_keyset_path(&tls_dir);

    let state = ApiState {
        policy_store: PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24),
        local_store: PolicyDiskStore::new(dir.path().join("policies")),
        service_accounts: ServiceAccountStore::local(dir.path().join("service-accounts")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        tls_dir,
        token_path: dir.path().join("bootstrap-token"),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        dns_map: None,
        readiness: None,
    };

    let app = Router::new()
        .route("/api/v1/auth/token-login", post(auth_token_login))
        .with_state(state);

    for _ in 0..AUTH_LOGIN_MAX_FAILURES {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/token-login")
                    .header(CONTENT_TYPE, "application/json")
                    .header("x-forwarded-for", "203.0.113.10")
                    .body(Body::from(r#"{"token":"invalid-token-a"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    let blocked_same_bucket = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/token-login")
                .header(CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "203.0.113.10")
                .body(Body::from(r#"{"token":"invalid-token-a"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked_same_bucket.status(), StatusCode::TOO_MANY_REQUESTS);

    let different_token = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/token-login")
                .header(CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "203.0.113.10")
                .body(Body::from(r#"{"token":"invalid-token-b"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(different_token.status(), StatusCode::UNAUTHORIZED);

    let different_client = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/token-login")
                .header(CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "203.0.113.11")
                .body(Body::from(r#"{"token":"invalid-token-a"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(different_client.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_token_login_prefers_connect_info_over_forwarded_header() {
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    api_auth::ensure_local_keyset(&tls_dir).unwrap();
    let keyset_path = api_auth::local_keyset_path(&tls_dir);

    let state = ApiState {
        policy_store: PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24),
        local_store: PolicyDiskStore::new(dir.path().join("policies")),
        service_accounts: ServiceAccountStore::local(dir.path().join("service-accounts")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        tls_dir,
        token_path: dir.path().join("bootstrap-token"),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        dns_map: None,
        readiness: None,
    };

    let app = Router::new()
        .route("/api/v1/auth/token-login", post(auth_token_login))
        .with_state(state);

    for _ in 0..AUTH_LOGIN_MAX_FAILURES {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/token-login")
            .header(CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", "203.0.113.10")
            .body(Body::from(r#"{"token":"invalid-token"}"#))
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "198.51.100.10:12345".parse::<SocketAddr>().unwrap(),
        ));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    let mut blocked = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/token-login")
        .header(CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "203.0.113.10")
        .body(Body::from(r#"{"token":"invalid-token"}"#))
        .unwrap();
    blocked.extensions_mut().insert(axum::extract::ConnectInfo(
        "198.51.100.10:12345".parse::<SocketAddr>().unwrap(),
    ));
    let blocked = app.clone().oneshot(blocked).await.unwrap();
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

    let mut different_peer_same_forwarded = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/token-login")
        .header(CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "203.0.113.10")
        .body(Body::from(r#"{"token":"invalid-token"}"#))
        .unwrap();
    different_peer_same_forwarded
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(
            "198.51.100.11:12345".parse::<SocketAddr>().unwrap(),
        ));
    let resp = app.oneshot(different_peer_same_forwarded).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_token_login_rejects_oversized_token_field() {
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    api_auth::ensure_local_keyset(&tls_dir).unwrap();
    let keyset_path = api_auth::local_keyset_path(&tls_dir);

    let state = ApiState {
        policy_store: PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24),
        local_store: PolicyDiskStore::new(dir.path().join("policies")),
        service_accounts: ServiceAccountStore::local(dir.path().join("service-accounts")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        tls_dir,
        token_path: dir.path().join("bootstrap-token"),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        dns_map: None,
        readiness: None,
    };

    let app = Router::new()
        .route("/api/v1/auth/token-login", post(auth_token_login))
        .with_state(state);

    let oversized = "a".repeat(AUTH_LOGIN_MAX_TOKEN_LEN + 1);
    let body = serde_json::json!({ "token": oversized }).to_string();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/token-login")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn metrics_bind_guardrail_treats_private_and_loopback_as_safe() {
    assert!(!metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        8080
    )));
    assert!(!metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
        8080
    )));
    assert!(!metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        8080
    )));
}

#[test]
fn metrics_bind_guardrail_requires_override_for_public_bind() {
    assert!(metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        8080
    )));
    assert!(parse_truthy_env("1"));
    assert!(parse_truthy_env("TrUe"));
    assert!(!parse_truthy_env("0"));
    assert!(!parse_truthy_env("false"));
}
