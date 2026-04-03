use super::*;

use std::net::Ipv4Addr;
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::controlplane::sso::{SsoProvider, SsoProviderKind, SsoStore};
use crate::dataplane::policy::DefaultPolicy;
use axum::http::{header::AUTHORIZATION, header::COOKIE, header::SET_COOKIE, HeaderValue, Method};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, SanType};
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

fn test_api_state(dir: &TempDir, auth_source: ApiAuthSource) -> ApiState {
    ApiState {
        policy_store: PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24),
        local_store: PolicyDiskStore::new(dir.path().join("policies")),
        service_accounts: ServiceAccountStore::local(dir.path().join("service-accounts")),
        sso: SsoStore::local(dir.path().join("sso")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 8443,
        auth_source,
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir: dir.path().join("http-tls"),
        token_path: dir.path().join("bootstrap-token"),
        external_url: "https://127.0.0.1:8443".to_string(),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
        dns_map: None,
        readiness: None,
    }
}

async fn spawn_oidc_discovery_server() -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)
{
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let base = format!("http://{addr}");
    let app = Router::new().route(
        "/.well-known/openid-configuration",
        get({
            let hits = hits.clone();
            let base = base.clone();
            move || {
                let hits = hits.clone();
                let base = base.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(json!({
                        "issuer": base,
                        "authorization_endpoint": format!("{base}/authorize"),
                        "token_endpoint": format!("{base}/token"),
                        "userinfo_endpoint": format!("{base}/userinfo"),
                        "jwks_uri": format!("{base}/jwks"),
                    }))
                }
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, hits, server)
}

fn generic_oidc_provider(issuer_url: String) -> SsoProvider {
    let mut provider = SsoProvider::new(
        "Private IdP".to_string(),
        SsoProviderKind::GenericOidc,
        "client-id".to_string(),
        "client-secret".to_string(),
    )
    .unwrap();
    provider.issuer_url = Some(issuer_url);
    provider
}

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
    let sso = SsoStore::local(dir.path().join("sso"));
    let integrations = IntegrationStore::local(dir.path().join("integrations"));
    let metrics = Metrics::new().unwrap();
    let state = ApiState {
        policy_store,
        local_store,
        service_accounts,
        sso,
        integrations,
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics,
        proxy_client: Some(client),
        http_port: addr.port(),
        auth_source: ApiAuthSource::Local(dir.path().join("auth.json")),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir: dir.path().join("http-tls"),
        token_path: dir.path().join("bootstrap-token"),
        external_url: format!("https://{}", addr),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
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
    let sso = SsoStore::local(dir.path().join("sso"));
    let integrations = IntegrationStore::local(dir.path().join("integrations"));
    let metrics = Metrics::new().unwrap();
    let state = ApiState {
        policy_store,
        local_store,
        service_accounts,
        sso,
        integrations,
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics: metrics.clone(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path.clone()),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir: tls_dir.clone(),
        token_path: dir.path().join("bootstrap-token"),
        external_url: "https://127.0.0.1:8443".to_string(),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
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
    let sso = SsoStore::local(dir.path().join("sso"));
    let integrations = IntegrationStore::local(dir.path().join("integrations"));
    let metrics = Metrics::new().unwrap();
    let state = ApiState {
        policy_store,
        local_store,
        service_accounts,
        sso,
        integrations,
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics,
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir: tls_dir.clone(),
        token_path: dir.path().join("bootstrap-token"),
        external_url: "https://127.0.0.1:8443".to_string(),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
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
        .clone()
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

#[tokio::test]
async fn ui_route_serves_local_assets_without_remote_script_origins() {
    let app = Router::new()
        .fallback(ui_handler)
        .layer(axum::middleware::from_fn(
            security::security_headers_middleware,
        ));

    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self'"));
    assert!(!csp.contains("unsafe-inline"));
    assert!(!csp.contains("cdn.tailwindcss.com"));
    assert!(!csp.contains("esm.sh"));

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body.contains("cdn.tailwindcss.com"));
    assert!(!body.contains("esm.sh"));
    assert!(!body.contains("type=\"importmap\""));
    assert!(body.contains("/assets/"));

    let css_name = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/dist/assets"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find(|name| name.ends_with(".css"))
        .expect("expected bundled UI stylesheet");
    let css_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/assets/{css_name}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(css_resp.status(), StatusCode::OK);
    let css = axum::body::to_bytes(css_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let css = String::from_utf8(css.to_vec()).unwrap();
    assert!(!css.contains("fonts.googleapis.com"));
    assert!(!css.contains("fonts.gstatic.com"));
    assert!(
        css.contains(".flex{display:flex")
            || css.contains(".h-screen{height:100vh")
            || css.contains(".min-h-screen{min-height:100vh"),
        "expected bundled UI stylesheet to contain generated utility classes"
    );
}

#[tokio::test]
async fn sso_start_allows_public_oidc_discovery_for_login() {
    let dir = TempDir::new().unwrap();
    let (addr, hits, server) = spawn_oidc_discovery_server().await;
    let issuer_url = format!("http://{addr}");
    let provider = generic_oidc_provider(issuer_url);

    let state = test_api_state(&dir, ApiAuthSource::Local(dir.path().join("auth.json")));
    state.sso.write_provider(&provider).await.unwrap();

    let app = Router::new()
        .route("/api/v1/auth/sso/:id/start", get(auth_sso_start))
        .with_state(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/auth/sso/{}/start", provider.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with(&format!("http://{addr}/authorize?")));
    server.abort();
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
        sso: SsoStore::local(dir.path().join("sso")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir,
        token_path: dir.path().join("bootstrap-token"),
        external_url: "https://127.0.0.1:8443".to_string(),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
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
        sso: SsoStore::local(dir.path().join("sso")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir,
        token_path: dir.path().join("bootstrap-token"),
        external_url: "https://127.0.0.1:8443".to_string(),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
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
        sso: SsoStore::local(dir.path().join("sso")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir,
        token_path: dir.path().join("bootstrap-token"),
        external_url: "https://127.0.0.1:8443".to_string(),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
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
        sso: SsoStore::local(dir.path().join("sso")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics: Metrics::new().unwrap(),
        proxy_client: None,
        http_port: 0,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir,
        token_path: dir.path().join("bootstrap-token"),
        external_url: "https://127.0.0.1:8443".to_string(),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
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
fn metrics_bind_guardrail_treats_private_loopback_and_link_local_as_safe() {
    assert!(!metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        8080
    )));
    assert!(!metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
        8080
    )));
    assert!(!metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(169, 254, 10, 20)),
        8080
    )));
    assert!(!metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V6("fd00::10".parse().unwrap()),
        8080
    )));
    assert!(!metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V6("fe80::10".parse().unwrap()),
        8080
    )));
}

#[test]
fn metrics_bind_guardrail_requires_override_for_unspecified_and_public_bind() {
    assert!(metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        8080
    )));
    assert!(metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        8080
    )));
    assert!(metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V6("::".parse().unwrap()),
        8080
    )));
    assert!(metrics_bind_requires_guardrail(SocketAddr::new(
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        8080
    )));
    assert!(parse_truthy_env("1"));
    assert!(parse_truthy_env("TrUe"));
    assert!(!parse_truthy_env("0"));
    assert!(!parse_truthy_env("false"));
}

#[test]
fn validate_metrics_bind_policy_rejects_public_bind_without_allow_flag() {
    let err = validate_metrics_bind_policy(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 8080),
        false,
    )
    .expect_err("public bind must be rejected without explicit allow flag");

    assert!(err.contains("metrics bind"));
}

#[test]
fn validate_metrics_bind_policy_allows_public_bind_with_allow_flag() {
    validate_metrics_bind_policy(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 8080),
        true,
    )
    .expect("public bind should be allowed when explicitly configured");
}

fn test_auth_setup(dir: &TempDir) -> std::path::PathBuf {
    let tls_dir = dir.path().join("http-tls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    api_auth::ensure_local_keyset(&tls_dir).unwrap();
    api_auth::local_keyset_path(&tls_dir)
}

fn mint_admin_token(keyset_path: &std::path::Path) -> String {
    let keyset = api_auth::load_keyset_from_file(keyset_path)
        .unwrap()
        .expect("missing keyset");
    api_auth::mint_token(&keyset, "sso-test-admin", None, None)
        .unwrap()
        .token
}

fn write_cluster_bootstrap_token(path: &std::path::Path) {
    let json = serde_json::json!({
        "tokens": [
            {
                "kid": "test",
                "token": "b64:dGVzdC1zZWNyZXQ=",
                "valid_until": "2027-01-01T00:00:00Z"
            }
        ]
    });
    std::fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn next_cluster_addr() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn test_cluster_config(
    data_dir: &TempDir,
    token_path: &std::path::Path,
) -> crate::controlplane::cluster::config::ClusterConfig {
    let mut cfg = crate::controlplane::cluster::config::ClusterConfig::disabled();
    let raft_addr = next_cluster_addr();
    cfg.enabled = true;
    cfg.data_dir = data_dir.path().to_path_buf();
    cfg.token_path = token_path.to_path_buf();
    cfg.node_id_path = data_dir.path().join("node_id");
    cfg.bind_addr = raft_addr;
    cfg.advertise_addr = raft_addr;
    cfg.join_bind_addr = next_cluster_addr();
    cfg
}

async fn wait_for_cluster_leader(
    raft: &openraft::Raft<crate::controlplane::cluster::types::ClusterTypeConfig>,
    timeout: Duration,
) -> u128 {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let snapshot = metrics.borrow().clone();
        if let Some(leader) = snapshot.current_leader {
            return leader;
        }
        let now = Instant::now();
        assert!(now < deadline, "timed out waiting for leader");
        tokio::time::timeout(deadline - now, metrics.changed())
            .await
            .expect("metrics wait timeout")
            .expect("metrics channel closed");
    }
}

async fn wait_for_cluster_voter(
    raft: &openraft::Raft<crate::controlplane::cluster::types::ClusterTypeConfig>,
    node_id: u128,
    timeout: Duration,
) {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let snapshot = metrics.borrow().clone();
        if snapshot
            .membership_config
            .membership()
            .voter_ids()
            .any(|id| id == node_id)
        {
            return;
        }
        let now = Instant::now();
        assert!(now < deadline, "timed out waiting for voter");
        tokio::time::timeout(deadline - now, metrics.changed())
            .await
            .expect("metrics wait timeout")
            .expect("metrics channel closed");
    }
}

async fn wait_for_stable_membership(
    raft: &openraft::Raft<crate::controlplane::cluster::types::ClusterTypeConfig>,
    timeout: Duration,
) {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let snapshot = metrics.borrow().clone();
        if snapshot.membership_config.membership().get_joint_config().len() == 1 {
            return;
        }
        let now = Instant::now();
        assert!(now < deadline, "timed out waiting for stable membership");
        tokio::time::timeout(deadline - now, metrics.changed())
            .await
            .expect("metrics wait timeout")
            .expect("metrics channel closed");
    }
}

async fn start_test_cluster(
    data_dir: &TempDir,
    token_path: &std::path::Path,
    join_seed: Option<SocketAddr>,
) -> crate::controlplane::cluster::ClusterRuntime {
    let mut cfg = test_cluster_config(data_dir, token_path);
    cfg.join_seed = join_seed;
    crate::controlplane::cluster::bootstrap::run_cluster(cfg, None, None)
        .await
        .unwrap()
}

fn test_state(dir: &TempDir, keyset_path: std::path::PathBuf, metrics: Metrics) -> ApiState {
    ApiState {
        policy_store: PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24),
        local_store: PolicyDiskStore::new(dir.path().join("policies")),
        service_accounts: ServiceAccountStore::local(dir.path().join("service-accounts")),
        sso: SsoStore::local(dir.path().join("sso")),
        integrations: IntegrationStore::local(dir.path().join("integrations")),
        audit_store: None,
        policy_telemetry_store: None,
        threat_store: None,
        cluster: None,
        metrics,
        proxy_client: None,
        http_port: 8443,
        auth_source: ApiAuthSource::Local(keyset_path),
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_dir: dir.path().join("http-tls"),
        token_path: dir.path().join("bootstrap-token"),
        external_url: "https://127.0.0.1:8443".to_string(),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
        leader_local_policy_apply_count: None,
        dns_map: None,
        readiness: None,
    }
}

#[tokio::test]
async fn cluster_members_requires_auth() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let state = test_state(&dir, keyset_path, Metrics::new().unwrap());

    let app = Router::new()
        .route("/api/v1/cluster/members", get(list_cluster_members))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth::auth_middleware,
        ));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/cluster/members")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cluster_members_remove_rejects_min_voters_violation() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let admin_token = mint_admin_token(&keyset_path);

    let seed_dir = TempDir::new().unwrap();
    let joiner_dir = TempDir::new().unwrap();
    let token_path = seed_dir.path().join("bootstrap.json");
    write_cluster_bootstrap_token(&token_path);

    let seed = start_test_cluster(&seed_dir, &token_path, None).await;
    let _leader_id = wait_for_cluster_leader(&seed.raft, Duration::from_secs(10)).await;
    let joiner = start_test_cluster(&joiner_dir, &token_path, Some(seed.join_bind_addr)).await;
    let joiner_id = joiner.raft.metrics().borrow().id;
    wait_for_cluster_voter(&seed.raft, joiner_id, Duration::from_secs(10)).await;
    wait_for_stable_membership(&seed.raft, Duration::from_secs(10)).await;

    let mut state = test_state(&dir, keyset_path, Metrics::new().unwrap());
    state.cluster_membership_min_voters = 2;
    state.cluster = Some(HttpApiCluster {
        raft: seed.raft.clone(),
        store: seed.store.clone(),
    });

    let app = Router::new()
        .route(
            "/api/v1/cluster/members/:node_id/remove",
            post(remove_cluster_member),
        )
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth::auth_middleware,
        ));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/cluster/members/{joiner_id}/remove"))
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::from(r#"{"force":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        payload
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .contains("min_voters")
    );

    joiner.shutdown().await;
    seed.shutdown().await;
}

#[tokio::test]
async fn cluster_members_list_marks_missing_members_from_replicated_state() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let admin_token = mint_admin_token(&keyset_path);

    let seed_dir = TempDir::new().unwrap();
    let joiner_dir = TempDir::new().unwrap();
    let token_path = seed_dir.path().join("bootstrap.json");
    write_cluster_bootstrap_token(&token_path);

    let seed = start_test_cluster(&seed_dir, &token_path, None).await;
    let _leader_id = wait_for_cluster_leader(&seed.raft, Duration::from_secs(10)).await;
    let joiner = start_test_cluster(&joiner_dir, &token_path, Some(seed.join_bind_addr)).await;
    let joiner_id = joiner.raft.metrics().borrow().id;
    wait_for_cluster_voter(&seed.raft, joiner_id, Duration::from_secs(10)).await;
    wait_for_stable_membership(&seed.raft, Duration::from_secs(10)).await;

    let missing_since = 1_717_171_717_i64;
    seed.raft
        .client_write(crate::controlplane::cluster::types::ClusterCommand::Put {
            key: crate::controlplane::cloud::missing_member_key(joiner_id),
            value: serde_json::to_vec(&crate::controlplane::cloud::types::MissingMemberState {
                first_missing_epoch: missing_since,
            })
            .unwrap(),
        })
        .await
        .unwrap();

    let mut state = test_state(&dir, keyset_path, Metrics::new().unwrap());
    state.cluster = Some(HttpApiCluster {
        raft: seed.raft.clone(),
        store: seed.store.clone(),
    });

    let app = Router::new()
        .route("/api/v1/cluster/members", get(list_cluster_members))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth::auth_middleware,
        ));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/cluster/members")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let members = payload
        .get("members")
        .and_then(serde_json::Value::as_array)
        .expect("members array");
    let member = members
        .iter()
        .find(|member| member.get("node_id") == Some(&serde_json::json!(joiner_id.to_string())))
        .expect("joiner member");
    assert_eq!(
        member
            .get("cloud_status")
            .and_then(serde_json::Value::as_str),
        Some("missing_from_discovery")
    );
    assert_eq!(
        member
            .get("auto_evict_reason")
            .and_then(serde_json::Value::as_str),
        Some(format!("missing_from_discovery:{missing_since}").as_str())
    );

    joiner.shutdown().await;
    seed.shutdown().await;
}

#[tokio::test]
async fn sso_public_providers_only_returns_enabled() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let state = test_state(&dir, keyset_path, Metrics::new().unwrap());

    let mut github = SsoProvider::new(
        "GitHub".to_string(),
        SsoProviderKind::Github,
        "cid-gh".to_string(),
        "secret-gh".to_string(),
    )
    .unwrap();
    github.display_order = 2;
    github.authorization_url = Some("http://127.0.0.1:5556/auth".to_string());
    github.token_url = Some("http://127.0.0.1:5556/token".to_string());
    github.userinfo_url = Some("http://127.0.0.1:5556/user".to_string());

    let mut disabled = SsoProvider::new(
        "Disabled".to_string(),
        SsoProviderKind::Github,
        "cid-disabled".to_string(),
        "secret-disabled".to_string(),
    )
    .unwrap();
    disabled.enabled = false;
    disabled.display_order = 0;
    disabled.authorization_url = Some("http://127.0.0.1:5556/auth".to_string());
    disabled.token_url = Some("http://127.0.0.1:5556/token".to_string());
    disabled.userinfo_url = Some("http://127.0.0.1:5556/user".to_string());

    let mut google = SsoProvider::new(
        "Google".to_string(),
        SsoProviderKind::Google,
        "cid-go".to_string(),
        "secret-go".to_string(),
    )
    .unwrap();
    google.display_order = 1;
    google.issuer_url = Some("http://127.0.0.1:5556/dex".to_string());
    google.authorization_url = Some("http://127.0.0.1:5556/auth".to_string());
    google.token_url = Some("http://127.0.0.1:5556/token".to_string());
    google.userinfo_url = Some("http://127.0.0.1:5556/userinfo".to_string());

    state.sso.write_provider(&github).await.unwrap();
    state.sso.write_provider(&disabled).await.unwrap();
    state.sso.write_provider(&google).await.unwrap();

    let app = Router::new()
        .route(
            "/api/v1/auth/sso/providers",
            get(auth_sso_supported_providers),
        )
        .with_state(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/sso/providers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let providers: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(providers.len(), 2);
    assert_eq!(
        providers[0].get("name").and_then(serde_json::Value::as_str),
        Some("Google")
    );
    assert_eq!(
        providers[1].get("name").and_then(serde_json::Value::as_str),
        Some("GitHub")
    );
}

#[tokio::test]
async fn sso_start_sets_state_cookie_and_redirects() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let state = test_state(&dir, keyset_path, Metrics::new().unwrap());

    let mut provider = SsoProvider::new(
        "GitHub".to_string(),
        SsoProviderKind::Github,
        "cid-gh".to_string(),
        "secret-gh".to_string(),
    )
    .unwrap();
    provider.authorization_url = Some("http://127.0.0.1:5556/auth".to_string());
    provider.token_url = Some("http://127.0.0.1:5556/token".to_string());
    provider.userinfo_url = Some("http://127.0.0.1:5556/user".to_string());
    state.sso.write_provider(&provider).await.unwrap();

    let app = Router::new()
        .route("/api/v1/auth/sso/:id/start", get(auth_sso_start))
        .with_state(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/auth/sso/{}/start?next=%2Fpolicies",
                    provider.id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);

    let location = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("http://127.0.0.1:5556/auth?"));
    assert!(location.contains("response_type=code"));
    assert!(location.contains("client_id=cid-gh"));
    assert!(
        location.contains("redirect_uri=https%3A%2F%2F127.0.0.1%3A8443%2Fapi%2Fv1%2Fauth%2Fsso")
    );
    assert!(location.contains("state="));

    let cookie = resp.headers().get(SET_COOKIE).unwrap().to_str().unwrap();
    assert!(cookie.contains("neuwerk_sso="));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn sso_callback_missing_cookie_denied_and_metric_recorded() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let metrics = Metrics::new().unwrap();
    let state = test_state(&dir, keyset_path, metrics.clone());

    let mut provider = SsoProvider::new(
        "GitHub".to_string(),
        SsoProviderKind::Github,
        "cid-gh".to_string(),
        "secret-gh".to_string(),
    )
    .unwrap();
    provider.authorization_url = Some("http://127.0.0.1:5556/auth".to_string());
    provider.token_url = Some("http://127.0.0.1:5556/token".to_string());
    provider.userinfo_url = Some("http://127.0.0.1:5556/user".to_string());
    state.sso.write_provider(&provider).await.unwrap();

    let app = Router::new()
        .route("/api/v1/auth/sso/:id/callback", get(auth_sso_callback))
        .with_state(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/auth/sso/{}/callback?code=abc&state=def",
                    provider.id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let cookie = resp.headers().get(SET_COOKIE).unwrap().to_str().unwrap();
    assert!(cookie.contains("neuwerk_sso=; Max-Age=0"));

    let rendered = metrics.render().unwrap();
    assert!(rendered.contains("http_auth_sso_total"));
    assert!(rendered.contains("reason=\"missing_state_cookie\""));
    assert!(rendered.contains("provider=\"none\""));
}

#[tokio::test]
async fn sso_settings_create_and_update_redacts_and_preserves_secret() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let admin_token = mint_admin_token(&keyset_path);
    let state = test_state(&dir, keyset_path, Metrics::new().unwrap());

    let app = Router::new()
        .route(
            "/api/v1/settings/sso/providers",
            get(list_sso_providers).post(create_sso_provider),
        )
        .route(
            "/api/v1/settings/sso/providers/:id",
            get(get_sso_provider).put(update_sso_provider),
        )
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    let create_payload = serde_json::json!({
        "name": "GitHub SSO",
        "kind": "github",
        "client_id": "cid-gh",
        "client_secret": "super-secret",
        "authorization_url": "http://127.0.0.1:5556/auth",
        "token_url": "http://127.0.0.1:5556/token",
        "userinfo_url": "http://127.0.0.1:5556/user",
        "default_role": "admin"
    });
    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/settings/sso/providers")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::from(create_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let create_body = axum::body::to_bytes(create_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
    assert_eq!(
        created
            .get("client_secret_configured")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(created.get("client_secret").is_none());

    let provider_id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .to_string();

    let update_payload = serde_json::json!({
        "name": "GitHub SSO Updated"
    });
    let update_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/api/v1/settings/sso/providers/{provider_id}"))
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::from(update_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_resp.status(), StatusCode::OK);

    let stored_id = Uuid::parse_str(&provider_id).unwrap();
    let stored = state.sso.get_provider(stored_id).await.unwrap().unwrap();
    assert_eq!(stored.name, "GitHub SSO Updated");
    assert_eq!(stored.client_secret, "super-secret");
}

#[tokio::test]
async fn performance_mode_settings_round_trip_local_state() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let admin_token = mint_admin_token(&keyset_path);
    let state = test_state(&dir, keyset_path, Metrics::new().unwrap());

    let app = Router::new()
        .route(
            "/api/v1/settings/performance-mode",
            get(get_performance_mode).put(put_performance_mode),
        )
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    let get_default = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/settings/performance-mode")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_default.status(), StatusCode::OK);
    let body = axum::body::to_bytes(get_default.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload.get("enabled").and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let put_disable = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/settings/performance-mode")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::from(r#"{"enabled":false}"#.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_disable.status(), StatusCode::OK);
    let body = axum::body::to_bytes(put_disable.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload.get("enabled").and_then(serde_json::Value::as_bool),
        Some(false)
    );

    let get_updated = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/settings/performance-mode")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_updated.status(), StatusCode::OK);
    let body = axum::body::to_bytes(get_updated.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload.get("enabled").and_then(serde_json::Value::as_bool),
        Some(false)
    );
}

#[tokio::test]
async fn cluster_sysdump_requires_cluster_mode() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let admin_token = mint_admin_token(&keyset_path);
    let state = test_state(&dir, keyset_path, Metrics::new().unwrap());

    let app = Router::new()
        .route("/api/v1/support/sysdump/cluster", post(cluster_sysdump))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth::auth_middleware,
        ));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/support/sysdump/cluster")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload.get("error").and_then(serde_json::Value::as_str),
        Some("cluster sysdump requires cluster mode")
    );
}

#[tokio::test]
async fn node_sysdump_requires_internal_fanout_header() {
    let dir = TempDir::new().unwrap();
    let keyset_path = test_auth_setup(&dir);
    let admin_token = mint_admin_token(&keyset_path);
    let state = test_state(&dir, keyset_path, Metrics::new().unwrap());

    let app = Router::new()
        .route("/api/v1/support/sysdump/node", post(node_sysdump))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth::auth_middleware,
        ));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/support/sysdump/node")
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload.get("error").and_then(serde_json::Value::as_str),
        Some("cluster sysdump fanout header required")
    );
}
