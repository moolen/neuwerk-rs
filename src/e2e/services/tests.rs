use super::*;

#[tokio::test(flavor = "current_thread")]
async fn https_h2_get_path_works_against_upstream_server() {
    let tls = generate_upstream_tls_material().expect("tls material");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    let server = tokio::spawn(run_https_server(addr, tls));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let response = https_h2_get_path(addr, "foo.allowed", "/external-secrets/external-secrets")
        .await
        .expect("h2 get");
    assert!(
        response.starts_with("HTTP/2 200"),
        "unexpected response: {response}"
    );

    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn http_stream_path_long_stream_allows_total_duration_above_timeout_when_progress_continues()
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    let server = tokio::spawn(server_runtime::run_http_server(addr));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let total = http_stream_path(
        addr,
        "foo.allowed",
        "/stream-long",
        std::time::Duration::from_millis(1500),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("long stream with continued progress should succeed");
    assert!(total > 0, "long stream should return body bytes");

    server.abort();
}
