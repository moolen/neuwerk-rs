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
