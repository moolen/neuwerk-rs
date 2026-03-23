use axum::extract::Request;
use axum::http::HeaderValue;
use axum::response::Response;

pub(super) async fn security_headers_middleware(
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers
        .entry("x-content-type-options")
        .or_insert_with(|| HeaderValue::from_static("nosniff"));
    headers
        .entry("x-frame-options")
        .or_insert_with(|| HeaderValue::from_static("DENY"));
    headers
        .entry("referrer-policy")
        .or_insert_with(|| HeaderValue::from_static("no-referrer"));
    headers.entry("permissions-policy").or_insert_with(|| {
        HeaderValue::from_static("accelerometer=(), camera=(), geolocation=(), microphone=()")
    });
    headers
        .entry("content-security-policy")
        .or_insert_with(|| content_security_policy_for_path(&path));
    headers
        .entry("strict-transport-security")
        .or_insert_with(|| HeaderValue::from_static("max-age=31536000; includeSubDomains"));
    if path.starts_with("/api/v1/auth/") {
        headers
            .entry("cache-control")
            .or_insert_with(|| HeaderValue::from_static("no-store"));
    }
    response
}

fn content_security_policy_for_path(path: &str) -> HeaderValue {
    if path.starts_with("/api/") {
        return HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        );
    }
    HeaderValue::from_static(
        "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
}
