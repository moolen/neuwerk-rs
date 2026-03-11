use std::collections::BTreeMap;

use axum::http::{Request, Response};
use h2::RecvStream;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::dataplane::policy::{
    HttpHeadersMatcher, HttpPathMatcher, HttpQueryMatcher, HttpRequestPolicy, HttpResponsePolicy,
    HttpStringMatcher,
};

pub(super) const HTTP_MAX_HEADER_BYTES: usize = 64 * 1024;
pub(super) const HTTP_MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub(super) struct ParsedHttpRequest {
    pub(super) method: String,
    pub(super) host: String,
    pub(super) path: String,
    pub(super) query: BTreeMap<String, Vec<String>>,
    pub(super) headers: BTreeMap<String, Vec<String>>,
    pub(super) raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(super) struct ParsedHttpResponse {
    pub(super) headers: BTreeMap<String, Vec<String>>,
    pub(super) raw: Vec<u8>,
}

fn parse_h2_headers(headers: &axum::http::HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (name, value) in headers {
        let key = name.as_str().to_ascii_lowercase();
        let value = value
            .to_str()
            .map(|v| v.to_string())
            .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).to_string());
        out.entry(key).or_insert_with(Vec::new).push(value);
    }
    out
}

pub(super) fn parsed_request_from_h2(req: &Request<RecvStream>) -> ParsedHttpRequest {
    let target = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers = parse_h2_headers(req.headers());
    let host = req
        .uri()
        .authority()
        .map(|value| value.host().to_ascii_lowercase())
        .or_else(|| {
            headers
                .get("host")
                .and_then(|values| values.first())
                .map(|value| {
                    value
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase()
                })
        })
        .unwrap_or_default();
    let (path, query) = parse_request_target(&target);
    ParsedHttpRequest {
        method: req.method().as_str().to_ascii_uppercase(),
        host,
        path,
        query,
        headers,
        raw: Vec::new(),
    }
}

pub(super) fn parsed_response_from_h2(response: &Response<()>) -> ParsedHttpResponse {
    ParsedHttpResponse {
        headers: parse_h2_headers(response.headers()),
        raw: Vec::new(),
    }
}

pub(super) fn request_for_upstream_h2(
    method: &str,
    target: &str,
    host: &str,
    request_headers: &axum::http::HeaderMap,
) -> Result<Request<()>, String> {
    let mut request = Request::builder()
        .method(method)
        .uri(target)
        .body(())
        .map_err(|err| format!("tls intercept: build upstream h2 request failed: {err}"))?;
    let upstream_headers = request.headers_mut();
    for (name, value) in request_headers {
        if should_skip_upstream_h2_request_header(name.as_str()) {
            continue;
        }
        upstream_headers.append(name, value.clone());
    }
    if !host.is_empty() {
        let host_value = axum::http::HeaderValue::from_str(host).map_err(|err| {
            format!("tls intercept: invalid upstream host header '{host}': {err}")
        })?;
        upstream_headers.insert(axum::http::header::HOST, host_value);
    }
    Ok(request)
}

fn should_skip_upstream_h2_request_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

pub(super) fn response_from_upstream_h2(response: &Response<()>) -> Result<Response<()>, String> {
    let mut builder = Response::builder().status(response.status());
    for (name, value) in response.headers() {
        if name.as_str().eq_ignore_ascii_case("connection")
            || name.as_str().eq_ignore_ascii_case("proxy-connection")
            || name.as_str().eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(|err| format!("tls intercept: build downstream h2 response failed: {err}"))
}

pub(super) async fn read_http_message<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut total_expected = None::<usize>;

    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|err| format!("http read failed: {err}"))?;
        if n == 0 {
            if buf.is_empty() {
                return Err("http read returned eof".to_string());
            }
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > HTTP_MAX_HEADER_BYTES + HTTP_MAX_BODY_BYTES {
            return Err("http message exceeds max size".to_string());
        }

        if total_expected.is_none() {
            if let Some(header_end) = header_end_offset(&buf) {
                let content_len = parse_content_length(&buf[..header_end])?;
                total_expected = Some(header_end + content_len);
            }
        }
        if let Some(total) = total_expected {
            if buf.len() >= total {
                buf.truncate(total);
                return Ok(buf);
            }
        }
    }

    if total_expected.is_none() {
        return Err("http header terminator missing".to_string());
    }
    Ok(buf)
}

fn header_end_offset(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn parse_content_length(header: &[u8]) -> Result<usize, String> {
    let header_text =
        std::str::from_utf8(header).map_err(|_| "invalid http header utf8".to_string())?;
    for line in header_text.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                let parsed = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid content-length".to_string())?;
                if parsed > HTTP_MAX_BODY_BYTES {
                    return Err("content-length exceeds max body size".to_string());
                }
                return Ok(parsed);
            }
        }
    }
    Ok(0)
}

pub(super) fn parse_http_request(raw: &[u8]) -> Result<ParsedHttpRequest, String> {
    let header_end = header_end_offset(raw)
        .ok_or_else(|| "http request header terminator missing".to_string())?;
    let header_text = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "invalid http request utf8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing request method".to_string())?
        .to_ascii_uppercase();
    let target = parts
        .next()
        .ok_or_else(|| "missing request target".to_string())?;
    let _version = parts
        .next()
        .ok_or_else(|| "missing request version".to_string())?;

    let headers = parse_headers(lines);
    let host = headers
        .get("host")
        .and_then(|values| values.first())
        .map(|value| {
            value
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let (path, query) = parse_request_target(target);

    Ok(ParsedHttpRequest {
        method,
        host,
        path,
        query,
        headers,
        raw: raw.to_vec(),
    })
}

pub(super) fn parse_http_response(raw: &[u8]) -> Result<ParsedHttpResponse, String> {
    let header_end = header_end_offset(raw)
        .ok_or_else(|| "http response header terminator missing".to_string())?;
    let header_text = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "invalid http response utf8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let _status = lines
        .next()
        .ok_or_else(|| "missing response status line".to_string())?;
    let headers = parse_headers(lines);
    Ok(ParsedHttpResponse {
        headers,
        raw: raw.to_vec(),
    })
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> BTreeMap<String, Vec<String>> {
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let key = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            headers.entry(key).or_insert_with(Vec::new).push(value);
        }
    }
    headers
}

fn parse_request_target(target: &str) -> (String, BTreeMap<String, Vec<String>>) {
    let path_and_query = if target.starts_with('/') {
        target
    } else if let Some(scheme_pos) = target.find("://") {
        let rest = &target[scheme_pos + 3..];
        if let Some(slash) = rest.find('/') {
            &rest[slash..]
        } else {
            "/"
        }
    } else {
        target
    };

    let (path, query_raw) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, query),
        None => (path_and_query, ""),
    };
    let path = if path.is_empty() { "/" } else { path }.to_string();
    let mut query = BTreeMap::new();
    if !query_raw.is_empty() {
        for pair in query_raw.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key, value),
                None => (pair, ""),
            };
            query
                .entry(key.to_string())
                .or_insert_with(Vec::new)
                .push(value.to_string());
        }
    }
    (path, query)
}

pub(super) fn request_allowed(policy: &HttpRequestPolicy, req: &ParsedHttpRequest) -> bool {
    if let Some(host) = policy.host.as_ref() {
        if !match_host(host, &req.host) {
            return false;
        }
    }
    if !policy.methods.is_empty()
        && !policy
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(&req.method))
    {
        return false;
    }
    if let Some(path) = policy.path.as_ref() {
        if !match_path(path, &req.path) {
            return false;
        }
    }
    if let Some(query) = policy.query.as_ref() {
        if !match_query(query, &req.query) {
            return false;
        }
    }
    if let Some(headers) = policy.headers.as_ref() {
        if !match_headers(headers, &req.headers) {
            return false;
        }
    }
    true
}

pub(super) fn response_allowed(policy: &HttpResponsePolicy, response: &ParsedHttpResponse) -> bool {
    if let Some(headers) = policy.headers.as_ref() {
        return match_headers(headers, &response.headers);
    }
    true
}

fn match_host(matcher: &HttpStringMatcher, host: &str) -> bool {
    if matcher.exact.is_empty() && matcher.regex.is_none() {
        return true;
    }
    if matcher
        .exact
        .iter()
        .any(|expected| expected.eq_ignore_ascii_case(host))
    {
        return true;
    }
    matcher
        .regex
        .as_ref()
        .map(|re| re.is_match(host))
        .unwrap_or(false)
}

fn match_path(matcher: &HttpPathMatcher, path: &str) -> bool {
    if matcher.exact.is_empty() && matcher.prefix.is_empty() && matcher.regex.is_none() {
        return true;
    }
    if matcher.exact.iter().any(|expected| expected == path) {
        return true;
    }
    if matcher.prefix.iter().any(|prefix| path.starts_with(prefix)) {
        return true;
    }
    matcher
        .regex
        .as_ref()
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

fn match_query(matcher: &HttpQueryMatcher, query: &BTreeMap<String, Vec<String>>) -> bool {
    for key in &matcher.keys_present {
        if !query.contains_key(key) {
            return false;
        }
    }
    for (key, allowed_values) in &matcher.key_values_exact {
        let Some(values) = query.get(key) else {
            return false;
        };
        if !values
            .iter()
            .any(|value| allowed_values.iter().any(|allowed| allowed == value))
        {
            return false;
        }
    }
    for (key, regex) in &matcher.key_values_regex {
        let Some(values) = query.get(key) else {
            return false;
        };
        if !values.iter().any(|value| regex.is_match(value)) {
            return false;
        }
    }
    true
}

fn match_headers(matcher: &HttpHeadersMatcher, headers: &BTreeMap<String, Vec<String>>) -> bool {
    for key in &matcher.require_present {
        if !headers.contains_key(&key.to_ascii_lowercase()) {
            return false;
        }
    }
    for key in &matcher.deny_present {
        if headers.contains_key(&key.to_ascii_lowercase()) {
            return false;
        }
    }
    for (key, allowed_values) in &matcher.exact {
        let key = key.to_ascii_lowercase();
        let Some(values) = headers.get(&key) else {
            return false;
        };
        if !values
            .iter()
            .any(|value| allowed_values.iter().any(|allowed| allowed == value))
        {
            return false;
        }
    }
    for (key, regex) in &matcher.regex {
        let key = key.to_ascii_lowercase();
        let Some(values) = headers.get(&key) else {
            return false;
        };
        if !values.iter().any(|value| regex.is_match(value)) {
            return false;
        }
    }
    true
}
