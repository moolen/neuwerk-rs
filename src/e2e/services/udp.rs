use super::*;

pub async fn udp_echo(
    bind: SocketAddr,
    server: SocketAddr,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("udp client bind failed: {e}"))?;
    socket
        .send_to(payload, server)
        .await
        .map_err(|e| format!("udp client send failed: {e}"))?;
    let mut buf = vec![0u8; payload.len().max(2048)];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => Ok(buf[..len].to_vec()),
        Ok(Err(err)) => Err(format!("udp client recv failed: {err}")),
        Err(_) => Err("udp client recv timed out".to_string()),
    }
}

pub async fn udp_echo_eventually(
    bind: SocketAddr,
    server: SocketAddr,
    payload: &[u8],
    per_attempt_timeout: std::time::Duration,
    overall_timeout: std::time::Duration,
) -> Result<Vec<u8>, String> {
    let deadline = std::time::Instant::now() + overall_timeout;
    loop {
        match udp_echo(bind, server, payload, per_attempt_timeout).await {
            Ok(resp) => return Ok(resp),
            Err(err) if std::time::Instant::now() >= deadline => {
                return Err(format!("udp echo did not succeed before timeout: {err}"));
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}
