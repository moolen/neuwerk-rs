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
