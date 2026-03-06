use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub async fn await_runtime_tasks(
    http_task: oneshot::Receiver<Result<(), String>>,
    dns_task: oneshot::Receiver<Result<(), String>>,
    dataplane_task: oneshot::Receiver<Result<(), String>>,
    dhcp_task: Option<JoinHandle<Result<(), String>>>,
) -> Result<(), String> {
    if let Some(mut dhcp_task) = dhcp_task {
        tokio::select! {
            res = http_task => {
                match res {
                    Ok(Ok(())) => Err("http api exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("http api thread failed: {err}")),
                }
            }
            res = dns_task => {
                match res {
                    Ok(Ok(())) => Err("dns proxy exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("dns proxy task failed: {err}")),
                }
            }
            res = dataplane_task => {
                match res {
                    Ok(Ok(())) => Err("dataplane exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(_) => Err("dataplane runtime channel closed unexpectedly".to_string()),
                }
            }
            res = &mut dhcp_task => {
                match res {
                    Ok(Ok(())) => Err("dhcp task exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("dhcp task failed: {err}")),
                }
            }
        }
    } else {
        tokio::select! {
            res = http_task => {
                match res {
                    Ok(Ok(())) => Err("http api exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("http api thread failed: {err}")),
                }
            }
            res = dns_task => {
                match res {
                    Ok(Ok(())) => Err("dns proxy exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("dns proxy task failed: {err}")),
                }
            }
            res = dataplane_task => {
                match res {
                    Ok(Ok(())) => Err("dataplane exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(_) => Err("dataplane runtime channel closed unexpectedly".to_string()),
                }
            }
        }
    }
}
