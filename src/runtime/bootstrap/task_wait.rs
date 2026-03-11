use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const HTTP_SHUTDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

async fn finalize_http_shutdown(
    http_task: &mut oneshot::Receiver<Result<(), String>>,
) -> Result<(), String> {
    match tokio::time::timeout(HTTP_SHUTDOWN_WAIT, http_task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(err))) => Err(err),
        Ok(Err(err)) => Err(format!("http api thread failed: {err}")),
        Err(_) => Err("http api shutdown timed out".to_string()),
    }
}

pub async fn await_runtime_tasks(
    http_task: oneshot::Receiver<Result<(), String>>,
    dns_task: oneshot::Receiver<Result<(), String>>,
    dataplane_task: oneshot::Receiver<Result<(), String>>,
    dhcp_task: Option<JoinHandle<Result<(), String>>>,
    shutdown_task: Option<oneshot::Receiver<()>>,
) -> Result<(), String> {
    let mut http_task = http_task;
    let mut dns_task = dns_task;
    let mut dataplane_task = dataplane_task;
    if let Some(mut dhcp_task) = dhcp_task {
        if let Some(mut shutdown_task) = shutdown_task {
            enum Outcome {
                Shutdown,
                Http(Result<Result<(), String>, oneshot::error::RecvError>),
                Dns(Result<Result<(), String>, oneshot::error::RecvError>),
                Dataplane(Result<Result<(), String>, oneshot::error::RecvError>),
                Dhcp(Result<Result<(), String>, tokio::task::JoinError>),
            }
            let outcome = tokio::select! {
                _ = &mut shutdown_task => Outcome::Shutdown,
                res = &mut http_task => Outcome::Http(res),
                res = &mut dns_task => Outcome::Dns(res),
                res = &mut dataplane_task => Outcome::Dataplane(res),
                res = &mut dhcp_task => Outcome::Dhcp(res),
            };
            match outcome {
                Outcome::Shutdown => finalize_http_shutdown(&mut http_task).await,
                Outcome::Http(res) => match res {
                    Ok(Ok(())) => Err("http api exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("http api thread failed: {err}")),
                },
                Outcome::Dns(res) => match res {
                    Ok(Ok(())) => Err("dns proxy exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("dns proxy task failed: {err}")),
                },
                Outcome::Dataplane(res) => match res {
                    Ok(Ok(())) => Err("dataplane exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(_) => Err("dataplane runtime channel closed unexpectedly".to_string()),
                },
                Outcome::Dhcp(res) => match res {
                    Ok(Ok(())) => Err("dhcp task exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("dhcp task failed: {err}")),
                },
            }
        } else {
            tokio::select! {
                res = &mut http_task => {
                    match res {
                        Ok(Ok(())) => Err("http api exited unexpectedly".to_string()),
                        Ok(Err(err)) => Err(err),
                        Err(err) => Err(format!("http api thread failed: {err}")),
                    }
                }
                res = &mut dns_task => {
                    match res {
                        Ok(Ok(())) => Err("dns proxy exited unexpectedly".to_string()),
                        Ok(Err(err)) => Err(err),
                        Err(err) => Err(format!("dns proxy task failed: {err}")),
                    }
                }
                res = &mut dataplane_task => {
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
        }
    } else if let Some(mut shutdown_task) = shutdown_task {
        enum Outcome {
            Shutdown,
            Http(Result<Result<(), String>, oneshot::error::RecvError>),
            Dns(Result<Result<(), String>, oneshot::error::RecvError>),
            Dataplane(Result<Result<(), String>, oneshot::error::RecvError>),
        }
        let outcome = tokio::select! {
            _ = &mut shutdown_task => Outcome::Shutdown,
            res = &mut http_task => Outcome::Http(res),
            res = &mut dns_task => Outcome::Dns(res),
            res = &mut dataplane_task => Outcome::Dataplane(res),
        };
        match outcome {
            Outcome::Shutdown => finalize_http_shutdown(&mut http_task).await,
            Outcome::Http(res) => match res {
                Ok(Ok(())) => Err("http api exited unexpectedly".to_string()),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(format!("http api thread failed: {err}")),
            },
            Outcome::Dns(res) => match res {
                Ok(Ok(())) => Err("dns proxy exited unexpectedly".to_string()),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(format!("dns proxy task failed: {err}")),
            },
            Outcome::Dataplane(res) => match res {
                Ok(Ok(())) => Err("dataplane exited unexpectedly".to_string()),
                Ok(Err(err)) => Err(err),
                Err(_) => Err("dataplane runtime channel closed unexpectedly".to_string()),
            },
        }
    } else {
        tokio::select! {
            res = &mut http_task => {
                match res {
                    Ok(Ok(())) => Err("http api exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("http api thread failed: {err}")),
                }
            }
            res = &mut dns_task => {
                match res {
                    Ok(Ok(())) => Err("dns proxy exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(format!("dns proxy task failed: {err}")),
                }
            }
            res = &mut dataplane_task => {
                match res {
                    Ok(Ok(())) => Err("dataplane exited unexpectedly".to_string()),
                    Ok(Err(err)) => Err(err),
                    Err(_) => Err("dataplane runtime channel closed unexpectedly".to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_ok_when_shutdown_signal_arrives() {
        let (http_tx, http_rx) = oneshot::channel();
        let (_dns_tx, dns_rx) = oneshot::channel();
        let (_dataplane_tx, dataplane_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let wait = tokio::spawn(async move {
            await_runtime_tasks(http_rx, dns_rx, dataplane_rx, None, Some(shutdown_rx)).await
        });

        shutdown_tx.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        http_tx.send(Ok(())).unwrap();
        let result = wait.await.unwrap();
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn returns_error_when_http_shutdown_times_out_after_signal() {
        let (_http_tx, http_rx) = oneshot::channel::<Result<(), String>>();
        let (_dns_tx, dns_rx) = oneshot::channel();
        let (_dataplane_tx, dataplane_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let wait = tokio::spawn(async move {
            await_runtime_tasks(http_rx, dns_rx, dataplane_rx, None, Some(shutdown_rx)).await
        });

        shutdown_tx.send(()).unwrap();
        let result = wait.await.unwrap();
        assert_eq!(result, Err("http api shutdown timed out".to_string()));
    }

    #[tokio::test]
    async fn returns_http_error_when_shutdown_not_requested() {
        let (http_tx, http_rx) = oneshot::channel();
        let (_dns_tx, dns_rx) = oneshot::channel();
        let (_dataplane_tx, dataplane_rx) = oneshot::channel();

        let wait = tokio::spawn(async move {
            await_runtime_tasks(http_rx, dns_rx, dataplane_rx, None, None).await
        });

        http_tx.send(Err("http failed".to_string())).unwrap();
        let result = wait.await.unwrap();
        assert_eq!(result, Err("http failed".to_string()));
    }
}
