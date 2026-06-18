use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    time::timeout,
};

use crate::{
    config::TcpProxyConfig,
    limiter::{ConnectionLimiter, LimitReason},
    telemetry::Stats,
    BoxError,
};

pub async fn run_tcp_proxy(
    cfg: TcpProxyConfig,
    stats: Arc<Stats>,
    startup: Option<oneshot::Sender<Result<(), String>>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BoxError> {
    let listen: SocketAddr = match cfg.listen.parse() {
        Ok(listen) => listen,
        Err(err) => {
            notify_startup(startup, Err(format!("invalid listen address: {err}")));
            return Err(Box::new(err));
        }
    };
    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(err) => {
            notify_startup(startup, Err(format!("bind failed: {err}")));
            return Err(Box::new(err));
        }
    };
    let limiter = ConnectionLimiter::new(&cfg.limits);
    eprintln!(
        "tcp proxy '{}' listening on {}, upstream {}",
        cfg.name, cfg.listen, cfg.upstream
    );
    notify_startup(startup, Ok(()));

    loop {
        let (mut inbound, peer_addr) = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    eprintln!("tcp proxy '{}' listener shutting down", cfg.name);
                    break;
                }
                continue;
            }
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("tcp accept error: {err}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            },
        };
        let limiter = Arc::clone(&limiter);
        let stats = Arc::clone(&stats);
        let upstream = cfg.upstream.clone();
        let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms.max(1));
        let max_connection_duration = Duration::from_secs(cfg.max_connection_duration_seconds.max(1));

        let permit = match limiter.try_acquire(peer_addr.ip()) {
            Ok(permit) => permit,
            Err(reason) => {
                Stats::inc(&stats.tcp_rejected);
                if reason != LimitReason::PerIpRate {
                    eprintln!("tcp rejected {peer_addr}: {reason:?}");
                }
                continue;
            }
        };

        tokio::spawn(async move {
            let _permit = permit;
            Stats::inc(&stats.tcp_accepted);
            let mut outbound = match timeout(connect_timeout, TcpStream::connect(&upstream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    Stats::inc(&stats.tcp_upstream_errors);
                    eprintln!("tcp upstream connect error for {peer_addr}: {err}");
                    return;
                }
                Err(_) => {
                    Stats::inc(&stats.tcp_upstream_errors);
                    eprintln!("tcp upstream connect timeout for {peer_addr}");
                    return;
                }
            };

            let _ = inbound.set_nodelay(true);
            let _ = outbound.set_nodelay(true);
            match timeout(max_connection_duration, copy_bidirectional(&mut inbound, &mut outbound)).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => eprintln!("tcp proxy copy error for {peer_addr}: {err}"),
                Err(_) => eprintln!("tcp proxy max connection duration reached for {peer_addr}"),
            }
        });
    }
    Ok(())
}

fn notify_startup(startup: Option<oneshot::Sender<Result<(), String>>>, result: Result<(), String>) {
    if let Some(startup) = startup {
        let _ = startup.send(result);
    }
}
