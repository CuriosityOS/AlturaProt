use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::{
    config::TcpProxyConfig,
    limiter::{ConnectionLimiter, LimitReason},
    telemetry::Stats,
    BoxError,
};

pub async fn run_tcp_proxy(cfg: TcpProxyConfig, stats: Arc<Stats>) -> Result<(), BoxError> {
    let listen: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(listen).await?;
    let limiter = ConnectionLimiter::new(&cfg.limits);
    eprintln!(
        "tcp proxy '{}' listening on {}, upstream {}",
        cfg.name, cfg.listen, cfg.upstream
    );

    loop {
        let (mut inbound, peer_addr) = listener.accept().await?;
        let limiter = Arc::clone(&limiter);
        let stats = Arc::clone(&stats);
        let upstream = cfg.upstream.clone();
        let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms.max(1));
        let idle_timeout = Duration::from_secs(cfg.idle_timeout_seconds.max(1));

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
            match timeout(idle_timeout, copy_bidirectional(&mut inbound, &mut outbound)).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => eprintln!("tcp proxy copy error for {peer_addr}: {err}"),
                Err(_) => eprintln!("tcp proxy idle timeout for {peer_addr}"),
            }
        });
    }
}
