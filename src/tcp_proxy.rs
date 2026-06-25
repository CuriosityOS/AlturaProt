use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch},
    time::{sleep, timeout, Instant},
};

use crate::{
    config::TcpProxyConfig,
    limiter::{ConnectionLimiter, LimitReason},
    listener::bind_tcp_listeners,
    log_limiter::{log_limited, LogLimiter, HOT_PATH_LOG_INTERVAL},
    telemetry::Stats,
    BoxError,
};

static TCP_ACCEPT_ERROR_LOG: LogLimiter = LogLimiter::new();
static TCP_REJECTED_LOG: LogLimiter = LogLimiter::new();
static TCP_UPSTREAM_CONNECT_ERROR_LOG: LogLimiter = LogLimiter::new();
static TCP_UPSTREAM_CONNECT_TIMEOUT_LOG: LogLimiter = LogLimiter::new();
static TCP_IDLE_TIMEOUT_LOG: LogLimiter = LogLimiter::new();
static TCP_DOWNSTREAM_TOO_SLOW_LOG: LogLimiter = LogLimiter::new();
static TCP_UPSTREAM_TOO_SLOW_LOG: LogLimiter = LogLimiter::new();
static TCP_COPY_ERROR_LOG: LogLimiter = LogLimiter::new();
static TCP_MAX_DURATION_LOG: LogLimiter = LogLimiter::new();

pub async fn run_tcp_proxy(
    cfg: TcpProxyConfig,
    stats: Arc<Stats>,
    startup: Option<oneshot::Sender<Result<(), String>>>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), BoxError> {
    let listen: SocketAddr = match cfg.listen.parse() {
        Ok(listen) => listen,
        Err(err) => {
            notify_startup(startup, Err(format!("invalid listen address: {err}")));
            return Err(Box::new(err));
        }
    };
    let listeners = match bind_tcp_listeners(listen, cfg.listen_backlog, cfg.accept_shards) {
        Ok(listeners) => listeners,
        Err(err) => {
            notify_startup(startup, Err(format!("bind failed: {err}")));
            return Err(Box::new(err));
        }
    };
    let limiter = ConnectionLimiter::new(&cfg.limits);
    eprintln!(
        "tcp proxy '{}' listening on {}, upstream {}, accept_shards={}",
        cfg.name,
        cfg.listen,
        cfg.upstream,
        listeners.len()
    );
    notify_startup(startup, Ok(()));

    let mut accept_tasks = Vec::with_capacity(listeners.len());
    for (idx, listener) in listeners.into_iter().enumerate() {
        let cfg = cfg.clone();
        let stats = Arc::clone(&stats);
        let limiter = Arc::clone(&limiter);
        let shutdown = shutdown.clone();
        accept_tasks.push(tokio::spawn(async move {
            run_tcp_accept_loop(listener, cfg, stats, limiter, shutdown, idx).await;
        }));
    }
    for task in accept_tasks {
        let _ = task.await;
    }
    Ok(())
}

async fn run_tcp_accept_loop(
    listener: TcpListener,
    cfg: TcpProxyConfig,
    stats: Arc<Stats>,
    limiter: Arc<ConnectionLimiter>,
    mut shutdown: watch::Receiver<bool>,
    shard_idx: usize,
) {
    loop {
        let (mut inbound, peer_addr) = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    eprintln!(
                        "tcp proxy '{}' listener shard {} shutting down",
                        cfg.name,
                        shard_idx + 1
                    );
                    break;
                }
                continue;
            }
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    log_limited(&TCP_ACCEPT_ERROR_LOG, HOT_PATH_LOG_INTERVAL, |suppressed| {
                        eprintln!("tcp accept error: {err}{suppressed}");
                    });
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            },
        };
        let limiter = Arc::clone(&limiter);
        let stats = Arc::clone(&stats);
        let upstream = cfg.upstream.clone();
        let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms.max(1));
        let idle_timeout = Duration::from_secs(cfg.idle_timeout_seconds);
        let min_rate_grace = Duration::from_millis(cfg.min_rate_grace_ms);
        let downstream_rate_limit =
            TcpRateLimit::new(cfg.downstream_min_rate_bytes_per_second, min_rate_grace);
        let upstream_rate_limit =
            TcpRateLimit::new(cfg.upstream_min_rate_bytes_per_second, min_rate_grace);
        let max_connection_duration =
            Duration::from_secs(cfg.max_connection_duration_seconds.max(1));

        let permit = match limiter.try_acquire(peer_addr.ip()) {
            Ok(permit) => permit,
            Err(reason) => {
                Stats::inc(&stats.tcp_rejected);
                if reason == LimitReason::GlobalRate {
                    Stats::inc(&stats.tcp_global_connect_rate_limited);
                }
                if reason != LimitReason::PerIpRate && reason != LimitReason::GlobalRate {
                    log_limited(&TCP_REJECTED_LOG, HOT_PATH_LOG_INTERVAL, |suppressed| {
                        eprintln!("tcp rejected {peer_addr}: {reason:?}{suppressed}");
                    });
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
                    log_limited(
                        &TCP_UPSTREAM_CONNECT_ERROR_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!(
                                "tcp upstream connect error for {peer_addr}: {err}{suppressed}"
                            );
                        },
                    );
                    return;
                }
                Err(_) => {
                    Stats::inc(&stats.tcp_upstream_errors);
                    log_limited(
                        &TCP_UPSTREAM_CONNECT_TIMEOUT_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!("tcp upstream connect timeout for {peer_addr}{suppressed}");
                        },
                    );
                    return;
                }
            };

            let _ = inbound.set_nodelay(true);
            let _ = outbound.set_nodelay(true);
            match timeout(
                max_connection_duration,
                relay_bidirectional_with_idle(
                    &mut inbound,
                    &mut outbound,
                    idle_timeout,
                    downstream_rate_limit,
                    upstream_rate_limit,
                ),
            )
            .await
            {
                Ok(Ok(TcpRelayOutcome::Completed)) => {}
                Ok(Ok(TcpRelayOutcome::IdleTimeout)) => {
                    Stats::inc(&stats.tcp_idle_timeouts);
                    log_limited(&TCP_IDLE_TIMEOUT_LOG, HOT_PATH_LOG_INTERVAL, |suppressed| {
                        eprintln!("tcp proxy idle timeout reached for {peer_addr}{suppressed}");
                    });
                }
                Ok(Ok(TcpRelayOutcome::DownstreamTooSlow)) => {
                    Stats::inc(&stats.tcp_downstream_too_slow);
                    log_limited(
                        &TCP_DOWNSTREAM_TOO_SLOW_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!(
                                "tcp proxy downstream minimum data rate not met for {peer_addr}{suppressed}"
                            );
                        },
                    );
                }
                Ok(Ok(TcpRelayOutcome::UpstreamTooSlow)) => {
                    Stats::inc(&stats.tcp_upstream_too_slow);
                    log_limited(
                        &TCP_UPSTREAM_TOO_SLOW_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!(
                            "tcp proxy upstream minimum data rate not met for {peer_addr}{suppressed}"
                        );
                        },
                    );
                }
                Ok(Err(err)) => {
                    log_limited(&TCP_COPY_ERROR_LOG, HOT_PATH_LOG_INTERVAL, |suppressed| {
                        eprintln!("tcp proxy copy error for {peer_addr}: {err}{suppressed}");
                    });
                }
                Err(_) => {
                    log_limited(&TCP_MAX_DURATION_LOG, HOT_PATH_LOG_INTERVAL, |suppressed| {
                        eprintln!(
                            "tcp proxy max connection duration reached for {peer_addr}{suppressed}"
                        );
                    });
                }
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpRelayOutcome {
    Completed,
    IdleTimeout,
    DownstreamTooSlow,
    UpstreamTooSlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpRateLimit {
    min_bytes_per_second: u64,
    grace: Duration,
}

impl TcpRateLimit {
    fn new(min_bytes_per_second: u64, grace: Duration) -> Self {
        Self {
            min_bytes_per_second,
            grace,
        }
    }

    #[cfg(test)]
    fn disabled() -> Self {
        Self::new(0, Duration::ZERO)
    }
}

#[derive(Debug, Clone)]
struct TcpRateGuard {
    limit: TcpRateLimit,
    started_at: Option<Instant>,
    window_started_at: Option<Instant>,
    window_bytes: u64,
    grace_complete: bool,
}

impl TcpRateGuard {
    fn new(limit: TcpRateLimit) -> Self {
        Self {
            limit,
            started_at: None,
            window_started_at: None,
            window_bytes: 0,
            grace_complete: false,
        }
    }

    fn observe(&mut self, bytes: usize) -> bool {
        if self.limit.min_bytes_per_second == 0 || bytes == 0 {
            return true;
        }
        let now = Instant::now();
        let started_at = *self.started_at.get_or_insert(now);
        if !self.grace_complete {
            if now.saturating_duration_since(started_at) <= self.limit.grace {
                return true;
            }
            self.grace_complete = true;
            self.window_started_at = Some(started_at + self.limit.grace);
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes as u64);
        let window_started_at = self.window_started_at.get_or_insert(now);
        let elapsed = now.saturating_duration_since(*window_started_at);
        let required = self
            .limit
            .min_bytes_per_second
            .saturating_mul(elapsed.as_millis() as u64)
            / 1_000;
        if self.window_bytes >= required {
            self.window_started_at = Some(now);
            self.window_bytes = 0;
            true
        } else {
            false
        }
    }
}

async fn relay_bidirectional_with_idle<A, B>(
    downstream: &mut A,
    upstream: &mut B,
    idle_timeout: Duration,
    downstream_rate_limit: TcpRateLimit,
    upstream_rate_limit: TcpRateLimit,
) -> io::Result<TcpRelayOutcome>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let idle_enabled = !idle_timeout.is_zero();
    let idle_sleep = sleep(idle_timeout);
    tokio::pin!(idle_sleep);
    let (mut downstream_read, mut downstream_write) = split(downstream);
    let (mut upstream_read, mut upstream_write) = split(upstream);
    let (activity_tx, mut activity_rx) = mpsc::channel(1);
    let downstream_activity_tx = if idle_enabled {
        Some(activity_tx.clone())
    } else {
        None
    };
    let upstream_activity_tx = if idle_enabled {
        Some(activity_tx)
    } else {
        None
    };

    let downstream_to_upstream = relay_direction(
        &mut downstream_read,
        &mut upstream_write,
        idle_timeout,
        TcpRateGuard::new(downstream_rate_limit),
        TcpRelayOutcome::DownstreamTooSlow,
        downstream_activity_tx,
    );
    let upstream_to_downstream = relay_direction(
        &mut upstream_read,
        &mut downstream_write,
        idle_timeout,
        TcpRateGuard::new(upstream_rate_limit),
        TcpRelayOutcome::UpstreamTooSlow,
        upstream_activity_tx,
    );
    tokio::pin!(downstream_to_upstream);
    tokio::pin!(upstream_to_downstream);

    let mut downstream_to_upstream_done = false;
    let mut upstream_to_downstream_done = false;
    loop {
        if downstream_to_upstream_done && upstream_to_downstream_done {
            return Ok(TcpRelayOutcome::Completed);
        }

        tokio::select! {
            _ = &mut idle_sleep, if idle_enabled => {
                return Ok(TcpRelayOutcome::IdleTimeout);
            }
            activity = activity_rx.recv(), if idle_enabled => {
                if activity.is_some() {
                    reset_idle(&mut idle_sleep, idle_timeout, idle_enabled);
                }
            }
            result = &mut downstream_to_upstream, if !downstream_to_upstream_done => {
                match result? {
                    TcpRelayOutcome::Completed => downstream_to_upstream_done = true,
                    outcome => return Ok(outcome),
                }
            }
            result = &mut upstream_to_downstream, if !upstream_to_downstream_done => {
                match result? {
                    TcpRelayOutcome::Completed => upstream_to_downstream_done = true,
                    outcome => return Ok(outcome),
                }
            }
        }
    }
}

async fn relay_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
    mut rate: TcpRateGuard,
    too_slow: TcpRelayOutcome,
    activity_tx: Option<mpsc::Sender<()>>,
) -> io::Result<TcpRelayOutcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(TcpRelayOutcome::Completed);
        }
        if !rate.observe(read) {
            return Ok(too_slow);
        }
        if !write_all_with_idle(writer, &buf[..read], idle_timeout).await? {
            return Ok(TcpRelayOutcome::IdleTimeout);
        }
        notify_activity(&activity_tx);
    }
}

fn notify_activity(activity_tx: &Option<mpsc::Sender<()>>) {
    if let Some(activity_tx) = activity_tx {
        let _ = activity_tx.try_send(());
    }
}

async fn write_all_with_idle<W>(
    writer: &mut W,
    bytes: &[u8],
    idle_timeout: Duration,
) -> io::Result<bool>
where
    W: AsyncWrite + Unpin,
{
    if idle_timeout.is_zero() {
        writer.write_all(bytes).await?;
        return Ok(true);
    }
    match timeout(idle_timeout, writer.write_all(bytes)).await {
        Ok(result) => {
            result?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

fn reset_idle(
    idle_sleep: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    idle_timeout: Duration,
    idle_enabled: bool,
) {
    if idle_enabled {
        idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
    }
}

fn notify_startup(
    startup: Option<oneshot::Sender<Result<(), String>>>,
    result: Result<(), String>,
) {
    if let Some(startup) = startup {
        let _ = startup.send(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relay_closes_idle_connection() {
        let (_client, mut downstream) = duplex(64);
        let (mut upstream, _origin) = duplex(64);

        let outcome = timeout(
            Duration::from_millis(200),
            relay_bidirectional_with_idle(
                &mut downstream,
                &mut upstream,
                Duration::from_millis(20),
                TcpRateLimit::disabled(),
                TcpRateLimit::disabled(),
            ),
        )
        .await
        .expect("relay should return before outer timeout")
        .expect("relay should not fail");

        assert_eq!(outcome, TcpRelayOutcome::IdleTimeout);
    }

    #[tokio::test]
    async fn relay_forwards_bytes_before_idle_timeout() {
        let (mut client, mut downstream) = duplex(64);
        let (mut upstream, mut origin) = duplex(64);

        let relay = tokio::spawn(async move {
            relay_bidirectional_with_idle(
                &mut downstream,
                &mut upstream,
                Duration::from_millis(100),
                TcpRateLimit::disabled(),
                TcpRateLimit::disabled(),
            )
            .await
        });

        client.write_all(b"ping").await.unwrap();
        let mut received = [0_u8; 4];
        origin.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");

        origin.write_all(b"pong").await.unwrap();
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"pong");

        drop(client);
        drop(origin);
        let _ = timeout(Duration::from_millis(200), relay).await;
    }

    #[tokio::test]
    async fn activity_notifications_are_bounded_and_coalesced() {
        let (activity_tx, mut activity_rx) = mpsc::channel(1);
        let activity_tx = Some(activity_tx);

        notify_activity(&activity_tx);
        notify_activity(&activity_tx);
        notify_activity(&activity_tx);

        assert!(activity_rx.try_recv().is_ok());
        assert!(matches!(
            activity_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn relay_keeps_upstream_to_downstream_flowing_when_downstream_write_stalls() {
        let (client, mut downstream) = duplex(64);
        let (mut upstream, mut origin) = duplex(8);
        let (mut client_read, mut client_write) = split(client);

        let relay = tokio::spawn(async move {
            relay_bidirectional_with_idle(
                &mut downstream,
                &mut upstream,
                Duration::from_secs(1),
                TcpRateLimit::disabled(),
                TcpRateLimit::disabled(),
            )
            .await
        });
        let blocked_client_write =
            tokio::spawn(async move { client_write.write_all(&vec![b'x'; 1024]).await });

        tokio::time::sleep(Duration::from_millis(30)).await;
        origin.write_all(b"pong").await.unwrap();

        let mut received = [0_u8; 4];
        timeout(
            Duration::from_millis(100),
            client_read.read_exact(&mut received),
        )
        .await
        .expect("upstream-to-downstream data should not wait for the stalled opposite write")
        .expect("client should receive upstream data");
        assert_eq!(&received, b"pong");

        relay.abort();
        blocked_client_write.abort();
    }

    #[tokio::test]
    async fn relay_closes_slow_downstream_stream() {
        let (mut client, mut downstream) = duplex(64);
        let (mut upstream, mut origin) = duplex(64);

        let relay = tokio::spawn(async move {
            relay_bidirectional_with_idle(
                &mut downstream,
                &mut upstream,
                Duration::from_secs(1),
                TcpRateLimit::new(1_000, Duration::from_millis(5)),
                TcpRateLimit::disabled(),
            )
            .await
        });

        client.write_all(b"a").await.unwrap();
        let mut received = [0_u8; 1];
        origin.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"a");

        tokio::time::sleep(Duration::from_millis(30)).await;
        client.write_all(b"b").await.unwrap();

        let outcome = timeout(Duration::from_millis(200), relay)
            .await
            .expect("relay should return before outer timeout")
            .expect("relay task should not panic")
            .expect("relay should not fail");
        assert_eq!(outcome, TcpRelayOutcome::DownstreamTooSlow);
        let forwarded = timeout(Duration::from_millis(20), origin.read_exact(&mut received)).await;
        assert!(!matches!(forwarded, Ok(Ok(_))));
    }

    #[tokio::test]
    async fn relay_closes_slow_upstream_stream() {
        let (mut client, mut downstream) = duplex(64);
        let (mut upstream, mut origin) = duplex(64);

        let relay = tokio::spawn(async move {
            relay_bidirectional_with_idle(
                &mut downstream,
                &mut upstream,
                Duration::from_secs(1),
                TcpRateLimit::disabled(),
                TcpRateLimit::new(1_000, Duration::from_millis(5)),
            )
            .await
        });

        origin.write_all(b"a").await.unwrap();
        let mut received = [0_u8; 1];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"a");

        tokio::time::sleep(Duration::from_millis(30)).await;
        origin.write_all(b"b").await.unwrap();

        let outcome = timeout(Duration::from_millis(200), relay)
            .await
            .expect("relay should return before outer timeout")
            .expect("relay task should not panic")
            .expect("relay should not fail");
        assert_eq!(outcome, TcpRelayOutcome::UpstreamTooSlow);
        let forwarded = timeout(Duration::from_millis(20), client.read_exact(&mut received)).await;
        assert!(!matches!(forwarded, Ok(Ok(_))));
    }

    #[tokio::test]
    async fn tcp_rate_guard_rejects_first_post_grace_slow_chunk() {
        let mut guard = TcpRateGuard::new(TcpRateLimit::new(1_000, Duration::from_millis(5)));

        assert!(guard.observe(1));
        tokio::time::sleep(Duration::from_millis(30)).await;

        assert!(!guard.observe(1));
    }
}
