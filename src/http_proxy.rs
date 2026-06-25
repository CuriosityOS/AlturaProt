use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    error::Error,
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant as StdInstant},
};

use bytes::{Buf, Bytes};
use http::{
    header::{
        HeaderName, HeaderValue, ACCEPT_ENCODING, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING,
        CONTENT_LENGTH, EXPECT, HOST, RANGE, TRANSFER_ENCODING,
    },
    uri::Authority,
    HeaderMap, Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    server::conn::http1,
    service::service_fn,
    Error as HyperError,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use tokio::time::{timeout, Sleep};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
};

use crate::{
    adaptive::AdaptiveDetector,
    config::{ClientIpConfig, HttpConfig, HTTP_ADMIN_TOKEN_MAX_BYTES},
    filter::{
        request_path_shape, request_signature, short_token_parent_shape, FilterEngine,
        RequestContext,
    },
    limiter::{
        HttpConnectionLimiter, LimitReason, PathShapeRateLimiter, RateLimiter,
        RequestConcurrencyLimiter, RequestConcurrencyPermit, ShortTokenSiblingRateLimiter,
        SignatureRateLimiter,
    },
    listener::bind_tcp_listeners,
    log_limiter::{log_limited, LogLimiter, HOT_PATH_LOG_INTERVAL},
    telemetry::{EventLogger, Stats},
    BoxError,
};

type ProxyBody = BoxBody<Bytes, BoxError>;
type HyperClient = Client<HttpConnector, GuardedBody<Incoming>>;
const GENERATED_RETRY_AFTER_SECONDS: &str = "1";
const GENERATED_CACHE_CONTROL: &str = "no-store";
const UPSTREAM_CIRCUIT_SHARDS: usize = 64;
const UPSTREAM_CIRCUIT_EVICTION_SCAN_LIMIT: usize = 32;

static HTTP_ACCEPT_ERROR_LOG: LogLimiter = LogLimiter::new();
static HTTP_CONNECTION_REJECTED_LOG: LogLimiter = LogLimiter::new();
static HTTP_INITIAL_HEADER_TOO_LARGE_LOG: LogLimiter = LogLimiter::new();
static HTTP_INITIAL_HEADER_TIMEOUT_LOG: LogLimiter = LogLimiter::new();
static HTTP_INITIAL_READ_ERROR_LOG: LogLimiter = LogLimiter::new();
static HTTP_CONNECTION_ERROR_LOG: LogLimiter = LogLimiter::new();
static HTTP_CONNECTION_MAX_DURATION_LOG: LogLimiter = LogLimiter::new();
static HTTP_REQUEST_BODY_REJECTED_LOG: LogLimiter = LogLimiter::new();
static HTTP_UPSTREAM_ERROR_LOG: LogLimiter = LogLimiter::new();
static HTTP_UPSTREAM_TIMEOUT_LOG: LogLimiter = LogLimiter::new();

#[derive(Debug)]
struct UpstreamFailureCircuitBreaker {
    threshold: u32,
    open_ms: u64,
    started_at: StdInstant,
    shard_capacity: usize,
    shards: Vec<Mutex<UpstreamFailureCircuitShard>>,
}

#[derive(Debug, Default)]
struct UpstreamFailureCircuitShard {
    entries: HashMap<String, UpstreamFailureCircuitEntry>,
    order: VecDeque<String>,
}

#[derive(Debug, Default)]
struct UpstreamFailureCircuitEntry {
    consecutive_failures: u32,
    open_until_ms: u64,
}

impl UpstreamFailureCircuitBreaker {
    fn from_config(cfg: &HttpConfig) -> Self {
        Self::new(
            cfg.upstream_failure_threshold,
            cfg.upstream_failure_open_ms,
            cfg.limits.max_tracked_path_shapes,
        )
    }

    fn new(threshold: u32, open_ms: u64, max_path_shapes: usize) -> Self {
        Self {
            threshold,
            open_ms,
            started_at: StdInstant::now(),
            shard_capacity: max_path_shapes
                .max(1)
                .div_ceil(UPSTREAM_CIRCUIT_SHARDS)
                .max(1),
            shards: (0..UPSTREAM_CIRCUIT_SHARDS)
                .map(|_| Mutex::new(UpstreamFailureCircuitShard::default()))
                .collect(),
        }
    }

    fn is_open(&self, path_shape: &str) -> bool {
        if self.threshold == 0 {
            return false;
        }
        let shard = self.shard(path_shape);
        let shard = match shard.lock() {
            Ok(shard) => shard,
            Err(poisoned) => poisoned.into_inner(),
        };
        shard
            .entries
            .get(path_shape)
            .is_some_and(|entry| self.now_ms() < entry.open_until_ms)
    }

    fn record_success(&self, path_shape: &str) {
        let shard = self.shard(path_shape);
        let mut shard = match shard.lock() {
            Ok(shard) => shard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = shard.entries.get_mut(path_shape) {
            entry.consecutive_failures = 0;
            entry.open_until_ms = 0;
        }
    }

    fn record_failure(&self, path_shape: &str) {
        if self.threshold == 0 {
            return;
        }
        let now_ms = self.now_ms();
        let shard = self.shard(path_shape);
        let mut shard = match shard.lock() {
            Ok(shard) => shard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !shard.entries.contains_key(path_shape) {
            if !ensure_upstream_circuit_shard_capacity(&mut shard, self.shard_capacity, now_ms) {
                return;
            }
            shard.order.push_back(path_shape.to_string());
            shard.entries.insert(
                path_shape.to_string(),
                UpstreamFailureCircuitEntry::default(),
            );
        }
        if let Some(entry) = shard.entries.get_mut(path_shape) {
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            if entry.consecutive_failures >= self.threshold {
                entry.open_until_ms = now_ms.saturating_add(self.open_ms);
                entry.consecutive_failures = 0;
            }
        }
    }

    fn shard(&self, path_shape: &str) -> &Mutex<UpstreamFailureCircuitShard> {
        &self.shards[upstream_circuit_shard_for(path_shape) % self.shards.len()]
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

fn upstream_circuit_shard_for(path_shape: &str) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path_shape.hash(&mut hasher);
    hasher.finish() as usize
}

fn ensure_upstream_circuit_shard_capacity(
    shard: &mut UpstreamFailureCircuitShard,
    capacity: usize,
    now_ms: u64,
) -> bool {
    if shard.entries.len() < capacity {
        return true;
    }
    let scan = shard.order.len().min(UPSTREAM_CIRCUIT_EVICTION_SCAN_LIMIT);
    for _ in 0..scan {
        let Some(oldest) = shard.order.pop_front() else {
            break;
        };
        let evict = shard
            .entries
            .get(&oldest)
            .is_some_and(|entry| now_ms >= entry.open_until_ms);
        if evict {
            shard.entries.remove(&oldest);
            return shard.entries.len() < capacity;
        }
        if shard.entries.contains_key(&oldest) {
            shard.order.push_back(oldest);
        }
    }
    shard.entries.len() < capacity
}

#[derive(Clone)]
struct HttpProxyState {
    cfg: HttpConfig,
    upstream: Uri,
    client: HyperClient,
    client_ip: ClientIpResolver,
    engine: Arc<FilterEngine>,
    limiter: Arc<RateLimiter>,
    trusted_proxy_limiter: Arc<RateLimiter>,
    signature_limiter: Arc<SignatureRateLimiter>,
    path_shape_limiter: Arc<PathShapeRateLimiter>,
    short_token_sibling_limiter: Arc<ShortTokenSiblingRateLimiter>,
    request_limiter: Arc<RequestConcurrencyLimiter>,
    trusted_proxy_request_limiter: Arc<RequestConcurrencyLimiter>,
    upstream_circuit: Arc<UpstreamFailureCircuitBreaker>,
    detector: Arc<AdaptiveDetector>,
    stats: Arc<Stats>,
    logger: Arc<EventLogger>,
}

pub async fn run_http_proxy(
    cfg: HttpConfig,
    engine: Arc<FilterEngine>,
    detector: Arc<AdaptiveDetector>,
    stats: Arc<Stats>,
    logger: Arc<EventLogger>,
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
    let upstream: Uri = match cfg.upstream.parse() {
        Ok(upstream) => upstream,
        Err(err) => {
            notify_startup(startup, Err(format!("invalid upstream URI: {err}")));
            return Err(Box::new(err));
        }
    };
    if upstream.scheme().is_none() || upstream.authority().is_none() {
        notify_startup(
            startup,
            Err("HTTP upstream must include scheme and authority".to_string()),
        );
        return Err("HTTP upstream must include scheme and authority".into());
    }
    if !upstream
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
    {
        notify_startup(
            startup,
            Err("HTTP upstream must use http:// scheme".to_string()),
        );
        return Err("HTTP upstream must use http:// scheme".into());
    }
    if upstream.query().is_some() {
        notify_startup(
            startup,
            Err("HTTP upstream must not include a query string".to_string()),
        );
        return Err("HTTP upstream must not include a query string".into());
    }
    if upstream
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        notify_startup(
            startup,
            Err("HTTP upstream must not contain URI userinfo".to_string()),
        );
        return Err("HTTP upstream must not contain URI userinfo".into());
    }

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_millis(cfg.upstream_connect_timeout_ms)));
    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder.http1_max_buf_size(cfg.upstream_max_header_bytes);
    client_builder.http1_max_headers(cfg.upstream_max_headers.max(1));
    client_builder.pool_max_idle_per_host(cfg.upstream_pool_max_idle_per_host);
    if cfg.upstream_pool_idle_timeout_ms == 0 {
        client_builder.pool_idle_timeout(None);
    } else {
        client_builder.pool_timer(TokioTimer::new());
        client_builder.pool_idle_timeout(Duration::from_millis(cfg.upstream_pool_idle_timeout_ms));
    }
    let client = client_builder.build(connector);
    let limiter = Arc::new(RateLimiter::new(&cfg.limits));
    let trusted_proxy_limiter = Arc::new(RateLimiter::trusted_proxy_aggregate(&cfg.limits));
    let signature_limiter = SignatureRateLimiter::new(&cfg.limits);
    let path_shape_limiter = PathShapeRateLimiter::new(&cfg.limits);
    let short_token_sibling_limiter = ShortTokenSiblingRateLimiter::new(&cfg.limits);
    let connection_limiter = HttpConnectionLimiter::new(&cfg.limits);
    let request_limiter = RequestConcurrencyLimiter::new(&cfg.limits);
    let trusted_proxy_request_limiter =
        RequestConcurrencyLimiter::trusted_proxy_aggregate(&cfg.limits);
    let upstream_circuit = Arc::new(UpstreamFailureCircuitBreaker::from_config(&cfg));
    let state = HttpProxyState {
        cfg: cfg.clone(),
        upstream,
        client,
        client_ip: ClientIpResolver::from_config(&cfg.client_ip),
        engine,
        limiter,
        trusted_proxy_limiter,
        signature_limiter,
        path_shape_limiter,
        short_token_sibling_limiter,
        request_limiter,
        trusted_proxy_request_limiter,
        upstream_circuit,
        detector,
        stats,
        logger,
    };

    let listeners = match bind_tcp_listeners(listen, cfg.listen_backlog, cfg.accept_shards) {
        Ok(listeners) => listeners,
        Err(err) => {
            notify_startup(startup, Err(format!("bind failed: {err}")));
            return Err(Box::new(err));
        }
    };
    eprintln!(
        "http proxy listening on {listen}, upstream {}, accept_shards={}",
        cfg.upstream,
        listeners.len()
    );
    notify_startup(startup, Ok(()));

    let mut accept_tasks = Vec::with_capacity(listeners.len());
    for (idx, listener) in listeners.into_iter().enumerate() {
        let state = state.clone();
        let connection_limiter = Arc::clone(&connection_limiter);
        let shutdown = shutdown.clone();
        accept_tasks.push(tokio::spawn(async move {
            run_http_accept_loop(listener, state, connection_limiter, shutdown, idx).await;
        }));
    }
    for task in accept_tasks {
        let _ = task.await;
    }
    Ok(())
}

async fn run_http_accept_loop(
    listener: TcpListener,
    state: HttpProxyState,
    connection_limiter: Arc<HttpConnectionLimiter>,
    mut shutdown: watch::Receiver<bool>,
    shard_idx: usize,
) {
    loop {
        let (stream, peer_addr) = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    eprintln!("http proxy listener shard {} shutting down", shard_idx + 1);
                    break;
                }
                continue;
            }
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    log_limited(&HTTP_ACCEPT_ERROR_LOG, HOT_PATH_LOG_INTERVAL, |suppressed| {
                        eprintln!("http accept error: {err}{suppressed}");
                    });
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            },
        };

        let permit = match connection_limiter.try_acquire(peer_addr.ip()) {
            Ok(permit) => permit,
            Err(reason) => {
                Stats::inc(&state.stats.http_connections_rejected);
                if reason != LimitReason::PerIpConnections
                    && reason != LimitReason::GlobalConnections
                {
                    log_limited(
                        &HTTP_CONNECTION_REJECTED_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!(
                                "http connection rejected {peer_addr}: {reason:?}{suppressed}"
                            );
                        },
                    );
                }
                continue;
            }
        };

        let conn_state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let max_header_bytes = conn_state.cfg.max_header_bytes;
            let max_header_line_bytes = conn_state.cfg.max_header_line_bytes;
            let max_headers = conn_state.cfg.max_headers.max(1);
            let max_connection_duration =
                Duration::from_secs(conn_state.cfg.max_connection_duration_seconds.max(1));
            let max_requests_per_connection = conn_state.cfg.max_requests_per_connection;
            let requests_seen = Arc::new(AtomicU64::new(0));
            let service_state = conn_state.clone();
            let service_requests = Arc::clone(&requests_seen);
            let service = service_fn(move |req| {
                let conn_state = service_state.clone();
                let service_requests = Arc::clone(&service_requests);
                async move {
                    let request_number = service_requests.fetch_add(1, Ordering::Relaxed) + 1;
                    if max_requests_per_connection > 0
                        && request_number > max_requests_per_connection
                    {
                        Stats::inc(&conn_state.stats.http_request_limited);
                        return Ok(connection_request_limit_response(
                            "connection request limit\n",
                        ));
                    }
                    handle_http(req, peer_addr, conn_state).await
                }
            });
            let mut builder = http1::Builder::new();
            builder.keep_alive(conn_state.cfg.downstream_keep_alive);
            builder.max_buf_size(max_header_bytes);
            builder.max_headers(max_headers);
            if conn_state.cfg.header_read_timeout_ms > 0 {
                builder.timer(TokioTimer::new());
                builder.header_read_timeout(Duration::from_millis(
                    conn_state.cfg.header_read_timeout_ms,
                ));
            }
            let stream = match prevalidate_initial_http1_request(
                stream,
                max_header_bytes,
                max_header_line_bytes,
                max_headers,
                RawRequestTargetLimits::from_config(&conn_state.cfg),
                Duration::from_millis(conn_state.cfg.header_read_timeout_ms),
                conn_state.cfg.allow_chunked_request_bodies,
            )
            .await
            {
                Ok(stream) => stream,
                Err(InitialRequestPrecheckError::Rejected { stream, reason }) => {
                    Stats::inc(&conn_state.stats.http_framing_rejected);
                    let _ = write_initial_bad_request_response(stream, reason).await;
                    return;
                }
                Err(InitialRequestPrecheckError::RequestTargetRejected { stream, reason }) => {
                    Stats::inc(&conn_state.stats.http_uri_rejected);
                    Stats::inc(&conn_state.stats.http_initial_request_target_rejected);
                    let _ = write_initial_request_target_rejected_response(stream, reason).await;
                    return;
                }
                Err(InitialRequestPrecheckError::HeaderTooLarge { stream }) => {
                    Stats::inc(&conn_state.stats.http_initial_header_too_large);
                    log_limited(
                        &HTTP_INITIAL_HEADER_TOO_LARGE_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!("initial http header too large from {peer_addr}{suppressed}");
                        },
                    );
                    let _ = write_initial_header_too_large_response(stream).await;
                    return;
                }
                Err(InitialRequestPrecheckError::HeaderCountTooLarge { stream }) => {
                    Stats::inc(&conn_state.stats.http_initial_headers_too_many);
                    log_limited(
                        &HTTP_INITIAL_HEADER_TOO_LARGE_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!(
                                "initial http header count too large from {peer_addr}{suppressed}"
                            );
                        },
                    );
                    let _ = write_initial_header_too_large_response(stream).await;
                    return;
                }
                Err(InitialRequestPrecheckError::Timeout { stream }) => {
                    Stats::inc(&conn_state.stats.http_initial_header_timeouts);
                    log_limited(
                        &HTTP_INITIAL_HEADER_TIMEOUT_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!("initial http header timeout from {peer_addr}{suppressed}");
                        },
                    );
                    let _ = write_initial_request_timeout_response(stream).await;
                    return;
                }
                Err(InitialRequestPrecheckError::Io(err)) => {
                    log_limited(
                        &HTTP_INITIAL_READ_ERROR_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!(
                                "initial http read error from {peer_addr}: {err}{suppressed}"
                            );
                        },
                    );
                    return;
                }
            };
            let io = TokioIo::new(DownstreamWriteTimeoutIo::new(
                stream,
                Duration::from_millis(conn_state.cfg.downstream_write_timeout_ms),
                Arc::clone(&conn_state.stats),
            ));
            match timeout(
                max_connection_duration,
                builder.serve_connection(io, service),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    log_limited(
                        &HTTP_CONNECTION_ERROR_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!("http connection error from {peer_addr}: {err}{suppressed}");
                        },
                    );
                }
                Err(_) => {
                    log_limited(
                        &HTTP_CONNECTION_MAX_DURATION_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!(
                                "http connection max duration reached for {peer_addr}{suppressed}"
                            );
                        },
                    );
                }
            }
        });
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

#[derive(Debug)]
enum InitialRequestPrecheckError {
    Rejected {
        stream: TcpStream,
        reason: &'static str,
    },
    RequestTargetRejected {
        stream: TcpStream,
        reason: &'static str,
    },
    HeaderTooLarge {
        stream: TcpStream,
    },
    HeaderCountTooLarge {
        stream: TcpStream,
    },
    Timeout {
        stream: TcpStream,
    },
    Io(io::Error),
}

struct PreReadStream {
    prefix: Bytes,
    offset: usize,
    inner: TcpStream,
}

impl AsyncRead for PreReadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let len = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..len]);
            self.offset += len;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PreReadStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn prevalidate_initial_http1_request(
    mut stream: TcpStream,
    max_header_bytes: usize,
    max_header_line_bytes: usize,
    max_headers: usize,
    request_target_limits: RawRequestTargetLimits,
    header_timeout: Duration,
    allow_chunked_request_bodies: bool,
) -> Result<PreReadStream, InitialRequestPrecheckError> {
    let mut prefix = Vec::with_capacity(1024);
    let mut scratch = [0_u8; 1024];
    let header_deadline = if header_timeout.is_zero() {
        None
    } else {
        Some(tokio::time::Instant::now() + header_timeout)
    };

    let mut header_scan_start = 0;

    loop {
        if let Some(header_end) = find_header_end_from(&prefix, header_scan_start) {
            if header_end > max_header_bytes {
                return Err(InitialRequestPrecheckError::HeaderTooLarge { stream });
            }
            if raw_http1_header_line_exceeds(&prefix[..header_end], max_header_line_bytes) {
                return Err(InitialRequestPrecheckError::HeaderTooLarge { stream });
            }
            if let Err(reason) =
                validate_raw_http1_header_block(&prefix[..header_end], allow_chunked_request_bodies)
            {
                return Err(InitialRequestPrecheckError::Rejected { stream, reason });
            }
            if let Err(reason) =
                validate_raw_request_target(&prefix[..header_end], request_target_limits)
            {
                return Err(InitialRequestPrecheckError::RequestTargetRejected { stream, reason });
            }
            if raw_http1_header_count_exceeds(&prefix[..header_end], max_headers) {
                return Err(InitialRequestPrecheckError::HeaderCountTooLarge { stream });
            }
            return Ok(PreReadStream {
                prefix: Bytes::from(prefix),
                offset: 0,
                inner: stream,
            });
        }
        if prefix.len() >= max_header_bytes {
            return Err(InitialRequestPrecheckError::HeaderTooLarge { stream });
        }

        let read = if let Some(deadline) = header_deadline {
            tokio::select! {
                read = stream.read(&mut scratch) => read.map_err(InitialRequestPrecheckError::Io)?,
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(InitialRequestPrecheckError::Timeout { stream });
                }
            }
        } else {
            stream
                .read(&mut scratch)
                .await
                .map_err(InitialRequestPrecheckError::Io)?
        };

        if read == 0 {
            return Ok(PreReadStream {
                prefix: Bytes::from(prefix),
                offset: 0,
                inner: stream,
            });
        }
        let previous_len = prefix.len();
        prefix.extend_from_slice(&scratch[..read]);
        header_scan_start = previous_len.saturating_sub(3);
    }
}

async fn write_initial_bad_request_response(mut stream: TcpStream, reason: &str) -> io::Result<()> {
    write_initial_error_response(&mut stream, "400 Bad Request", reason).await?;
    stream.shutdown().await
}

async fn write_initial_header_too_large_response(mut stream: TcpStream) -> io::Result<()> {
    write_initial_error_response(
        &mut stream,
        "431 Request Header Fields Too Large",
        "request header fields too large",
    )
    .await?;
    stream.shutdown().await
}

async fn write_initial_request_timeout_response(mut stream: TcpStream) -> io::Result<()> {
    write_initial_error_response(&mut stream, "408 Request Timeout", "request timeout").await?;
    stream.shutdown().await
}

async fn write_initial_request_target_rejected_response(
    mut stream: TcpStream,
    reason: &str,
) -> io::Result<()> {
    write_initial_error_response(&mut stream, "414 URI Too Long", reason).await?;
    stream.shutdown().await
}

async fn write_initial_error_response(
    stream: &mut TcpStream,
    status_line: &str,
    reason: &str,
) -> io::Result<()> {
    let body = format!("{reason}\n");
    stream
        .write_all(
            format!(
                "HTTP/1.1 {}\r\nCache-Control: {}\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                status_line,
                GENERATED_CACHE_CONTROL,
                body.len(),
                body
            )
            .as_bytes(),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    find_header_end_from(bytes, 0)
}

fn find_header_end_from(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.len() < 4 {
        return None;
    }
    if start > bytes.len().saturating_sub(4) {
        return None;
    }
    bytes
        .get(start..)
        .unwrap_or_default()
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| start + idx + 4)
}

#[derive(Clone, Copy)]
struct RawRequestTargetLimits {
    max_uri_bytes: usize,
    max_query_bytes: usize,
    max_query_pairs: usize,
    max_path_segments: usize,
}

impl RawRequestTargetLimits {
    fn from_config(cfg: &HttpConfig) -> Self {
        Self {
            max_uri_bytes: cfg.max_uri_bytes,
            max_query_bytes: cfg.max_query_bytes,
            max_query_pairs: cfg.max_query_pairs,
            max_path_segments: cfg.max_path_segments,
        }
    }
}

fn validate_raw_request_target(
    block: &[u8],
    limits: RawRequestTargetLimits,
) -> Result<(), &'static str> {
    let Some(target) = raw_http1_request_target(block) else {
        return Ok(());
    };
    if limits.max_uri_bytes > 0 && target.len() > limits.max_uri_bytes {
        return Err("request uri too long");
    }

    let path_and_query = raw_target_path_and_query(target);
    if let Some(query) = raw_target_query(path_and_query) {
        if limits.max_query_bytes > 0 && query.len() > limits.max_query_bytes {
            return Err("request query too long");
        }
        if limits.max_query_pairs > 0
            && query
                .split(|byte| *byte == b'&')
                .take(limits.max_query_pairs + 1)
                .count()
                > limits.max_query_pairs
        {
            return Err("too many query parameters");
        }
    }

    if limits.max_path_segments > 0
        && raw_target_path_segment_count(path_and_query, limits.max_path_segments)
            > limits.max_path_segments
    {
        return Err("too many path segments");
    }

    Ok(())
}

fn raw_http1_request_target(block: &[u8]) -> Option<&[u8]> {
    let request_line = block.split(|byte| *byte == b'\n').next()?;
    let request_line = request_line.strip_suffix(b"\r").unwrap_or(request_line);
    let mut parts = request_line.split(|byte| *byte == b' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if method.is_empty() || target.is_empty() || version.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(target)
}

fn raw_target_path_and_query(target: &[u8]) -> &[u8] {
    if target.starts_with(b"/") || target.starts_with(b"?") || target == b"*" {
        return target;
    }
    if let Some(scheme_end) = target.windows(3).position(|window| window == b"://") {
        let authority_start = scheme_end + 3;
        let slash = target[authority_start..]
            .iter()
            .position(|byte| *byte == b'/')
            .map(|idx| authority_start + idx);
        let query = target[authority_start..]
            .iter()
            .position(|byte| *byte == b'?')
            .map(|idx| authority_start + idx);
        return match (slash, query) {
            (Some(slash), Some(query)) => &target[slash.min(query)..],
            (Some(slash), None) => &target[slash..],
            (None, Some(query)) => &target[query..],
            (None, None) => b"",
        };
    }
    b""
}

fn raw_target_query(path_and_query: &[u8]) -> Option<&[u8]> {
    path_and_query
        .iter()
        .position(|byte| *byte == b'?')
        .map(|idx| &path_and_query[idx + 1..])
}

fn raw_target_path_segment_count(path_and_query: &[u8], max_segments: usize) -> usize {
    let path = path_and_query
        .split(|byte| *byte == b'?')
        .next()
        .unwrap_or(path_and_query);
    path.split(|byte| *byte == b'/')
        .filter(|segment| !segment.is_empty() && *segment != b"*")
        .take(max_segments + 1)
        .count()
}

fn raw_http1_header_count_exceeds(block: &[u8], max_headers: usize) -> bool {
    if max_headers == 0 {
        return false;
    }
    raw_http1_header_count(block) > max_headers
}

fn raw_http1_header_line_exceeds(block: &[u8], max_header_line_bytes: usize) -> bool {
    if max_header_line_bytes == 0 {
        return false;
    }
    let mut lines = block.split(|byte| *byte == b'\n');
    let _request_line = lines.next();
    for raw_line in lines {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        if line.len() > max_header_line_bytes {
            return true;
        }
    }
    false
}

fn raw_http1_header_count(block: &[u8]) -> usize {
    let mut lines = block.split(|byte| *byte == b'\n');
    let _request_line = lines.next();
    let mut count = 0;
    for raw_line in lines {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        count += 1;
    }
    count
}

fn validate_raw_http1_header_block(
    block: &[u8],
    allow_chunked_request_bodies: bool,
) -> Result<(), &'static str> {
    let mut lines = block.split(|byte| *byte == b'\n');
    let Some(request_line) = lines.next() else {
        return Err("missing request line");
    };
    if request_line.trim_ascii_end().is_empty() {
        return Err("missing request line");
    }

    let mut content_length_count = 0_usize;
    let mut transfer_encoding_count = 0_usize;
    let mut transfer_encoding_value: Option<&[u8]> = None;

    for raw_line in lines {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            return Err("obsolete folded header line");
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err("invalid header line");
        };
        let name = &line[..colon];
        if name.is_empty() || name.iter().any(|byte| byte.is_ascii_whitespace()) {
            return Err("invalid header name");
        }
        let value = trim_header_value(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            content_length_count += 1;
            validate_raw_content_length(value)?;
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_encoding_count += 1;
            transfer_encoding_value = Some(value);
        }
    }

    if content_length_count > 1 {
        return Err("multiple content-length headers");
    }
    if transfer_encoding_count == 0 {
        return Ok(());
    }
    if content_length_count > 0 {
        return Err("ambiguous transfer-encoding and content-length");
    }
    if transfer_encoding_count > 1 {
        return Err("multiple transfer-encoding headers");
    }
    validate_raw_transfer_encoding(
        transfer_encoding_value.unwrap_or_default(),
        allow_chunked_request_bodies,
    )
}

fn trim_header_value(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &value[start..end]
}

fn validate_raw_content_length(value: &[u8]) -> Result<(), &'static str> {
    if value.is_empty() || value.contains(&b',') || !value.iter().all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid content-length header");
    }
    Ok(())
}

fn validate_raw_transfer_encoding(
    value: &[u8],
    allow_chunked_request_bodies: bool,
) -> Result<(), &'static str> {
    let mut saw_coding = false;
    for coding in value
        .split(|byte| *byte == b',')
        .map(trim_header_value)
        .filter(|coding| !coding.is_empty())
    {
        if saw_coding || !coding.eq_ignore_ascii_case(b"chunked") {
            return Err("unsupported transfer-encoding");
        }
        saw_coding = true;
    }
    if !saw_coding {
        return Err("invalid transfer-encoding header");
    }
    if !allow_chunked_request_bodies {
        return Err("chunked request body not allowed");
    }
    Ok(())
}

fn validate_header_lines(
    headers: &HeaderMap<HeaderValue>,
    max_header_line_bytes: usize,
) -> Result<(), &'static str> {
    if max_header_line_bytes == 0 {
        return Ok(());
    }
    for (name, value) in headers {
        let line_len = name
            .as_str()
            .len()
            .saturating_add(2)
            .saturating_add(value.as_bytes().len());
        if line_len > max_header_line_bytes {
            return Err("header field too large");
        }
    }
    Ok(())
}

async fn handle_http(
    mut req: Request<Incoming>,
    peer_addr: SocketAddr,
    state: HttpProxyState,
) -> Result<Response<ProxyBody>, Infallible> {
    Stats::inc(&state.stats.http_total);

    if let Err(reason) = validate_header_lines(req.headers(), state.cfg.max_header_line_bytes) {
        Stats::inc(&state.stats.http_header_line_rejected);
        return Ok(request_metadata_too_large_response(format!("{reason}\n")));
    }

    let peer_trusted_for_forwarded = state.client_ip.is_trusted(peer_addr.ip());
    let client_ip = match state.client_ip.resolve(peer_addr.ip(), req.headers()) {
        Ok(client_ip) => client_ip,
        Err(reason) => {
            Stats::inc(&state.stats.http_forwarded_rejected);
            return Ok(early_rejection_response(400, format!("{reason}\n"), None));
        }
    };
    let method = req.method().as_str().to_string();
    if !method_allowed(req.method(), &state.cfg) {
        Stats::inc(&state.stats.http_method_rejected);
        return Ok(method_not_allowed_response(&state.cfg));
    }
    if let Err(reason) =
        validate_method_override_headers(req.headers(), state.cfg.allow_method_override_headers)
    {
        Stats::inc(&state.stats.http_method_rejected);
        return Ok(early_rejection_response(400, format!("{reason}\n"), None));
    }
    let original_host = match validate_effective_host(req.uri(), req.headers(), &state.cfg) {
        Ok(host) => host,
        Err(reason) => {
            Stats::inc(&state.stats.http_host_rejected);
            return Ok(early_rejection_response(400, format!("{reason}\n"), None));
        }
    };
    if let Err(reason) =
        validate_request_framing(req.headers(), state.cfg.allow_chunked_request_bodies)
    {
        Stats::inc(&state.stats.http_framing_rejected);
        return Ok(request_framing_rejected_response(format!("{reason}\n")));
    }
    if let Err(reason) =
        validate_request_content_encoding(req.headers(), state.cfg.allow_compressed_request_bodies)
    {
        Stats::inc(&state.stats.http_content_encoding_rejected);
        return Ok(unsupported_content_encoding_response(format!("{reason}\n")));
    }
    if let Err(reason) = validate_request_expect(req.headers(), state.cfg.allow_expect_continue) {
        Stats::inc(&state.stats.http_expect_rejected);
        return Ok(early_rejection_response(417, format!("{reason}\n"), None));
    }
    if let Err(reason) = validate_request_range(req.headers(), state.cfg.max_ranges) {
        Stats::inc(&state.stats.http_range_rejected);
        return Ok(early_rejection_response(416, format!("{reason}\n"), None));
    }
    if let Err(reason) = validate_request_target(req.uri(), &state.cfg) {
        Stats::inc(&state.stats.http_uri_rejected);
        return Ok(request_target_rejected_response(format!("{reason}\n")));
    }
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(ToString::to_string);
    let signature = request_signature(&method, &path, query.as_deref(), req.headers());
    let path_shape = request_path_shape(&path);
    let short_token_parent = short_token_parent_shape(&path);

    let ctx = RequestContext {
        client_ip,
        method: &method,
        path: &path,
        query: query.as_deref(),
        headers: req.headers(),
        signature,
    };

    if admin_endpoint(&state.cfg.admin_path_prefix, &method, &path).is_some() {
        if let Some(response) =
            maybe_rate_limit_response(&state.limiter, &state.stats, client_ip, None, &ctx)
        {
            return Ok(response);
        }
        if let Some(response) = maybe_trusted_proxy_rate_limit_response(
            &state.trusted_proxy_limiter,
            &state.stats,
            client_ip,
            peer_addr.ip(),
            None,
            &ctx,
        ) {
            return Ok(response);
        }
        if let Some(response) =
            maybe_signature_rate_limit_response(&state.signature_limiter, &state.stats, None, &ctx)
        {
            return Ok(response);
        }
        if let Some(response) = maybe_path_shape_rate_limit_response(
            &state.path_shape_limiter,
            &state.stats,
            None,
            &ctx,
            &path_shape,
        ) {
            return Ok(response);
        }
        if let Some(response) = maybe_short_token_sibling_rate_limit_response(
            &state.short_token_sibling_limiter,
            &state.stats,
            None,
            &ctx,
            short_token_parent.as_ref(),
        ) {
            return Ok(response);
        }
        if let Some(admin) = maybe_admin_response(&state, &method, &path, req.headers()) {
            return Ok(admin);
        }
    }

    state.detector.observe(&ctx, "observed");

    if let Some(length) = content_length(req.headers()) {
        if state.cfg.max_body_bytes > 0 && length > state.cfg.max_body_bytes {
            Stats::inc(&state.stats.http_body_rejected);
            state.detector.observe(&ctx, "body_too_large");
            return Ok(content_too_large_response("request body too large\n"));
        }
    }

    if let Some(response) = maybe_signature_rate_limit_response(
        &state.signature_limiter,
        &state.stats,
        Some(&state.detector),
        &ctx,
    ) {
        return Ok(response);
    }

    if let Some(response) = maybe_path_shape_rate_limit_response(
        &state.path_shape_limiter,
        &state.stats,
        Some(&state.detector),
        &ctx,
        &path_shape,
    ) {
        return Ok(response);
    }
    if let Some(response) = maybe_short_token_sibling_rate_limit_response(
        &state.short_token_sibling_limiter,
        &state.stats,
        Some(&state.detector),
        &ctx,
        short_token_parent.as_ref(),
    ) {
        return Ok(response);
    }

    if let Some(response) = maybe_rate_limit_response(
        &state.limiter,
        &state.stats,
        client_ip,
        Some(&state.detector),
        &ctx,
    ) {
        return Ok(response);
    }
    if let Some(response) = maybe_trusted_proxy_rate_limit_response(
        &state.trusted_proxy_limiter,
        &state.stats,
        client_ip,
        peer_addr.ip(),
        Some(&state.detector),
        &ctx,
    ) {
        return Ok(response);
    }

    if let Some(decision) = state.engine.evaluate(&ctx) {
        Stats::inc(&state.stats.http_blocked);
        state.detector.observe(&ctx, "filter_block");
        return Ok(early_rejection_response(
            decision.status,
            decision.body,
            Some(("x-altura-filter", decision.rule_id)),
        ));
    }

    if state.upstream_circuit.is_open(&path_shape) {
        Stats::inc(&state.stats.http_upstream_circuit_open);
        return Ok(upstream_circuit_open_response("upstream circuit open\n"));
    }

    match rewrite_request(
        &mut req,
        &state.upstream,
        ForwardingContext {
            original_host: original_host.as_deref(),
            client_ip,
            peer_ip: peer_addr.ip(),
            preserve_host: state.cfg.preserve_host,
            preserve_forwarded_chain: peer_trusted_for_forwarded
                && state.client_ip.uses_x_forwarded_for(),
            forward_accept_encoding: state.cfg.forward_accept_encoding,
        },
        &state.stats,
    ) {
        Ok(()) => {}
        Err(err) => {
            Stats::inc(&state.stats.http_blocked);
            return Ok(early_rejection_response(
                400,
                format!("bad request: {err}\n"),
                None,
            ));
        }
    }

    let trusted_proxy_upstream_permit = match maybe_trusted_proxy_request_permit(
        &state.trusted_proxy_request_limiter,
        &state.stats,
        client_ip,
        peer_addr.ip(),
    ) {
        Ok(permit) => permit,
        Err(response) => return Ok(*response),
    };

    let upstream_permit = match state.request_limiter.try_acquire(client_ip) {
        Ok(permit) => permit,
        Err(_) => {
            Stats::inc(&state.stats.http_upstream_in_flight_rejected);
            return Ok(upstream_overload_response("upstream concurrency limit\n"));
        }
    };
    let upstream_permits =
        RequestConcurrencyPermits::new(upstream_permit, trusted_proxy_upstream_permit);

    let req = req.map(|body| {
        GuardedBody::new(
            body,
            state.cfg.max_body_bytes,
            Duration::from_millis(state.cfg.request_body_idle_timeout_ms),
            state.cfg.request_body_min_rate_bytes_per_second,
            Duration::from_millis(state.cfg.request_body_min_rate_grace_ms),
            TrailerPolicy {
                forward: state.cfg.forward_request_trailers,
                max_headers: state.cfg.max_trailers,
                max_bytes: state.cfg.max_trailer_bytes,
            },
            Arc::clone(&state.stats),
        )
    });

    match timeout(
        Duration::from_millis(state.cfg.upstream_timeout_ms.max(1)),
        state.client.request(req),
    )
    .await
    {
        Ok(Ok(mut resp)) => {
            if let Err(reason) =
                validate_header_lines(resp.headers(), state.cfg.upstream_max_header_line_bytes)
            {
                Stats::inc(&state.stats.http_upstream_header_rejected);
                state.upstream_circuit.record_failure(&path_shape);
                Stats::inc(&state.stats.http_upstream_errors);
                log_limited(
                    &HTTP_UPSTREAM_ERROR_LOG,
                    HOT_PATH_LOG_INTERVAL,
                    |suppressed| {
                        eprintln!("upstream response rejected: {reason}{suppressed}");
                    },
                );
                return Ok(upstream_bad_gateway_response(
                    "upstream response headers too large\n",
                ));
            }
            if let Some(length) = content_length(resp.headers()) {
                if state.cfg.max_upstream_body_bytes > 0
                    && length > state.cfg.max_upstream_body_bytes
                {
                    Stats::inc(&state.stats.http_upstream_body_rejected);
                    state.upstream_circuit.record_failure(&path_shape);
                    Stats::inc(&state.stats.http_upstream_errors);
                    log_limited(
                        &HTTP_UPSTREAM_ERROR_LOG,
                        HOT_PATH_LOG_INTERVAL,
                        |suppressed| {
                            eprintln!("upstream response rejected: body too large{suppressed}");
                        },
                    );
                    return Ok(upstream_bad_gateway_response(
                        "upstream response body too large\n",
                    ));
                }
            }
            state.upstream_circuit.record_success(&path_shape);
            Stats::inc(&state.stats.http_proxied);
            sanitize_upstream_response(&mut resp);
            Ok(resp.map(|body| {
                ResponseGuardBody::new(
                    PermitBody::new(body, upstream_permits),
                    state.cfg.max_upstream_body_bytes,
                    Duration::from_millis(state.cfg.upstream_body_idle_timeout_ms),
                    state.cfg.upstream_body_min_rate_bytes_per_second,
                    Duration::from_millis(state.cfg.upstream_body_min_rate_grace_ms),
                    TrailerPolicy {
                        forward: state.cfg.forward_response_trailers,
                        max_headers: state.cfg.upstream_max_trailers,
                        max_bytes: state.cfg.upstream_max_trailer_bytes,
                    },
                    Arc::clone(&state.stats),
                )
                .boxed()
            }))
        }
        Ok(Err(err)) => {
            if let Some(guard_error) = find_body_guard_error(&err) {
                log_limited(
                    &HTTP_REQUEST_BODY_REJECTED_LOG,
                    HOT_PATH_LOG_INTERVAL,
                    |suppressed| {
                        eprintln!("request body rejected: {guard_error}{suppressed}");
                    },
                );
                return Ok(match guard_error {
                    BodyGuardError::TooLarge => {
                        content_too_large_response("request body too large\n")
                    }
                    BodyGuardError::IdleTimeout => {
                        request_timeout_response("request body timeout\n")
                    }
                    BodyGuardError::TooSlow => request_timeout_response("request body too slow\n"),
                    BodyGuardError::TrailersTooLarge => {
                        request_metadata_too_large_response("request trailers too large\n")
                    }
                });
            }
            if find_hyper_parse_too_large(&err) {
                Stats::inc(&state.stats.http_upstream_header_rejected);
            }
            state.upstream_circuit.record_failure(&path_shape);
            Stats::inc(&state.stats.http_upstream_errors);
            log_limited(
                &HTTP_UPSTREAM_ERROR_LOG,
                HOT_PATH_LOG_INTERVAL,
                |suppressed| {
                    eprintln!("upstream error: {err}{suppressed}");
                },
            );
            Ok(upstream_bad_gateway_response("bad gateway\n"))
        }
        Err(_) => {
            state.upstream_circuit.record_failure(&path_shape);
            Stats::inc(&state.stats.http_upstream_timeouts);
            log_limited(
                &HTTP_UPSTREAM_TIMEOUT_LOG,
                HOT_PATH_LOG_INTERVAL,
                |suppressed| {
                    eprintln!(
                        "upstream timeout after {} ms{}",
                        state.cfg.upstream_timeout_ms.max(1),
                        suppressed
                    );
                },
            );
            Ok(upstream_gateway_timeout_response("gateway timeout\n"))
        }
    }
}

fn content_length(headers: &HeaderMap<HeaderValue>) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn validate_request_framing(
    headers: &HeaderMap<HeaderValue>,
    allow_chunked_request_bodies: bool,
) -> Result<(), &'static str> {
    let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
    let content_length = content_lengths.next();
    if content_lengths.next().is_some() {
        return Err("multiple content-length headers");
    }
    if let Some(value) = content_length {
        let value = value
            .to_str()
            .map_err(|_| "invalid content-length header")?
            .trim();
        if value.is_empty()
            || value.contains(',')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("invalid content-length header");
        }
    }

    let mut transfer_encodings = headers.get_all(TRANSFER_ENCODING).iter();
    let Some(transfer_encoding) = transfer_encodings.next() else {
        return Ok(());
    };
    if content_length.is_some() {
        return Err("ambiguous transfer-encoding and content-length");
    }
    if transfer_encodings.next().is_some() {
        return Err("multiple transfer-encoding headers");
    }
    let value = transfer_encoding
        .to_str()
        .map_err(|_| "invalid transfer-encoding header")?;
    let mut saw_coding = false;
    for coding in value
        .split(',')
        .map(str::trim)
        .filter(|coding| !coding.is_empty())
    {
        if saw_coding || !coding.eq_ignore_ascii_case("chunked") {
            return Err("unsupported transfer-encoding");
        }
        saw_coding = true;
    }
    if !saw_coding {
        return Err("invalid transfer-encoding header");
    }
    if !allow_chunked_request_bodies {
        return Err("chunked request body not allowed");
    }

    Ok(())
}

fn validate_request_content_encoding(
    headers: &HeaderMap<HeaderValue>,
    allow_compressed_request_bodies: bool,
) -> Result<(), &'static str> {
    let mut saw_coding = false;
    let mut saw_header = false;
    for value in headers.get_all(CONTENT_ENCODING).iter() {
        saw_header = true;
        let value = value
            .to_str()
            .map_err(|_| "invalid request content-encoding")?;
        for coding in value.split(',').map(str::trim) {
            if coding.is_empty() {
                continue;
            }
            saw_coding = true;
            if !allow_compressed_request_bodies && !coding.eq_ignore_ascii_case("identity") {
                return Err("unsupported request content-encoding");
            }
        }
    }

    if !saw_header {
        return Ok(());
    }
    if saw_coding {
        Ok(())
    } else {
        Err("invalid request content-encoding")
    }
}

fn validate_request_expect(
    headers: &HeaderMap<HeaderValue>,
    allow_expect_continue: bool,
) -> Result<(), &'static str> {
    let mut expects = headers.get_all(EXPECT).iter();
    let Some(first_expect) = expects.next() else {
        return Ok(());
    };
    if !allow_expect_continue {
        return Err("expect header not supported");
    }

    let mut saw_expectation = false;
    for value in std::iter::once(first_expect).chain(expects) {
        let value = value.to_str().map_err(|_| "invalid expect header")?;
        for expectation in value.split(',').map(str::trim) {
            if expectation.is_empty() {
                continue;
            }
            saw_expectation = true;
            if !expectation.eq_ignore_ascii_case("100-continue") {
                return Err("unsupported expectation");
            }
        }
    }

    if saw_expectation {
        Ok(())
    } else {
        Err("invalid expect header")
    }
}

fn validate_request_range(
    headers: &HeaderMap<HeaderValue>,
    max_ranges: usize,
) -> Result<(), &'static str> {
    let mut ranges = headers.get_all(RANGE).iter();
    let Some(range) = ranges.next() else {
        return Ok(());
    };
    if ranges.next().is_some() {
        return Err("multiple range headers");
    }

    let value = range.to_str().map_err(|_| "invalid range header")?.trim();
    let Some((unit, specifier)) = value.split_once('=') else {
        return Err("invalid range header");
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return Err("unsupported range unit");
    }
    let specifier = specifier.trim();
    if specifier.is_empty() {
        return Err("invalid range header");
    }

    let mut count = 0usize;
    for range in specifier.split(',').map(str::trim) {
        if range.is_empty() {
            return Err("invalid byte range");
        }
        count += 1;
        if count > max_ranges {
            return Err("too many ranges");
        }
        validate_byte_range(range)?;
    }

    Ok(())
}

fn validate_byte_range(range: &str) -> Result<(), &'static str> {
    let Some((start, end)) = range.split_once('-') else {
        return Err("invalid byte range");
    };
    if start.contains('-') || end.contains('-') || (start.is_empty() && end.is_empty()) {
        return Err("invalid byte range");
    }
    if !start.is_empty() && !start.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid byte range");
    }
    if !end.is_empty() && !end.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid byte range");
    }

    if !start.is_empty() && !end.is_empty() {
        let start = start.parse::<u128>().map_err(|_| "invalid byte range")?;
        let end = end.parse::<u128>().map_err(|_| "invalid byte range")?;
        if end < start {
            return Err("invalid byte range");
        }
    }

    Ok(())
}

fn validate_request_target(uri: &Uri, cfg: &HttpConfig) -> Result<(), &'static str> {
    let mut target_len = uri
        .path_and_query()
        .map(|value| value.as_str().len())
        .unwrap_or_else(|| uri.path().len());
    if let Some(scheme) = uri.scheme_str() {
        target_len = target_len.saturating_add(scheme.len() + 1);
        if uri.authority().is_some() {
            target_len = target_len.saturating_add(2);
        }
    }
    if let Some(authority) = uri.authority() {
        target_len = target_len.saturating_add(authority.as_str().len());
    }
    if cfg.max_uri_bytes > 0 && target_len > cfg.max_uri_bytes {
        return Err("request uri too long");
    }

    if let Some(query) = uri.query() {
        if cfg.max_query_bytes > 0 && query.len() > cfg.max_query_bytes {
            return Err("request query too long");
        }
        if cfg.max_query_pairs > 0
            && !query.is_empty()
            && query.split('&').take(cfg.max_query_pairs + 1).count() > cfg.max_query_pairs
        {
            return Err("too many query parameters");
        }
    }

    if cfg.max_path_segments > 0 {
        let segments = uri
            .path()
            .split('/')
            .filter(|segment| !segment.is_empty())
            .count();
        if segments > cfg.max_path_segments {
            return Err("too many path segments");
        }
    }

    Ok(())
}

fn validate_effective_host(
    uri: &Uri,
    headers: &HeaderMap<HeaderValue>,
    cfg: &HttpConfig,
) -> Result<Option<String>, &'static str> {
    if let Some(scheme) = uri.scheme_str() {
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err("unsupported absolute-form scheme");
        }
        validate_host_header_with_policy(headers, cfg, false)?;
        let Some(authority) = uri.authority() else {
            return Err("invalid absolute-form authority");
        };
        validate_authority(authority, cfg, true)?;
        return Ok(Some(authority.as_str().to_string()));
    }
    validate_host_header_with_policy(headers, cfg, true)
}

#[cfg(test)]
fn validate_host_header(
    headers: &HeaderMap<HeaderValue>,
    cfg: &HttpConfig,
) -> Result<Option<String>, &'static str> {
    validate_host_header_with_policy(headers, cfg, true)
}

fn validate_host_header_with_policy(
    headers: &HeaderMap<HeaderValue>,
    cfg: &HttpConfig,
    enforce_allowed_hosts: bool,
) -> Result<Option<String>, &'static str> {
    let mut values = headers.get_all(HOST).iter();
    let Some(value) = values.next() else {
        return if cfg.require_host_header {
            Err("missing host header")
        } else {
            Ok(None)
        };
    };
    if values.next().is_some() {
        return Err("multiple host headers");
    }

    let host = value.to_str().map_err(|_| "invalid host header")?;
    if host.is_empty() {
        return Err("empty host header");
    }
    if cfg.max_host_bytes > 0 && host.len() > cfg.max_host_bytes {
        return Err("host header too long");
    }
    let authority: Authority = host.parse().map_err(|_| "invalid host header")?;
    validate_authority(&authority, cfg, enforce_allowed_hosts)?;

    Ok(Some(host.to_string()))
}

fn validate_authority(
    authority: &Authority,
    cfg: &HttpConfig,
    enforce_allowed_hosts: bool,
) -> Result<(), &'static str> {
    if cfg.max_host_bytes > 0 && authority.as_str().len() > cfg.max_host_bytes {
        return Err("host header too long");
    }
    if authority.as_str().contains('@') {
        return Err("invalid host header");
    }
    if enforce_allowed_hosts
        && !cfg.allowed_hosts.is_empty()
        && !host_allowed(authority, &cfg.allowed_hosts)
    {
        return Err("host not allowed");
    }
    Ok(())
}

fn host_allowed(authority: &Authority, allowed_hosts: &[String]) -> bool {
    let full = authority.as_str();
    let host = authority.host();
    let unbracketed_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    allowed_hosts.iter().any(|allowed| {
        let allowed = allowed.trim();
        allowed.eq_ignore_ascii_case(full)
            || allowed.eq_ignore_ascii_case(host)
            || allowed.eq_ignore_ascii_case(unbracketed_host)
    })
}

fn method_allowed(method: &Method, cfg: &HttpConfig) -> bool {
    cfg.allowed_methods
        .iter()
        .any(|allowed| allowed == method.as_str())
}

fn validate_method_override_headers(
    headers: &HeaderMap<HeaderValue>,
    allow_override_headers: bool,
) -> Result<(), &'static str> {
    if allow_override_headers {
        return Ok(());
    }
    for name in [
        "x-http-method",
        "x-http-method-override",
        "x-method-override",
    ] {
        if headers.contains_key(name) {
            return Err("method override headers not allowed");
        }
    }
    Ok(())
}

fn method_not_allowed_response(cfg: &HttpConfig) -> Response<ProxyBody> {
    Response::builder()
        .status(405)
        .header("allow", allowed_methods_header(&cfg.allowed_methods))
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body("method not allowed\n"))
        .expect("static method-not-allowed response should build")
}

fn allowed_methods_header(methods: &[String]) -> String {
    methods
        .iter()
        .filter(|method| Method::from_bytes(method.as_bytes()).is_ok())
        .cloned()
        .collect::<Vec<_>>()
        .join(", ")
}

fn rate_limit_response(body: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(429)
        .header("retry-after", GENERATED_RETRY_AFTER_SECONDS)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("static rate-limit response should build")
}

fn connection_request_limit_response(body: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(429)
        .header("retry-after", GENERATED_RETRY_AFTER_SECONDS)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("static connection request limit response should build")
}

fn upstream_overload_response(body: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(503)
        .header("retry-after", GENERATED_RETRY_AFTER_SECONDS)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("static overload response should build")
}

fn upstream_circuit_open_response(body: &'static str) -> Response<ProxyBody> {
    upstream_overload_response(body)
}

fn upstream_bad_gateway_response(body: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(502)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("static bad-gateway response should build")
}

fn upstream_gateway_timeout_response(body: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(504)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("static gateway-timeout response should build")
}

fn request_timeout_response(body: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(408)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("static request-timeout response should build")
}

fn content_too_large_response(body: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(413)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("static content-too-large response should build")
}

fn request_framing_rejected_response(body: impl Into<Bytes>) -> Response<ProxyBody> {
    Response::builder()
        .status(400)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("request-framing rejection response should build")
}

fn unsupported_content_encoding_response(body: impl Into<Bytes>) -> Response<ProxyBody> {
    Response::builder()
        .status(415)
        .header(ACCEPT_ENCODING, "identity")
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("unsupported content-encoding response should build")
}

fn request_target_rejected_response(body: impl Into<Bytes>) -> Response<ProxyBody> {
    Response::builder()
        .status(414)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("request-target rejection response should build")
}

fn request_metadata_too_large_response(body: impl Into<Bytes>) -> Response<ProxyBody> {
    Response::builder()
        .status(431)
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close")
        .body(full_body(body))
        .expect("request-metadata-too-large response should build")
}

fn maybe_rate_limit_response(
    limiter: &RateLimiter,
    stats: &Stats,
    client_ip: IpAddr,
    detector: Option<&AdaptiveDetector>,
    ctx: &RequestContext<'_>,
) -> Option<Response<ProxyBody>> {
    let limit = limiter.check(client_ip);
    if limit.allowed {
        return None;
    }
    Stats::inc(&stats.http_rate_limited);
    if let Some(detector) = detector {
        detector.observe(
            ctx,
            match limit.reason {
                Some(LimitReason::GlobalRate) => "global_rate_limited",
                Some(LimitReason::PerIpRate) => "per_ip_rate_limited",
                _ => "rate_limited",
            },
        );
    }
    Some(rate_limit_response("rate limited\n"))
}

fn maybe_signature_rate_limit_response(
    limiter: &SignatureRateLimiter,
    stats: &Stats,
    detector: Option<&AdaptiveDetector>,
    ctx: &RequestContext<'_>,
) -> Option<Response<ProxyBody>> {
    if limiter.check(&ctx.signature) {
        return None;
    }
    Stats::inc(&stats.http_rate_limited);
    Stats::inc(&stats.http_signature_rate_limited);
    if let Some(detector) = detector {
        detector.observe(ctx, "signature_rate_limited");
    }
    Some(rate_limit_response("signature rate limited\n"))
}

fn maybe_path_shape_rate_limit_response(
    limiter: &PathShapeRateLimiter,
    stats: &Stats,
    detector: Option<&AdaptiveDetector>,
    ctx: &RequestContext<'_>,
    path_shape: &str,
) -> Option<Response<ProxyBody>> {
    if limiter.check(path_shape) {
        return None;
    }
    Stats::inc(&stats.http_rate_limited);
    Stats::inc(&stats.http_path_shape_rate_limited);
    if let Some(detector) = detector {
        detector.observe_with_path_shape(ctx, "path_shape_rate_limited", path_shape);
    }
    Some(rate_limit_response("path shape rate limited\n"))
}

fn maybe_short_token_sibling_rate_limit_response(
    limiter: &ShortTokenSiblingRateLimiter,
    stats: &Stats,
    detector: Option<&AdaptiveDetector>,
    ctx: &RequestContext<'_>,
    short_token_parent: Option<&(String, String)>,
) -> Option<Response<ProxyBody>> {
    let (parent_shape, token) = short_token_parent?;
    if limiter.check(parent_shape, token) {
        return None;
    }
    Stats::inc(&stats.http_rate_limited);
    Stats::inc(&stats.http_path_shape_rate_limited);
    if let Some(detector) = detector {
        detector.observe_with_path_shape(ctx, "path_shape_rate_limited", parent_shape);
    }
    Some(rate_limit_response("path shape rate limited\n"))
}

fn maybe_trusted_proxy_rate_limit_response(
    limiter: &RateLimiter,
    stats: &Stats,
    client_ip: IpAddr,
    peer_ip: IpAddr,
    detector: Option<&AdaptiveDetector>,
    ctx: &RequestContext<'_>,
) -> Option<Response<ProxyBody>> {
    if client_ip == peer_ip {
        return None;
    }
    let limit = limiter.check(peer_ip);
    if limit.allowed {
        return None;
    }
    Stats::inc(&stats.http_rate_limited);
    Stats::inc(&stats.http_trusted_proxy_rate_limited);
    if let Some(detector) = detector {
        detector.observe(ctx, "trusted_proxy_rate_limited");
    }
    Some(rate_limit_response("trusted proxy rate limited\n"))
}

fn maybe_trusted_proxy_request_permit(
    limiter: &Arc<RequestConcurrencyLimiter>,
    stats: &Stats,
    client_ip: IpAddr,
    peer_ip: IpAddr,
) -> Result<Option<RequestConcurrencyPermit>, Box<Response<ProxyBody>>> {
    if client_ip == peer_ip {
        return Ok(None);
    }
    match limiter.try_acquire(peer_ip) {
        Ok(permit) => Ok(Some(permit)),
        Err(_) => {
            Stats::inc(&stats.http_upstream_in_flight_rejected);
            Stats::inc(&stats.http_trusted_proxy_in_flight_rejected);
            Err(Box::new(upstream_overload_response(
                "trusted proxy upstream concurrency limit\n",
            )))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TrailerPolicy {
    forward: bool,
    max_headers: usize,
    max_bytes: usize,
}

fn validate_trailers(
    trailers: &HeaderMap<HeaderValue>,
    policy: TrailerPolicy,
) -> Result<(), &'static str> {
    if policy.max_headers > 0 && trailers.len() > policy.max_headers {
        return Err("too many trailers");
    }
    if policy.max_bytes > 0 && trailer_header_bytes(trailers) > policy.max_bytes {
        return Err("trailers too large");
    }
    Ok(())
}

fn trailer_header_bytes(trailers: &HeaderMap<HeaderValue>) -> usize {
    trailers
        .iter()
        .map(|(name, value)| name.as_str().len().saturating_add(value.as_bytes().len()))
        .sum()
}

#[derive(Debug)]
struct GuardedBody<B> {
    inner: B,
    remaining: Option<u64>,
    idle_timeout: Option<Duration>,
    idle_sleep: Option<Pin<Box<Sleep>>>,
    rate_guard: BodyRateGuard,
    trailer_policy: TrailerPolicy,
    stats: Option<Arc<Stats>>,
}

impl<B> GuardedBody<B> {
    fn new(
        inner: B,
        max_bytes: u64,
        idle_timeout: Duration,
        min_rate_bytes_per_second: u64,
        min_rate_grace: Duration,
        trailer_policy: TrailerPolicy,
        stats: Arc<Stats>,
    ) -> Self {
        Self {
            inner,
            remaining: (max_bytes > 0).then_some(max_bytes),
            idle_timeout: (!idle_timeout.is_zero()).then_some(idle_timeout),
            idle_sleep: None,
            rate_guard: BodyRateGuard::new(min_rate_bytes_per_second, min_rate_grace),
            trailer_policy,
            stats: Some(stats),
        }
    }

    fn record_failure(&mut self, error: BodyGuardError) -> BoxError {
        if let Some(stats) = self.stats.take() {
            match error {
                BodyGuardError::TooLarge => Stats::inc(&stats.http_body_rejected),
                BodyGuardError::IdleTimeout => Stats::inc(&stats.http_body_timeouts),
                BodyGuardError::TooSlow => Stats::inc(&stats.http_body_too_slow),
                BodyGuardError::TrailersTooLarge => {
                    Stats::inc(&stats.http_request_trailers_rejected)
                }
            }
        }
        Box::new(error)
    }
}

impl<B> Body for GuardedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.idle_sleep.is_none() {
            if let Some(idle_timeout) = this.idle_timeout {
                this.idle_sleep = Some(Box::pin(tokio::time::sleep(idle_timeout)));
            }
        }
        this.rate_guard.start();

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.idle_sleep = None;
                if let Some(data) = frame.data_ref() {
                    if let Some(remaining) = &mut this.remaining {
                        let data_len = data.remaining() as u64;
                        if data_len > *remaining {
                            *remaining = 0;
                            return Poll::Ready(Some(Err(
                                this.record_failure(BodyGuardError::TooLarge)
                            )));
                        }
                        *remaining -= data_len;
                    }
                    if !this.rate_guard.record(data.remaining() as u64) {
                        return Poll::Ready(Some(
                            Err(this.record_failure(BodyGuardError::TooSlow)),
                        ));
                    }
                }
                if let Some(trailers) = frame.trailers_ref() {
                    if !this.trailer_policy.forward {
                        if let Some(stats) = &this.stats {
                            Stats::inc(&stats.http_request_trailers_dropped);
                        }
                        return Poll::Ready(None);
                    }
                    if validate_trailers(trailers, this.trailer_policy).is_err() {
                        return Poll::Ready(Some(Err(
                            this.record_failure(BodyGuardError::TrailersTooLarge)
                        )));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                if let Some(sleep) = &mut this.idle_sleep {
                    if sleep.as_mut().poll(cx).is_ready() {
                        this.idle_sleep = None;
                        return Poll::Ready(Some(Err(
                            this.record_failure(BodyGuardError::IdleTimeout)
                        )));
                    }
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.inner.size_hint();
        if let Some(remaining) = self.remaining {
            if hint.lower() >= remaining {
                hint.set_exact(remaining);
            } else if let Some(upper) = hint.upper() {
                hint.set_upper(upper.min(remaining));
            } else {
                hint.set_upper(remaining);
            }
        }
        hint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyGuardError {
    TooLarge,
    IdleTimeout,
    TooSlow,
    TrailersTooLarge,
}

impl fmt::Display for BodyGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("request body length limit exceeded"),
            Self::IdleTimeout => f.write_str("request body idle timeout"),
            Self::TooSlow => f.write_str("request body minimum data rate not met"),
            Self::TrailersTooLarge => f.write_str("request trailers too large"),
        }
    }
}

impl Error for BodyGuardError {}

#[derive(Debug)]
struct ResponseGuardBody<B> {
    inner: B,
    remaining: Option<u64>,
    idle_timeout: Option<Duration>,
    idle_sleep: Option<Pin<Box<Sleep>>>,
    rate_guard: BodyRateGuard,
    trailer_policy: TrailerPolicy,
    stats: Option<Arc<Stats>>,
}

impl<B> ResponseGuardBody<B> {
    fn new(
        inner: B,
        max_bytes: u64,
        idle_timeout: Duration,
        min_rate_bytes_per_second: u64,
        min_rate_grace: Duration,
        trailer_policy: TrailerPolicy,
        stats: Arc<Stats>,
    ) -> Self {
        Self {
            inner,
            remaining: (max_bytes > 0).then_some(max_bytes),
            idle_timeout: (!idle_timeout.is_zero()).then_some(idle_timeout),
            idle_sleep: None,
            rate_guard: BodyRateGuard::new(min_rate_bytes_per_second, min_rate_grace),
            trailer_policy,
            stats: Some(stats),
        }
    }

    fn record_failure(&mut self, error: ResponseBodyGuardError) -> BoxError {
        if let Some(stats) = self.stats.take() {
            match error {
                ResponseBodyGuardError::TooLarge => Stats::inc(&stats.http_upstream_body_rejected),
                ResponseBodyGuardError::IdleTimeout => {
                    Stats::inc(&stats.http_upstream_body_timeouts)
                }
                ResponseBodyGuardError::TooSlow => Stats::inc(&stats.http_upstream_body_too_slow),
                ResponseBodyGuardError::TrailersTooLarge => {
                    Stats::inc(&stats.http_upstream_trailers_rejected)
                }
            }
        }
        Box::new(error)
    }
}

impl<B> Body for ResponseGuardBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.idle_sleep.is_none() {
            if let Some(idle_timeout) = this.idle_timeout {
                this.idle_sleep = Some(Box::pin(tokio::time::sleep(idle_timeout)));
            }
        }
        this.rate_guard.start();

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.idle_sleep = None;
                if let Some(data) = frame.data_ref() {
                    if let Some(remaining) = &mut this.remaining {
                        let data_len = data.remaining() as u64;
                        if data_len > *remaining {
                            *remaining = 0;
                            return Poll::Ready(Some(Err(
                                this.record_failure(ResponseBodyGuardError::TooLarge)
                            )));
                        }
                        *remaining -= data_len;
                    }
                    if !this.rate_guard.record(data.remaining() as u64) {
                        return Poll::Ready(Some(Err(
                            this.record_failure(ResponseBodyGuardError::TooSlow)
                        )));
                    }
                }
                if let Some(trailers) = frame.trailers_ref() {
                    if !this.trailer_policy.forward {
                        if let Some(stats) = &this.stats {
                            Stats::inc(&stats.http_upstream_trailers_dropped);
                        }
                        return Poll::Ready(None);
                    }
                    if validate_trailers(trailers, this.trailer_policy).is_err() {
                        return Poll::Ready(Some(Err(
                            this.record_failure(ResponseBodyGuardError::TrailersTooLarge)
                        )));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                if let Some(sleep) = &mut this.idle_sleep {
                    if sleep.as_mut().poll(cx).is_ready() {
                        this.idle_sleep = None;
                        return Poll::Ready(Some(Err(
                            this.record_failure(ResponseBodyGuardError::IdleTimeout)
                        )));
                    }
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.inner.size_hint();
        if let Some(remaining) = self.remaining {
            if hint.lower() >= remaining {
                hint.set_exact(remaining);
            } else if let Some(upper) = hint.upper() {
                hint.set_upper(upper.min(remaining));
            } else {
                hint.set_upper(remaining);
            }
        }
        hint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseBodyGuardError {
    TooLarge,
    IdleTimeout,
    TooSlow,
    TrailersTooLarge,
}

impl fmt::Display for ResponseBodyGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("upstream response body length limit exceeded"),
            Self::IdleTimeout => f.write_str("upstream response body idle timeout"),
            Self::TooSlow => f.write_str("upstream response body minimum data rate not met"),
            Self::TrailersTooLarge => f.write_str("upstream response trailers too large"),
        }
    }
}

impl Error for ResponseBodyGuardError {}

#[derive(Debug)]
struct DownstreamWriteTimeoutIo<T> {
    inner: T,
    write_timeout: Option<Duration>,
    write_sleep: Option<Pin<Box<Sleep>>>,
    stats: Arc<Stats>,
    timeout_recorded: bool,
}

impl<T> DownstreamWriteTimeoutIo<T> {
    fn new(inner: T, write_timeout: Duration, stats: Arc<Stats>) -> Self {
        Self {
            inner,
            write_timeout: (!write_timeout.is_zero()).then_some(write_timeout),
            write_sleep: None,
            stats,
            timeout_recorded: false,
        }
    }

    fn reset_write_timeout(&mut self) {
        self.write_sleep = None;
    }

    fn poll_write_timeout(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(write_timeout) = self.write_timeout else {
            return Poll::Pending;
        };
        if self.write_sleep.is_none() {
            self.write_sleep = Some(Box::pin(tokio::time::sleep(write_timeout)));
        }
        if let Some(sleep) = &mut self.write_sleep {
            if sleep.as_mut().poll(cx).is_ready() {
                self.write_sleep = None;
                return Poll::Ready(Err(self.timeout_error()));
            }
        }
        Poll::Pending
    }

    fn timeout_error(&mut self) -> io::Error {
        if !self.timeout_recorded {
            self.timeout_recorded = true;
            Stats::inc(&self.stats.http_downstream_write_timeouts);
        }
        io::Error::new(
            io::ErrorKind::TimedOut,
            "downstream write timeout while sending response",
        )
    }
}

impl<T> AsyncRead for DownstreamWriteTimeoutIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for DownstreamWriteTimeoutIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 || buf.is_empty() {
                    this.reset_write_timeout();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => {
                this.reset_write_timeout();
                Poll::Ready(Err(err))
            }
            Poll::Pending => match this.poll_write_timeout(cx) {
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) | Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.reset_write_timeout();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                this.reset_write_timeout();
                Poll::Ready(Err(err))
            }
            Poll::Pending => this.poll_write_timeout(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.reset_write_timeout();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                this.reset_write_timeout();
                Poll::Ready(Err(err))
            }
            Poll::Pending => this.poll_write_timeout(cx),
        }
    }
}

#[derive(Debug)]
struct BodyRateGuard {
    min_bytes_per_second: u64,
    grace: Duration,
    started_at: Option<StdInstant>,
    window_started_at: Option<StdInstant>,
    window_bytes: u64,
    grace_complete: bool,
}

impl BodyRateGuard {
    fn new(min_bytes_per_second: u64, grace: Duration) -> Self {
        Self {
            min_bytes_per_second,
            grace,
            started_at: None,
            window_started_at: None,
            window_bytes: 0,
            grace_complete: false,
        }
    }

    fn start(&mut self) {
        if self.min_bytes_per_second > 0 && self.started_at.is_none() {
            let now = StdInstant::now();
            self.started_at = Some(now);
            self.window_started_at = Some(now);
        }
    }

    fn record(&mut self, bytes: u64) -> bool {
        if self.min_bytes_per_second == 0 {
            return true;
        }
        self.start();
        let now = StdInstant::now();
        let Some(started_at) = self.started_at else {
            return true;
        };
        if !self.grace_complete {
            if now.saturating_duration_since(started_at) <= self.grace {
                return true;
            }
            self.grace_complete = true;
            self.window_started_at = Some(started_at + self.grace);
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes);
        let window_started_at = self.window_started_at.get_or_insert(now);
        let measured = now.saturating_duration_since(*window_started_at);
        let required =
            (self.min_bytes_per_second as u128).saturating_mul(measured.as_nanos()) / 1_000_000_000;
        if (self.window_bytes as u128) >= required {
            self.window_started_at = Some(now);
            self.window_bytes = 0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
struct PermitBody<B> {
    inner: B,
    _permits: RequestConcurrencyPermits,
}

impl<B> PermitBody<B> {
    fn new(inner: B, permits: RequestConcurrencyPermits) -> Self {
        Self {
            inner,
            _permits: permits,
        }
    }
}

#[derive(Debug)]
struct RequestConcurrencyPermits {
    _client: RequestConcurrencyPermit,
    _trusted_proxy: Option<RequestConcurrencyPermit>,
}

impl RequestConcurrencyPermits {
    fn new(
        client: RequestConcurrencyPermit,
        trusted_proxy: Option<RequestConcurrencyPermit>,
    ) -> Self {
        Self {
            _client: client,
            _trusted_proxy: trusted_proxy,
        }
    }
}

impl<B> Body for PermitBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn find_body_guard_error(err: &(dyn Error + 'static)) -> Option<BodyGuardError> {
    let mut current = Some(err);
    while let Some(error) = current {
        if let Some(guard_error) = error.downcast_ref::<BodyGuardError>() {
            return Some(*guard_error);
        }
        current = error.source();
    }
    None
}

fn find_hyper_parse_too_large(err: &(dyn Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(error) = current {
        if let Some(hyper_error) = error.downcast_ref::<HyperError>() {
            if hyper_error.is_parse_too_large() {
                return true;
            }
        }
        current = error.source();
    }
    false
}

#[derive(Clone, Debug)]
struct ClientIpResolver {
    header: HeaderName,
    trusted_proxies: Arc<Vec<IpRange>>,
    max_forwarded_for_bytes: usize,
    max_forwarded_for_hops: usize,
}

impl ClientIpResolver {
    fn from_config(cfg: &ClientIpConfig) -> Self {
        let header =
            HeaderName::from_bytes(cfg.header.as_bytes()).expect("validated client_ip header");
        let trusted_proxies = cfg
            .trusted_proxies
            .iter()
            .map(|entry| IpRange::parse(entry).expect("validated trusted proxy range"))
            .collect();
        Self {
            header,
            trusted_proxies: Arc::new(trusted_proxies),
            max_forwarded_for_bytes: cfg.max_forwarded_for_bytes,
            max_forwarded_for_hops: cfg.max_forwarded_for_hops,
        }
    }

    fn resolve(
        &self,
        peer_ip: IpAddr,
        headers: &HeaderMap<HeaderValue>,
    ) -> Result<IpAddr, ClientIpHeaderError> {
        if self.trusted_proxies.is_empty() || !self.is_trusted(peer_ip) {
            return Ok(peer_ip);
        }
        if !self.uses_x_forwarded_for() {
            return self.resolve_singleton_header(peer_ip, headers);
        }
        let mut chain: Vec<IpAddr> = Vec::new();
        let mut saw_header = false;
        let mut total_bytes = 0usize;
        for value in headers.get_all(&self.header).iter() {
            saw_header = true;
            let value = value.to_str().map_err(|_| ClientIpHeaderError::Invalid)?;
            total_bytes = total_bytes.saturating_add(value.len());
            if self.max_forwarded_for_bytes > 0 && total_bytes > self.max_forwarded_for_bytes {
                return Err(ClientIpHeaderError::TooLong);
            }
            for token in value.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    return Err(ClientIpHeaderError::Invalid);
                }
                if self.max_forwarded_for_hops > 0
                    && chain.len().saturating_add(1) > self.max_forwarded_for_hops
                {
                    return Err(ClientIpHeaderError::TooManyHops);
                }
                let Some(ip) = parse_forwarded_ip_token(token) else {
                    return Err(ClientIpHeaderError::Invalid);
                };
                chain.push(ip);
            }
        }
        if !saw_header {
            return Ok(peer_ip);
        }
        chain.push(peer_ip);
        for ip in chain.iter().rev() {
            if !self.is_trusted(*ip) {
                return Ok(*ip);
            }
        }
        Ok(peer_ip)
    }

    fn resolve_singleton_header(
        &self,
        peer_ip: IpAddr,
        headers: &HeaderMap<HeaderValue>,
    ) -> Result<IpAddr, ClientIpHeaderError> {
        let mut values = headers.get_all(&self.header).iter();
        let Some(value) = values.next() else {
            return Ok(peer_ip);
        };
        if values.next().is_some() {
            return Err(ClientIpHeaderError::Invalid);
        }
        let value = value
            .to_str()
            .map_err(|_| ClientIpHeaderError::Invalid)?
            .trim();
        if value.is_empty() || value.contains(',') {
            return Err(ClientIpHeaderError::Invalid);
        }
        if self.max_forwarded_for_bytes > 0 && value.len() > self.max_forwarded_for_bytes {
            return Err(ClientIpHeaderError::TooLong);
        }
        parse_forwarded_ip_token(value).ok_or(ClientIpHeaderError::Invalid)
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|range| range.contains(ip))
    }

    fn uses_x_forwarded_for(&self) -> bool {
        self.header == HeaderName::from_static("x-forwarded-for")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientIpHeaderError {
    Invalid,
    TooLong,
    TooManyHops,
}

impl fmt::Display for ClientIpHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("invalid forwarded client ip header"),
            Self::TooLong => f.write_str("forwarded client ip header too long"),
            Self::TooManyHops => f.write_str("too many forwarded client ip hops"),
        }
    }
}

#[derive(Clone, Debug)]
enum IpRange {
    V4(u32, u8),
    V6(u128, u8),
}

impl IpRange {
    fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let (ip_raw, prefix_raw) = raw
            .split_once('/')
            .map(|(ip, prefix)| (ip, Some(prefix)))
            .unwrap_or((raw, None));
        let ip: IpAddr = ip_raw
            .parse()
            .map_err(|err| format!("invalid IP address: {err}"))?;
        match ip {
            IpAddr::V4(ip) => {
                let prefix = parse_prefix(prefix_raw, 32)?;
                Ok(Self::V4(u32::from(ip), prefix))
            }
            IpAddr::V6(ip) => {
                let prefix = parse_prefix(prefix_raw, 128)?;
                Ok(Self::V6(u128::from(ip), prefix))
            }
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(network, prefix), IpAddr::V4(ip)) => {
                let mask = prefix_mask_u32(*prefix);
                (u32::from(ip) & mask) == (*network & mask)
            }
            (Self::V6(network, prefix), IpAddr::V6(ip)) => {
                let mask = prefix_mask_u128(*prefix);
                (u128::from(ip) & mask) == (*network & mask)
            }
            _ => false,
        }
    }
}

fn parse_prefix(raw: Option<&str>, max: u8) -> Result<u8, String> {
    let Some(raw) = raw else {
        return Ok(max);
    };
    let prefix = raw
        .parse::<u8>()
        .map_err(|err| format!("invalid prefix: {err}"))?;
    if prefix > max {
        return Err(format!("prefix {prefix} exceeds max {max}"));
    }
    Ok(prefix)
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn parse_forwarded_ip_token(raw: &str) -> Option<IpAddr> {
    let token = raw.trim();
    if token.is_empty() {
        return None;
    }
    if let Some(rest) = token.strip_prefix('[') {
        let (ip, suffix) = rest.split_once(']')?;
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':')?;
            if port.is_empty() || port.parse::<u16>().is_err() {
                return None;
            }
        }
        return ip.parse().ok();
    }
    if let Ok(ip) = token.parse() {
        return Some(ip);
    }
    if token.matches(':').count() == 1 {
        let (host, port) = token.rsplit_once(':')?;
        if port.is_empty() || port.parse::<u16>().is_err() {
            return None;
        }
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(IpAddr::V4(ip));
        }
    }
    token.parse::<Ipv6Addr>().map(IpAddr::V6).ok()
}

fn maybe_admin_response(
    state: &HttpProxyState,
    method: &str,
    path: &str,
    headers: &HeaderMap<HeaderValue>,
) -> Option<Response<ProxyBody>> {
    match admin_endpoint(&state.cfg.admin_path_prefix, method, path)? {
        AdminEndpoint::Health => Some(simple_response(200, "{\"ok\":true}\n", None)),
        AdminEndpoint::Metrics => {
            let Some(expected) = &state.cfg.admin_token else {
                return Some(simple_response(403, "forbidden\n", None));
            };
            if !admin_token_matches(expected, headers) {
                return Some(simple_response(403, "forbidden\n", None));
            }
            let active_filters = state.engine.active_rule_count();
            let adaptive_windows = state.detector.window_stats();
            Some(simple_response(
                200,
                state.stats.render_prometheus(
                    active_filters,
                    state.logger.dropped_events(),
                    adaptive_windows,
                ),
                None,
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminEndpoint {
    Health,
    Metrics,
}

fn admin_endpoint(prefix: &str, method: &str, path: &str) -> Option<AdminEndpoint> {
    if method != "GET" {
        return None;
    }
    let prefix = prefix.trim_end_matches('/');
    if path == format!("{prefix}/health") {
        return Some(AdminEndpoint::Health);
    }
    if path == format!("{prefix}/metrics") {
        return Some(AdminEndpoint::Metrics);
    }
    None
}

fn admin_token_matches(expected: &str, headers: &HeaderMap<HeaderValue>) -> bool {
    let mut values = headers.get_all("x-altura-admin-token").iter();
    let Some(actual) = values.next().map(HeaderValue::as_bytes) else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    constant_time_eq_bounded(expected.as_bytes(), actual, HTTP_ADMIN_TOKEN_MAX_BYTES)
}

fn constant_time_eq_bounded(expected: &[u8], actual: &[u8], max_len: usize) -> bool {
    if expected.len() > max_len {
        return false;
    }
    let mut diff = expected.len() ^ actual.len();
    for idx in 0..max_len {
        let expected_byte = expected.get(idx).copied().unwrap_or(0);
        let actual_byte = actual.get(idx).copied().unwrap_or(0);
        diff |= (expected_byte ^ actual_byte) as usize;
    }
    diff == 0
}

#[derive(Debug, Clone, Copy)]
struct ForwardingContext<'a> {
    original_host: Option<&'a str>,
    client_ip: std::net::IpAddr,
    peer_ip: std::net::IpAddr,
    preserve_host: bool,
    preserve_forwarded_chain: bool,
    forward_accept_encoding: bool,
}

fn rewrite_request(
    req: &mut Request<Incoming>,
    upstream: &Uri,
    forwarding: ForwardingContext<'_>,
    stats: &Stats,
) -> Result<(), BoxError> {
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = upstream.scheme().cloned();
    parts.authority = upstream.authority().cloned();
    let new_path = joined_path_and_query(upstream, req.uri())?;
    parts.path_and_query = Some(new_path);
    *req.uri_mut() = Uri::from_parts(parts)?;

    remove_hop_by_hop_headers(req.headers_mut());
    maybe_strip_accept_encoding(req.headers_mut(), forwarding.forward_accept_encoding, stats);

    if forwarding.preserve_host {
        if let Some(host) = forwarding.original_host {
            req.headers_mut().insert(
                HOST,
                HeaderValue::from_str(host).map_err(|_| "invalid host header")?,
            );
        }
    } else if let Some(authority) = upstream.authority() {
        req.headers_mut().insert(
            HOST,
            HeaderValue::from_str(authority.as_str()).map_err(|_| "invalid upstream host")?,
        );
    }
    append_forwarded_headers(
        req.headers_mut(),
        forwarding.original_host,
        forwarding.client_ip,
        forwarding.peer_ip,
        forwarding.preserve_forwarded_chain,
        stats,
    )?;
    Ok(())
}

fn maybe_strip_accept_encoding(
    headers: &mut HeaderMap<HeaderValue>,
    forward_accept_encoding: bool,
    stats: &Stats,
) {
    if forward_accept_encoding {
        return;
    }
    if headers.remove(ACCEPT_ENCODING).is_some() {
        Stats::inc(&stats.http_accept_encoding_stripped);
    }
}

fn joined_path_and_query(
    upstream: &Uri,
    incoming: &Uri,
) -> Result<http::uri::PathAndQuery, BoxError> {
    let incoming_pq = incoming
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let base = upstream.path().trim_end_matches('/');
    let path = if base.is_empty() || base == "/" {
        incoming_pq.to_string()
    } else {
        format!("{base}{incoming_pq}")
    };
    Ok(http::uri::PathAndQuery::from_maybe_shared(path)?)
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    let mut extra = Vec::new();
    for connection in headers.get_all(http::header::CONNECTION).iter() {
        if let Ok(connection) = connection.to_str() {
            for token in connection.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                    extra.push(name);
                }
            }
        }
    }

    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    for name in extra {
        headers.remove(name);
    }
}

fn sanitize_upstream_response<B>(response: &mut Response<B>) {
    remove_hop_by_hop_headers(response.headers_mut());
}

fn append_forwarded_headers(
    headers: &mut HeaderMap<HeaderValue>,
    original_host: Option<&str>,
    client_ip: std::net::IpAddr,
    peer_ip: std::net::IpAddr,
    preserve_forwarded_chain: bool,
    stats: &Stats,
) -> Result<(), BoxError> {
    let xff = HeaderName::from_static("x-forwarded-for");
    let (had_incoming_xff, incoming_xff) = canonical_x_forwarded_for(headers, &xff);
    let sanitized = sanitize_spoofable_forwarded_headers(headers, preserve_forwarded_chain);
    let next_for = if preserve_forwarded_chain {
        if let Some(existing) = incoming_xff.as_deref() {
            format!("{existing}, {peer_ip}")
        } else {
            peer_ip.to_string()
        }
    } else if client_ip != peer_ip {
        format!("{client_ip}, {peer_ip}")
    } else {
        peer_ip.to_string()
    };
    if sanitized
        || (!preserve_forwarded_chain && had_incoming_xff)
        || (had_incoming_xff && incoming_xff.is_none())
    {
        Stats::inc(&stats.http_forwarded_sanitized);
    }
    headers.insert(xff, HeaderValue::from_str(&next_for)?);
    headers.insert(
        HeaderName::from_static("x-real-ip"),
        HeaderValue::from_str(&client_ip.to_string())?,
    );
    if let Some(host) = original_host {
        headers.insert(
            HeaderName::from_static("x-forwarded-host"),
            HeaderValue::from_str(host)?,
        );
    }
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("http"),
    );
    Ok(())
}

fn canonical_x_forwarded_for(
    headers: &HeaderMap<HeaderValue>,
    name: &HeaderName,
) -> (bool, Option<String>) {
    let mut values = Vec::new();
    let mut had_value = false;
    for value in headers.get_all(name).iter() {
        had_value = true;
        let Ok(value) = value.to_str() else {
            return (true, None);
        };
        let value = value.trim();
        if value.is_empty() {
            return (true, None);
        }
        values.push(value);
    }

    if values.is_empty() {
        (had_value, None)
    } else {
        (had_value, Some(values.join(", ")))
    }
}

fn sanitize_spoofable_forwarded_headers(
    headers: &mut HeaderMap<HeaderValue>,
    preserve_forwarded_chain: bool,
) -> bool {
    let mut removed = false;
    for name in [
        "forwarded",
        "x-forwarded",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-server",
        "x-forwarded-port",
        "x-forwarded-scheme",
        "x-forwarded-prefix",
        "x-forwarded-uri",
        "x-forwarded-path",
        "x-real-ip",
        "x-original-forwarded-for",
        "x-original-host",
        "x-original-url",
        "x-rewrite-url",
        "cf-connecting-ip",
        "true-client-ip",
        "fastly-client-ip",
        "client-ip",
        "x-client-ip",
        "x-cluster-client-ip",
        "x-originating-ip",
        "x-remote-ip",
        "x-remote-addr",
    ] {
        removed |= headers.remove(name).is_some();
    }
    if !preserve_forwarded_chain {
        removed |= headers.remove("x-forwarded-for").is_some();
    }
    removed
}

fn simple_response(
    status: u16,
    body: impl Into<Bytes>,
    header: Option<(&'static str, String)>,
) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close");
    if let Some((name, value)) = header {
        builder = builder.header(name, value);
    }
    builder
        .body(full_body(body))
        .expect("static response should build")
}

fn early_rejection_response(
    status: u16,
    body: impl Into<Bytes>,
    header: Option<(&'static str, String)>,
) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(CACHE_CONTROL, GENERATED_CACHE_CONTROL)
        .header(CONNECTION, "close");
    if let Some((name, value)) = header {
        builder = builder.header(name, value);
    }
    builder
        .body(full_body(body))
        .expect("early rejection response should build")
}

fn full_body(body: impl Into<Bytes>) -> ProxyBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trailer_policy(forward: bool) -> TrailerPolicy {
        TrailerPolicy {
            forward,
            max_headers: 4,
            max_bytes: 128,
        }
    }

    fn assert_retry_after_header(response: &Response<ProxyBody>) {
        assert_eq!(
            response.headers().get("retry-after"),
            Some(&HeaderValue::from_static(GENERATED_RETRY_AFTER_SECONDS))
        );
    }

    fn assert_generated_no_store_header(response: &Response<ProxyBody>) {
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static(GENERATED_CACHE_CONTROL))
        );
    }

    fn assert_connection_close_header(response: &Response<ProxyBody>) {
        assert_eq!(
            response.headers().get(CONNECTION),
            Some(&HeaderValue::from_static("close"))
        );
    }

    #[test]
    fn joins_upstream_base_path() {
        let upstream: Uri = "http://127.0.0.1:9000/base".parse().unwrap();
        let incoming: Uri = "/hello?x=1".parse().unwrap();
        assert_eq!(
            joined_path_and_query(&upstream, &incoming)
                .unwrap()
                .as_str(),
            "/base/hello?x=1"
        );
    }

    #[test]
    fn strips_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("x-test, upgrade"));
        headers.append("connection", HeaderValue::from_static("x-second-hop"));
        headers.insert("x-test", HeaderValue::from_static("1"));
        headers.insert("x-second-hop", HeaderValue::from_static("2"));
        headers.insert("upgrade", HeaderValue::from_static("websocket"));
        remove_hop_by_hop_headers(&mut headers);
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("x-test"));
        assert!(!headers.contains_key("x-second-hop"));
        assert!(!headers.contains_key("upgrade"));
    }

    #[test]
    fn upstream_response_hop_by_hop_headers_are_sanitized() {
        let mut response = Response::builder()
            .status(200)
            .header("connection", "close")
            .header("proxy-connection", "keep-alive")
            .header("keep-alive", "timeout=999")
            .header("te", "trailers")
            .header("trailer", "x-origin-trailer")
            .header("upgrade", "websocket")
            .body(full_body("ok"))
            .unwrap();
        response
            .headers_mut()
            .append("connection", HeaderValue::from_static("x-origin-hop"));
        response
            .headers_mut()
            .insert("x-origin-hop", HeaderValue::from_static("1"));

        sanitize_upstream_response(&mut response);

        assert!(!response.headers().contains_key("connection"));
        assert!(!response.headers().contains_key("proxy-connection"));
        assert!(!response.headers().contains_key("keep-alive"));
        assert!(!response.headers().contains_key("te"));
        assert!(!response.headers().contains_key("trailer"));
        assert!(!response.headers().contains_key("upgrade"));
        assert!(!response.headers().contains_key("x-origin-hop"));
    }

    #[test]
    fn strips_accept_encoding_for_origin_by_default() {
        let stats = Stats::default();
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, br"));

        maybe_strip_accept_encoding(&mut headers, false, &stats);

        assert!(!headers.contains_key(ACCEPT_ENCODING));
        assert_eq!(
            stats.http_accept_encoding_stripped.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn preserves_accept_encoding_when_forwarding_is_enabled() {
        let stats = Stats::default();
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, br"));

        maybe_strip_accept_encoding(&mut headers, true, &stats);

        assert_eq!(headers.get(ACCEPT_ENCODING).unwrap(), "gzip, br");
        assert_eq!(
            stats.http_accept_encoding_stripped.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn client_ip_ignores_forwarded_header_from_untrusted_peer() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "x-forwarded-for".to_string(),
            trusted_proxies: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        });
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        let peer: IpAddr = "198.51.100.20".parse().unwrap();
        assert_eq!(resolver.resolve(peer, &headers).unwrap(), peer);
    }

    #[test]
    fn client_ip_uses_rightmost_non_trusted_forwarded_ip() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "x-forwarded-for".to_string(),
            trusted_proxies: vec!["10.0.0.0/8".to_string(), "192.0.2.10".to_string()],
            ..Default::default()
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.1, 203.0.113.2, 10.1.2.3"),
        );
        let peer: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(
            resolver.resolve(peer, &headers).unwrap(),
            "203.0.113.2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_rejects_oversized_forwarded_header_from_trusted_peer() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "x-forwarded-for".to_string(),
            trusted_proxies: vec!["127.0.0.1/32".to_string()],
            max_forwarded_for_bytes: 16,
            ..Default::default()
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.20"),
        );
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolver.resolve(peer, &headers).unwrap_err(),
            ClientIpHeaderError::TooLong
        );
    }

    #[test]
    fn client_ip_rejects_too_many_forwarded_hops_from_trusted_peer() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "x-forwarded-for".to_string(),
            trusted_proxies: vec!["127.0.0.1/32".to_string()],
            max_forwarded_for_hops: 2,
            ..Default::default()
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.20, 192.0.2.30"),
        );
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolver.resolve(peer, &headers).unwrap_err(),
            ClientIpHeaderError::TooManyHops
        );
    }

    #[test]
    fn client_ip_rejects_malformed_forwarded_header_from_trusted_peer() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "x-forwarded-for".to_string(),
            trusted_proxies: vec!["127.0.0.1/32".to_string()],
            ..Default::default()
        });
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolver.resolve(peer, &headers).unwrap_err(),
            ClientIpHeaderError::Invalid
        );
    }

    #[test]
    fn client_ip_does_not_parse_oversized_forwarded_header_from_untrusted_peer() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "x-forwarded-for".to_string(),
            trusted_proxies: vec!["127.0.0.1/32".to_string()],
            max_forwarded_for_bytes: 8,
            ..Default::default()
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.20"),
        );
        let peer: IpAddr = "198.51.100.20".parse().unwrap();
        assert_eq!(resolver.resolve(peer, &headers).unwrap(), peer);
    }

    #[test]
    fn client_ip_custom_identity_header_is_singleton_for_trusted_peer() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "cf-connecting-ip".to_string(),
            trusted_proxies: vec!["127.0.0.1/32".to_string()],
            max_forwarded_for_bytes: 16,
            ..Default::default()
        });
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let fallback_peer: IpAddr = "198.51.100.20".parse().unwrap();

        assert_eq!(resolver.resolve(peer, &HeaderMap::new()).unwrap(), peer);

        let mut valid = HeaderMap::new();
        valid.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.10"));
        assert_eq!(
            resolver.resolve(peer, &valid).unwrap(),
            "203.0.113.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            resolver.resolve(fallback_peer, &valid).unwrap(),
            fallback_peer
        );

        let mut duplicate = HeaderMap::new();
        duplicate.append("cf-connecting-ip", HeaderValue::from_static("203.0.113.10"));
        duplicate.append("cf-connecting-ip", HeaderValue::from_static("203.0.113.11"));
        assert_eq!(
            resolver.resolve(peer, &duplicate).unwrap_err(),
            ClientIpHeaderError::Invalid
        );

        let mut comma_list = HeaderMap::new();
        comma_list.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("203.0.113.10, 203.0.113.11"),
        );
        assert_eq!(
            resolver.resolve(peer, &comma_list).unwrap_err(),
            ClientIpHeaderError::Invalid
        );

        let mut oversized = HeaderMap::new();
        oversized.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("2001:db8:abcd::1234"),
        );
        assert_eq!(
            resolver.resolve(peer, &oversized).unwrap_err(),
            ClientIpHeaderError::TooLong
        );
    }

    #[test]
    fn forwarded_headers_are_sanitized_for_untrusted_peers() {
        let stats = Stats::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.200"));
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.201"));
        headers.insert("forwarded", HeaderValue::from_static("for=203.0.113.202"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("attacker.example"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("x-forwarded", HeaderValue::from_static("for=203.0.113.203"));
        headers.insert(
            "x-forwarded-server",
            HeaderValue::from_static("edge-attacker"),
        );
        headers.insert("x-forwarded-port", HeaderValue::from_static("443"));
        headers.insert("x-forwarded-scheme", HeaderValue::from_static("https"));
        headers.insert("x-forwarded-prefix", HeaderValue::from_static("/admin"));
        headers.insert("x-forwarded-uri", HeaderValue::from_static("/admin"));
        headers.insert("x-forwarded-path", HeaderValue::from_static("/admin"));
        headers.insert(
            "x-original-forwarded-for",
            HeaderValue::from_static("203.0.113.213"),
        );
        headers.insert(
            "x-original-host",
            HeaderValue::from_static("attacker.local"),
        );
        headers.insert("x-original-url", HeaderValue::from_static("/admin"));
        headers.insert("x-rewrite-url", HeaderValue::from_static("/admin"));
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("203.0.113.204"),
        );
        headers.insert("true-client-ip", HeaderValue::from_static("203.0.113.205"));
        headers.insert(
            "fastly-client-ip",
            HeaderValue::from_static("203.0.113.206"),
        );
        headers.insert("client-ip", HeaderValue::from_static("203.0.113.207"));
        headers.insert("x-client-ip", HeaderValue::from_static("203.0.113.208"));
        headers.insert(
            "x-cluster-client-ip",
            HeaderValue::from_static("203.0.113.209"),
        );
        headers.insert(
            "x-originating-ip",
            HeaderValue::from_static("203.0.113.210"),
        );
        headers.insert("x-remote-ip", HeaderValue::from_static("203.0.113.211"));
        headers.insert("x-remote-addr", HeaderValue::from_static("203.0.113.212"));

        append_forwarded_headers(
            &mut headers,
            Some("good.local"),
            "198.51.100.10".parse().unwrap(),
            "198.51.100.10".parse().unwrap(),
            false,
            &stats,
        )
        .unwrap();

        assert_eq!(headers.get("x-forwarded-for").unwrap(), "198.51.100.10");
        assert_eq!(headers.get("x-real-ip").unwrap(), "198.51.100.10");
        assert_eq!(headers.get("x-forwarded-host").unwrap(), "good.local");
        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "http");
        for name in [
            "forwarded",
            "x-forwarded",
            "x-forwarded-server",
            "x-forwarded-port",
            "x-forwarded-scheme",
            "x-forwarded-prefix",
            "x-forwarded-uri",
            "x-forwarded-path",
            "x-original-forwarded-for",
            "x-original-host",
            "x-original-url",
            "x-rewrite-url",
            "cf-connecting-ip",
            "true-client-ip",
            "fastly-client-ip",
            "client-ip",
            "x-client-ip",
            "x-cluster-client-ip",
            "x-originating-ip",
            "x-remote-ip",
            "x-remote-addr",
        ] {
            assert!(!headers.contains_key(name), "{name} should be stripped");
        }
        assert_eq!(stats.http_forwarded_sanitized.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn forwarded_headers_append_xff_for_trusted_peers() {
        let stats = Stats::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.200"));
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.77"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("203.0.113.201"),
        );
        headers.insert("true-client-ip", HeaderValue::from_static("203.0.113.202"));
        headers.insert(
            "fastly-client-ip",
            HeaderValue::from_static("203.0.113.203"),
        );
        headers.insert("x-client-ip", HeaderValue::from_static("203.0.113.204"));
        headers.insert("x-forwarded", HeaderValue::from_static("for=203.0.113.205"));
        headers.insert("x-forwarded-port", HeaderValue::from_static("443"));
        headers.insert(
            "x-original-forwarded-for",
            HeaderValue::from_static("203.0.113.206"),
        );
        headers.insert("x-original-url", HeaderValue::from_static("/admin"));

        append_forwarded_headers(
            &mut headers,
            Some("good.local"),
            "198.51.100.10".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            true,
            &stats,
        )
        .unwrap();

        assert_eq!(
            headers.get("x-forwarded-for").unwrap(),
            "203.0.113.200, 198.51.100.77, 192.0.2.10"
        );
        assert_eq!(headers.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(headers.get("x-real-ip").unwrap(), "198.51.100.10");
        assert_eq!(headers.get("x-forwarded-host").unwrap(), "good.local");
        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "http");
        for name in [
            "cf-connecting-ip",
            "true-client-ip",
            "fastly-client-ip",
            "x-client-ip",
            "x-forwarded",
            "x-forwarded-port",
            "x-original-forwarded-for",
            "x-original-url",
        ] {
            assert!(!headers.contains_key(name), "{name} should be stripped");
        }
        assert_eq!(stats.http_forwarded_sanitized.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn forwarded_headers_replace_empty_preserved_xff_for_trusted_peers() {
        let stats = Stats::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static(""));

        append_forwarded_headers(
            &mut headers,
            Some("good.local"),
            "198.51.100.10".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            true,
            &stats,
        )
        .unwrap();

        assert_eq!(headers.get("x-forwarded-for").unwrap(), "192.0.2.10");
        assert_eq!(headers.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(stats.http_forwarded_sanitized.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn forwarded_headers_synthesize_xff_from_validated_custom_identity() {
        let stats = Stats::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.200"));
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.77"));
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("203.0.113.203"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        append_forwarded_headers(
            &mut headers,
            Some("good.local"),
            "203.0.113.203".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            false,
            &stats,
        )
        .unwrap();

        assert_eq!(
            headers.get("x-forwarded-for").unwrap(),
            "203.0.113.203, 192.0.2.10"
        );
        assert_eq!(headers.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(headers.get("x-real-ip").unwrap(), "203.0.113.203");
        assert!(!headers.contains_key("cf-connecting-ip"));
        assert_eq!(headers.get("x-forwarded-host").unwrap(), "good.local");
        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "http");
        assert_eq!(stats.http_forwarded_sanitized.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn parses_forwarded_ips_with_ports_and_ipv6_brackets() {
        assert_eq!(
            parse_forwarded_ip_token("198.51.100.7:443"),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(
            parse_forwarded_ip_token("[2001:db8::1]:443"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            parse_forwarded_ip_token("[2001:db8::1]"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(parse_forwarded_ip_token("198.51.100.7:notaport"), None);
        assert_eq!(parse_forwarded_ip_token("198.51.100.7:"), None);
        assert_eq!(parse_forwarded_ip_token("[2001:db8::1]:notaport"), None);
        assert_eq!(parse_forwarded_ip_token("[2001:db8::1]junk"), None);
    }

    #[test]
    fn parses_content_length_header() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        assert_eq!(content_length(&headers), Some(42));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static(" \t42\t "));
        assert_eq!(content_length(&headers), Some(42));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("not-a-number"));
        assert_eq!(content_length(&headers), None);
    }

    #[test]
    fn request_framing_allows_single_content_length_and_opt_in_chunked() {
        let mut content_length_headers = HeaderMap::new();
        content_length_headers.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        let mut chunked_headers = HeaderMap::new();
        chunked_headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));

        assert_eq!(
            validate_request_framing(&content_length_headers, false),
            Ok(())
        );
        assert_eq!(
            validate_request_framing(&chunked_headers, false),
            Err("chunked request body not allowed")
        );
        assert_eq!(validate_request_framing(&chunked_headers, true), Ok(()));
    }

    #[test]
    fn request_framing_rejects_bad_content_length() {
        let mut duplicate = HeaderMap::new();
        duplicate.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        duplicate.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        let mut comma_list = HeaderMap::new();
        comma_list.insert(CONTENT_LENGTH, HeaderValue::from_static("4, 4"));
        let mut invalid = HeaderMap::new();
        invalid.insert(CONTENT_LENGTH, HeaderValue::from_static("nope"));

        assert_eq!(
            validate_request_framing(&duplicate, false),
            Err("multiple content-length headers")
        );
        assert_eq!(
            validate_request_framing(&comma_list, false),
            Err("invalid content-length header")
        );
        assert_eq!(
            validate_request_framing(&invalid, false),
            Err("invalid content-length header")
        );
    }

    #[test]
    fn request_framing_rejects_ambiguous_or_bad_transfer_encoding() {
        let mut te_and_cl = HeaderMap::new();
        te_and_cl.insert(CONTENT_LENGTH, HeaderValue::from_static("4"));
        te_and_cl.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        let mut duplicate_te = HeaderMap::new();
        duplicate_te.append(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        duplicate_te.append(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        let mut unsupported = HeaderMap::new();
        unsupported.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip"));
        let mut extra_coding = HeaderMap::new();
        extra_coding.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));

        assert_eq!(
            validate_request_framing(&te_and_cl, true),
            Err("ambiguous transfer-encoding and content-length")
        );
        assert_eq!(
            validate_request_framing(&duplicate_te, true),
            Err("multiple transfer-encoding headers")
        );
        assert_eq!(
            validate_request_framing(&unsupported, true),
            Err("unsupported transfer-encoding")
        );
        assert_eq!(
            validate_request_framing(&extra_coding, true),
            Err("unsupported transfer-encoding")
        );
    }

    #[test]
    fn request_framing_rejects_transfer_encoding_comma_spray() {
        let comma_spray = std::iter::repeat_n("gzip", 64)
            .collect::<Vec<_>>()
            .join(", ");
        let mut unsupported = HeaderMap::new();
        unsupported.insert(
            TRANSFER_ENCODING,
            HeaderValue::from_bytes(comma_spray.as_bytes()).unwrap(),
        );

        assert_eq!(
            validate_request_framing(&unsupported, true),
            Err("unsupported transfer-encoding")
        );

        let empty_spray = ", ".repeat(64);
        let mut invalid = HeaderMap::new();
        invalid.insert(
            TRANSFER_ENCODING,
            HeaderValue::from_bytes(empty_spray.as_bytes()).unwrap(),
        );

        assert_eq!(
            validate_request_framing(&invalid, true),
            Err("invalid transfer-encoding header")
        );
    }

    #[test]
    fn request_content_encoding_rejects_compressed_by_default() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

        assert_eq!(
            validate_request_content_encoding(&headers, false),
            Err("unsupported request content-encoding")
        );
    }

    #[test]
    fn request_content_encoding_allows_identity_by_default() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));

        assert_eq!(validate_request_content_encoding(&headers, false), Ok(()));
    }

    #[test]
    fn request_content_encoding_allows_compressed_when_opted_in() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("br, gzip"));

        assert_eq!(validate_request_content_encoding(&headers, true), Ok(()));
    }

    #[test]
    fn request_expect_allows_absent_header_by_default() {
        assert_eq!(validate_request_expect(&HeaderMap::new(), false), Ok(()));
    }

    #[test]
    fn request_expect_rejects_100_continue_by_default() {
        let mut headers = HeaderMap::new();
        headers.insert(EXPECT, HeaderValue::from_static("100-continue"));

        assert_eq!(
            validate_request_expect(&headers, false),
            Err("expect header not supported")
        );
    }

    #[test]
    fn request_expect_allows_100_continue_when_opted_in() {
        for value in ["100-continue", "100-CONTINUE", "100-continue, 100-continue"] {
            let mut headers = HeaderMap::new();
            headers.insert(EXPECT, HeaderValue::from_static(value));

            assert_eq!(validate_request_expect(&headers, true), Ok(()), "{value}");
        }
    }

    #[test]
    fn request_expect_rejects_unsupported_values_when_opted_in() {
        for (value, reason) in [
            ("", "invalid expect header"),
            ("wait-for-magic", "unsupported expectation"),
            ("100-continue, wait-for-magic", "unsupported expectation"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(EXPECT, HeaderValue::from_static(value));

            assert_eq!(
                validate_request_expect(&headers, true),
                Err(reason),
                "{value}"
            );
        }
    }

    #[test]
    fn request_range_allows_single_byte_range_by_default() {
        for value in ["bytes=0-499", "bytes=500-", "bytes=-500", "BYTES=0-0"] {
            let mut headers = HeaderMap::new();
            headers.insert(RANGE, HeaderValue::from_static(value));

            assert_eq!(validate_request_range(&headers, 1), Ok(()), "{value}");
        }
    }

    #[test]
    fn request_range_rejects_multiple_ranges_by_default() {
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, HeaderValue::from_static("bytes=0-0, 2-2"));

        assert_eq!(validate_request_range(&headers, 1), Err("too many ranges"));
    }

    #[test]
    fn request_range_accepts_custom_range_cap() {
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, HeaderValue::from_static("bytes=0-0, 2-2"));

        assert_eq!(validate_request_range(&headers, 2), Ok(()));
    }

    #[test]
    fn request_range_rejects_bad_syntax_and_unit() {
        for (value, reason) in [
            ("items=0-1", "unsupported range unit"),
            ("bytes=", "invalid range header"),
            ("bytes=abc", "invalid byte range"),
            ("bytes=-", "invalid byte range"),
            ("bytes=10-1", "invalid byte range"),
            ("bytes=0-1,", "invalid byte range"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(RANGE, HeaderValue::from_static(value));

            assert_eq!(validate_request_range(&headers, 1), Err(reason), "{value}");
        }
    }

    #[test]
    fn request_range_rejects_multiple_range_headers() {
        let mut headers = HeaderMap::new();
        headers.append(RANGE, HeaderValue::from_static("bytes=0-0"));
        headers.append(RANGE, HeaderValue::from_static("bytes=2-2"));

        assert_eq!(
            validate_request_range(&headers, 2),
            Err("multiple range headers")
        );
    }

    #[test]
    fn request_range_guard_fails_closed_when_capacity_is_zero() {
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, HeaderValue::from_static("bytes=0-0"));

        assert_eq!(validate_request_range(&headers, 0), Err("too many ranges"));
    }

    #[test]
    fn raw_initial_framing_precheck_allows_valid_content_length_and_opt_in_chunked() {
        assert_eq!(
            validate_raw_http1_header_block(
                b"POST /drain HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n",
                false
            ),
            Ok(())
        );
        assert_eq!(
            validate_raw_http1_header_block(
                b"POST /drain HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
                false
            ),
            Err("chunked request body not allowed")
        );
        assert_eq!(
            validate_raw_http1_header_block(
                b"POST /drain HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
                true
            ),
            Ok(())
        );
    }

    #[test]
    fn raw_initial_framing_precheck_rejects_smuggling_ambiguity() {
        assert_eq!(
            validate_raw_http1_header_block(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                false
            ),
            Err("multiple content-length headers")
        );
        assert_eq!(
            validate_raw_http1_header_block(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
                false
            ),
            Err("ambiguous transfer-encoding and content-length")
        );
        assert_eq!(
            validate_raw_http1_header_block(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nX-Test: ok\r\n Content-Length: 0\r\n\r\n",
                false
            ),
            Err("obsolete folded header line")
        );
        assert_eq!(
            validate_raw_http1_header_block(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                true
            ),
            Err("unsupported transfer-encoding")
        );
    }

    #[test]
    fn raw_initial_framing_precheck_rejects_transfer_encoding_comma_spray() {
        let comma_spray = std::iter::repeat_n("gzip", 64)
            .collect::<Vec<_>>()
            .join(", ");
        let block = format!(
            "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: {comma_spray}\r\n\r\n"
        );

        assert_eq!(
            validate_raw_http1_header_block(block.as_bytes(), true),
            Err("unsupported transfer-encoding")
        );

        let empty_spray = ", ".repeat(64);
        let block = format!(
            "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: {empty_spray}\r\n\r\n"
        );

        assert_eq!(
            validate_raw_http1_header_block(block.as_bytes(), true),
            Err("invalid transfer-encoding header")
        );
    }

    #[test]
    fn raw_initial_header_count_detects_configured_cap() {
        let block =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n";

        assert_eq!(raw_http1_header_count(block), 3);
        assert!(!raw_http1_header_count_exceeds(block, 3));
        assert!(raw_http1_header_count_exceeds(block, 2));
        assert!(!raw_http1_header_count_exceeds(block, 0));
    }

    #[test]
    fn raw_initial_header_line_detects_configured_cap() {
        let block =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: 1234567890\r\nAccept: */*\r\n\r\n";

        assert!(!raw_http1_header_line_exceeds(block, 17));
        assert!(raw_http1_header_line_exceeds(block, 16));
        assert!(!raw_http1_header_line_exceeds(block, 0));
    }

    #[test]
    fn parsed_header_line_guard_detects_configured_cap() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("example.com"));
        headers.insert("x-big", HeaderValue::from_static("1234567890"));

        assert_eq!(validate_header_lines(&headers, 17), Ok(()));
        assert_eq!(
            validate_header_lines(&headers, 16),
            Err("header field too large")
        );
        assert_eq!(validate_header_lines(&headers, 0), Ok(()));
    }

    #[test]
    fn initial_header_end_search_finds_delimiter_from_overlap_window() {
        let block =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n";
        let delimiter_start = block.len() - 4;
        let previous_len = delimiter_start + 2;
        let overlap_start = previous_len.saturating_sub(3);

        assert_eq!(find_header_end_from(block, 0), Some(block.len()));
        assert_eq!(
            find_header_end_from(block, overlap_start),
            Some(block.len())
        );
        assert_eq!(find_header_end_from(block, delimiter_start + 1), None);
    }

    #[test]
    fn raw_initial_request_target_guard_matches_uri_caps() {
        let limits = RawRequestTargetLimits {
            max_uri_bytes: 16,
            max_query_bytes: 8,
            max_query_pairs: 2,
            max_path_segments: 3,
        };

        assert_eq!(
            validate_raw_request_target(
                b"GET /api/catalog/42?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                limits
            ),
            Err("request uri too long")
        );
        assert_eq!(
            validate_raw_request_target(
                b"GET /ok?x=123456789 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                limits
            ),
            Err("request query too long")
        );
        assert_eq!(
            validate_raw_request_target(
                b"GET /ok?a=&b=&c= HTTP/1.1\r\nHost: example.com\r\n\r\n",
                limits
            ),
            Err("too many query parameters")
        );
        assert_eq!(
            validate_raw_request_target(
                b"GET /a/b/c/d HTTP/1.1\r\nHost: example.com\r\n\r\n",
                limits
            ),
            Err("too many path segments")
        );
    }

    #[test]
    fn raw_initial_request_target_guard_handles_absolute_form() {
        let limits = RawRequestTargetLimits {
            max_uri_bytes: 128,
            max_query_bytes: 8,
            max_query_pairs: 2,
            max_path_segments: 3,
        };

        assert_eq!(
            validate_raw_request_target(
                b"GET http://example.com/ok?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                limits
            ),
            Ok(())
        );
        assert_eq!(
            validate_raw_request_target(
                b"GET http://example.com/a/b/c/d HTTP/1.1\r\nHost: example.com\r\n\r\n",
                limits
            ),
            Err("too many path segments")
        );
        assert_eq!(
            validate_raw_request_target(
                b"GET http://example.com/ok?x=123456789 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                limits
            ),
            Err("request query too long")
        );
    }

    #[tokio::test]
    async fn initial_bad_request_response_is_not_stored_and_closes() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            write_initial_bad_request_response(stream, "obsolete folded header line")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut received = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();

        let response = String::from_utf8(received).unwrap();
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("Connection: close\r\n"));
        assert!(response.ends_with("obsolete folded header line\n"));
    }

    #[tokio::test]
    async fn initial_header_too_large_response_is_431_not_stored_and_closes() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            write_initial_header_too_large_response(stream)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut received = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();

        let response = String::from_utf8(received).unwrap();
        assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("Connection: close\r\n"));
        assert!(response.ends_with("request header fields too large\n"));
    }

    #[tokio::test]
    async fn initial_request_timeout_response_is_408_not_stored_and_closes() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            write_initial_request_timeout_response(stream)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut received = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();

        let response = String::from_utf8(received).unwrap();
        assert!(response.starts_with("HTTP/1.1 408 Request Timeout\r\n"));
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("Connection: close\r\n"));
        assert!(response.ends_with("request timeout\n"));
    }

    #[tokio::test]
    async fn initial_request_target_rejected_response_is_414_not_stored_and_closes() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            write_initial_request_target_rejected_response(stream, "request uri too long")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut received = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();

        let response = String::from_utf8(received).unwrap();
        assert!(response.starts_with("HTTP/1.1 414 URI Too Long\r\n"));
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("Connection: close\r\n"));
        assert!(response.ends_with("request uri too long\n"));
    }

    #[tokio::test]
    async fn initial_precheck_rejects_header_end_after_configured_byte_cap() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            prevalidate_initial_http1_request(
                stream,
                32,
                32,
                16,
                RawRequestTargetLimits {
                    max_uri_bytes: 1024,
                    max_query_bytes: 1024,
                    max_query_pairs: 64,
                    max_path_segments: 64,
                },
                Duration::from_secs(1),
                false,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let result = timeout(Duration::from_secs(1), server)
            .await
            .expect("precheck should return before outer timeout")
            .expect("precheck task should not panic");

        assert!(matches!(
            result,
            Err(InitialRequestPrecheckError::HeaderTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn initial_precheck_rejects_header_line_after_configured_byte_cap() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            prevalidate_initial_http1_request(
                stream,
                1024,
                24,
                16,
                RawRequestTargetLimits {
                    max_uri_bytes: 1024,
                    max_query_bytes: 1024,
                    max_query_pairs: 64,
                    max_path_segments: 64,
                },
                Duration::from_secs(1),
                false,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: 123456789012345678901234\r\n\r\n",
            )
            .await
            .unwrap();

        let result = timeout(Duration::from_secs(1), server)
            .await
            .expect("precheck should return before outer timeout")
            .expect("precheck task should not panic");

        assert!(matches!(
            result,
            Err(InitialRequestPrecheckError::HeaderTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn downstream_keep_alive_disabled_closes_before_second_request() {
        let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_hits = Arc::new(AtomicU64::new(0));
        let upstream_hits_for_task = Arc::clone(&upstream_hits);
        let upstream_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = upstream_listener.accept().await else {
                    break;
                };
                let upstream_hits = Arc::clone(&upstream_hits_for_task);
                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let mut scratch = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut scratch).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        received.extend_from_slice(&scratch[..read]);
                        if find_header_end(&received).is_some() {
                            break;
                        }
                    }
                    upstream_hits.fetch_add(1, Ordering::Relaxed);
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                        )
                        .await;
                });
            }
        });

        let proxy_port = unused_tcp_port();
        let temp_suffix = format!("{}-{}", std::process::id(), upstream_addr.port());
        let filter_file =
            std::env::temp_dir().join(format!("altura-prot-keepalive-{temp_suffix}.json"));
        let event_file =
            std::env::temp_dir().join(format!("altura-prot-keepalive-{temp_suffix}.jsonl"));
        std::fs::write(&filter_file, r#"{"filters":[]}"#).unwrap();
        let engine =
            FilterEngine::new(Vec::new(), filter_file.clone(), Duration::from_secs(60)).await;
        let logger = Arc::new(crate::telemetry::EventLogger::new(&event_file).unwrap());
        let detector = AdaptiveDetector::new(
            crate::adaptive::AdaptiveDetectorConfig {
                enabled: false,
                threshold_per_second: 1_000_000,
                activation_ttl: Duration::from_secs(60),
                event_cooldown: Duration::from_secs(1),
                max_signature_windows: 8_192,
                max_path_shape_windows: 8_192,
            },
            Arc::clone(&engine),
            Arc::clone(&logger),
        );
        let stats = Arc::new(Stats::default());
        let cfg = test_http_config(&format!(
            r#"{{
                "listen":"127.0.0.1:{proxy_port}",
                "upstream":"http://{upstream_addr}",
                "downstream_keep_alive":false
            }}"#
        ));
        let (startup_tx, startup_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut proxy_task = tokio::spawn(run_http_proxy(
            cfg,
            engine,
            detector,
            stats,
            logger,
            Some(startup_tx),
            shutdown_rx,
        ));
        startup_rx.await.unwrap().unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
            .await
            .unwrap();
        let first = read_test_response(&mut stream).await;
        assert!(first.starts_with(b"HTTP/1.1 204 No Content"));
        assert_eq!(upstream_hits.load(Ordering::Relaxed), 1);

        let second_write = stream
            .write_all(b"GET /second HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await;
        if second_write.is_ok() {
            let mut buf = [0_u8; 256];
            let second_read = timeout(Duration::from_secs(1), stream.read(&mut buf)).await;
            let closed_without_response = match second_read {
                Ok(Ok(0)) => true,
                Ok(Err(ref err)) => matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ),
                _ => false,
            };
            assert!(
                closed_without_response,
                "unexpected second response: {second_read:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(upstream_hits.load(Ordering::Relaxed), 1);

        let _ = shutdown_tx.send(true);
        if timeout(Duration::from_secs(1), &mut proxy_task)
            .await
            .is_err()
        {
            proxy_task.abort();
            panic!("proxy task did not stop before test timeout");
        }
        upstream_task.abort();
        let _ = std::fs::remove_file(filter_file);
        let _ = std::fs::remove_file(event_file);
    }

    #[tokio::test]
    async fn upstream_declared_oversized_body_is_rejected_before_success() {
        let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let Ok((mut stream, _)) = upstream_listener.accept().await else {
                return;
            };
            let mut received = Vec::new();
            let mut scratch = [0_u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut scratch).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                received.extend_from_slice(&scratch[..read]);
                if find_header_end(&received).is_some() {
                    break;
                }
            }
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: \t128 \r\nConnection: close\r\n\r\noversized",
                )
                .await;
        });

        let proxy_port = unused_tcp_port();
        let temp_suffix = format!("{}-{}", std::process::id(), upstream_addr.port());
        let filter_file =
            std::env::temp_dir().join(format!("altura-prot-upstream-size-{temp_suffix}.json"));
        let event_file =
            std::env::temp_dir().join(format!("altura-prot-upstream-size-{temp_suffix}.jsonl"));
        std::fs::write(&filter_file, r#"{"filters":[]}"#).unwrap();
        let engine =
            FilterEngine::new(Vec::new(), filter_file.clone(), Duration::from_secs(60)).await;
        let logger = Arc::new(crate::telemetry::EventLogger::new(&event_file).unwrap());
        let detector = AdaptiveDetector::new(
            crate::adaptive::AdaptiveDetectorConfig {
                enabled: false,
                threshold_per_second: 1_000_000,
                activation_ttl: Duration::from_secs(60),
                event_cooldown: Duration::from_secs(1),
                max_signature_windows: 8_192,
                max_path_shape_windows: 8_192,
            },
            Arc::clone(&engine),
            Arc::clone(&logger),
        );
        let stats = Arc::new(Stats::default());
        let cfg = test_http_config(&format!(
            r#"{{
                "listen":"127.0.0.1:{proxy_port}",
                "upstream":"http://{upstream_addr}",
                "max_upstream_body_bytes":16
            }}"#
        ));
        let (startup_tx, startup_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut proxy_task = tokio::spawn(run_http_proxy(
            cfg,
            engine,
            detector,
            Arc::clone(&stats),
            logger,
            Some(startup_tx),
            shutdown_rx,
        ));
        startup_rx.await.unwrap().unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        stream
            .write_all(b"GET /large HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let response = read_test_response(&mut stream).await;
        assert!(
            response.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "unexpected response: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"upstream response body too large\n"));
        assert_eq!(stats.http_proxied.load(Ordering::Relaxed), 0);
        assert_eq!(stats.http_upstream_body_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(stats.http_upstream_errors.load(Ordering::Relaxed), 1);

        let _ = shutdown_tx.send(true);
        if timeout(Duration::from_secs(1), &mut proxy_task)
            .await
            .is_err()
        {
            proxy_task.abort();
            panic!("proxy task did not stop before test timeout");
        }
        upstream_task.abort();
        let _ = std::fs::remove_file(filter_file);
        let _ = std::fs::remove_file(event_file);
    }

    #[tokio::test]
    async fn request_declared_oversized_body_with_ows_is_rejected_before_upstream() {
        let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_hits = Arc::new(AtomicU64::new(0));
        let upstream_hits_for_task = Arc::clone(&upstream_hits);
        let upstream_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = upstream_listener.accept().await else {
                    break;
                };
                upstream_hits_for_task.fetch_add(1, Ordering::Relaxed);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });

        let proxy_port = unused_tcp_port();
        let temp_suffix = format!("{}-{}", std::process::id(), upstream_addr.port());
        let filter_file =
            std::env::temp_dir().join(format!("altura-prot-request-size-{temp_suffix}.json"));
        let event_file =
            std::env::temp_dir().join(format!("altura-prot-request-size-{temp_suffix}.jsonl"));
        std::fs::write(&filter_file, r#"{"filters":[]}"#).unwrap();
        let engine =
            FilterEngine::new(Vec::new(), filter_file.clone(), Duration::from_secs(60)).await;
        let logger = Arc::new(crate::telemetry::EventLogger::new(&event_file).unwrap());
        let detector = AdaptiveDetector::new(
            crate::adaptive::AdaptiveDetectorConfig {
                enabled: false,
                threshold_per_second: 1_000_000,
                activation_ttl: Duration::from_secs(60),
                event_cooldown: Duration::from_secs(1),
                max_signature_windows: 8_192,
                max_path_shape_windows: 8_192,
            },
            Arc::clone(&engine),
            Arc::clone(&logger),
        );
        let stats = Arc::new(Stats::default());
        let cfg = test_http_config(&format!(
            r#"{{
                "listen":"127.0.0.1:{proxy_port}",
                "upstream":"http://{upstream_addr}",
                "max_body_bytes":16
            }}"#
        ));
        let (startup_tx, startup_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut proxy_task = tokio::spawn(run_http_proxy(
            cfg,
            engine,
            detector,
            Arc::clone(&stats),
            logger,
            Some(startup_tx),
            shutdown_rx,
        ));
        startup_rx.await.unwrap().unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        stream
            .write_all(
                b"POST /large HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: \t32 \r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_test_response(&mut stream).await;
        assert!(
            response.starts_with(b"HTTP/1.1 413 Payload Too Large"),
            "unexpected response: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"request body too large\n"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(upstream_hits.load(Ordering::Relaxed), 0);
        assert_eq!(stats.http_body_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(stats.http_proxied.load(Ordering::Relaxed), 0);

        let _ = shutdown_tx.send(true);
        if timeout(Duration::from_secs(1), &mut proxy_task)
            .await
            .is_err()
        {
            proxy_task.abort();
            panic!("proxy task did not stop before test timeout");
        }
        upstream_task.abort();
        let _ = std::fs::remove_file(filter_file);
        let _ = std::fs::remove_file(event_file);
    }

    #[tokio::test]
    async fn rate_limit_denial_precedes_filter_evaluation() {
        let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_hits = Arc::new(AtomicU64::new(0));
        let upstream_hits_for_task = Arc::clone(&upstream_hits);
        let upstream_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = upstream_listener.accept().await else {
                    break;
                };
                let upstream_hits = Arc::clone(&upstream_hits_for_task);
                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let mut scratch = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut scratch).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        received.extend_from_slice(&scratch[..read]);
                        if find_header_end(&received).is_some() {
                            break;
                        }
                    }
                    upstream_hits.fetch_add(1, Ordering::Relaxed);
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });

        let proxy_port = unused_tcp_port();
        let temp_suffix = format!("{}-{}", std::process::id(), upstream_addr.port());
        let filter_file =
            std::env::temp_dir().join(format!("altura-prot-rate-filter-order-{temp_suffix}.json"));
        let event_file =
            std::env::temp_dir().join(format!("altura-prot-rate-filter-order-{temp_suffix}.jsonl"));
        std::fs::write(&filter_file, r#"{"filters":[]}"#).unwrap();
        let engine = FilterEngine::new(
            vec![crate::filter::FilterRule {
                id: "rate-limit-before-filter".to_string(),
                enabled: true,
                adaptive: false,
                priority: 100,
                ttl_seconds: None,
                expires_at_unix_ms: None,
                condition: crate::filter::FilterCondition {
                    path_exact: Some("/filter-before-rate-limit".to_string()),
                    ..Default::default()
                },
                action: crate::filter::FilterAction {
                    kind: "block".to_string(),
                    status: 403,
                    body: "blocked\n".to_string(),
                },
            }],
            filter_file.clone(),
            Duration::from_secs(60),
        )
        .await;
        let logger = Arc::new(crate::telemetry::EventLogger::new(&event_file).unwrap());
        let detector = AdaptiveDetector::new(
            crate::adaptive::AdaptiveDetectorConfig {
                enabled: false,
                threshold_per_second: 1_000_000,
                activation_ttl: Duration::from_secs(60),
                event_cooldown: Duration::from_secs(1),
                max_signature_windows: 8_192,
                max_path_shape_windows: 8_192,
            },
            Arc::clone(&engine),
            Arc::clone(&logger),
        );
        let stats = Arc::new(Stats::default());
        let cfg = test_http_config(&format!(
            r#"{{
                "listen":"127.0.0.1:{proxy_port}",
                "upstream":"http://{upstream_addr}",
                "limits":{{
                    "per_ip_rps":0.000001,
                    "per_ip_burst":1,
                    "global_rps":1000000,
                    "global_burst":1000000,
                    "signature_rps":1000000,
                    "signature_burst":1000000,
                    "path_shape_rps":1000000,
                    "path_shape_burst":1000000,
                    "max_connections":128,
                    "max_connections_per_ip":128,
                    "max_in_flight_requests":128,
                    "max_in_flight_requests_per_ip":128,
                    "max_tracked_ips":1024
                }}
            }}"#
        ));
        let (startup_tx, startup_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut proxy_task = tokio::spawn(run_http_proxy(
            cfg,
            engine,
            detector,
            Arc::clone(&stats),
            logger,
            Some(startup_tx),
            shutdown_rx,
        ));
        startup_rx.await.unwrap().unwrap();

        let mut first_stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        first_stream
            .write_all(b"GET /rate-prime HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let first = read_test_response(&mut first_stream).await;
        assert!(first.starts_with(b"HTTP/1.1 204 No Content"));
        assert_eq!(upstream_hits.load(Ordering::Relaxed), 1);

        let mut second_stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        second_stream
            .write_all(
                b"GET /filter-before-rate-limit HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let second = read_test_response(&mut second_stream).await;
        assert!(
            second.starts_with(b"HTTP/1.1 429 Too Many Requests"),
            "unexpected response: {}",
            String::from_utf8_lossy(&second)
        );
        assert_eq!(upstream_hits.load(Ordering::Relaxed), 1);
        assert_eq!(stats.http_rate_limited.load(Ordering::Relaxed), 1);
        assert_eq!(stats.http_blocked.load(Ordering::Relaxed), 0);

        let _ = shutdown_tx.send(true);
        if timeout(Duration::from_secs(1), &mut proxy_task)
            .await
            .is_err()
        {
            proxy_task.abort();
            panic!("proxy task did not stop before test timeout");
        }
        upstream_task.abort();
        let _ = std::fs::remove_file(filter_file);
        let _ = std::fs::remove_file(event_file);
    }

    #[test]
    fn host_guard_allows_single_valid_host() {
        let cfg = test_http_config("{}");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("Example.COM:8443"));

        assert_eq!(
            validate_host_header(&headers, &cfg),
            Ok(Some("Example.COM:8443".to_string()))
        );
    }

    #[test]
    fn host_guard_rejects_missing_duplicate_invalid_and_long_hosts() {
        let cfg = test_http_config("{}");
        let mut duplicate = HeaderMap::new();
        duplicate.append(HOST, HeaderValue::from_static("example.com"));
        duplicate.append(HOST, HeaderValue::from_static("evil.example"));
        let mut invalid = HeaderMap::new();
        invalid.insert(HOST, HeaderValue::from_static("http://evil.example"));
        let mut too_long = HeaderMap::new();
        too_long.insert(
            HOST,
            HeaderValue::from_str(&format!("{}.example", "a".repeat(256))).unwrap(),
        );

        assert_eq!(
            validate_host_header(&HeaderMap::new(), &cfg),
            Err("missing host header")
        );
        assert_eq!(
            validate_host_header(&duplicate, &cfg),
            Err("multiple host headers")
        );
        assert_eq!(
            validate_host_header(&invalid, &cfg),
            Err("invalid host header")
        );
        assert_eq!(
            validate_host_header(&too_long, &cfg),
            Err("host header too long")
        );
    }

    #[test]
    fn host_guard_applies_allowed_hosts_case_insensitively() {
        let cfg = test_http_config(
            r#"{"allowed_hosts":["example.com","api.example.com:8443","[2001:db8::1]"]}"#,
        );
        let mut allowed = HeaderMap::new();
        allowed.insert(HOST, HeaderValue::from_static("EXAMPLE.com"));
        let mut allowed_authority = HeaderMap::new();
        allowed_authority.insert(HOST, HeaderValue::from_static("api.example.com:8443"));
        let mut allowed_ipv6 = HeaderMap::new();
        allowed_ipv6.insert(HOST, HeaderValue::from_static("[2001:db8::1]"));
        let mut denied = HeaderMap::new();
        denied.insert(HOST, HeaderValue::from_static("evil.example"));

        assert!(validate_host_header(&allowed, &cfg).is_ok());
        assert!(validate_host_header(&allowed_authority, &cfg).is_ok());
        assert!(validate_host_header(&allowed_ipv6, &cfg).is_ok());
        assert_eq!(validate_host_header(&denied, &cfg), Err("host not allowed"));
    }

    #[test]
    fn host_guard_uses_absolute_form_authority_for_effective_host() {
        let cfg = test_http_config(r#"{"allowed_hosts":["good.local"]}"#);
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("evil.local"));
        let uri: Uri = "http://good.local/app?x=1".parse().unwrap();

        assert_eq!(
            validate_effective_host(&uri, &headers, &cfg),
            Ok(Some("good.local".to_string()))
        );

        headers.insert(HOST, HeaderValue::from_static("good.local"));
        let uri: Uri = "http://evil.local/app?x=1".parse().unwrap();
        assert_eq!(
            validate_effective_host(&uri, &headers, &cfg),
            Err("host not allowed")
        );
    }

    #[test]
    fn host_guard_rejects_unsupported_absolute_form_scheme() {
        let cfg = test_http_config(r#"{"allowed_hosts":["good.local"]}"#);
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("good.local"));
        let ftp_uri: Uri = "ftp://good.local/app?x=1".parse().unwrap();
        let http_uri: Uri = "http://good.local/app?x=1".parse().unwrap();
        let https_uri: Uri = "https://good.local/app?x=1".parse().unwrap();

        assert_eq!(
            validate_effective_host(&ftp_uri, &headers, &cfg),
            Err("unsupported absolute-form scheme")
        );
        assert_eq!(
            validate_effective_host(&http_uri, &headers, &cfg),
            Ok(Some("good.local".to_string()))
        );
        assert_eq!(
            validate_effective_host(&https_uri, &headers, &cfg),
            Ok(Some("good.local".to_string()))
        );
    }

    #[test]
    fn host_guard_still_rejects_duplicate_host_on_absolute_form() {
        let cfg = test_http_config(r#"{"allowed_hosts":["good.local"]}"#);
        let mut headers = HeaderMap::new();
        headers.append(HOST, HeaderValue::from_static("good.local"));
        headers.append(HOST, HeaderValue::from_static("evil.local"));
        let uri: Uri = "http://good.local/app".parse().unwrap();

        assert_eq!(
            validate_effective_host(&uri, &headers, &cfg),
            Err("multiple host headers")
        );
    }

    #[test]
    fn host_guard_can_disable_required_host_for_legacy_clients() {
        let cfg = test_http_config(r#"{"require_host_header":false}"#);

        assert_eq!(validate_host_header(&HeaderMap::new(), &cfg), Ok(None));
    }

    #[test]
    fn request_target_guard_allows_normal_uri() {
        let cfg = test_http_config(
            r#"{
                "max_uri_bytes": 64,
                "max_query_bytes": 32,
                "max_query_pairs": 4,
                "max_path_segments": 4
            }"#,
        );
        let uri: Uri = "/api/catalog/42?page=1&sort=asc".parse().unwrap();

        assert_eq!(validate_request_target(&uri, &cfg), Ok(()));
    }

    #[test]
    fn request_target_guard_rejects_long_uri() {
        let cfg = test_http_config(r#"{"max_uri_bytes": 16}"#);
        let uri: Uri = "/api/catalog/42?x=1234567890".parse().unwrap();

        assert_eq!(
            validate_request_target(&uri, &cfg),
            Err("request uri too long")
        );
    }

    #[test]
    fn request_target_guard_counts_absolute_form_authority_bytes() {
        let cfg = test_http_config(r#"{"max_uri_bytes": 16}"#);
        let uri: Uri = "http://very-long-authority.example/".parse().unwrap();

        assert_eq!(
            validate_request_target(&uri, &cfg),
            Err("request uri too long")
        );
    }

    #[test]
    fn request_target_guard_rejects_query_pressure() {
        let byte_cfg = test_http_config(r#"{"max_query_bytes": 8,"max_query_pairs":0}"#);
        let pair_cfg = test_http_config(r#"{"max_query_bytes": 64,"max_query_pairs":2}"#);
        let long_query: Uri = "/api?a=123456789".parse().unwrap();
        let many_pairs: Uri = "/api?a=1&b=2&c=3".parse().unwrap();

        assert_eq!(
            validate_request_target(&long_query, &byte_cfg),
            Err("request query too long")
        );
        assert_eq!(
            validate_request_target(&many_pairs, &pair_cfg),
            Err("too many query parameters")
        );
    }

    #[test]
    fn request_target_guard_rejects_too_many_path_segments() {
        let cfg = test_http_config(r#"{"max_path_segments":3}"#);
        let uri: Uri = "/a/b/c/d".parse().unwrap();

        assert_eq!(
            validate_request_target(&uri, &cfg),
            Err("too many path segments")
        );
    }

    #[test]
    fn method_guard_rejects_risky_and_arbitrary_methods_by_default() {
        let cfg = test_http_config("{}");

        assert!(method_allowed(&Method::GET, &cfg));
        assert!(method_allowed(&Method::POST, &cfg));
        assert!(!method_allowed(&Method::TRACE, &cfg));
        assert!(!method_allowed(&Method::CONNECT, &cfg));
        assert!(!method_allowed(
            &Method::from_bytes(b"TRACK").unwrap(),
            &cfg
        ));
        assert!(!method_allowed(&Method::from_bytes(b"JEFF").unwrap(), &cfg));
    }

    #[test]
    fn method_guard_accepts_configured_extension_methods() {
        let cfg = test_http_config(r#"{"allowed_methods":["GET","REPORT"]}"#);

        assert!(method_allowed(&Method::GET, &cfg));
        assert!(method_allowed(
            &Method::from_bytes(b"REPORT").unwrap(),
            &cfg
        ));
        assert!(!method_allowed(&Method::POST, &cfg));
        assert_eq!(allowed_methods_header(&cfg.allowed_methods), "GET, REPORT");
    }

    #[test]
    fn method_override_headers_are_rejected_unless_opted_in() {
        for name in [
            "x-http-method",
            "x-http-method-override",
            "x-method-override",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static("DELETE"));

            assert_eq!(
                validate_method_override_headers(&headers, false),
                Err("method override headers not allowed")
            );
            assert_eq!(validate_method_override_headers(&headers, true), Ok(()));
        }
    }

    #[test]
    fn method_not_allowed_response_preserves_allow_and_is_not_stored() {
        let cfg = test_http_config(r#"{"allowed_methods":["GET","POST"]}"#);
        let response = method_not_allowed_response(&cfg);
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get("allow"),
            Some(&HeaderValue::from_static("GET, POST"))
        );
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn admin_endpoint_only_matches_get_health_and_metrics() {
        assert_eq!(
            admin_endpoint("/__altura", "GET", "/__altura/health"),
            Some(AdminEndpoint::Health)
        );
        assert_eq!(
            admin_endpoint("/__altura/", "GET", "/__altura/metrics"),
            Some(AdminEndpoint::Metrics)
        );
        assert_eq!(
            admin_endpoint("/__altura", "POST", "/__altura/health"),
            None
        );
        assert_eq!(admin_endpoint("/__altura", "GET", "/__altura/other"), None);
    }

    #[test]
    fn simple_generated_responses_are_not_stored() {
        let response = simple_response(
            200,
            "ok\n",
            Some(("content-type", "text/plain".to_string())),
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type"),
            Some(&HeaderValue::from_static("text/plain"))
        );
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn metrics_admin_token_must_match() {
        let mut headers = HeaderMap::new();
        assert!(!admin_token_matches("secret", &headers));
        headers.insert("x-altura-admin-token", HeaderValue::from_static("wrong"));
        assert!(!admin_token_matches("secret", &headers));
        headers.insert("x-altura-admin-token", HeaderValue::from_static("secret2"));
        assert!(!admin_token_matches("secret", &headers));
        headers.insert("x-altura-admin-token", HeaderValue::from_static("secret"));
        assert!(admin_token_matches("secret", &headers));
        headers.insert(
            "x-altura-admin-token",
            HeaderValue::from_str(&"s".repeat(HTTP_ADMIN_TOKEN_MAX_BYTES + 1)).unwrap(),
        );
        assert!(!admin_token_matches("secret", &headers));
    }

    #[test]
    fn metrics_admin_token_rejects_duplicate_headers() {
        let mut headers = HeaderMap::new();
        headers.append("x-altura-admin-token", HeaderValue::from_static("secret"));
        headers.append("x-altura-admin-token", HeaderValue::from_static("secret"));
        assert!(!admin_token_matches("secret", &headers));

        let mut mixed = HeaderMap::new();
        mixed.append("x-altura-admin-token", HeaderValue::from_static("secret"));
        mixed.append("x-altura-admin-token", HeaderValue::from_static("wrong"));
        assert!(!admin_token_matches("secret", &mixed));
    }

    #[test]
    fn bounded_constant_time_compare_rejects_lengths_outside_budget() {
        assert!(constant_time_eq_bounded(b"secret", b"secret", 16));
        assert!(!constant_time_eq_bounded(b"secret", b"secret2", 16));
        assert!(!constant_time_eq_bounded(b"secret", b"wrong", 16));
        assert!(!constant_time_eq_bounded(b"toolong", b"toolong", 4));
        assert!(!constant_time_eq_bounded(
            b"secret",
            &vec![b's'; HTTP_ADMIN_TOKEN_MAX_BYTES + 1],
            HTTP_ADMIN_TOKEN_MAX_BYTES,
        ));
    }

    #[test]
    fn rate_limit_response_increments_counter() {
        let cfg = crate::config::HttpLimitConfig {
            per_ip_rps: 0.1,
            per_ip_burst: 1,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..crate::config::HttpLimitConfig::default()
        };
        let limiter = RateLimiter::new(&cfg);
        let stats = Stats::default();
        let headers = HeaderMap::new();
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let signature = request_signature("GET", "/__altura/health", None, &headers);
        let ctx = RequestContext {
            client_ip,
            method: "GET",
            path: "/__altura/health",
            query: None,
            headers: &headers,
            signature,
        };

        assert!(maybe_rate_limit_response(&limiter, &stats, client_ip, None, &ctx).is_none());
        let response = maybe_rate_limit_response(&limiter, &stats, client_ip, None, &ctx)
            .expect("second request should be rate limited");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
        assert_eq!(
            stats
                .http_rate_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn connection_request_limit_response_is_retryable_not_stored_and_closes() {
        let response = connection_request_limit_response("connection request limit\n");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn signature_rate_limit_response_is_signature_scoped() {
        let cfg = crate::config::HttpLimitConfig {
            signature_rps: 0.000001,
            signature_burst: 1,
            max_tracked_signatures: 64,
            per_ip_rps: 0.0,
            global_rps: 0.0,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            ..crate::config::HttpLimitConfig::default()
        };
        let limiter = SignatureRateLimiter::new(&cfg);
        let stats = Stats::default();
        let headers = HeaderMap::new();
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let ctx = RequestContext {
            client_ip,
            method: "GET",
            path: "/hot",
            query: None,
            headers: &headers,
            signature: "hot-signature".to_string(),
        };
        let other_ctx = RequestContext {
            client_ip,
            method: "GET",
            path: "/cold",
            query: None,
            headers: &headers,
            signature: "cold-signature".to_string(),
        };

        assert!(maybe_signature_rate_limit_response(&limiter, &stats, None, &ctx).is_none());
        let response = maybe_signature_rate_limit_response(&limiter, &stats, None, &ctx)
            .expect("second hot signature request should be limited");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
        assert!(maybe_signature_rate_limit_response(&limiter, &stats, None, &other_ctx).is_none());
        assert_eq!(
            stats
                .http_signature_rate_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn path_shape_rate_limit_response_is_shape_scoped() {
        let cfg = crate::config::HttpLimitConfig {
            path_shape_rps: 0.000001,
            path_shape_burst: 1,
            max_tracked_path_shapes: 64,
            per_ip_rps: 0.0,
            global_rps: 0.0,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            ..crate::config::HttpLimitConfig::default()
        };
        let limiter = PathShapeRateLimiter::new(&cfg);
        let stats = Stats::default();
        let headers = HeaderMap::new();
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let first_ctx = RequestContext {
            client_ip,
            method: "GET",
            path: "/api/alpha/1",
            query: None,
            headers: &headers,
            signature: "sig-a".to_string(),
        };
        let second_ctx = RequestContext {
            client_ip,
            method: "GET",
            path: "/api/beta/2",
            query: None,
            headers: &headers,
            signature: "sig-b".to_string(),
        };
        let other_ctx = RequestContext {
            client_ip,
            method: "GET",
            path: "/static/app.css",
            query: None,
            headers: &headers,
            signature: "sig-c".to_string(),
        };
        let hot_shape = "/api/:token/:num";

        assert!(maybe_path_shape_rate_limit_response(
            &limiter, &stats, None, &first_ctx, hot_shape
        )
        .is_none());
        let response =
            maybe_path_shape_rate_limit_response(&limiter, &stats, None, &second_ctx, hot_shape)
                .expect("second request to same shape should be limited");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
        assert!(maybe_path_shape_rate_limit_response(
            &limiter,
            &stats,
            None,
            &other_ctx,
            "/static/app.css"
        )
        .is_none());
        assert_eq!(
            stats
                .http_path_shape_rate_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn short_token_sibling_rate_limit_response_uses_path_shape_contract() {
        let cfg = crate::config::HttpLimitConfig {
            path_shape_rps: 0.000001,
            path_shape_burst: 2,
            max_tracked_path_shapes: 64,
            per_ip_rps: 0.0,
            global_rps: 0.0,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            ..crate::config::HttpLimitConfig::default()
        };
        let limiter = ShortTokenSiblingRateLimiter::new(&cfg);
        let stats = Stats::default();
        let headers = HeaderMap::new();
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let ctx = RequestContext {
            client_ip,
            method: "GET",
            path: "/api/ef",
            query: None,
            headers: &headers,
            signature: "sig-short".to_string(),
        };
        let parent = ("/api/:short-token".to_string(), "ab".to_string());
        let second = ("/api/:short-token".to_string(), "cd".to_string());
        let third = ("/api/:short-token".to_string(), "ef".to_string());

        assert!(maybe_short_token_sibling_rate_limit_response(
            &limiter,
            &stats,
            None,
            &ctx,
            Some(&parent),
        )
        .is_none());
        assert!(maybe_short_token_sibling_rate_limit_response(
            &limiter,
            &stats,
            None,
            &ctx,
            Some(&second),
        )
        .is_none());
        let response = maybe_short_token_sibling_rate_limit_response(
            &limiter,
            &stats,
            None,
            &ctx,
            Some(&third),
        )
        .expect("third distinct short sibling should be limited");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
        assert_eq!(
            stats
                .http_path_shape_rate_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn trusted_proxy_rate_limit_response_tracks_peer_ip() {
        let cfg = crate::config::HttpLimitConfig {
            per_ip_rps: 1_000_000.0,
            per_ip_burst: 1_000_000,
            global_rps: 0.0,
            global_burst: 1,
            trusted_proxy_rps: 0.1,
            trusted_proxy_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..crate::config::HttpLimitConfig::default()
        };
        let limiter = RateLimiter::trusted_proxy_aggregate(&cfg);
        let stats = Stats::default();
        let headers = HeaderMap::new();
        let client_ip: IpAddr = "198.51.100.10".parse().unwrap();
        let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let signature = request_signature("GET", "/api/login", None, &headers);
        let ctx = RequestContext {
            client_ip,
            method: "GET",
            path: "/api/login",
            query: None,
            headers: &headers,
            signature,
        };

        assert!(maybe_trusted_proxy_rate_limit_response(
            &limiter, &stats, client_ip, peer_ip, None, &ctx
        )
        .is_none());
        let response = maybe_trusted_proxy_rate_limit_response(
            &limiter, &stats, client_ip, peer_ip, None, &ctx,
        )
        .expect("second trusted-proxy request should be rate limited");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
        assert_eq!(
            stats
                .http_trusted_proxy_rate_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(maybe_trusted_proxy_rate_limit_response(
            &limiter, &stats, peer_ip, peer_ip, None, &ctx
        )
        .is_none());
    }

    #[test]
    fn trusted_proxy_in_flight_response_tracks_peer_ip() {
        let cfg = crate::config::HttpLimitConfig {
            trusted_proxy_max_in_flight_requests: 1,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..crate::config::HttpLimitConfig::default()
        };
        let limiter = RequestConcurrencyLimiter::trusted_proxy_aggregate(&cfg);
        let stats = Stats::default();
        let client_ip: IpAddr = "198.51.100.10".parse().unwrap();
        let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();

        let permit = maybe_trusted_proxy_request_permit(&limiter, &stats, client_ip, peer_ip)
            .expect("first trusted-proxy request should acquire")
            .expect("forwarded client should be tracked by peer");
        let response = maybe_trusted_proxy_request_permit(&limiter, &stats, client_ip, peer_ip)
            .expect_err("second trusted-proxy request should be rejected");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
        assert_eq!(
            stats
                .http_upstream_in_flight_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .http_trusted_proxy_in_flight_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(
            maybe_trusted_proxy_request_permit(&limiter, &stats, peer_ip, peer_ip)
                .unwrap()
                .is_none()
        );
        drop(permit);
        assert!(
            maybe_trusted_proxy_request_permit(&limiter, &stats, client_ip, peer_ip)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn upstream_overload_response_is_retryable_and_not_stored() {
        let response = upstream_overload_response("upstream concurrency limit\n");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn upstream_circuit_open_response_is_retryable_not_stored_and_closes() {
        let response = upstream_circuit_open_response("upstream circuit open\n");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_retry_after_header(&response);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn upstream_failure_circuit_opens_after_threshold_and_recovers() {
        let breaker = UpstreamFailureCircuitBreaker::new(2, 10, 64);

        assert!(!breaker.is_open("/api/fail"));
        breaker.record_failure("/api/fail");
        assert!(!breaker.is_open("/api/fail"));
        breaker.record_failure("/api/fail");
        assert!(breaker.is_open("/api/fail"));

        std::thread::sleep(Duration::from_millis(15));
        assert!(!breaker.is_open("/api/fail"));
        breaker.record_failure("/api/fail");
        assert!(!breaker.is_open("/api/fail"));
        breaker.record_success("/api/fail");
        breaker.record_failure("/api/fail");
        assert!(!breaker.is_open("/api/fail"));
    }

    #[test]
    fn upstream_failure_circuit_is_scoped_by_path_shape() {
        let breaker = UpstreamFailureCircuitBreaker::new(2, 10_000, 64);

        breaker.record_failure("/api/fail/:num");
        breaker.record_failure("/api/fail/:num");

        assert!(breaker.is_open("/api/fail/:num"));
        assert!(!breaker.is_open("/api/healthy/:num"));

        breaker.record_success("/api/healthy/:num");
        assert!(breaker.is_open("/api/fail/:num"));

        breaker.record_success("/api/fail/:num");
        assert!(!breaker.is_open("/api/fail/:num"));
    }

    #[test]
    fn upstream_failure_circuit_bounds_tracked_path_shapes() {
        let breaker = UpstreamFailureCircuitBreaker::new(2, 10_000, 1);
        let first = "/api/first";
        let first_shard = upstream_circuit_shard_for(first) % UPSTREAM_CIRCUIT_SHARDS;
        let second = (0..10_000)
            .map(|idx| format!("/api/second-{idx}"))
            .find(|shape| {
                upstream_circuit_shard_for(shape) % UPSTREAM_CIRCUIT_SHARDS == first_shard
            })
            .expect("test should find a same-shard path shape");

        breaker.record_failure(first);
        breaker.record_failure(first);
        assert!(breaker.is_open(first));

        breaker.record_failure(&second);
        assert!(breaker.is_open(first));
        assert!(!breaker.is_open(&second));
    }

    #[test]
    fn upstream_failure_circuit_reclaims_closed_entries_at_capacity() {
        let breaker = UpstreamFailureCircuitBreaker::new(2, 10_000, 1);
        let first = "/api/first";
        let first_shard = upstream_circuit_shard_for(first) % UPSTREAM_CIRCUIT_SHARDS;
        let second = (0..10_000)
            .map(|idx| format!("/api/second-closed-{idx}"))
            .find(|shape| {
                upstream_circuit_shard_for(shape) % UPSTREAM_CIRCUIT_SHARDS == first_shard
            })
            .expect("test should find a same-shard path shape");

        breaker.record_failure(first);
        assert!(!breaker.is_open(first));

        breaker.record_failure(&second);
        breaker.record_failure(&second);

        assert!(!breaker.is_open(first));
        assert!(breaker.is_open(&second));
    }

    #[test]
    fn upstream_bad_gateway_response_is_not_stored_and_closes() {
        let response = upstream_bad_gateway_response("bad gateway\n");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn upstream_gateway_timeout_response_is_not_stored_and_closes() {
        let response = upstream_gateway_timeout_response("gateway timeout\n");
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn request_timeout_response_closes_connection() {
        let response = request_timeout_response("request body timeout\n");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn content_too_large_response_closes_connection() {
        let response = content_too_large_response("request body too large\n");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn request_framing_rejected_response_closes_connection() {
        let response = request_framing_rejected_response("chunked request body not allowed\n");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn unsupported_content_encoding_response_advertises_identity_and_closes_connection() {
        let response =
            unsupported_content_encoding_response("unsupported request content-encoding\n");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            response.headers().get(ACCEPT_ENCODING),
            Some(&HeaderValue::from_static("identity"))
        );
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn request_target_rejected_response_is_not_stored() {
        let response = request_target_rejected_response("uri too long\n");
        assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn request_metadata_too_large_response_is_not_stored_and_closes() {
        let response = request_metadata_too_large_response("request trailers too large\n");
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn early_rejection_response_closes_connection_and_preserves_header() {
        let response = early_rejection_response(
            403,
            "blocked\n",
            Some(("x-altura-filter", "block-test".to_string())),
        );
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get("x-altura-filter"),
            Some(&HeaderValue::from_static("block-test"))
        );
        assert_generated_no_store_header(&response);
        assert_connection_close_header(&response);
    }

    #[test]
    fn finds_body_guard_error_in_source_chain() {
        let err = ErrorWrapper {
            source: Box::new(BodyGuardError::IdleTimeout),
        };
        assert_eq!(
            find_body_guard_error(&err),
            Some(BodyGuardError::IdleTimeout)
        );
    }

    #[tokio::test]
    async fn guarded_body_allows_under_limit() {
        let stats = Arc::new(Stats::default());
        let body = GuardedBody::new(
            Full::new(Bytes::from_static(b"hello")),
            8,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
            trailer_policy(false),
            Arc::clone(&stats),
        );
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected, Bytes::from_static(b"hello"));
        assert_eq!(
            stats
                .http_body_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn guarded_body_rejects_streaming_over_limit() {
        let stats = Arc::new(Stats::default());
        let body = GuardedBody::new(
            Full::new(Bytes::from_static(b"too-large")),
            4,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
            trailer_policy(false),
            Arc::clone(&stats),
        );
        let err = body.collect().await.unwrap_err();
        assert_eq!(err.to_string(), "request body length limit exceeded");
        assert_eq!(
            stats
                .http_body_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn guarded_body_times_out_idle_frame() {
        let stats = Arc::new(Stats::default());
        let body = GuardedBody::new(
            PendingBody,
            1024,
            Duration::from_millis(5),
            0,
            Duration::ZERO,
            trailer_policy(false),
            Arc::clone(&stats),
        );
        let err = tokio::time::timeout(Duration::from_millis(100), body.collect())
            .await
            .expect("guarded body should return before outer timeout")
            .unwrap_err();
        assert_eq!(err.to_string(), "request body idle timeout");
        assert_eq!(
            stats
                .http_body_timeouts
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn guarded_body_rejects_body_below_minimum_rate() {
        let stats = Arc::new(Stats::default());
        let body = GuardedBody::new(
            DelayedTwoChunkBody::new(Duration::from_millis(30)),
            1024,
            Duration::from_secs(1),
            1_000,
            Duration::from_millis(1),
            trailer_policy(false),
            Arc::clone(&stats),
        );
        let err = body.collect().await.unwrap_err();
        assert_eq!(err.to_string(), "request body minimum data rate not met");
        assert_eq!(
            stats
                .http_body_too_slow
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn body_rate_guard_rejects_first_post_grace_slow_chunk() {
        let mut guard = BodyRateGuard::new(1_000, Duration::from_millis(5));
        guard.start();

        std::thread::sleep(Duration::from_millis(30));

        assert!(!guard.record(1));
    }

    #[test]
    fn body_rate_guard_does_not_bank_pre_grace_bytes() {
        let mut guard = BodyRateGuard::new(1_000, Duration::from_millis(5));
        guard.start();

        assert!(guard.record(512));
        std::thread::sleep(Duration::from_millis(30));

        assert!(!guard.record(1));
    }

    #[tokio::test]
    async fn response_guard_allows_under_limit() {
        let stats = Arc::new(Stats::default());
        let body = ResponseGuardBody::new(
            Full::new(Bytes::from_static(b"hello")),
            8,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
            trailer_policy(false),
            Arc::clone(&stats),
        );
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected, Bytes::from_static(b"hello"));
        assert_eq!(
            stats
                .http_upstream_body_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn response_guard_rejects_streaming_over_limit() {
        let stats = Arc::new(Stats::default());
        let body = ResponseGuardBody::new(
            Full::new(Bytes::from_static(b"too-large")),
            4,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
            trailer_policy(false),
            Arc::clone(&stats),
        );
        let err = body.collect().await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "upstream response body length limit exceeded"
        );
        assert_eq!(
            stats
                .http_upstream_body_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn response_guard_times_out_idle_frame() {
        let stats = Arc::new(Stats::default());
        let body = ResponseGuardBody::new(
            PendingBody,
            1024,
            Duration::from_millis(5),
            0,
            Duration::ZERO,
            trailer_policy(false),
            Arc::clone(&stats),
        );
        let err = tokio::time::timeout(Duration::from_millis(100), body.collect())
            .await
            .expect("response guard should return before outer timeout")
            .unwrap_err();
        assert_eq!(err.to_string(), "upstream response body idle timeout");
        assert_eq!(
            stats
                .http_upstream_body_timeouts
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn response_guard_rejects_body_below_minimum_rate() {
        let stats = Arc::new(Stats::default());
        let body = ResponseGuardBody::new(
            DelayedTwoChunkBody::new(Duration::from_millis(30)),
            1024,
            Duration::from_secs(1),
            1_000,
            Duration::from_millis(1),
            trailer_policy(false),
            Arc::clone(&stats),
        );
        let err = body.collect().await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "upstream response body minimum data rate not met"
        );
        assert_eq!(
            stats
                .http_upstream_body_too_slow
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn guarded_body_drops_request_trailers_by_default() {
        let stats = Arc::new(Stats::default());
        let body = GuardedBody::new(
            DataThenTrailersBody::new("x-request-trailer", "drop-me"),
            1024,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
            trailer_policy(false),
            Arc::clone(&stats),
        );

        let collected = body.collect().await.unwrap();
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"hello"));
        assert_eq!(
            stats
                .http_request_trailers_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .http_request_trailers_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn guarded_body_rejects_oversized_forwarded_request_trailers() {
        let stats = Arc::new(Stats::default());
        let body = GuardedBody::new(
            DataThenTrailersBody::new("x-request-trailer", "x".repeat(256)),
            1024,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
            trailer_policy(true),
            Arc::clone(&stats),
        );

        let err = body.collect().await.unwrap_err();
        assert_eq!(err.to_string(), "request trailers too large");
        assert_eq!(
            stats
                .http_request_trailers_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn response_guard_drops_upstream_trailers_by_default() {
        let stats = Arc::new(Stats::default());
        let body = ResponseGuardBody::new(
            DataThenTrailersBody::new("x-origin-trailer", "drop-me"),
            1024,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
            trailer_policy(false),
            Arc::clone(&stats),
        );

        let collected = body.collect().await.unwrap();
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"hello"));
        assert_eq!(
            stats
                .http_upstream_trailers_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .http_upstream_trailers_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn response_guard_rejects_oversized_forwarded_upstream_trailers() {
        let stats = Arc::new(Stats::default());
        let body = ResponseGuardBody::new(
            DataThenTrailersBody::new("x-origin-trailer", "x".repeat(256)),
            1024,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
            trailer_policy(true),
            Arc::clone(&stats),
        );

        let err = body.collect().await.unwrap_err();
        assert_eq!(err.to_string(), "upstream response trailers too large");
        assert_eq!(
            stats
                .http_upstream_trailers_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn downstream_write_timeout_counts_slow_reader() {
        let stats = Arc::new(Stats::default());
        let mut io = DownstreamWriteTimeoutIo::new(
            PendingWriteIo,
            Duration::from_millis(5),
            Arc::clone(&stats),
        );

        let err = tokio::time::timeout(Duration::from_millis(100), io.write_all(b"hello"))
            .await
            .expect("downstream writer should timeout before outer timeout")
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            stats
                .http_downstream_write_timeouts
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    struct PendingBody;

    struct PendingWriteIo;

    impl AsyncRead for PendingWriteIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingWriteIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct DelayedTwoChunkBody {
        chunks_sent: u8,
        delay: Duration,
        sleep: Option<Pin<Box<Sleep>>>,
    }

    impl DelayedTwoChunkBody {
        fn new(delay: Duration) -> Self {
            Self {
                chunks_sent: 0,
                delay,
                sleep: None,
            }
        }
    }

    struct DataThenTrailersBody {
        data_sent: bool,
        trailers_sent: bool,
        trailer_name: &'static str,
        trailer_value: String,
    }

    impl DataThenTrailersBody {
        fn new(trailer_name: &'static str, trailer_value: impl Into<String>) -> Self {
            Self {
                data_sent: false,
                trailers_sent: false,
                trailer_name,
                trailer_value: trailer_value.into(),
            }
        }
    }

    impl Body for DataThenTrailersBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if !self.data_sent {
                self.data_sent = true;
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"hello")))));
            }
            if self.trailers_sent {
                return Poll::Ready(None);
            }
            self.trailers_sent = true;
            let mut trailers = HeaderMap::new();
            trailers.insert(
                HeaderName::from_static(self.trailer_name),
                HeaderValue::from_str(&self.trailer_value).unwrap(),
            );
            Poll::Ready(Some(Ok(Frame::trailers(trailers))))
        }
    }

    impl Body for DelayedTwoChunkBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.chunks_sent == 0 {
                self.chunks_sent += 1;
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"a")))));
            }
            if self.chunks_sent >= 3 {
                return Poll::Ready(None);
            }
            if self.sleep.is_none() {
                self.sleep = Some(Box::pin(tokio::time::sleep(self.delay)));
            }
            if let Some(sleep) = &mut self.sleep {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            self.sleep = None;
            self.chunks_sent += 1;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"b")))))
        }
    }

    #[derive(Debug)]
    struct ErrorWrapper {
        source: BoxError,
    }

    fn test_http_config(overrides: &str) -> HttpConfig {
        let mut value = serde_json::json!({
            "listen": "127.0.0.1:0",
            "upstream": "http://127.0.0.1:1"
        });
        let overrides: serde_json::Value = serde_json::from_str(overrides).unwrap();
        let base = value.as_object_mut().unwrap();
        for (key, value) in overrides.as_object().unwrap() {
            base.insert(key.clone(), value.clone());
        }
        serde_json::from_value(value).unwrap()
    }

    fn unused_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn read_test_response(stream: &mut TcpStream) -> Vec<u8> {
        let mut received = Vec::new();
        let mut scratch = [0_u8; 512];
        loop {
            let read = timeout(Duration::from_secs(1), stream.read(&mut scratch))
                .await
                .unwrap()
                .unwrap();
            if read == 0 {
                break;
            }
            received.extend_from_slice(&scratch[..read]);
            if find_header_end(&received).is_some() {
                break;
            }
        }
        received
    }

    impl fmt::Display for ErrorWrapper {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("wrapped error")
        }
    }

    impl Error for ErrorWrapper {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.source.as_ref())
        }
    }

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }
}
