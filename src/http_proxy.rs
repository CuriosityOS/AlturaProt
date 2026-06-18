use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http::{
    header::{HeaderName, HeaderValue, HOST},
    HeaderMap, Request, Response, StatusCode, Uri,
};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

use crate::{
    adaptive::AdaptiveDetector,
    config::{ClientIpConfig, HttpConfig},
    filter::{request_signature, FilterEngine, RequestContext},
    limiter::{LimitReason, RateLimiter},
    telemetry::Stats,
    BoxError,
};

type ProxyBody = BoxBody<Bytes, hyper::Error>;
type HyperClient = Client<HttpConnector, Incoming>;

#[derive(Clone)]
struct HttpProxyState {
    cfg: HttpConfig,
    upstream: Uri,
    client: HyperClient,
    client_ip: ClientIpResolver,
    engine: Arc<FilterEngine>,
    limiter: Arc<RateLimiter>,
    detector: Arc<AdaptiveDetector>,
    stats: Arc<Stats>,
}

pub async fn run_http_proxy(
    cfg: HttpConfig,
    engine: Arc<FilterEngine>,
    detector: Arc<AdaptiveDetector>,
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
    let upstream: Uri = match cfg.upstream.parse() {
        Ok(upstream) => upstream,
        Err(err) => {
            notify_startup(startup, Err(format!("invalid upstream URI: {err}")));
            return Err(Box::new(err));
        }
    };
    if upstream.scheme().is_none() || upstream.authority().is_none() {
        notify_startup(startup, Err("HTTP upstream must include scheme and authority".to_string()));
        return Err("HTTP upstream must include scheme and authority".into());
    }

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let limiter = Arc::new(RateLimiter::new(&cfg.limits));
    let state = HttpProxyState {
        cfg: cfg.clone(),
        upstream,
        client,
        client_ip: ClientIpResolver::from_config(&cfg.client_ip),
        engine,
        limiter,
        detector,
        stats,
    };

    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(err) => {
            notify_startup(startup, Err(format!("bind failed: {err}")));
            return Err(Box::new(err));
        }
    };
    eprintln!("http proxy listening on {listen}, upstream {}", cfg.upstream);
    notify_startup(startup, Ok(()));

    loop {
        let (stream, peer_addr) = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    eprintln!("http proxy listener shutting down");
                    break;
                }
                continue;
            }
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("http accept error: {err}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            },
        };
        let io = TokioIo::new(stream);
        let conn_state = state.clone();
        tokio::spawn(async move {
            let max_header_bytes = conn_state.cfg.max_header_bytes.max(4096);
            let service =
                service_fn(move |req| handle_http(req, peer_addr, conn_state.clone()));
            let mut builder = http1::Builder::new();
            builder.keep_alive(true);
            builder.max_buf_size(max_header_bytes);
            if let Err(err) = builder.serve_connection(io, service).await {
                eprintln!("http connection error from {peer_addr}: {err}");
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

async fn handle_http(
    mut req: Request<Incoming>,
    peer_addr: SocketAddr,
    state: HttpProxyState,
) -> Result<Response<ProxyBody>, Infallible> {
    Stats::inc(&state.stats.http_total);

    let client_ip = state.client_ip.resolve(peer_addr.ip(), req.headers());
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(ToString::to_string);
    let signature = request_signature(&method, &path, query.as_deref(), req.headers());

    if let Some(admin) = maybe_admin_response(&state, &path, req.headers()) {
        return Ok(admin);
    }

    let ctx = RequestContext {
        client_ip,
        method: &method,
        path: &path,
        query: query.as_deref(),
        headers: req.headers(),
        signature,
    };

    state.detector.observe(&ctx, "observed");

    if let Some(decision) = state.engine.evaluate(&ctx) {
        Stats::inc(&state.stats.http_blocked);
        state.detector.observe(&ctx, "filter_block");
        return Ok(simple_response(
            decision.status,
            decision.body,
            Some(("x-altura-filter", decision.rule_id)),
        ));
    }

    let limit = state.limiter.check(client_ip);
    if !limit.allowed {
        Stats::inc(&state.stats.http_rate_limited);
        state
            .detector
            .observe(
                &ctx,
                match limit.reason {
                    Some(LimitReason::GlobalRate) => "global_rate_limited",
                    Some(LimitReason::PerIpRate) => "per_ip_rate_limited",
                    _ => "rate_limited",
                },
            );
        return Ok(simple_response(429, "rate limited\n", None));
    }

    let original_host = req
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);

    match rewrite_request(&mut req, &state.upstream, original_host.as_deref(), client_ip, state.cfg.preserve_host) {
        Ok(()) => {}
        Err(err) => {
            Stats::inc(&state.stats.http_blocked);
            return Ok(simple_response(400, format!("bad request: {err}\n"), None));
        }
    }

    match state.client.request(req).await {
        Ok(resp) => {
            Stats::inc(&state.stats.http_proxied);
            Ok(resp.map(|body| body.boxed()))
        }
        Err(err) => {
            Stats::inc(&state.stats.http_upstream_errors);
            eprintln!("upstream error: {err}");
            Ok(simple_response(502, "bad gateway\n", None))
        }
    }
}

#[derive(Clone, Debug)]
struct ClientIpResolver {
    header: HeaderName,
    trusted_proxies: Arc<Vec<IpRange>>,
}

impl ClientIpResolver {
    fn from_config(cfg: &ClientIpConfig) -> Self {
        let header = match HeaderName::from_bytes(cfg.header.as_bytes()) {
            Ok(header) => header,
            Err(err) => {
                eprintln!(
                    "invalid client_ip header '{}': {err}; falling back to x-forwarded-for",
                    cfg.header
                );
                HeaderName::from_static("x-forwarded-for")
            }
        };
        let trusted_proxies = cfg
            .trusted_proxies
            .iter()
            .filter_map(|entry| match IpRange::parse(entry) {
                Ok(range) => Some(range),
                Err(err) => {
                    eprintln!("ignoring invalid trusted proxy range '{entry}': {err}");
                    None
                }
            })
            .collect();
        Self {
            header,
            trusted_proxies: Arc::new(trusted_proxies),
        }
    }

    fn resolve(&self, peer_ip: IpAddr, headers: &HeaderMap<HeaderValue>) -> IpAddr {
        if self.trusted_proxies.is_empty() || !self.is_trusted(peer_ip) {
            return peer_ip;
        }
        let Some(header) = headers.get(&self.header).and_then(|value| value.to_str().ok()) else {
            return peer_ip;
        };
        let mut chain: Vec<IpAddr> = header
            .split(',')
            .filter_map(parse_forwarded_ip_token)
            .collect();
        chain.push(peer_ip);
        for ip in chain.iter().rev() {
            if !self.is_trusted(*ip) {
                return *ip;
            }
        }
        peer_ip
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|range| range.contains(ip))
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
        let (ip, _) = rest.split_once(']')?;
        return ip.parse().ok();
    }
    if let Ok(ip) = token.parse() {
        return Some(ip);
    }
    if token.matches(':').count() == 1 {
        let (host, _) = token.rsplit_once(':')?;
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(IpAddr::V4(ip));
        }
    }
    token.parse::<Ipv6Addr>().map(IpAddr::V6).ok()
}

fn maybe_admin_response(
    state: &HttpProxyState,
    path: &str,
    headers: &HeaderMap<HeaderValue>,
) -> Option<Response<ProxyBody>> {
    let prefix = state.cfg.admin_path_prefix.trim_end_matches('/');
    if path == format!("{prefix}/health") {
        return Some(simple_response(200, "{\"ok\":true}\n", None));
    }
    if path == format!("{prefix}/metrics") {
        if let Some(expected) = &state.cfg.admin_token {
            let supplied = headers
                .get("x-altura-admin-token")
                .and_then(|value| value.to_str().ok());
            if supplied != Some(expected.as_str()) {
                return Some(simple_response(403, "forbidden\n", None));
            }
        }
        let active_filters = state.engine.active_rule_count();
        return Some(simple_response(
            200,
            state.stats.render_prometheus(active_filters),
            None,
        ));
    }
    None
}

fn rewrite_request(
    req: &mut Request<Incoming>,
    upstream: &Uri,
    original_host: Option<&str>,
    client_ip: std::net::IpAddr,
    preserve_host: bool,
) -> Result<(), BoxError> {
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = upstream.scheme().cloned();
    parts.authority = upstream.authority().cloned();
    let new_path = joined_path_and_query(upstream, req.uri())?;
    parts.path_and_query = Some(new_path);
    *req.uri_mut() = Uri::from_parts(parts)?;

    remove_hop_by_hop_headers(req.headers_mut());

    if preserve_host {
        if let Some(host) = original_host {
            req.headers_mut()
                .insert(HOST, HeaderValue::from_str(host).map_err(|_| "invalid host header")?);
        }
    } else if let Some(authority) = upstream.authority() {
        req.headers_mut().insert(
            HOST,
            HeaderValue::from_str(authority.as_str()).map_err(|_| "invalid upstream host")?,
        );
    }
    append_forwarded_headers(req.headers_mut(), original_host, client_ip)?;
    Ok(())
}

fn joined_path_and_query(upstream: &Uri, incoming: &Uri) -> Result<http::uri::PathAndQuery, BoxError> {
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
    if let Some(connection) = headers.get(http::header::CONNECTION) {
        if let Ok(connection) = connection.to_str() {
            for token in connection.split(',') {
                if let Ok(name) = HeaderName::from_bytes(token.trim().as_bytes()) {
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

fn append_forwarded_headers(
    headers: &mut HeaderMap<HeaderValue>,
    original_host: Option<&str>,
    client_ip: std::net::IpAddr,
) -> Result<(), BoxError> {
    let xff = HeaderName::from_static("x-forwarded-for");
    let next_for = if let Some(existing) = headers.get(&xff).and_then(|value| value.to_str().ok()) {
        format!("{existing}, {client_ip}")
    } else {
        client_ip.to_string()
    };
    headers.insert(xff, HeaderValue::from_str(&next_for)?);
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

fn simple_response(
    status: u16,
    body: impl Into<Bytes>,
    header: Option<(&'static str, String)>,
) -> Response<ProxyBody> {
    let mut builder = Response::builder().status(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    );
    if let Some((name, value)) = header {
        builder = builder.header(name, value);
    }
    builder
        .body(full_body(body))
        .expect("static response should build")
}

fn full_body(body: impl Into<Bytes>) -> ProxyBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_upstream_base_path() {
        let upstream: Uri = "http://127.0.0.1:9000/base".parse().unwrap();
        let incoming: Uri = "/hello?x=1".parse().unwrap();
        assert_eq!(
            joined_path_and_query(&upstream, &incoming).unwrap().as_str(),
            "/base/hello?x=1"
        );
    }

    #[test]
    fn strips_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("x-test, upgrade"));
        headers.insert("x-test", HeaderValue::from_static("1"));
        headers.insert("upgrade", HeaderValue::from_static("websocket"));
        remove_hop_by_hop_headers(&mut headers);
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("x-test"));
        assert!(!headers.contains_key("upgrade"));
    }

    #[test]
    fn client_ip_ignores_forwarded_header_from_untrusted_peer() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "x-forwarded-for".to_string(),
            trusted_proxies: vec!["10.0.0.0/8".to_string()],
        });
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        let peer: IpAddr = "198.51.100.20".parse().unwrap();
        assert_eq!(resolver.resolve(peer, &headers), peer);
    }

    #[test]
    fn client_ip_uses_rightmost_non_trusted_forwarded_ip() {
        let resolver = ClientIpResolver::from_config(&ClientIpConfig {
            header: "x-forwarded-for".to_string(),
            trusted_proxies: vec!["10.0.0.0/8".to_string(), "192.0.2.10".to_string()],
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.1, 203.0.113.2, 10.1.2.3"),
        );
        let peer: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(
            resolver.resolve(peer, &headers),
            "203.0.113.2".parse::<IpAddr>().unwrap()
        );
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
    }
}
