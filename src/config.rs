use std::{
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use http::{header::HeaderName, uri::Authority, Method, Uri};
use serde::Deserialize;

use crate::{
    filter::{
        validate_filter_rules, FilterRule, DEFAULT_RUNTIME_FILTER_MAX_BYTES,
        DEFAULT_RUNTIME_FILTER_MAX_RULES, DEFAULT_STATIC_FILTER_MAX_RULES, FILTER_TTL_MAX_SECONDS,
    },
    telemetry::{
        DEFAULT_EVENT_LOG_BACKUP_COUNT, DEFAULT_EVENT_LOG_MAX_BYTES,
        DEFAULT_EVENT_LOG_QUEUE_CAPACITY,
    },
    BoxError,
};

pub const DEFAULT_CONFIG_MAX_BYTES: u64 = DEFAULT_RUNTIME_FILTER_MAX_BYTES;
const DEFAULT_HTTP_MAX_ALLOWED_METHODS: usize = 16;
const DEFAULT_HTTP_MAX_ALLOWED_METHOD_BYTES: usize = 32;
const HTTP_UNSUPPORTED_ALLOWED_METHODS: &[&str] = &["CONNECT", "TRACE", "TRACK"];
const DEFAULT_HTTP_MAX_ALLOWED_HOSTS: usize = 128;
const DEFAULT_HTTP_MAX_ALLOWED_HOST_BYTES: usize = 255;
pub const HTTP_ADMIN_TOKEN_MAX_BYTES: usize = 256;
const DEFAULT_HTTP_CLIENT_IP_HEADER_MAX_BYTES: usize = 64;
const DEFAULT_HTTP_MAX_TRUSTED_PROXIES: usize = 128;
const DEFAULT_HTTP_MAX_TRUSTED_PROXY_BYTES: usize = 64;
const DEFAULT_MAX_ACCEPT_SHARDS: usize = 64;
const FILTER_RUNTIME_FILE_MAX_BYTES_MAX: u64 = 16 * 1024 * 1024;
const FILTER_RULE_COUNT_MAX: usize = 8_192;
const ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX: u64 = 1_073_741_824;
const ADAPTIVE_WINDOW_COUNT_MAX: usize = 262_144;
const LIMITER_MAX_TRACKED_IPS_MAX: usize = 1_048_576;
const LIMITER_MAX_TRACKED_SIGNATURES_MAX: usize = 262_144;
const LIMITER_MAX_TRACKED_PATH_SHAPES_MAX: usize = 262_144;
const EVENT_LOG_BACKUP_COUNT_MAX: u32 = 128;
const EVENT_LOG_QUEUE_CAPACITY_MAX: usize = 8_192;
const HYPER_HTTP1_MIN_BUFFER_BYTES: usize = 8 * 1024;
const HTTP_HEADER_BUFFER_MAX_BYTES: usize = 256 * 1024;
const HTTP_HEADER_LINE_MAX_BYTES: usize = HTTP_HEADER_BUFFER_MAX_BYTES;
const HTTP_HEADER_COUNT_MAX: usize = 1024;
const HTTP_HOST_MAX_BYTES_MAX: usize = 1024;
const HTTP_REQUEST_TARGET_MAX_BYTES: usize = 64 * 1024;
const HTTP_QUERY_PAIR_COUNT_MAX: usize = 8_192;
const HTTP_PATH_SEGMENT_COUNT_MAX: usize = 4_096;
const HTTP_HEADER_READ_TIMEOUT_MAX_MS: u64 = 60_000;
const HTTP_DOWNSTREAM_WRITE_TIMEOUT_MAX_MS: u64 = 60_000;
const HTTP_BODY_IDLE_TIMEOUT_MAX_MS: u64 = 60_000;
const HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX: u64 = 1_048_576;
const HTTP_BODY_MIN_RATE_GRACE_MAX_MS: u64 = 60_000;
const HTTP_MAX_BODY_BYTES_MAX: u64 = 1_073_741_824;
const HTTP_MAX_UPSTREAM_BODY_BYTES_MAX: u64 = 1_073_741_824;
const HTTP_TRAILER_BYTES_MAX: usize = HTTP_HEADER_BUFFER_MAX_BYTES;
const HTTP_TRAILER_COUNT_MAX: usize = HTTP_HEADER_COUNT_MAX;
const HTTP_FORWARDED_FOR_BYTES_MAX: usize = 16 * 1024;
const HTTP_FORWARDED_FOR_HOPS_MAX: usize = 256;
const HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS: u64 = 60_000;
const HTTP_UPSTREAM_TIMEOUT_MAX_MS: u64 = 60_000;
const HTTP_UPSTREAM_FAILURE_THRESHOLD_MAX: u32 = 1_024;
const HTTP_UPSTREAM_FAILURE_OPEN_MAX_MS: u64 = 300_000;
const HTTP_UPSTREAM_POOL_IDLE_TIMEOUT_MAX_MS: u64 = 60_000;
const HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST_MAX: usize = 4_096;
const HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS: u64 = 3_600;
const HTTP_MAX_REQUESTS_PER_CONNECTION_MAX: u64 = 10_000;
const TCP_CONNECT_TIMEOUT_MAX_MS: u64 = 60_000;
const TCP_MIN_RATE_BYTES_PER_SECOND_MAX: u64 = 1_048_576;
const TCP_MAX_CONNECTION_DURATION_MAX_SECONDS: u64 = 3_600;
const DEFAULT_RUNTIME_SHUTDOWN_GRACE_MS: u64 = 2_000;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub http: Option<HttpConfig>,
    #[serde(default)]
    pub tcp: Vec<TcpProxyConfig>,
    #[serde(default)]
    pub filters: FilterConfig,
    #[serde(default)]
    pub adaptive: AdaptiveConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub min_nofile: u64,
    #[serde(default = "default_runtime_shutdown_grace_ms")]
    pub shutdown_grace_ms: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            min_nofile: 0,
            shutdown_grace_ms: default_runtime_shutdown_grace_ms(),
        }
    }
}

impl AppConfig {
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, BoxError> {
        let path = path.into();
        let raw = read_config_file(&path, DEFAULT_CONFIG_MAX_BYTES)?;
        let mut cfg: Self = serde_json::from_str(&raw)?;
        cfg.filters
            .resolve_relative_paths(path.parent().map(PathBuf::from));
        cfg.adaptive
            .resolve_relative_paths(path.parent().map(PathBuf::from));
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), BoxError> {
        validate_filter_config(&self.filters)?;
        validate_adaptive_config(&self.adaptive)?;
        if let Some(http) = &self.http {
            validate_http_endpoint_config(http)?;
            validate_http_admin_path_prefix(http)?;
            validate_http_admin_token(http)?;
            validate_http_allowed_methods(http)?;
            validate_http_allowed_hosts(http)?;
            validate_http_trusted_proxy_config(http)?;
            validate_http_rate_limits(http)?;
            validate_http_capacity_limits(http)?;
        }
        for (idx, tcp) in self.tcp.iter().enumerate() {
            validate_tcp_endpoint_config(idx, tcp)?;
            validate_tcp_rate_limits(idx, tcp)?;
            validate_tcp_capacity_limits(idx, tcp)?;
        }
        Ok(())
    }
}

fn read_config_file(path: &Path, max_bytes: u64) -> Result<String, BoxError> {
    validate_positive_u64("config.max_bytes", max_bytes)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(format!("config file {} must be a regular file", path.display()).into());
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "config file {} is {} bytes, above configured cap of {} bytes",
            path.display(),
            metadata.len(),
            max_bytes
        )
        .into());
    }

    let file = fs::File::open(path)?;
    let mut limited = file.take(max_bytes.saturating_add(1));
    let mut raw = Vec::new();
    limited.read_to_end(&mut raw)?;
    if raw.len() as u64 > max_bytes {
        return Err(format!(
            "config file {} exceeded configured read cap of {} bytes",
            path.display(),
            max_bytes
        )
        .into());
    }

    Ok(String::from_utf8(raw)?)
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    pub listen: String,
    pub upstream: String,
    #[serde(default = "default_true")]
    pub preserve_host: bool,
    #[serde(default = "default_admin_prefix")]
    pub admin_path_prefix: String,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default = "default_http_allowed_methods")]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allow_method_override_headers: bool,
    #[serde(default = "default_true")]
    pub require_host_header: bool,
    #[serde(default = "default_http_max_host_bytes")]
    pub max_host_bytes: usize,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default = "default_listen_backlog")]
    pub listen_backlog: u32,
    #[serde(default = "default_accept_shards")]
    pub accept_shards: usize,
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_http_max_header_line_bytes")]
    pub max_header_line_bytes: usize,
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    #[serde(default = "default_http_max_uri_bytes")]
    pub max_uri_bytes: usize,
    #[serde(default = "default_http_max_query_bytes")]
    pub max_query_bytes: usize,
    #[serde(default = "default_http_max_query_pairs")]
    pub max_query_pairs: usize,
    #[serde(default = "default_http_max_path_segments")]
    pub max_path_segments: usize,
    #[serde(default = "default_header_read_timeout_ms")]
    pub header_read_timeout_ms: u64,
    #[serde(default)]
    pub downstream_keep_alive: bool,
    #[serde(default = "default_http_downstream_write_timeout_ms")]
    pub downstream_write_timeout_ms: u64,
    #[serde(default = "default_http_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
    #[serde(default = "default_connect_timeout_ms")]
    pub upstream_connect_timeout_ms: u64,
    #[serde(default = "default_http_upstream_failure_threshold")]
    pub upstream_failure_threshold: u32,
    #[serde(default = "default_http_upstream_failure_open_ms")]
    pub upstream_failure_open_ms: u64,
    #[serde(default = "default_http_upstream_pool_idle_timeout_ms")]
    pub upstream_pool_idle_timeout_ms: u64,
    #[serde(default = "default_http_upstream_pool_max_idle_per_host")]
    pub upstream_pool_max_idle_per_host: usize,
    #[serde(default = "default_http_upstream_max_header_bytes")]
    pub upstream_max_header_bytes: usize,
    #[serde(default = "default_http_upstream_max_header_line_bytes")]
    pub upstream_max_header_line_bytes: usize,
    #[serde(default = "default_http_upstream_max_headers")]
    pub upstream_max_headers: usize,
    #[serde(default = "default_http_upstream_body_idle_timeout_ms")]
    pub upstream_body_idle_timeout_ms: u64,
    #[serde(default = "default_http_max_upstream_body_bytes")]
    pub max_upstream_body_bytes: u64,
    #[serde(default = "default_http_upstream_body_min_rate_bytes_per_second")]
    pub upstream_body_min_rate_bytes_per_second: u64,
    #[serde(default = "default_http_upstream_body_min_rate_grace_ms")]
    pub upstream_body_min_rate_grace_ms: u64,
    #[serde(default = "default_http_max_connection_duration_seconds")]
    pub max_connection_duration_seconds: u64,
    #[serde(default = "default_http_max_requests_per_connection")]
    pub max_requests_per_connection: u64,
    #[serde(default = "default_http_max_body_bytes")]
    pub max_body_bytes: u64,
    #[serde(default = "default_request_body_idle_timeout_ms")]
    pub request_body_idle_timeout_ms: u64,
    #[serde(default = "default_request_body_min_rate_bytes_per_second")]
    pub request_body_min_rate_bytes_per_second: u64,
    #[serde(default = "default_request_body_min_rate_grace_ms")]
    pub request_body_min_rate_grace_ms: u64,
    #[serde(default)]
    pub allow_compressed_request_bodies: bool,
    #[serde(default)]
    pub allow_chunked_request_bodies: bool,
    #[serde(default)]
    pub allow_expect_continue: bool,
    #[serde(default = "default_http_max_ranges")]
    pub max_ranges: usize,
    #[serde(default)]
    pub forward_accept_encoding: bool,
    #[serde(default)]
    pub forward_request_trailers: bool,
    #[serde(default = "default_http_max_trailer_bytes")]
    pub max_trailer_bytes: usize,
    #[serde(default = "default_http_max_trailers")]
    pub max_trailers: usize,
    #[serde(default)]
    pub forward_response_trailers: bool,
    #[serde(default = "default_http_max_trailer_bytes")]
    pub upstream_max_trailer_bytes: usize,
    #[serde(default = "default_http_max_trailers")]
    pub upstream_max_trailers: usize,
    #[serde(default)]
    pub client_ip: ClientIpConfig,
    #[serde(default)]
    pub limits: HttpLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientIpConfig {
    #[serde(default = "default_client_ip_header")]
    pub header: String,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_client_ip_max_forwarded_for_bytes")]
    pub max_forwarded_for_bytes: usize,
    #[serde(default = "default_client_ip_max_forwarded_for_hops")]
    pub max_forwarded_for_hops: usize,
}

impl Default for ClientIpConfig {
    fn default() -> Self {
        Self {
            header: default_client_ip_header(),
            trusted_proxies: Vec::new(),
            max_forwarded_for_bytes: default_client_ip_max_forwarded_for_bytes(),
            max_forwarded_for_hops: default_client_ip_max_forwarded_for_hops(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpLimitConfig {
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: f64,
    #[serde(default = "default_per_ip_burst")]
    pub per_ip_burst: u32,
    #[serde(default = "default_ipv4_prefix_len")]
    pub ipv4_prefix_len: u8,
    #[serde(default = "default_ipv6_prefix_len")]
    pub ipv6_prefix_len: u8,
    #[serde(default = "default_global_rps")]
    pub global_rps: f64,
    #[serde(default = "default_global_burst")]
    pub global_burst: u32,
    #[serde(default = "default_trusted_proxy_rps")]
    pub trusted_proxy_rps: f64,
    #[serde(default = "default_trusted_proxy_burst")]
    pub trusted_proxy_burst: u32,
    #[serde(default = "default_trusted_proxy_max_in_flight_requests")]
    pub trusted_proxy_max_in_flight_requests: usize,
    #[serde(default = "default_signature_rps")]
    pub signature_rps: f64,
    #[serde(default = "default_signature_burst")]
    pub signature_burst: u32,
    #[serde(default = "default_max_tracked_signatures")]
    pub max_tracked_signatures: usize,
    #[serde(default = "default_path_shape_rps")]
    pub path_shape_rps: f64,
    #[serde(default = "default_path_shape_burst")]
    pub path_shape_burst: u32,
    #[serde(default = "default_max_tracked_path_shapes")]
    pub max_tracked_path_shapes: usize,
    #[serde(default = "default_http_per_ip_connects_per_second")]
    pub per_ip_connects_per_second: f64,
    #[serde(default = "default_http_per_ip_connect_burst")]
    pub per_ip_connect_burst: u32,
    #[serde(default = "default_http_global_connects_per_second")]
    pub global_connects_per_second: f64,
    #[serde(default = "default_http_global_connect_burst")]
    pub global_connect_burst: u32,
    #[serde(default = "default_http_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_http_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    #[serde(default = "default_http_max_in_flight_requests")]
    pub max_in_flight_requests: usize,
    #[serde(default = "default_http_max_in_flight_requests_per_ip")]
    pub max_in_flight_requests_per_ip: usize,
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
}

impl Default for HttpLimitConfig {
    fn default() -> Self {
        Self {
            per_ip_rps: default_per_ip_rps(),
            per_ip_burst: default_per_ip_burst(),
            ipv4_prefix_len: default_ipv4_prefix_len(),
            ipv6_prefix_len: default_ipv6_prefix_len(),
            global_rps: default_global_rps(),
            global_burst: default_global_burst(),
            trusted_proxy_rps: default_trusted_proxy_rps(),
            trusted_proxy_burst: default_trusted_proxy_burst(),
            trusted_proxy_max_in_flight_requests: default_trusted_proxy_max_in_flight_requests(),
            signature_rps: default_signature_rps(),
            signature_burst: default_signature_burst(),
            max_tracked_signatures: default_max_tracked_signatures(),
            path_shape_rps: default_path_shape_rps(),
            path_shape_burst: default_path_shape_burst(),
            max_tracked_path_shapes: default_max_tracked_path_shapes(),
            per_ip_connects_per_second: default_http_per_ip_connects_per_second(),
            per_ip_connect_burst: default_http_per_ip_connect_burst(),
            global_connects_per_second: default_http_global_connects_per_second(),
            global_connect_burst: default_http_global_connect_burst(),
            max_connections: default_http_max_connections(),
            max_connections_per_ip: default_http_max_connections_per_ip(),
            max_in_flight_requests: default_http_max_in_flight_requests(),
            max_in_flight_requests_per_ip: default_http_max_in_flight_requests_per_ip(),
            max_tracked_ips: default_max_tracked_ips(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpProxyConfig {
    pub name: String,
    pub listen: String,
    pub upstream: String,
    #[serde(default = "default_listen_backlog")]
    pub listen_backlog: u32,
    #[serde(default = "default_accept_shards")]
    pub accept_shards: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_tcp_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_tcp_min_rate_bytes_per_second")]
    pub downstream_min_rate_bytes_per_second: u64,
    #[serde(default = "default_tcp_min_rate_bytes_per_second")]
    pub upstream_min_rate_bytes_per_second: u64,
    #[serde(default = "default_tcp_min_rate_grace_ms")]
    pub min_rate_grace_ms: u64,
    #[serde(default = "default_tcp_max_connection_duration_seconds")]
    pub max_connection_duration_seconds: u64,
    #[serde(default)]
    pub limits: TcpLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpLimitConfig {
    #[serde(default = "default_tcp_connects_per_second")]
    pub per_ip_connects_per_second: f64,
    #[serde(default = "default_tcp_connect_burst")]
    pub per_ip_connect_burst: u32,
    #[serde(default = "default_ipv4_prefix_len")]
    pub ipv4_prefix_len: u8,
    #[serde(default = "default_ipv6_prefix_len")]
    pub ipv6_prefix_len: u8,
    #[serde(default = "default_tcp_global_connects_per_second")]
    pub global_connects_per_second: f64,
    #[serde(default = "default_tcp_global_connect_burst")]
    pub global_connect_burst: u32,
    #[serde(default = "default_tcp_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_tcp_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
}

impl Default for TcpLimitConfig {
    fn default() -> Self {
        Self {
            per_ip_connects_per_second: default_tcp_connects_per_second(),
            per_ip_connect_burst: default_tcp_connect_burst(),
            ipv4_prefix_len: default_ipv4_prefix_len(),
            ipv6_prefix_len: default_ipv6_prefix_len(),
            global_connects_per_second: default_tcp_global_connects_per_second(),
            global_connect_burst: default_tcp_global_connect_burst(),
            max_connections: default_tcp_max_connections(),
            max_connections_per_ip: default_tcp_max_connections_per_ip(),
            max_tracked_ips: default_max_tracked_ips(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilterConfig {
    #[serde(default = "default_runtime_filter_file")]
    pub runtime_file: PathBuf,
    #[serde(default = "default_reload_seconds")]
    pub reload_seconds: u64,
    #[serde(default = "default_runtime_filter_max_bytes")]
    pub max_runtime_file_bytes: u64,
    #[serde(default = "default_runtime_filter_max_rules")]
    pub max_runtime_filters: usize,
    #[serde(default = "default_static_filter_max_rules")]
    pub max_static_filters: usize,
    #[serde(default)]
    pub static_rules: Vec<FilterRule>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            runtime_file: default_runtime_filter_file(),
            reload_seconds: default_reload_seconds(),
            max_runtime_file_bytes: default_runtime_filter_max_bytes(),
            max_runtime_filters: default_runtime_filter_max_rules(),
            max_static_filters: default_static_filter_max_rules(),
            static_rules: Vec::new(),
        }
    }
}

impl FilterConfig {
    fn resolve_relative_paths(&mut self, base: Option<PathBuf>) {
        if self.runtime_file.is_relative() {
            if let Some(base) = base {
                self.runtime_file = base.join(&self.runtime_file);
            }
        }
    }

    pub fn reload_interval(&self) -> Duration {
        Duration::from_secs(self.reload_seconds.max(1))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdaptiveConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_signature_threshold")]
    pub signature_threshold_per_second: u64,
    #[serde(default = "default_activation_ttl_seconds")]
    pub activation_ttl_seconds: u64,
    #[serde(default = "default_attack_event_log")]
    pub event_log: PathBuf,
    #[serde(default = "default_event_log_flush_interval_ms")]
    pub event_log_flush_interval_ms: u64,
    #[serde(default = "default_event_log_max_bytes")]
    pub event_log_max_bytes: u64,
    #[serde(default = "default_event_log_backup_count")]
    pub event_log_backup_count: u32,
    #[serde(default = "default_event_log_queue_capacity")]
    pub event_log_queue_capacity: usize,
    #[serde(default = "default_event_cooldown_seconds")]
    pub event_cooldown_seconds: u64,
    #[serde(default = "default_adaptive_max_signature_windows")]
    pub max_signature_windows: usize,
    #[serde(default = "default_adaptive_max_path_shape_windows")]
    pub max_path_shape_windows: usize,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            signature_threshold_per_second: default_signature_threshold(),
            activation_ttl_seconds: default_activation_ttl_seconds(),
            event_log: default_attack_event_log(),
            event_log_flush_interval_ms: default_event_log_flush_interval_ms(),
            event_log_max_bytes: default_event_log_max_bytes(),
            event_log_backup_count: default_event_log_backup_count(),
            event_log_queue_capacity: default_event_log_queue_capacity(),
            event_cooldown_seconds: default_event_cooldown_seconds(),
            max_signature_windows: default_adaptive_max_signature_windows(),
            max_path_shape_windows: default_adaptive_max_path_shape_windows(),
        }
    }
}

impl AdaptiveConfig {
    fn resolve_relative_paths(&mut self, base: Option<PathBuf>) {
        if self.event_log.is_relative() {
            if let Some(base) = base {
                self.event_log = base.join(&self.event_log);
            }
        }
    }

    pub fn activation_ttl(&self) -> Duration {
        Duration::from_secs(self.activation_ttl_seconds.max(1))
    }

    pub fn event_cooldown(&self) -> Duration {
        Duration::from_secs(self.event_cooldown_seconds.max(1))
    }

    pub fn event_log_flush_interval(&self) -> Duration {
        Duration::from_millis(self.event_log_flush_interval_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedProxyFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustedProxyRange {
    family: TrustedProxyFamily,
    prefix: u8,
}

impl TrustedProxyRange {
    fn trusts_all_peers(self) -> bool {
        self.prefix == 0
    }

    fn family_name(self) -> &'static str {
        match self.family {
            TrustedProxyFamily::V4 => "IPv4",
            TrustedProxyFamily::V6 => "IPv6",
        }
    }
}

fn validate_http_admin_path_prefix(cfg: &HttpConfig) -> Result<(), BoxError> {
    let prefix = cfg.admin_path_prefix.as_str();
    let trimmed = prefix.trim_end_matches('/');
    if !prefix.starts_with('/') {
        return Err(
            "http.admin_path_prefix must start with '/' and use a non-root absolute path prefix such as /__altura"
                .into(),
        );
    }
    if trimmed.is_empty() {
        return Err(
            "http.admin_path_prefix must use a non-root absolute path prefix such as /__altura"
                .into(),
        );
    }
    if prefix.contains('?') || prefix.contains('#') {
        return Err("http.admin_path_prefix must not contain query or fragment markers".into());
    }
    if prefix
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(
            "http.admin_path_prefix must not contain whitespace or control characters".into(),
        );
    }
    Ok(())
}

fn validate_http_admin_token(cfg: &HttpConfig) -> Result<(), BoxError> {
    let Some(token) = &cfg.admin_token else {
        return Ok(());
    };
    if token.is_empty() {
        return Err("http.admin_token must not be empty when configured".into());
    }
    if token.trim().is_empty() {
        return Err("http.admin_token must not be blank when configured".into());
    }
    if token.trim() != token {
        return Err("http.admin_token must not start or end with whitespace".into());
    }
    if token.len() > HTTP_ADMIN_TOKEN_MAX_BYTES {
        return Err(format!(
            "http.admin_token is {} bytes, above configured cap of {}",
            token.len(),
            HTTP_ADMIN_TOKEN_MAX_BYTES
        )
        .into());
    }
    if token.chars().any(char::is_control) {
        return Err("http.admin_token must not contain control characters".into());
    }
    Ok(())
}

fn validate_http_endpoint_config(cfg: &HttpConfig) -> Result<(), BoxError> {
    cfg.listen
        .parse::<SocketAddr>()
        .map_err(|err| format!("invalid http.listen address '{}': {err}", cfg.listen))?;

    let upstream: Uri = cfg
        .upstream
        .parse()
        .map_err(|err| format!("invalid http.upstream URI '{}': {err}", cfg.upstream))?;
    match upstream.scheme_str() {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => {}
        Some(scheme) => {
            return Err(format!(
                "http.upstream must use http:// scheme; unsupported scheme '{scheme}'"
            )
            .into());
        }
        None => return Err("http.upstream must include http:// scheme".into()),
    }
    let Some(authority) = upstream.authority() else {
        return Err("http.upstream must include a host authority".into());
    };
    if authority.as_str().contains('@') {
        return Err("http.upstream must not contain URI userinfo".into());
    }
    if upstream.query().is_some() {
        return Err("http.upstream must not include a query string".into());
    }
    Ok(())
}

fn validate_tcp_endpoint_config(idx: usize, cfg: &TcpProxyConfig) -> Result<(), BoxError> {
    cfg.listen
        .parse::<SocketAddr>()
        .map_err(|err| format!("invalid tcp[{idx}].listen address '{}': {err}", cfg.listen))?;

    if cfg
        .upstream
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(format!(
            "tcp[{idx}].upstream must not contain whitespace or control characters"
        )
        .into());
    }
    if cfg.upstream.contains("://") {
        return Err(format!("tcp[{idx}].upstream must be host:port without a URL scheme").into());
    }
    if cfg.upstream.contains('/') || cfg.upstream.contains('?') || cfg.upstream.contains('#') {
        return Err(
            format!("tcp[{idx}].upstream must not include a path, query, or fragment").into(),
        );
    }

    let upstream: Authority = cfg.upstream.parse().map_err(|err| {
        format!(
            "invalid tcp[{idx}].upstream authority '{}': {err}",
            cfg.upstream
        )
    })?;
    if upstream.as_str().contains('@') {
        return Err(format!("tcp[{idx}].upstream must not contain URI userinfo").into());
    }
    if upstream.host().is_empty() {
        return Err(format!("tcp[{idx}].upstream must include a host").into());
    }
    let Some(port) = upstream.port_u16() else {
        return Err(format!("tcp[{idx}].upstream must include a numeric port").into());
    };
    if port == 0 {
        return Err(format!("tcp[{idx}].upstream port must be greater than zero").into());
    }
    Ok(())
}

fn validate_http_allowed_methods(cfg: &HttpConfig) -> Result<(), BoxError> {
    if cfg.allowed_methods.is_empty() {
        return Err("http.allowed_methods must contain at least one method".into());
    }
    if cfg.allowed_methods.len() > DEFAULT_HTTP_MAX_ALLOWED_METHODS {
        return Err(format!(
            "http.allowed_methods contains {} methods, above configured cap of {}",
            cfg.allowed_methods.len(),
            DEFAULT_HTTP_MAX_ALLOWED_METHODS
        )
        .into());
    }

    for (idx, method) in cfg.allowed_methods.iter().enumerate() {
        if method.is_empty() {
            return Err(format!("http.allowed_methods[{idx}] must not be empty").into());
        }
        if method.len() > DEFAULT_HTTP_MAX_ALLOWED_METHOD_BYTES {
            return Err(format!(
                "http.allowed_methods[{idx}] is {} bytes, above configured cap of {} bytes",
                method.len(),
                DEFAULT_HTTP_MAX_ALLOWED_METHOD_BYTES
            )
            .into());
        }
        if Method::from_bytes(method.as_bytes()).is_err() {
            return Err(
                format!("http.allowed_methods[{idx}] is not a valid HTTP method token").into(),
            );
        }
        if HTTP_UNSUPPORTED_ALLOWED_METHODS
            .iter()
            .any(|unsupported| method.eq_ignore_ascii_case(unsupported))
        {
            return Err(format!(
                "http.allowed_methods[{idx}] must not include unsupported tunnel or diagnostic method '{method}'"
            )
            .into());
        }
        if cfg.allowed_methods[..idx]
            .iter()
            .any(|previous| previous == method)
        {
            return Err(format!("http.allowed_methods[{idx}] duplicates '{method}'").into());
        }
    }
    Ok(())
}

fn validate_http_allowed_hosts(cfg: &HttpConfig) -> Result<(), BoxError> {
    if cfg.allowed_hosts.len() > DEFAULT_HTTP_MAX_ALLOWED_HOSTS {
        return Err(format!(
            "http.allowed_hosts contains {} hosts, above configured cap of {}",
            cfg.allowed_hosts.len(),
            DEFAULT_HTTP_MAX_ALLOWED_HOSTS
        )
        .into());
    }

    let entry_max_bytes = if cfg.max_host_bytes == 0 {
        DEFAULT_HTTP_MAX_ALLOWED_HOST_BYTES
    } else {
        DEFAULT_HTTP_MAX_ALLOWED_HOST_BYTES.min(cfg.max_host_bytes)
    };
    for (idx, host) in cfg.allowed_hosts.iter().enumerate() {
        let path = format!("http.allowed_hosts[{idx}]");
        if host.is_empty() {
            return Err(format!("{path} must not be empty").into());
        }
        if host.trim().is_empty() {
            return Err(format!("{path} must not be blank").into());
        }
        if host.trim() != host {
            return Err(format!("{path} must not start or end with whitespace").into());
        }
        if host.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
            return Err(format!("{path} must not contain whitespace or control characters").into());
        }
        if host.len() > entry_max_bytes {
            return Err(format!(
                "{path} is {} bytes, above configured cap of {} bytes",
                host.len(),
                entry_max_bytes
            )
            .into());
        }
        if host.contains('*') {
            return Err(
                format!("{path} must be an exact host or host:port, not a wildcard").into(),
            );
        }
        let authority: Authority = host
            .parse()
            .map_err(|err| format!("{path} is not a valid HTTP authority: {err}"))?;
        if authority.as_str().contains('@') {
            return Err(format!("{path} must not contain URI userinfo").into());
        }
        let normalized = host.to_ascii_lowercase();
        if cfg.allowed_hosts[..idx]
            .iter()
            .any(|previous| previous.to_ascii_lowercase() == normalized)
        {
            return Err(format!("{path} duplicates '{host}'").into());
        }
    }
    Ok(())
}

fn validate_http_trusted_proxy_config(cfg: &HttpConfig) -> Result<(), BoxError> {
    validate_http_client_ip_header(&cfg.client_ip.header)?;
    validate_trusted_proxy_list_shape(&cfg.client_ip.trusted_proxies)?;

    let listen: SocketAddr = cfg
        .listen
        .parse()
        .map_err(|err| format!("invalid http.listen address '{}': {err}", cfg.listen))?;
    let public_listener = !listen.ip().is_loopback();
    for entry in &cfg.client_ip.trusted_proxies {
        let range = parse_trusted_proxy_range(entry).map_err(|err| {
            format!("invalid http.client_ip.trusted_proxies entry '{entry}': {err}")
        })?;
        if public_listener && range.trusts_all_peers() {
            return Err(format!(
                "http.client_ip.trusted_proxies entry '{entry}' must not trust all {} peers on non-loopback listener {}; configure exact trusted proxy CIDRs instead",
                range.family_name(),
                cfg.listen
            )
            .into());
        }
    }
    Ok(())
}

fn validate_http_client_ip_header(header: &str) -> Result<(), BoxError> {
    if header.is_empty() {
        return Err("http.client_ip.header must not be empty".into());
    }
    if header.trim().is_empty() {
        return Err("http.client_ip.header must not be blank".into());
    }
    if header.trim() != header {
        return Err("http.client_ip.header must not start or end with whitespace".into());
    }
    if header.len() > DEFAULT_HTTP_CLIENT_IP_HEADER_MAX_BYTES {
        return Err(format!(
            "http.client_ip.header is {} bytes, above configured cap of {} bytes",
            header.len(),
            DEFAULT_HTTP_CLIENT_IP_HEADER_MAX_BYTES
        )
        .into());
    }
    HeaderName::from_bytes(header.as_bytes())
        .map_err(|err| format!("http.client_ip.header is not a valid HTTP field name: {err}"))?;
    Ok(())
}

fn validate_trusted_proxy_list_shape(trusted_proxies: &[String]) -> Result<(), BoxError> {
    if trusted_proxies.len() > DEFAULT_HTTP_MAX_TRUSTED_PROXIES {
        return Err(format!(
            "http.client_ip.trusted_proxies contains {} entries, above configured cap of {}",
            trusted_proxies.len(),
            DEFAULT_HTTP_MAX_TRUSTED_PROXIES
        )
        .into());
    }
    for (idx, entry) in trusted_proxies.iter().enumerate() {
        let path = format!("http.client_ip.trusted_proxies[{idx}]");
        if entry.is_empty() {
            return Err(format!("{path} must not be empty").into());
        }
        if entry.trim().is_empty() {
            return Err(format!("{path} must not be blank").into());
        }
        if entry.trim() != entry {
            return Err(format!("{path} must not start or end with whitespace").into());
        }
        if entry
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(format!("{path} must not contain whitespace or control characters").into());
        }
        if entry.len() > DEFAULT_HTTP_MAX_TRUSTED_PROXY_BYTES {
            return Err(format!(
                "{path} is {} bytes, above configured cap of {} bytes",
                entry.len(),
                DEFAULT_HTTP_MAX_TRUSTED_PROXY_BYTES
            )
            .into());
        }
        let normalized = entry.to_ascii_lowercase();
        if trusted_proxies[..idx]
            .iter()
            .any(|previous| previous.to_ascii_lowercase() == normalized)
        {
            return Err(format!("{path} duplicates '{entry}'").into());
        }
    }
    Ok(())
}

fn validate_http_rate_limits(cfg: &HttpConfig) -> Result<(), BoxError> {
    let limits = &cfg.limits;
    for (path, value) in [
        ("http.limits.per_ip_rps", limits.per_ip_rps),
        ("http.limits.global_rps", limits.global_rps),
        ("http.limits.trusted_proxy_rps", limits.trusted_proxy_rps),
        ("http.limits.signature_rps", limits.signature_rps),
        ("http.limits.path_shape_rps", limits.path_shape_rps),
        (
            "http.limits.per_ip_connects_per_second",
            limits.per_ip_connects_per_second,
        ),
        (
            "http.limits.global_connects_per_second",
            limits.global_connects_per_second,
        ),
    ] {
        validate_non_negative_finite_rate(path, value)?;
    }
    validate_ip_prefix_len("http.limits.ipv4_prefix_len", limits.ipv4_prefix_len, 32)?;
    validate_ip_prefix_len("http.limits.ipv6_prefix_len", limits.ipv6_prefix_len, 128)?;
    Ok(())
}

fn validate_http_capacity_limits(cfg: &HttpConfig) -> Result<(), BoxError> {
    for (path, value) in [
        ("http.max_host_bytes", cfg.max_host_bytes),
        ("http.max_header_bytes", cfg.max_header_bytes),
        ("http.max_header_line_bytes", cfg.max_header_line_bytes),
        ("http.max_headers", cfg.max_headers),
        ("http.max_uri_bytes", cfg.max_uri_bytes),
        ("http.max_query_bytes", cfg.max_query_bytes),
        ("http.max_query_pairs", cfg.max_query_pairs),
        ("http.max_path_segments", cfg.max_path_segments),
        (
            "http.upstream_pool_idle_timeout_ms",
            usize::try_from(cfg.upstream_pool_idle_timeout_ms).unwrap_or(usize::MAX),
        ),
        (
            "http.upstream_max_header_bytes",
            cfg.upstream_max_header_bytes,
        ),
        (
            "http.upstream_max_header_line_bytes",
            cfg.upstream_max_header_line_bytes,
        ),
        ("http.upstream_max_headers", cfg.upstream_max_headers),
        (
            "http.upstream_body_idle_timeout_ms",
            usize::try_from(cfg.upstream_body_idle_timeout_ms).unwrap_or(usize::MAX),
        ),
        (
            "http.upstream_failure_threshold",
            cfg.upstream_failure_threshold as usize,
        ),
        (
            "http.upstream_failure_open_ms",
            usize::try_from(cfg.upstream_failure_open_ms).unwrap_or(usize::MAX),
        ),
        (
            "http.max_upstream_body_bytes",
            usize::try_from(cfg.max_upstream_body_bytes).unwrap_or(usize::MAX),
        ),
        (
            "http.max_connection_duration_seconds",
            usize::try_from(cfg.max_connection_duration_seconds).unwrap_or(usize::MAX),
        ),
        (
            "http.max_requests_per_connection",
            usize::try_from(cfg.max_requests_per_connection).unwrap_or(usize::MAX),
        ),
        (
            "http.max_body_bytes",
            usize::try_from(cfg.max_body_bytes).unwrap_or(usize::MAX),
        ),
        (
            "http.request_body_idle_timeout_ms",
            usize::try_from(cfg.request_body_idle_timeout_ms).unwrap_or(usize::MAX),
        ),
        (
            "http.request_body_min_rate_grace_ms",
            usize::try_from(cfg.request_body_min_rate_grace_ms).unwrap_or(usize::MAX),
        ),
        (
            "http.upstream_body_min_rate_grace_ms",
            usize::try_from(cfg.upstream_body_min_rate_grace_ms).unwrap_or(usize::MAX),
        ),
        ("http.max_ranges", cfg.max_ranges),
        ("http.max_trailer_bytes", cfg.max_trailer_bytes),
        ("http.max_trailers", cfg.max_trailers),
        (
            "http.upstream_max_trailer_bytes",
            cfg.upstream_max_trailer_bytes,
        ),
        ("http.upstream_max_trailers", cfg.upstream_max_trailers),
        (
            "http.client_ip.max_forwarded_for_bytes",
            cfg.client_ip.max_forwarded_for_bytes,
        ),
        (
            "http.client_ip.max_forwarded_for_hops",
            cfg.client_ip.max_forwarded_for_hops,
        ),
        ("http.limits.per_ip_burst", cfg.limits.per_ip_burst as usize),
        ("http.limits.global_burst", cfg.limits.global_burst as usize),
        (
            "http.limits.trusted_proxy_burst",
            cfg.limits.trusted_proxy_burst as usize,
        ),
        (
            "http.limits.trusted_proxy_max_in_flight_requests",
            cfg.limits.trusted_proxy_max_in_flight_requests,
        ),
        (
            "http.limits.signature_burst",
            cfg.limits.signature_burst as usize,
        ),
        (
            "http.limits.max_tracked_signatures",
            cfg.limits.max_tracked_signatures,
        ),
        (
            "http.limits.path_shape_burst",
            cfg.limits.path_shape_burst as usize,
        ),
        (
            "http.limits.max_tracked_path_shapes",
            cfg.limits.max_tracked_path_shapes,
        ),
        (
            "http.limits.per_ip_connect_burst",
            cfg.limits.per_ip_connect_burst as usize,
        ),
        (
            "http.limits.global_connect_burst",
            cfg.limits.global_connect_burst as usize,
        ),
        ("http.limits.max_connections", cfg.limits.max_connections),
        (
            "http.limits.max_connections_per_ip",
            cfg.limits.max_connections_per_ip,
        ),
        (
            "http.limits.max_in_flight_requests",
            cfg.limits.max_in_flight_requests,
        ),
        (
            "http.limits.max_in_flight_requests_per_ip",
            cfg.limits.max_in_flight_requests_per_ip,
        ),
        ("http.limits.max_tracked_ips", cfg.limits.max_tracked_ips),
    ] {
        validate_positive_capacity(path, value)?;
    }
    validate_positive_capacity("http.listen_backlog", cfg.listen_backlog as usize)?;
    validate_accept_shards("http.accept_shards", cfg.accept_shards)?;
    validate_max_capacity(
        "http.max_host_bytes",
        cfg.max_host_bytes,
        HTTP_HOST_MAX_BYTES_MAX,
    )?;
    validate_max_capacity(
        "http.max_uri_bytes",
        cfg.max_uri_bytes,
        HTTP_REQUEST_TARGET_MAX_BYTES,
    )?;
    validate_max_capacity(
        "http.max_query_bytes",
        cfg.max_query_bytes,
        HTTP_REQUEST_TARGET_MAX_BYTES,
    )?;
    validate_max_capacity(
        "http.max_query_pairs",
        cfg.max_query_pairs,
        HTTP_QUERY_PAIR_COUNT_MAX,
    )?;
    validate_max_capacity(
        "http.max_path_segments",
        cfg.max_path_segments,
        HTTP_PATH_SEGMENT_COUNT_MAX,
    )?;
    validate_max_u64(
        "http.max_body_bytes",
        cfg.max_body_bytes,
        HTTP_MAX_BODY_BYTES_MAX,
    )?;
    validate_max_u64(
        "http.max_upstream_body_bytes",
        cfg.max_upstream_body_bytes,
        HTTP_MAX_UPSTREAM_BODY_BYTES_MAX,
    )?;
    validate_positive_u64("http.header_read_timeout_ms", cfg.header_read_timeout_ms)?;
    validate_max_u64(
        "http.header_read_timeout_ms",
        cfg.header_read_timeout_ms,
        HTTP_HEADER_READ_TIMEOUT_MAX_MS,
    )?;
    validate_positive_capacity(
        "http.downstream_write_timeout_ms",
        usize::try_from(cfg.downstream_write_timeout_ms).unwrap_or(usize::MAX),
    )?;
    validate_max_u64(
        "http.downstream_write_timeout_ms",
        cfg.downstream_write_timeout_ms,
        HTTP_DOWNSTREAM_WRITE_TIMEOUT_MAX_MS,
    )?;
    validate_max_u64(
        "http.request_body_idle_timeout_ms",
        cfg.request_body_idle_timeout_ms,
        HTTP_BODY_IDLE_TIMEOUT_MAX_MS,
    )?;
    validate_max_u64(
        "http.upstream_body_idle_timeout_ms",
        cfg.upstream_body_idle_timeout_ms,
        HTTP_BODY_IDLE_TIMEOUT_MAX_MS,
    )?;
    validate_max_u64(
        "http.request_body_min_rate_grace_ms",
        cfg.request_body_min_rate_grace_ms,
        HTTP_BODY_MIN_RATE_GRACE_MAX_MS,
    )?;
    validate_max_u64(
        "http.upstream_body_min_rate_grace_ms",
        cfg.upstream_body_min_rate_grace_ms,
        HTTP_BODY_MIN_RATE_GRACE_MAX_MS,
    )?;
    validate_max_u64(
        "http.request_body_min_rate_bytes_per_second",
        cfg.request_body_min_rate_bytes_per_second,
        HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX,
    )?;
    validate_max_u64(
        "http.upstream_body_min_rate_bytes_per_second",
        cfg.upstream_body_min_rate_bytes_per_second,
        HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX,
    )?;
    validate_positive_capacity(
        "http.upstream_timeout_ms",
        usize::try_from(cfg.upstream_timeout_ms).unwrap_or(usize::MAX),
    )?;
    validate_max_u64(
        "http.upstream_timeout_ms",
        cfg.upstream_timeout_ms,
        HTTP_UPSTREAM_TIMEOUT_MAX_MS,
    )?;
    validate_max_u32(
        "http.upstream_failure_threshold",
        cfg.upstream_failure_threshold,
        HTTP_UPSTREAM_FAILURE_THRESHOLD_MAX,
    )?;
    validate_max_u64(
        "http.upstream_failure_open_ms",
        cfg.upstream_failure_open_ms,
        HTTP_UPSTREAM_FAILURE_OPEN_MAX_MS,
    )?;
    validate_positive_capacity(
        "http.upstream_connect_timeout_ms",
        usize::try_from(cfg.upstream_connect_timeout_ms).unwrap_or(usize::MAX),
    )?;
    validate_max_u64(
        "http.upstream_connect_timeout_ms",
        cfg.upstream_connect_timeout_ms,
        HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS,
    )?;
    validate_max_u64(
        "http.upstream_pool_idle_timeout_ms",
        cfg.upstream_pool_idle_timeout_ms,
        HTTP_UPSTREAM_POOL_IDLE_TIMEOUT_MAX_MS,
    )?;
    validate_max_capacity(
        "http.upstream_pool_max_idle_per_host",
        cfg.upstream_pool_max_idle_per_host,
        HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST_MAX,
    )?;
    validate_max_u64(
        "http.max_connection_duration_seconds",
        cfg.max_connection_duration_seconds,
        HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS,
    )?;
    validate_max_u64(
        "http.max_requests_per_connection",
        cfg.max_requests_per_connection,
        HTTP_MAX_REQUESTS_PER_CONNECTION_MAX,
    )?;
    validate_capacity_range(
        "http.max_header_bytes",
        cfg.max_header_bytes,
        HYPER_HTTP1_MIN_BUFFER_BYTES,
        HTTP_HEADER_BUFFER_MAX_BYTES,
    )?;
    validate_capacity_range(
        "http.upstream_max_header_bytes",
        cfg.upstream_max_header_bytes,
        HYPER_HTTP1_MIN_BUFFER_BYTES,
        HTTP_HEADER_BUFFER_MAX_BYTES,
    )?;
    validate_max_capacity(
        "http.max_header_line_bytes",
        cfg.max_header_line_bytes,
        HTTP_HEADER_LINE_MAX_BYTES,
    )?;
    validate_max_capacity(
        "http.upstream_max_header_line_bytes",
        cfg.upstream_max_header_line_bytes,
        HTTP_HEADER_LINE_MAX_BYTES,
    )?;
    validate_related_capacity_at_most(
        "http.max_header_line_bytes",
        cfg.max_header_line_bytes,
        "http.max_header_bytes",
        cfg.max_header_bytes,
    )?;
    validate_related_capacity_at_most(
        "http.upstream_max_header_line_bytes",
        cfg.upstream_max_header_line_bytes,
        "http.upstream_max_header_bytes",
        cfg.upstream_max_header_bytes,
    )?;
    validate_max_capacity("http.max_headers", cfg.max_headers, HTTP_HEADER_COUNT_MAX)?;
    validate_max_capacity(
        "http.upstream_max_headers",
        cfg.upstream_max_headers,
        HTTP_HEADER_COUNT_MAX,
    )?;
    validate_max_capacity(
        "http.max_trailer_bytes",
        cfg.max_trailer_bytes,
        HTTP_TRAILER_BYTES_MAX,
    )?;
    validate_max_capacity(
        "http.upstream_max_trailer_bytes",
        cfg.upstream_max_trailer_bytes,
        HTTP_TRAILER_BYTES_MAX,
    )?;
    validate_max_capacity(
        "http.max_trailers",
        cfg.max_trailers,
        HTTP_TRAILER_COUNT_MAX,
    )?;
    validate_max_capacity(
        "http.upstream_max_trailers",
        cfg.upstream_max_trailers,
        HTTP_TRAILER_COUNT_MAX,
    )?;
    validate_max_capacity(
        "http.client_ip.max_forwarded_for_bytes",
        cfg.client_ip.max_forwarded_for_bytes,
        HTTP_FORWARDED_FOR_BYTES_MAX,
    )?;
    validate_max_capacity(
        "http.client_ip.max_forwarded_for_hops",
        cfg.client_ip.max_forwarded_for_hops,
        HTTP_FORWARDED_FOR_HOPS_MAX,
    )?;
    validate_max_capacity(
        "http.limits.max_tracked_ips",
        cfg.limits.max_tracked_ips,
        LIMITER_MAX_TRACKED_IPS_MAX,
    )?;
    validate_max_capacity(
        "http.limits.max_tracked_signatures",
        cfg.limits.max_tracked_signatures,
        LIMITER_MAX_TRACKED_SIGNATURES_MAX,
    )?;
    validate_max_capacity(
        "http.limits.max_tracked_path_shapes",
        cfg.limits.max_tracked_path_shapes,
        LIMITER_MAX_TRACKED_PATH_SHAPES_MAX,
    )?;
    Ok(())
}

fn validate_tcp_rate_limits(idx: usize, cfg: &TcpProxyConfig) -> Result<(), BoxError> {
    let limits = &cfg.limits;
    validate_non_negative_finite_rate(
        &format!("tcp[{idx}].limits.per_ip_connects_per_second"),
        limits.per_ip_connects_per_second,
    )?;
    validate_non_negative_finite_rate(
        &format!("tcp[{idx}].limits.global_connects_per_second"),
        limits.global_connects_per_second,
    )?;
    validate_ip_prefix_len(
        &format!("tcp[{idx}].limits.ipv4_prefix_len"),
        limits.ipv4_prefix_len,
        32,
    )?;
    validate_ip_prefix_len(
        &format!("tcp[{idx}].limits.ipv6_prefix_len"),
        limits.ipv6_prefix_len,
        128,
    )?;
    Ok(())
}

fn validate_tcp_capacity_limits(idx: usize, cfg: &TcpProxyConfig) -> Result<(), BoxError> {
    validate_positive_capacity("tcp[].listen_backlog", cfg.listen_backlog as usize)
        .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_accept_shards("tcp[].accept_shards", cfg.accept_shards)
        .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_positive_capacity(
        "tcp[].connect_timeout_ms",
        usize::try_from(cfg.connect_timeout_ms).unwrap_or(usize::MAX),
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_max_u64(
        "tcp[].connect_timeout_ms",
        cfg.connect_timeout_ms,
        TCP_CONNECT_TIMEOUT_MAX_MS,
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_positive_capacity(
        "tcp[].idle_timeout_seconds",
        usize::try_from(cfg.idle_timeout_seconds).unwrap_or(usize::MAX),
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_positive_capacity(
        "tcp[].min_rate_grace_ms",
        usize::try_from(cfg.min_rate_grace_ms).unwrap_or(usize::MAX),
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_max_u64(
        "tcp[].downstream_min_rate_bytes_per_second",
        cfg.downstream_min_rate_bytes_per_second,
        TCP_MIN_RATE_BYTES_PER_SECOND_MAX,
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_max_u64(
        "tcp[].upstream_min_rate_bytes_per_second",
        cfg.upstream_min_rate_bytes_per_second,
        TCP_MIN_RATE_BYTES_PER_SECOND_MAX,
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_positive_capacity(
        "tcp[].max_connection_duration_seconds",
        usize::try_from(cfg.max_connection_duration_seconds).unwrap_or(usize::MAX),
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    validate_max_u64(
        "tcp[].max_connection_duration_seconds",
        cfg.max_connection_duration_seconds,
        TCP_MAX_CONNECTION_DURATION_MAX_SECONDS,
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    for (path, value) in [
        (
            "tcp[].limits.per_ip_connect_burst",
            cfg.limits.per_ip_connect_burst as usize,
        ),
        (
            "tcp[].limits.global_connect_burst",
            cfg.limits.global_connect_burst as usize,
        ),
        ("tcp[].limits.max_connections", cfg.limits.max_connections),
        (
            "tcp[].limits.max_connections_per_ip",
            cfg.limits.max_connections_per_ip,
        ),
        ("tcp[].limits.max_tracked_ips", cfg.limits.max_tracked_ips),
    ] {
        validate_positive_capacity(path, value).map_err(|err| qualify_tcp_error(idx, err))?;
    }
    validate_max_capacity(
        "tcp[].limits.max_tracked_ips",
        cfg.limits.max_tracked_ips,
        LIMITER_MAX_TRACKED_IPS_MAX,
    )
    .map_err(|err| qualify_tcp_error(idx, err))?;
    Ok(())
}

fn validate_filter_config(cfg: &FilterConfig) -> Result<(), BoxError> {
    validate_positive_u64("filters.reload_seconds", cfg.reload_seconds)?;
    validate_positive_u64("filters.max_runtime_file_bytes", cfg.max_runtime_file_bytes)?;
    validate_positive_capacity("filters.max_runtime_filters", cfg.max_runtime_filters)?;
    validate_positive_capacity("filters.max_static_filters", cfg.max_static_filters)?;
    validate_max_u64(
        "filters.max_runtime_file_bytes",
        cfg.max_runtime_file_bytes,
        FILTER_RUNTIME_FILE_MAX_BYTES_MAX,
    )?;
    validate_max_capacity(
        "filters.max_runtime_filters",
        cfg.max_runtime_filters,
        FILTER_RULE_COUNT_MAX,
    )?;
    validate_max_capacity(
        "filters.max_static_filters",
        cfg.max_static_filters,
        FILTER_RULE_COUNT_MAX,
    )?;
    validate_filter_rules(
        "filters.static_rules",
        &cfg.static_rules,
        cfg.max_static_filters,
    )?;
    Ok(())
}

fn validate_adaptive_config(cfg: &AdaptiveConfig) -> Result<(), BoxError> {
    for (path, value) in [
        (
            "adaptive.signature_threshold_per_second",
            cfg.signature_threshold_per_second,
        ),
        (
            "adaptive.activation_ttl_seconds",
            cfg.activation_ttl_seconds,
        ),
        (
            "adaptive.event_log_flush_interval_ms",
            cfg.event_log_flush_interval_ms,
        ),
        ("adaptive.event_log_max_bytes", cfg.event_log_max_bytes),
        (
            "adaptive.event_cooldown_seconds",
            cfg.event_cooldown_seconds,
        ),
    ] {
        validate_positive_u64(path, value)?;
    }
    validate_positive_u32(
        "adaptive.event_log_backup_count",
        cfg.event_log_backup_count,
    )?;
    validate_max_u64(
        "adaptive.activation_ttl_seconds",
        cfg.activation_ttl_seconds,
        FILTER_TTL_MAX_SECONDS,
    )?;
    validate_max_u64(
        "adaptive.event_log_max_bytes",
        cfg.event_log_max_bytes,
        ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX,
    )?;
    validate_max_u32(
        "adaptive.event_log_backup_count",
        cfg.event_log_backup_count,
        EVENT_LOG_BACKUP_COUNT_MAX,
    )?;
    validate_positive_capacity(
        "adaptive.event_log_queue_capacity",
        cfg.event_log_queue_capacity,
    )?;
    validate_max_capacity(
        "adaptive.event_log_queue_capacity",
        cfg.event_log_queue_capacity,
        EVENT_LOG_QUEUE_CAPACITY_MAX,
    )?;
    validate_positive_capacity("adaptive.max_signature_windows", cfg.max_signature_windows)?;
    validate_positive_capacity(
        "adaptive.max_path_shape_windows",
        cfg.max_path_shape_windows,
    )?;
    validate_max_capacity(
        "adaptive.max_signature_windows",
        cfg.max_signature_windows,
        ADAPTIVE_WINDOW_COUNT_MAX,
    )?;
    validate_max_capacity(
        "adaptive.max_path_shape_windows",
        cfg.max_path_shape_windows,
        ADAPTIVE_WINDOW_COUNT_MAX,
    )?;
    Ok(())
}

fn qualify_tcp_error(idx: usize, err: BoxError) -> BoxError {
    err.to_string()
        .replace("tcp[]", &format!("tcp[{idx}]"))
        .into()
}

fn validate_non_negative_finite_rate(path: &str, value: f64) -> Result<(), BoxError> {
    if !value.is_finite() || value < 0.0 {
        return Err(format!("{path} must be finite and non-negative, got {value}").into());
    }
    Ok(())
}

fn validate_positive_capacity(path: &str, value: usize) -> Result<(), BoxError> {
    if value == 0 {
        return Err(format!("{path} must be greater than zero").into());
    }
    Ok(())
}

fn validate_accept_shards(path: &str, value: usize) -> Result<(), BoxError> {
    validate_positive_capacity(path, value)?;
    if value > DEFAULT_MAX_ACCEPT_SHARDS {
        return Err(format!("{path} must be no higher than {DEFAULT_MAX_ACCEPT_SHARDS}").into());
    }
    Ok(())
}

fn validate_min_capacity(path: &str, value: usize, min: usize) -> Result<(), BoxError> {
    validate_positive_capacity(path, value)?;
    if value < min {
        return Err(format!("{path} must be at least {min}").into());
    }
    Ok(())
}

fn validate_capacity_range(
    path: &str,
    value: usize,
    min: usize,
    max: usize,
) -> Result<(), BoxError> {
    validate_min_capacity(path, value, min)?;
    if value > max {
        return Err(format!("{path} must be no higher than {max}").into());
    }
    Ok(())
}

fn validate_max_capacity(path: &str, value: usize, max: usize) -> Result<(), BoxError> {
    if value > max {
        return Err(format!("{path} must be no higher than {max}").into());
    }
    Ok(())
}

fn validate_related_capacity_at_most(
    path: &str,
    value: usize,
    ceiling_path: &str,
    ceiling: usize,
) -> Result<(), BoxError> {
    if value > ceiling {
        return Err(format!("{path} must be no higher than {ceiling_path}").into());
    }
    Ok(())
}

fn validate_positive_u64(path: &str, value: u64) -> Result<(), BoxError> {
    if value == 0 {
        return Err(format!("{path} must be greater than zero").into());
    }
    Ok(())
}

fn validate_max_u64(path: &str, value: u64, max: u64) -> Result<(), BoxError> {
    if value > max {
        return Err(format!("{path} must be no higher than {max}").into());
    }
    Ok(())
}

fn validate_positive_u32(path: &str, value: u32) -> Result<(), BoxError> {
    if value == 0 {
        return Err(format!("{path} must be greater than zero").into());
    }
    Ok(())
}

fn validate_max_u32(path: &str, value: u32, max: u32) -> Result<(), BoxError> {
    if value > max {
        return Err(format!("{path} must be no higher than {max}").into());
    }
    Ok(())
}

fn validate_ip_prefix_len(path: &str, value: u8, max: u8) -> Result<(), BoxError> {
    if value == 0 || value > max {
        return Err(format!("{path} must be between 1 and {max}, got {value}").into());
    }
    Ok(())
}

fn parse_trusted_proxy_range(raw: &str) -> Result<TrustedProxyRange, String> {
    let raw = raw.trim();
    let (ip_raw, prefix_raw) = raw
        .split_once('/')
        .map(|(ip, prefix)| (ip.trim(), Some(prefix.trim())))
        .unwrap_or((raw, None));
    let ip: IpAddr = ip_raw
        .parse()
        .map_err(|err| format!("invalid IP address: {err}"))?;
    match ip {
        IpAddr::V4(_) => Ok(TrustedProxyRange {
            family: TrustedProxyFamily::V4,
            prefix: parse_trusted_proxy_prefix(prefix_raw, 32)?,
        }),
        IpAddr::V6(_) => Ok(TrustedProxyRange {
            family: TrustedProxyFamily::V6,
            prefix: parse_trusted_proxy_prefix(prefix_raw, 128)?,
        }),
    }
}

fn parse_trusted_proxy_prefix(raw: Option<&str>, max: u8) -> Result<u8, String> {
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

fn default_true() -> bool {
    true
}

fn default_admin_prefix() -> String {
    "/__altura".to_string()
}

fn default_http_allowed_methods() -> Vec<String> {
    ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn default_http_max_host_bytes() -> usize {
    255
}

fn default_listen_backlog() -> u32 {
    4096
}

fn default_accept_shards() -> usize {
    1
}

fn default_runtime_shutdown_grace_ms() -> u64 {
    DEFAULT_RUNTIME_SHUTDOWN_GRACE_MS
}

fn default_max_header_bytes() -> usize {
    32 * 1024
}

fn default_http_max_header_line_bytes() -> usize {
    8 * 1024
}

fn default_max_headers() -> usize {
    100
}

fn default_http_max_uri_bytes() -> usize {
    8 * 1024
}

fn default_http_max_query_bytes() -> usize {
    4 * 1024
}

fn default_http_max_query_pairs() -> usize {
    128
}

fn default_http_max_path_segments() -> usize {
    64
}

fn default_header_read_timeout_ms() -> u64 {
    5_000
}

fn default_http_downstream_write_timeout_ms() -> u64 {
    15_000
}

fn default_http_upstream_timeout_ms() -> u64 {
    15_000
}

fn default_http_upstream_failure_threshold() -> u32 {
    8
}

fn default_http_upstream_failure_open_ms() -> u64 {
    1_000
}

fn default_http_upstream_pool_idle_timeout_ms() -> u64 {
    30_000
}

fn default_http_upstream_pool_max_idle_per_host() -> usize {
    256
}

fn default_http_upstream_max_header_bytes() -> usize {
    32 * 1024
}

fn default_http_upstream_max_header_line_bytes() -> usize {
    8 * 1024
}

fn default_http_upstream_max_headers() -> usize {
    100
}

fn default_http_upstream_body_idle_timeout_ms() -> u64 {
    15_000
}

fn default_http_max_upstream_body_bytes() -> u64 {
    100 * 1024 * 1024
}

fn default_http_upstream_body_min_rate_bytes_per_second() -> u64 {
    512
}

fn default_http_upstream_body_min_rate_grace_ms() -> u64 {
    10_000
}

fn default_http_max_connection_duration_seconds() -> u64 {
    120
}

fn default_http_max_requests_per_connection() -> u64 {
    1_000
}

fn default_http_max_body_bytes() -> u64 {
    10 * 1024 * 1024
}

fn default_request_body_idle_timeout_ms() -> u64 {
    10_000
}

fn default_request_body_min_rate_bytes_per_second() -> u64 {
    512
}

fn default_request_body_min_rate_grace_ms() -> u64 {
    10_000
}

fn default_http_max_ranges() -> usize {
    1
}

fn default_http_max_trailer_bytes() -> usize {
    8 * 1024
}

fn default_http_max_trailers() -> usize {
    32
}

fn default_client_ip_header() -> String {
    "x-forwarded-for".to_string()
}

fn default_client_ip_max_forwarded_for_bytes() -> usize {
    1024
}

fn default_client_ip_max_forwarded_for_hops() -> usize {
    32
}

fn default_per_ip_rps() -> f64 {
    200.0
}

fn default_per_ip_burst() -> u32 {
    400
}

fn default_ipv4_prefix_len() -> u8 {
    32
}

fn default_ipv6_prefix_len() -> u8 {
    64
}

fn default_global_rps() -> f64 {
    20_000.0
}

fn default_global_burst() -> u32 {
    40_000
}

fn default_trusted_proxy_rps() -> f64 {
    5_000.0
}

fn default_trusted_proxy_burst() -> u32 {
    10_000
}

fn default_trusted_proxy_max_in_flight_requests() -> usize {
    4_096
}

fn default_signature_rps() -> f64 {
    5_000.0
}

fn default_signature_burst() -> u32 {
    10_000
}

fn default_max_tracked_signatures() -> usize {
    8_192
}

fn default_path_shape_rps() -> f64 {
    10_000.0
}

fn default_path_shape_burst() -> u32 {
    20_000
}

fn default_max_tracked_path_shapes() -> usize {
    4_096
}

fn default_http_per_ip_connects_per_second() -> f64 {
    default_per_ip_rps()
}

fn default_http_per_ip_connect_burst() -> u32 {
    default_per_ip_burst()
}

fn default_http_global_connects_per_second() -> f64 {
    20_000.0
}

fn default_http_global_connect_burst() -> u32 {
    40_000
}

fn default_http_max_connections() -> usize {
    10_000
}

fn default_http_max_connections_per_ip() -> usize {
    1_024
}

fn default_http_max_in_flight_requests() -> usize {
    8_192
}

fn default_http_max_in_flight_requests_per_ip() -> usize {
    512
}

fn default_max_tracked_ips() -> usize {
    65_536
}

fn default_tcp_connects_per_second() -> f64 {
    25.0
}

fn default_tcp_connect_burst() -> u32 {
    50
}

fn default_tcp_global_connects_per_second() -> f64 {
    20_000.0
}

fn default_tcp_global_connect_burst() -> u32 {
    40_000
}

fn default_tcp_max_connections() -> usize {
    10_000
}

fn default_tcp_max_connections_per_ip() -> usize {
    128
}

fn default_connect_timeout_ms() -> u64 {
    1000
}

fn default_tcp_idle_timeout_seconds() -> u64 {
    60
}

fn default_tcp_min_rate_bytes_per_second() -> u64 {
    512
}

fn default_tcp_min_rate_grace_ms() -> u64 {
    10_000
}

fn default_tcp_max_connection_duration_seconds() -> u64 {
    300
}

fn default_runtime_filter_file() -> PathBuf {
    PathBuf::from("runtime/filters.json")
}

fn default_reload_seconds() -> u64 {
    2
}

fn default_runtime_filter_max_bytes() -> u64 {
    DEFAULT_RUNTIME_FILTER_MAX_BYTES
}

fn default_runtime_filter_max_rules() -> usize {
    DEFAULT_RUNTIME_FILTER_MAX_RULES
}

fn default_static_filter_max_rules() -> usize {
    DEFAULT_STATIC_FILTER_MAX_RULES
}

fn default_signature_threshold() -> u64 {
    300
}

fn default_activation_ttl_seconds() -> u64 {
    60
}

fn default_attack_event_log() -> PathBuf {
    PathBuf::from("runtime/attack_events.jsonl")
}

fn default_event_log_flush_interval_ms() -> u64 {
    100
}

fn default_event_log_max_bytes() -> u64 {
    DEFAULT_EVENT_LOG_MAX_BYTES
}

fn default_event_log_backup_count() -> u32 {
    DEFAULT_EVENT_LOG_BACKUP_COUNT
}

fn default_event_log_queue_capacity() -> usize {
    DEFAULT_EVENT_LOG_QUEUE_CAPACITY
}

fn default_adaptive_max_signature_windows() -> usize {
    8_192
}

fn default_adaptive_max_path_shape_windows() -> usize {
    8_192
}

fn default_event_cooldown_seconds() -> u64 {
    5
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        AdaptiveConfig, AppConfig, FilterConfig, HttpConfig, ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX,
        ADAPTIVE_WINDOW_COUNT_MAX, DEFAULT_CONFIG_MAX_BYTES,
        DEFAULT_HTTP_CLIENT_IP_HEADER_MAX_BYTES, DEFAULT_HTTP_MAX_ALLOWED_HOSTS,
        DEFAULT_HTTP_MAX_ALLOWED_HOST_BYTES, DEFAULT_HTTP_MAX_ALLOWED_METHODS,
        DEFAULT_HTTP_MAX_ALLOWED_METHOD_BYTES, DEFAULT_HTTP_MAX_TRUSTED_PROXIES,
        DEFAULT_HTTP_MAX_TRUSTED_PROXY_BYTES, DEFAULT_RUNTIME_SHUTDOWN_GRACE_MS,
        EVENT_LOG_BACKUP_COUNT_MAX, EVENT_LOG_QUEUE_CAPACITY_MAX, FILTER_RULE_COUNT_MAX,
        FILTER_RUNTIME_FILE_MAX_BYTES_MAX, FILTER_TTL_MAX_SECONDS, HTTP_ADMIN_TOKEN_MAX_BYTES,
        HTTP_BODY_IDLE_TIMEOUT_MAX_MS, HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX,
        HTTP_BODY_MIN_RATE_GRACE_MAX_MS, HTTP_DOWNSTREAM_WRITE_TIMEOUT_MAX_MS,
        HTTP_FORWARDED_FOR_BYTES_MAX, HTTP_FORWARDED_FOR_HOPS_MAX, HTTP_HEADER_BUFFER_MAX_BYTES,
        HTTP_HEADER_COUNT_MAX, HTTP_HEADER_READ_TIMEOUT_MAX_MS, HTTP_HOST_MAX_BYTES_MAX,
        HTTP_MAX_BODY_BYTES_MAX, HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS,
        HTTP_MAX_REQUESTS_PER_CONNECTION_MAX, HTTP_MAX_UPSTREAM_BODY_BYTES_MAX,
        HTTP_PATH_SEGMENT_COUNT_MAX, HTTP_QUERY_PAIR_COUNT_MAX, HTTP_REQUEST_TARGET_MAX_BYTES,
        HTTP_TRAILER_BYTES_MAX, HTTP_TRAILER_COUNT_MAX, HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS,
        HTTP_UPSTREAM_FAILURE_OPEN_MAX_MS, HTTP_UPSTREAM_FAILURE_THRESHOLD_MAX,
        HTTP_UPSTREAM_POOL_IDLE_TIMEOUT_MAX_MS, HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST_MAX,
        HTTP_UPSTREAM_TIMEOUT_MAX_MS, LIMITER_MAX_TRACKED_IPS_MAX,
        LIMITER_MAX_TRACKED_PATH_SHAPES_MAX, LIMITER_MAX_TRACKED_SIGNATURES_MAX,
        TCP_CONNECT_TIMEOUT_MAX_MS, TCP_MAX_CONNECTION_DURATION_MAX_SECONDS,
        TCP_MIN_RATE_BYTES_PER_SECOND_MAX,
    };

    fn temp_config_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "altura-prot-{name}-{}-{unique}.json",
            std::process::id()
        ))
    }

    fn app_config_with_allowed_methods(methods: Vec<String>) -> AppConfig {
        serde_json::from_value(serde_json::json!({
            "http": {
                "listen": "127.0.0.1:8080",
                "upstream": "http://127.0.0.1:1",
                "allowed_methods": methods
            }
        }))
        .unwrap()
    }

    fn app_config_with_allowed_hosts(hosts: Vec<String>) -> AppConfig {
        serde_json::from_value(serde_json::json!({
            "http": {
                "listen": "127.0.0.1:8080",
                "upstream": "http://127.0.0.1:1",
                "allowed_hosts": hosts
            }
        }))
        .unwrap()
    }

    fn app_config_with_client_ip(client_ip: serde_json::Value) -> AppConfig {
        serde_json::from_value(serde_json::json!({
            "http": {
                "listen": "127.0.0.1:8080",
                "upstream": "http://127.0.0.1:1",
                "client_ip": client_ip
            }
        }))
        .unwrap()
    }

    #[test]
    fn app_config_accepts_runtime_nofile_floor() {
        let cfg: AppConfig =
            serde_json::from_str(r#"{"runtime":{"min_nofile":65536,"shutdown_grace_ms":2500}}"#)
                .unwrap();

        assert_eq!(cfg.runtime.min_nofile, 65_536);
        assert_eq!(cfg.runtime.shutdown_grace_ms, 2_500);
    }

    #[test]
    fn runtime_config_defaults_to_nonzero_shutdown_grace() {
        let cfg: AppConfig = serde_json::from_str("{}").unwrap();

        assert_eq!(
            cfg.runtime.shutdown_grace_ms,
            DEFAULT_RUNTIME_SHUTDOWN_GRACE_MS
        );
    }

    #[test]
    fn filter_config_accepts_runtime_reload_bounds() {
        let default_cfg: FilterConfig = serde_json::from_str("{}").unwrap();
        let custom_cfg: FilterConfig = serde_json::from_str(
            r#"{"runtime_file":"runtime/custom-filters.json","reload_seconds":5,"max_runtime_file_bytes":4096,"max_runtime_filters":32}"#,
        )
        .unwrap();

        assert_eq!(default_cfg.reload_seconds, 2);
        assert_eq!(default_cfg.max_runtime_file_bytes, 1024 * 1024);
        assert_eq!(default_cfg.max_runtime_filters, 1024);
        assert_eq!(default_cfg.max_static_filters, 1024);
        assert_eq!(custom_cfg.reload_seconds, 5);
        assert_eq!(custom_cfg.max_runtime_file_bytes, 4096);
        assert_eq!(custom_cfg.max_runtime_filters, 32);
    }

    #[test]
    fn app_config_rejects_zero_filter_capacity_limits() {
        for (snippet, path) in [
            (r#""reload_seconds":0"#, "filters.reload_seconds"),
            (
                r#""max_runtime_file_bytes":0"#,
                "filters.max_runtime_file_bytes",
            ),
            (r#""max_runtime_filters":0"#, "filters.max_runtime_filters"),
            (r#""max_static_filters":0"#, "filters.max_static_filters"),
        ] {
            let raw = format!(r#"{{"filters":{{{snippet}}}}}"#);
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be greater than zero"), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_static_filter_rule_capacity_and_shape_errors() {
        for (raw, expected) in [
            (
                r#"{"filters":{"max_static_filters":1,"static_rules":[{"id":"one","condition":{"path_exact":"/one"}},{"id":"two","condition":{"path_exact":"/two"}}]}}"#,
                "filters.static_rules contains 2 filters",
            ),
            (
                r#"{"filters":{"static_rules":[{"id":"","condition":{"path_exact":"/bad"}}]}}"#,
                "filters.static_rules[0].id",
            ),
            (
                r#"{"filters":{"static_rules":[{"id":"catchall"}]}}"#,
                "filters.static_rules[0].condition must include at least one matcher",
            ),
            (
                r#"{"filters":{"static_rules":[{"id":"bad-action","condition":{"path_exact":"/bad"},"action":{"kind":"allow","status":403,"body":"blocked\n"}}]}}"#,
                "filters.static_rules[0].action.kind",
            ),
            (
                r#"{"filters":{"static_rules":[{"id":"bad-status","condition":{"path_exact":"/bad"},"action":{"kind":"block","status":200,"body":"blocked\n"}}]}}"#,
                "filters.static_rules[0].action.status",
            ),
            (
                r#"{"filters":{"static_rules":[{"id":"bad-header","condition":{"headers":[{"name":"bad header","contains":"x"}]}}]}}"#,
                "filters.static_rules[0].condition.headers[0].name",
            ),
        ] {
            let cfg: AppConfig = serde_json::from_str(raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_zero_adaptive_capacity_limits() {
        for (snippet, path) in [
            (
                r#""signature_threshold_per_second":0"#,
                "adaptive.signature_threshold_per_second",
            ),
            (
                r#""activation_ttl_seconds":0"#,
                "adaptive.activation_ttl_seconds",
            ),
            (
                r#""event_log_flush_interval_ms":0"#,
                "adaptive.event_log_flush_interval_ms",
            ),
            (r#""event_log_max_bytes":0"#, "adaptive.event_log_max_bytes"),
            (
                r#""event_log_backup_count":0"#,
                "adaptive.event_log_backup_count",
            ),
            (
                r#""event_log_queue_capacity":0"#,
                "adaptive.event_log_queue_capacity",
            ),
            (
                r#""event_cooldown_seconds":0"#,
                "adaptive.event_cooldown_seconds",
            ),
            (
                r#""max_signature_windows":0"#,
                "adaptive.max_signature_windows",
            ),
            (
                r#""max_path_shape_windows":0"#,
                "adaptive.max_path_shape_windows",
            ),
        ] {
            let raw = format!(r#"{{"adaptive":{{{snippet}}}}}"#);
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be greater than zero"), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_control_plane_state_caps_above_startup_ceiling() {
        let cases = [
            (
                format!(
                    r#"{{"filters":{{"max_runtime_file_bytes":{}}}}}"#,
                    FILTER_RUNTIME_FILE_MAX_BYTES_MAX + 1
                ),
                "filters.max_runtime_file_bytes",
                FILTER_RUNTIME_FILE_MAX_BYTES_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"filters":{{"max_runtime_filters":{}}}}}"#,
                    FILTER_RULE_COUNT_MAX + 1
                ),
                "filters.max_runtime_filters",
                FILTER_RULE_COUNT_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"filters":{{"max_static_filters":{}}}}}"#,
                    FILTER_RULE_COUNT_MAX + 1
                ),
                "filters.max_static_filters",
                FILTER_RULE_COUNT_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"adaptive":{{"event_log_max_bytes":{}}}}}"#,
                    ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX + 1
                ),
                "adaptive.event_log_max_bytes",
                ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"adaptive":{{"max_signature_windows":{}}}}}"#,
                    ADAPTIVE_WINDOW_COUNT_MAX + 1
                ),
                "adaptive.max_signature_windows",
                ADAPTIVE_WINDOW_COUNT_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"adaptive":{{"max_path_shape_windows":{}}}}}"#,
                    ADAPTIVE_WINDOW_COUNT_MAX + 1
                ),
                "adaptive.max_path_shape_windows",
                ADAPTIVE_WINDOW_COUNT_MAX.to_string(),
            ),
        ];

        for (raw, path, ceiling) in cases {
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_control_plane_state_caps_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{
                "filters": {{
                    "max_runtime_file_bytes": {},
                    "max_runtime_filters": {},
                    "max_static_filters": {}
                }},
                "adaptive": {{
                    "event_log_max_bytes": {},
                    "max_signature_windows": {},
                    "max_path_shape_windows": {}
                }}
            }}"#,
            FILTER_RUNTIME_FILE_MAX_BYTES_MAX,
            FILTER_RULE_COUNT_MAX,
            FILTER_RULE_COUNT_MAX,
            ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX,
            ADAPTIVE_WINDOW_COUNT_MAX,
            ADAPTIVE_WINDOW_COUNT_MAX
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_limiter_state_caps_above_startup_ceiling() {
        let cases = [
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","limits":{{"max_tracked_ips":{}}}}}}}"#,
                    LIMITER_MAX_TRACKED_IPS_MAX + 1
                ),
                "http.limits.max_tracked_ips",
                LIMITER_MAX_TRACKED_IPS_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","limits":{{"max_tracked_signatures":{}}}}}}}"#,
                    LIMITER_MAX_TRACKED_SIGNATURES_MAX + 1
                ),
                "http.limits.max_tracked_signatures",
                LIMITER_MAX_TRACKED_SIGNATURES_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","limits":{{"max_tracked_path_shapes":{}}}}}}}"#,
                    LIMITER_MAX_TRACKED_PATH_SHAPES_MAX + 1
                ),
                "http.limits.max_tracked_path_shapes",
                LIMITER_MAX_TRACKED_PATH_SHAPES_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:8081","upstream":"127.0.0.1:1","limits":{{"max_tracked_ips":{}}}}}]}}"#,
                    LIMITER_MAX_TRACKED_IPS_MAX + 1
                ),
                "tcp[0].limits.max_tracked_ips",
                LIMITER_MAX_TRACKED_IPS_MAX.to_string(),
            ),
        ];

        for (raw, path, ceiling) in cases {
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_limiter_state_caps_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{
                "http": {{
                    "listen": "127.0.0.1:8080",
                    "upstream": "http://127.0.0.1:1",
                    "limits": {{
                        "max_tracked_ips": {},
                        "max_tracked_signatures": {},
                        "max_tracked_path_shapes": {}
                    }}
                }},
                "tcp": [{{
                    "name": "tcp",
                    "listen": "127.0.0.1:8081",
                    "upstream": "127.0.0.1:1",
                    "limits": {{
                        "max_tracked_ips": {}
                    }}
                }}]
            }}"#,
            LIMITER_MAX_TRACKED_IPS_MAX,
            LIMITER_MAX_TRACKED_SIGNATURES_MAX,
            LIMITER_MAX_TRACKED_PATH_SHAPES_MAX,
            LIMITER_MAX_TRACKED_IPS_MAX
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_from_path_rejects_oversized_config_file() {
        let path = temp_config_path("oversized-config");
        let oversized = format!(
            r#"{{"padding":"{}"}}"#,
            "x".repeat(DEFAULT_CONFIG_MAX_BYTES as usize)
        );
        fs::write(&path, oversized).unwrap();

        let err = AppConfig::from_path(path.clone()).unwrap_err().to_string();

        assert!(err.contains("config file"), "{err}");
        assert!(err.contains("above configured cap"), "{err}");
        assert!(err.contains(&DEFAULT_CONFIG_MAX_BYTES.to_string()), "{err}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn app_config_from_path_rejects_non_regular_config_file() {
        let path = temp_config_path("config-dir");
        fs::create_dir(&path).unwrap();

        let err = AppConfig::from_path(path.clone()).unwrap_err().to_string();

        assert!(err.contains("config file"), "{err}");
        assert!(err.contains("must be a regular file"), "{err}");
        let _ = fs::remove_dir(path);
    }

    #[test]
    fn http_config_defaults_header_count_cap() {
        let cfg: HttpConfig =
            serde_json::from_str(r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1"}"#)
                .unwrap();

        assert_eq!(cfg.max_headers, 100);
        assert_eq!(cfg.listen_backlog, 4096);
        assert_eq!(cfg.max_header_bytes, 32 * 1024);
        assert_eq!(cfg.max_header_line_bytes, 8 * 1024);
        assert_eq!(cfg.max_uri_bytes, 8 * 1024);
        assert_eq!(cfg.max_query_bytes, 4 * 1024);
        assert_eq!(cfg.max_query_pairs, 128);
        assert_eq!(cfg.max_path_segments, 64);
        assert_eq!(cfg.limits.ipv4_prefix_len, 32);
        assert_eq!(cfg.limits.ipv6_prefix_len, 64);
        assert_eq!(cfg.limits.trusted_proxy_rps, 5_000.0);
        assert_eq!(cfg.limits.trusted_proxy_burst, 10_000);
        assert_eq!(cfg.limits.trusted_proxy_max_in_flight_requests, 4_096);
        assert_eq!(cfg.limits.signature_rps, 5_000.0);
        assert_eq!(cfg.limits.signature_burst, 10_000);
        assert_eq!(cfg.limits.max_tracked_signatures, 8_192);
        assert_eq!(cfg.limits.path_shape_rps, 10_000.0);
        assert_eq!(cfg.limits.path_shape_burst, 20_000);
        assert_eq!(cfg.limits.max_tracked_path_shapes, 4_096);
        assert_eq!(cfg.limits.per_ip_connects_per_second, 200.0);
        assert_eq!(cfg.limits.per_ip_connect_burst, 400);
        assert_eq!(cfg.limits.global_connects_per_second, 20_000.0);
        assert_eq!(cfg.limits.global_connect_burst, 40_000);
        assert!(cfg.limits.per_ip_connects_per_second < cfg.limits.global_connects_per_second);
        assert!(cfg.limits.per_ip_connect_burst < cfg.limits.global_connect_burst);
        assert_eq!(
            cfg.allowed_methods,
            ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        );
        assert!(cfg.require_host_header);
        assert_eq!(cfg.max_host_bytes, 255);
        assert!(cfg.allowed_hosts.is_empty());
        assert_eq!(cfg.upstream_pool_idle_timeout_ms, 30_000);
        assert_eq!(cfg.upstream_connect_timeout_ms, 1_000);
        assert_eq!(cfg.upstream_failure_threshold, 8);
        assert_eq!(cfg.upstream_failure_open_ms, 1_000);
        assert_eq!(cfg.upstream_pool_max_idle_per_host, 256);
        assert_eq!(cfg.upstream_max_header_bytes, 32 * 1024);
        assert_eq!(cfg.upstream_max_header_line_bytes, 8 * 1024);
        assert_eq!(cfg.upstream_max_headers, 100);
        assert_eq!(cfg.request_body_min_rate_bytes_per_second, 512);
        assert_eq!(cfg.request_body_min_rate_grace_ms, 10_000);
        assert_eq!(cfg.upstream_body_min_rate_bytes_per_second, 512);
        assert_eq!(cfg.upstream_body_min_rate_grace_ms, 10_000);
        assert!(!cfg.allow_compressed_request_bodies);
        assert!(!cfg.allow_chunked_request_bodies);
        assert!(!cfg.allow_expect_continue);
        assert_eq!(cfg.max_ranges, 1);
        assert!(!cfg.forward_accept_encoding);
        assert!(!cfg.forward_request_trailers);
        assert_eq!(cfg.max_trailer_bytes, 8 * 1024);
        assert_eq!(cfg.max_trailers, 32);
        assert!(!cfg.forward_response_trailers);
        assert_eq!(cfg.upstream_max_trailer_bytes, 8 * 1024);
        assert_eq!(cfg.upstream_max_trailers, 32);
        assert!(!cfg.downstream_keep_alive);
        assert_eq!(cfg.downstream_write_timeout_ms, 15_000);
        assert_eq!(cfg.client_ip.max_forwarded_for_bytes, 1024);
        assert_eq!(cfg.client_ip.max_forwarded_for_hops, 32);
    }

    #[test]
    fn http_config_accepts_custom_header_count_cap() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","max_header_line_bytes":4096,"max_headers":16}"#,
        )
        .unwrap();

        assert_eq!(cfg.max_header_line_bytes, 4_096);
        assert_eq!(cfg.max_headers, 16);
    }

    #[test]
    fn http_config_accepts_custom_upstream_pool_caps() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","upstream_pool_idle_timeout_ms":5000,"upstream_pool_max_idle_per_host":4}"#,
        )
        .unwrap();

        assert_eq!(cfg.upstream_pool_idle_timeout_ms, 5_000);
        assert_eq!(cfg.upstream_pool_max_idle_per_host, 4);
    }

    #[test]
    fn http_config_accepts_custom_upstream_connect_timeout() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","upstream_connect_timeout_ms":250}"#,
        )
        .unwrap();

        assert_eq!(cfg.upstream_connect_timeout_ms, 250);
    }

    #[test]
    fn http_config_accepts_custom_upstream_failure_circuit() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","upstream_failure_threshold":3,"upstream_failure_open_ms":250}"#,
        )
        .unwrap();

        assert_eq!(cfg.upstream_failure_threshold, 3);
        assert_eq!(cfg.upstream_failure_open_ms, 250);
    }

    #[test]
    fn http_config_accepts_custom_connection_rate_caps() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","limits":{"per_ip_connects_per_second":12.5,"per_ip_connect_burst":7,"global_connects_per_second":300.0,"global_connect_burst":33}}"#,
        )
        .unwrap();

        assert_eq!(cfg.limits.per_ip_connects_per_second, 12.5);
        assert_eq!(cfg.limits.per_ip_connect_burst, 7);
        assert_eq!(cfg.limits.global_connects_per_second, 300.0);
        assert_eq!(cfg.limits.global_connect_burst, 33);
    }

    #[test]
    fn http_config_accepts_custom_ip_prefix_lengths() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","limits":{"ipv4_prefix_len":24,"ipv6_prefix_len":56}}"#,
        )
        .unwrap();

        assert_eq!(cfg.limits.ipv4_prefix_len, 24);
        assert_eq!(cfg.limits.ipv6_prefix_len, 56);
    }

    #[test]
    fn http_config_accepts_custom_trusted_proxy_rate_caps() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","limits":{"trusted_proxy_rps":1234.5,"trusted_proxy_burst":321,"trusted_proxy_max_in_flight_requests":123}}"#,
        )
        .unwrap();

        assert_eq!(cfg.limits.trusted_proxy_rps, 1234.5);
        assert_eq!(cfg.limits.trusted_proxy_burst, 321);
        assert_eq!(cfg.limits.trusted_proxy_max_in_flight_requests, 123);
    }

    #[test]
    fn http_config_accepts_custom_signature_rate_caps() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","limits":{"signature_rps":777.5,"signature_burst":999,"max_tracked_signatures":2048}}"#,
        )
        .unwrap();

        assert_eq!(cfg.limits.signature_rps, 777.5);
        assert_eq!(cfg.limits.signature_burst, 999);
        assert_eq!(cfg.limits.max_tracked_signatures, 2048);
    }

    #[test]
    fn http_config_accepts_custom_path_shape_rate_caps() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","limits":{"path_shape_rps":888.5,"path_shape_burst":111,"max_tracked_path_shapes":512}}"#,
        )
        .unwrap();

        assert_eq!(cfg.limits.path_shape_rps, 888.5);
        assert_eq!(cfg.limits.path_shape_burst, 111);
        assert_eq!(cfg.limits.max_tracked_path_shapes, 512);
    }

    #[test]
    fn http_config_accepts_custom_body_min_rate_caps() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","request_body_min_rate_bytes_per_second":2048,"request_body_min_rate_grace_ms":1500,"upstream_body_min_rate_bytes_per_second":4096,"upstream_body_min_rate_grace_ms":2500}"#,
        )
        .unwrap();

        assert_eq!(cfg.request_body_min_rate_bytes_per_second, 2048);
        assert_eq!(cfg.request_body_min_rate_grace_ms, 1500);
        assert_eq!(cfg.upstream_body_min_rate_bytes_per_second, 4096);
        assert_eq!(cfg.upstream_body_min_rate_grace_ms, 2500);
    }

    #[test]
    fn http_config_accepts_compressed_request_body_opt_in() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","allow_compressed_request_bodies":true}"#,
        )
        .unwrap();

        assert!(cfg.allow_compressed_request_bodies);
    }

    #[test]
    fn http_config_accepts_chunked_request_body_opt_in() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","allow_chunked_request_bodies":true}"#,
        )
        .unwrap();

        assert!(cfg.allow_chunked_request_bodies);
    }

    #[test]
    fn http_config_accepts_expect_continue_opt_in() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","allow_expect_continue":true}"#,
        )
        .unwrap();

        assert!(cfg.allow_expect_continue);
    }

    #[test]
    fn http_config_accepts_custom_range_cap() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","max_ranges":4}"#,
        )
        .unwrap();

        assert_eq!(cfg.max_ranges, 4);
    }

    #[test]
    fn http_config_accepts_accept_encoding_passthrough_opt_in() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","forward_accept_encoding":true}"#,
        )
        .unwrap();

        assert!(cfg.forward_accept_encoding);
    }

    #[test]
    fn http_config_accepts_custom_downstream_keep_alive() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","downstream_keep_alive":true}"#,
        )
        .unwrap();

        assert!(cfg.downstream_keep_alive);
    }

    #[test]
    fn http_config_accepts_custom_downstream_write_timeout() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","downstream_write_timeout_ms":2500}"#,
        )
        .unwrap();

        assert_eq!(cfg.downstream_write_timeout_ms, 2_500);
    }

    #[test]
    fn http_config_accepts_custom_listen_backlog() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","listen_backlog":128}"#,
        )
        .unwrap();

        assert_eq!(cfg.listen_backlog, 128);
        assert_eq!(cfg.accept_shards, 1);
    }

    #[test]
    fn http_config_accepts_custom_accept_shards() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","accept_shards":4}"#,
        )
        .unwrap();

        assert_eq!(cfg.accept_shards, 4);
    }

    #[test]
    fn http_config_accepts_custom_uri_caps() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","max_uri_bytes":1024,"max_query_bytes":512,"max_query_pairs":8,"max_path_segments":16}"#,
        )
        .unwrap();

        assert_eq!(cfg.max_uri_bytes, 1024);
        assert_eq!(cfg.max_query_bytes, 512);
        assert_eq!(cfg.max_query_pairs, 8);
        assert_eq!(cfg.max_path_segments, 16);
    }

    #[test]
    fn http_config_accepts_custom_allowed_methods() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","allowed_methods":["GET","POST","REPORT"]}"#,
        )
        .unwrap();

        assert_eq!(cfg.allowed_methods, ["GET", "POST", "REPORT"]);
    }

    #[test]
    fn http_config_accepts_method_override_header_opt_in() {
        let default_cfg: HttpConfig =
            serde_json::from_str(r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1"}"#)
                .unwrap();
        let opt_in_cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","allow_method_override_headers":true}"#,
        )
        .unwrap();

        assert!(!default_cfg.allow_method_override_headers);
        assert!(opt_in_cfg.allow_method_override_headers);
    }

    #[test]
    fn app_config_accepts_custom_allowed_methods() {
        let cfg = app_config_with_allowed_methods(vec![
            "GET".to_string(),
            "POST".to_string(),
            "REPORT".to_string(),
        ]);

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_invalid_allowed_methods() {
        let oversized_method = "A".repeat(DEFAULT_HTTP_MAX_ALLOWED_METHOD_BYTES + 1);
        let too_many_methods = (0..=DEFAULT_HTTP_MAX_ALLOWED_METHODS)
            .map(|idx| format!("M{idx}"))
            .collect::<Vec<_>>();

        for (methods, expected) in [
            (
                Vec::<String>::new(),
                "http.allowed_methods must contain at least one method".to_string(),
            ),
            (
                vec!["".to_string()],
                "http.allowed_methods[0] must not be empty".to_string(),
            ),
            (
                vec!["BAD METHOD".to_string()],
                "http.allowed_methods[0] is not a valid HTTP method token".to_string(),
            ),
            (
                vec![oversized_method],
                format!(
                    "http.allowed_methods[0] is {} bytes",
                    DEFAULT_HTTP_MAX_ALLOWED_METHOD_BYTES + 1
                ),
            ),
            (
                vec!["GET".to_string(), "GET".to_string()],
                "http.allowed_methods[1] duplicates 'GET'".to_string(),
            ),
            (
                too_many_methods,
                format!(
                    "http.allowed_methods contains {} methods",
                    DEFAULT_HTTP_MAX_ALLOWED_METHODS + 1
                ),
            ),
        ] {
            let cfg = app_config_with_allowed_methods(methods);

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(&expected), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_unsupported_allowed_methods() {
        for method in ["CONNECT", "trace", "TRACK"] {
            let cfg = app_config_with_allowed_methods(vec!["GET".to_string(), method.to_string()]);

            let err = cfg.validate().unwrap_err().to_string();

            assert!(
                err.contains(&format!(
                    "http.allowed_methods[1] must not include unsupported tunnel or diagnostic method '{method}'"
                )),
                "{err}"
            );
        }
    }

    #[test]
    fn http_config_accepts_custom_host_guard() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","require_host_header":false,"max_host_bytes":64,"allowed_hosts":["example.com","api.example.com:8443"]}"#,
        )
        .unwrap();

        assert!(!cfg.require_host_header);
        assert_eq!(cfg.max_host_bytes, 64);
        assert_eq!(cfg.allowed_hosts, ["example.com", "api.example.com:8443"]);
    }

    #[test]
    fn app_config_accepts_custom_allowed_hosts() {
        let cfg = app_config_with_allowed_hosts(vec![
            "example.com".to_string(),
            "api.example.com:8443".to_string(),
            "[2001:db8::1]".to_string(),
        ]);

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_invalid_allowed_hosts() {
        let oversized_host = format!(
            "{}.example",
            "a".repeat(DEFAULT_HTTP_MAX_ALLOWED_HOST_BYTES)
        );
        let too_many_hosts = (0..=DEFAULT_HTTP_MAX_ALLOWED_HOSTS)
            .map(|idx| format!("h{idx}.example"))
            .collect::<Vec<_>>();

        for (hosts, expected) in [
            (
                vec!["".to_string()],
                "http.allowed_hosts[0] must not be empty".to_string(),
            ),
            (
                vec!["   ".to_string()],
                "http.allowed_hosts[0] must not be blank".to_string(),
            ),
            (
                vec![" example.com".to_string()],
                "http.allowed_hosts[0] must not start or end with whitespace".to_string(),
            ),
            (
                vec!["bad host".to_string()],
                "http.allowed_hosts[0] must not contain whitespace or control characters"
                    .to_string(),
            ),
            (
                vec!["http://example.com".to_string()],
                "http.allowed_hosts[0] is not a valid HTTP authority".to_string(),
            ),
            (
                vec!["user@example.com".to_string()],
                "http.allowed_hosts[0] must not contain URI userinfo".to_string(),
            ),
            (
                vec!["*.example.com".to_string()],
                "http.allowed_hosts[0] must be an exact host or host:port".to_string(),
            ),
            (
                vec![oversized_host],
                format!(
                    "http.allowed_hosts[0] is {} bytes",
                    DEFAULT_HTTP_MAX_ALLOWED_HOST_BYTES + ".example".len()
                ),
            ),
            (
                vec!["example.com".to_string(), "EXAMPLE.com".to_string()],
                "http.allowed_hosts[1] duplicates 'EXAMPLE.com'".to_string(),
            ),
            (
                too_many_hosts,
                format!(
                    "http.allowed_hosts contains {} hosts",
                    DEFAULT_HTTP_MAX_ALLOWED_HOSTS + 1
                ),
            ),
        ] {
            let cfg = app_config_with_allowed_hosts(hosts);

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(&expected), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_allowed_host_above_max_host_bytes() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_host_bytes":8,"allowed_hosts":["too-long.example"]}}"#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("http.allowed_hosts[0]"), "{err}");
        assert!(err.contains("above configured cap of 8 bytes"), "{err}");
    }

    #[test]
    fn http_config_accepts_custom_client_ip_forwarded_bounds() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","client_ip":{"header":"x-forwarded-for","trusted_proxies":["127.0.0.1/32"],"max_forwarded_for_bytes":256,"max_forwarded_for_hops":4}}"#,
        )
        .unwrap();

        assert_eq!(cfg.client_ip.max_forwarded_for_bytes, 256);
        assert_eq!(cfg.client_ip.max_forwarded_for_hops, 4);
    }

    #[test]
    fn app_config_accepts_custom_client_ip_config() {
        let cfg = app_config_with_client_ip(serde_json::json!({
            "header": "x-real-ip",
            "trusted_proxies": ["127.0.0.1/32", "2001:db8::1/128"],
            "max_forwarded_for_bytes": 256,
            "max_forwarded_for_hops": 4
        }));

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_invalid_client_ip_header() {
        let oversized_header = format!(
            "x-{}",
            "a".repeat(DEFAULT_HTTP_CLIENT_IP_HEADER_MAX_BYTES - 1)
        );
        for (header, expected) in [
            ("", "http.client_ip.header must not be empty".to_string()),
            ("   ", "http.client_ip.header must not be blank".to_string()),
            (
                " x-forwarded-for",
                "http.client_ip.header must not start or end with whitespace".to_string(),
            ),
            (
                "bad header",
                "http.client_ip.header is not a valid HTTP field name".to_string(),
            ),
            (
                oversized_header.as_str(),
                format!(
                    "http.client_ip.header is {} bytes",
                    DEFAULT_HTTP_CLIENT_IP_HEADER_MAX_BYTES + 1
                ),
            ),
        ] {
            let cfg = app_config_with_client_ip(serde_json::json!({"header": header}));

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(&expected), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_trusted_proxy_shape_errors() {
        let oversized_proxy = "1".repeat(DEFAULT_HTTP_MAX_TRUSTED_PROXY_BYTES + 1);
        let too_many_proxies = (0..=DEFAULT_HTTP_MAX_TRUSTED_PROXIES)
            .map(|idx| format!("2001:db8::{idx}"))
            .collect::<Vec<_>>();

        for (trusted_proxies, expected) in [
            (
                vec!["".to_string()],
                "http.client_ip.trusted_proxies[0] must not be empty".to_string(),
            ),
            (
                vec!["   ".to_string()],
                "http.client_ip.trusted_proxies[0] must not be blank".to_string(),
            ),
            (
                vec![" 127.0.0.1/32".to_string()],
                "http.client_ip.trusted_proxies[0] must not start or end with whitespace"
                    .to_string(),
            ),
            (
                vec!["127.0.0.1 /32".to_string()],
                "http.client_ip.trusted_proxies[0] must not contain whitespace or control characters"
                    .to_string(),
            ),
            (
                vec![oversized_proxy],
                format!(
                    "http.client_ip.trusted_proxies[0] is {} bytes",
                    DEFAULT_HTTP_MAX_TRUSTED_PROXY_BYTES + 1
                ),
            ),
            (
                vec!["127.0.0.1/32".to_string(), "127.0.0.1/32".to_string()],
                "http.client_ip.trusted_proxies[1] duplicates '127.0.0.1/32'".to_string(),
            ),
            (
                too_many_proxies,
                format!(
                    "http.client_ip.trusted_proxies contains {} entries",
                    DEFAULT_HTTP_MAX_TRUSTED_PROXIES + 1
                ),
            ),
        ] {
            let cfg =
                app_config_with_client_ip(serde_json::json!({"trusted_proxies": trusted_proxies}));

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(&expected), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_global_trusted_proxy_on_public_http_listener() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"0.0.0.0:8080","upstream":"http://127.0.0.1:1","client_ip":{"trusted_proxies":["0.0.0.0/0"]}}}"#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("must not trust all IPv4 peers"), "{err}");
        assert!(err.contains("non-loopback listener 0.0.0.0:8080"), "{err}");
    }

    #[test]
    fn app_config_rejects_invalid_trusted_proxy_range() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","client_ip":{"trusted_proxies":["not-a-cidr"]}}}"#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(
            err.contains("invalid http.client_ip.trusted_proxies entry 'not-a-cidr'"),
            "{err}"
        );
    }

    #[test]
    fn app_config_allows_global_trusted_proxy_on_loopback_listener_for_local_stacks() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","client_ip":{"trusted_proxies":["0.0.0.0/0","::/0"]}}}"#,
        )
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_negative_http_rate_limits() {
        for (field, path) in [
            ("per_ip_rps", "http.limits.per_ip_rps"),
            ("global_rps", "http.limits.global_rps"),
            ("trusted_proxy_rps", "http.limits.trusted_proxy_rps"),
            ("signature_rps", "http.limits.signature_rps"),
            ("path_shape_rps", "http.limits.path_shape_rps"),
            (
                "per_ip_connects_per_second",
                "http.limits.per_ip_connects_per_second",
            ),
            (
                "global_connects_per_second",
                "http.limits.global_connects_per_second",
            ),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","limits":{{"{field}":-1.0}}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be finite and non-negative"), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_negative_tcp_rate_limits() {
        for (field, path) in [
            (
                "per_ip_connects_per_second",
                "tcp[0].limits.per_ip_connects_per_second",
            ),
            (
                "global_connects_per_second",
                "tcp[0].limits.global_connects_per_second",
            ),
        ] {
            let raw = format!(
                r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","limits":{{"{field}":-1.0}}}}]}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be finite and non-negative"), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_non_finite_rate_limits() {
        let mut http_cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1"}}"#,
        )
        .unwrap();
        http_cfg.http.as_mut().unwrap().limits.global_rps = f64::INFINITY;

        let http_err = http_cfg.validate().unwrap_err().to_string();

        assert!(http_err.contains("http.limits.global_rps"), "{http_err}");
        assert!(
            http_err.contains("must be finite and non-negative"),
            "{http_err}"
        );

        let mut tcp_cfg: AppConfig = serde_json::from_str(
            r#"{"tcp":[{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1"}]}"#,
        )
        .unwrap();
        tcp_cfg.tcp[0].limits.per_ip_connects_per_second = f64::NAN;

        let tcp_err = tcp_cfg.validate().unwrap_err().to_string();

        assert!(
            tcp_err.contains("tcp[0].limits.per_ip_connects_per_second"),
            "{tcp_err}"
        );
        assert!(
            tcp_err.contains("must be finite and non-negative"),
            "{tcp_err}"
        );
    }

    #[test]
    fn app_config_allows_zero_rate_limits_as_explicit_disable() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","limits":{"per_ip_rps":0.0,"global_rps":0.0,"trusted_proxy_rps":0.0,"signature_rps":0.0,"path_shape_rps":0.0,"per_ip_connects_per_second":0.0,"global_connects_per_second":0.0}},"tcp":[{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","limits":{"per_ip_connects_per_second":0.0,"global_connects_per_second":0.0}}]}"#,
        )
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_invalid_http_ip_prefix_lengths() {
        for (field, value, expected) in [
            ("ipv4_prefix_len", 0, "between 1 and 32"),
            ("ipv4_prefix_len", 33, "between 1 and 32"),
            ("ipv6_prefix_len", 0, "between 1 and 128"),
            ("ipv6_prefix_len", 129, "between 1 and 128"),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","limits":{{"{field}":{value}}}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(&format!("http.limits.{field}")), "{err}");
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_invalid_tcp_ip_prefix_lengths() {
        for (field, value, expected) in [
            ("ipv4_prefix_len", 0, "between 1 and 32"),
            ("ipv4_prefix_len", 33, "between 1 and 32"),
            ("ipv6_prefix_len", 0, "between 1 and 128"),
            ("ipv6_prefix_len", 129, "between 1 and 128"),
        ] {
            let raw = format!(
                r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","limits":{{"{field}":{value}}}}}]}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(&format!("tcp[0].limits.{field}")), "{err}");
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_invalid_admin_path_prefix() {
        for (prefix, expected) in [
            (
                "",
                "must start with '/' and use a non-root absolute path prefix",
            ),
            ("/", "must use a non-root absolute path prefix"),
            (
                "admin",
                "must start with '/' and use a non-root absolute path prefix",
            ),
            ("/admin?debug=true", "must not contain query or fragment"),
            ("/admin#metrics", "must not contain query or fragment"),
            ("/admin path", "must not contain whitespace or control"),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","admin_path_prefix":"{prefix}"}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains("http.admin_path_prefix"), "{err}");
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn app_config_allows_trailing_slash_admin_path_prefix() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","admin_path_prefix":"/internal/admin/"}}"#,
        )
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_invalid_admin_token() {
        for (token_json, expected) in [
            (r#""""#.to_string(), "must not be empty"),
            (r#""   ""#.to_string(), "must not be blank"),
            (
                r#"" secret""#.to_string(),
                "must not start or end with whitespace",
            ),
            (
                r#""secret ""#.to_string(),
                "must not start or end with whitespace",
            ),
            (
                r#""line\nfeed""#.to_string(),
                "must not contain control characters",
            ),
            (
                format!(r#""{}""#, "a".repeat(HTTP_ADMIN_TOKEN_MAX_BYTES + 1)),
                "above configured cap",
            ),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","admin_token":{token_json}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains("http.admin_token"), "{err}");
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn app_config_allows_valid_admin_token() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","admin_token":"metrics-secret-123"}}"#,
        )
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_invalid_http_endpoints() {
        for (http, expected) in [
            (
                r#""listen":"not-a-socket","upstream":"http://127.0.0.1:1""#,
                "invalid http.listen address",
            ),
            (
                r#""listen":"127.0.0.1:8080","upstream":"127.0.0.1:1""#,
                "http.upstream must include http:// scheme",
            ),
            (
                r#""listen":"127.0.0.1:8080","upstream":"https://127.0.0.1:1""#,
                "http.upstream must use http:// scheme; unsupported scheme 'https'",
            ),
            (
                r#""listen":"127.0.0.1:8080","upstream":"http://user@127.0.0.1:1""#,
                "http.upstream must not contain URI userinfo",
            ),
            (
                r#""listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1/base?x=1""#,
                "http.upstream must not include a query string",
            ),
        ] {
            let cfg: AppConfig = serde_json::from_str(&format!("{{\"http\":{{{http}}}}}"))
                .expect("test config should deserialize");

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn app_config_accepts_http_upstream_with_base_path() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1/base"}}"#,
        )
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_invalid_tcp_endpoints() {
        for (tcp, expected) in [
            (
                r#""name":"tcp","listen":"not-a-socket","upstream":"127.0.0.1:1""#,
                "invalid tcp[0].listen address",
            ),
            (
                r#""name":"tcp","listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1""#,
                "tcp[0].upstream must be host:port without a URL scheme",
            ),
            (
                r#""name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1""#,
                "tcp[0].upstream must include a numeric port",
            ),
            (
                r#""name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:0""#,
                "tcp[0].upstream port must be greater than zero",
            ),
            (
                r#""name":"tcp","listen":"127.0.0.1:0","upstream":"user@127.0.0.1:1""#,
                "tcp[0].upstream must not contain URI userinfo",
            ),
            (
                r#""name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1/base""#,
                "tcp[0].upstream must not include a path, query, or fragment",
            ),
            (
                r#""name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1?x=1""#,
                "tcp[0].upstream must not include a path, query, or fragment",
            ),
            (
                r#""name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1\n""#,
                "tcp[0].upstream must not contain whitespace or control characters",
            ),
        ] {
            let cfg: AppConfig = serde_json::from_str(&format!(r#"{{"tcp":[{{{tcp}}}]}}"#))
                .expect("test config should deserialize");

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    fn app_config_accepts_valid_tcp_endpoints() {
        for upstream in ["127.0.0.1:1", "example.internal:443", "[::1]:443"] {
            let cfg: AppConfig = serde_json::from_str(&format!(
                r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:0","upstream":"{upstream}"}}]}}"#
            ))
            .unwrap();

            cfg.validate().unwrap();
        }
    }

    #[test]
    fn app_config_rejects_zero_http_capacity_limits() {
        for (snippet, path) in [
            (r#""max_host_bytes":0"#, "http.max_host_bytes"),
            (r#""listen_backlog":0"#, "http.listen_backlog"),
            (r#""accept_shards":0"#, "http.accept_shards"),
            (r#""max_header_bytes":0"#, "http.max_header_bytes"),
            (r#""max_header_line_bytes":0"#, "http.max_header_line_bytes"),
            (r#""max_headers":0"#, "http.max_headers"),
            (r#""max_uri_bytes":0"#, "http.max_uri_bytes"),
            (r#""max_query_bytes":0"#, "http.max_query_bytes"),
            (r#""max_query_pairs":0"#, "http.max_query_pairs"),
            (r#""max_path_segments":0"#, "http.max_path_segments"),
            (
                r#""header_read_timeout_ms":0"#,
                "http.header_read_timeout_ms",
            ),
            (
                r#""downstream_write_timeout_ms":0"#,
                "http.downstream_write_timeout_ms",
            ),
            (r#""upstream_timeout_ms":0"#, "http.upstream_timeout_ms"),
            (
                r#""upstream_connect_timeout_ms":0"#,
                "http.upstream_connect_timeout_ms",
            ),
            (
                r#""upstream_pool_idle_timeout_ms":0"#,
                "http.upstream_pool_idle_timeout_ms",
            ),
            (
                r#""upstream_max_header_bytes":0"#,
                "http.upstream_max_header_bytes",
            ),
            (
                r#""upstream_max_header_line_bytes":0"#,
                "http.upstream_max_header_line_bytes",
            ),
            (r#""upstream_max_headers":0"#, "http.upstream_max_headers"),
            (
                r#""upstream_body_idle_timeout_ms":0"#,
                "http.upstream_body_idle_timeout_ms",
            ),
            (
                r#""upstream_failure_threshold":0"#,
                "http.upstream_failure_threshold",
            ),
            (
                r#""upstream_failure_open_ms":0"#,
                "http.upstream_failure_open_ms",
            ),
            (
                r#""max_upstream_body_bytes":0"#,
                "http.max_upstream_body_bytes",
            ),
            (
                r#""max_connection_duration_seconds":0"#,
                "http.max_connection_duration_seconds",
            ),
            (
                r#""max_requests_per_connection":0"#,
                "http.max_requests_per_connection",
            ),
            (r#""max_body_bytes":0"#, "http.max_body_bytes"),
            (
                r#""request_body_idle_timeout_ms":0"#,
                "http.request_body_idle_timeout_ms",
            ),
            (
                r#""request_body_min_rate_grace_ms":0"#,
                "http.request_body_min_rate_grace_ms",
            ),
            (
                r#""upstream_body_min_rate_grace_ms":0"#,
                "http.upstream_body_min_rate_grace_ms",
            ),
            (r#""max_ranges":0"#, "http.max_ranges"),
            (r#""max_trailer_bytes":0"#, "http.max_trailer_bytes"),
            (r#""max_trailers":0"#, "http.max_trailers"),
            (
                r#""upstream_max_trailer_bytes":0"#,
                "http.upstream_max_trailer_bytes",
            ),
            (r#""upstream_max_trailers":0"#, "http.upstream_max_trailers"),
            (
                r#""client_ip":{"max_forwarded_for_bytes":0}"#,
                "http.client_ip.max_forwarded_for_bytes",
            ),
            (
                r#""client_ip":{"max_forwarded_for_hops":0}"#,
                "http.client_ip.max_forwarded_for_hops",
            ),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1",{snippet}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be greater than zero"), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_http_header_buffers_below_hyper_floor() {
        for (snippet, path) in [
            (r#""max_header_bytes":8191"#, "http.max_header_bytes"),
            (
                r#""upstream_max_header_bytes":8191"#,
                "http.upstream_max_header_bytes",
            ),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1",{snippet}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be at least 8192"), "{err}");
        }
    }

    #[test]
    fn app_config_accepts_http_header_buffers_at_hyper_floor() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_header_bytes":8192,"upstream_max_header_bytes":8192}}"#,
        )
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_http_header_buffers_above_startup_ceiling() {
        let oversized = HTTP_HEADER_BUFFER_MAX_BYTES + 1;
        for (field, path) in [
            ("max_header_bytes", "http.max_header_bytes"),
            ("max_header_line_bytes", "http.max_header_line_bytes"),
            (
                "upstream_max_header_bytes",
                "http.upstream_max_header_bytes",
            ),
            (
                "upstream_max_header_line_bytes",
                "http.upstream_max_header_line_bytes",
            ),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","{field}":{oversized}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!(
                    "must be no higher than {HTTP_HEADER_BUFFER_MAX_BYTES}"
                )),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_http_header_buffers_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_header_bytes":{HTTP_HEADER_BUFFER_MAX_BYTES},"max_header_line_bytes":{HTTP_HEADER_BUFFER_MAX_BYTES},"upstream_max_header_bytes":{HTTP_HEADER_BUFFER_MAX_BYTES},"upstream_max_header_line_bytes":{HTTP_HEADER_BUFFER_MAX_BYTES}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_header_line_caps_above_total_header_buffers() {
        for (field, value, expected) in [
            ("max_header_line_bytes", 16_384, "http.max_header_bytes"),
            (
                "upstream_max_header_line_bytes",
                16_384,
                "http.upstream_max_header_bytes",
            ),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_header_bytes":8192,"upstream_max_header_bytes":8192,"{field}":{value}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(field), "{err}");
            assert!(err.contains(expected), "{err}");
            assert!(err.contains("must be no higher than"), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_http_header_counts_above_startup_ceiling() {
        let oversized = HTTP_HEADER_COUNT_MAX + 1;
        for (field, path) in [
            ("max_headers", "http.max_headers"),
            ("upstream_max_headers", "http.upstream_max_headers"),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","{field}":{oversized}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {HTTP_HEADER_COUNT_MAX}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_http_header_counts_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_headers":{HTTP_HEADER_COUNT_MAX},"upstream_max_headers":{HTTP_HEADER_COUNT_MAX}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_http_metadata_caps_above_startup_ceiling() {
        for (snippet, path, ceiling) in [
            (
                format!(r#""max_host_bytes":{}"#, HTTP_HOST_MAX_BYTES_MAX + 1),
                "http.max_host_bytes",
                HTTP_HOST_MAX_BYTES_MAX,
            ),
            (
                format!(r#""max_uri_bytes":{}"#, HTTP_REQUEST_TARGET_MAX_BYTES + 1),
                "http.max_uri_bytes",
                HTTP_REQUEST_TARGET_MAX_BYTES,
            ),
            (
                format!(r#""max_query_bytes":{}"#, HTTP_REQUEST_TARGET_MAX_BYTES + 1),
                "http.max_query_bytes",
                HTTP_REQUEST_TARGET_MAX_BYTES,
            ),
            (
                format!(r#""max_query_pairs":{}"#, HTTP_QUERY_PAIR_COUNT_MAX + 1),
                "http.max_query_pairs",
                HTTP_QUERY_PAIR_COUNT_MAX,
            ),
            (
                format!(r#""max_path_segments":{}"#, HTTP_PATH_SEGMENT_COUNT_MAX + 1),
                "http.max_path_segments",
                HTTP_PATH_SEGMENT_COUNT_MAX,
            ),
            (
                format!(r#""max_trailer_bytes":{}"#, HTTP_TRAILER_BYTES_MAX + 1),
                "http.max_trailer_bytes",
                HTTP_TRAILER_BYTES_MAX,
            ),
            (
                format!(r#""max_trailers":{}"#, HTTP_TRAILER_COUNT_MAX + 1),
                "http.max_trailers",
                HTTP_TRAILER_COUNT_MAX,
            ),
            (
                format!(
                    r#""upstream_max_trailer_bytes":{}"#,
                    HTTP_TRAILER_BYTES_MAX + 1
                ),
                "http.upstream_max_trailer_bytes",
                HTTP_TRAILER_BYTES_MAX,
            ),
            (
                format!(r#""upstream_max_trailers":{}"#, HTTP_TRAILER_COUNT_MAX + 1),
                "http.upstream_max_trailers",
                HTTP_TRAILER_COUNT_MAX,
            ),
            (
                format!(
                    r#""client_ip":{{"max_forwarded_for_bytes":{}}}"#,
                    HTTP_FORWARDED_FOR_BYTES_MAX + 1
                ),
                "http.client_ip.max_forwarded_for_bytes",
                HTTP_FORWARDED_FOR_BYTES_MAX,
            ),
            (
                format!(
                    r#""client_ip":{{"max_forwarded_for_hops":{}}}"#,
                    HTTP_FORWARDED_FOR_HOPS_MAX + 1
                ),
                "http.client_ip.max_forwarded_for_hops",
                HTTP_FORWARDED_FOR_HOPS_MAX,
            ),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1",{snippet}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_http_metadata_caps_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_host_bytes":{HTTP_HOST_MAX_BYTES_MAX},"max_uri_bytes":{HTTP_REQUEST_TARGET_MAX_BYTES},"max_query_bytes":{HTTP_REQUEST_TARGET_MAX_BYTES},"max_query_pairs":{HTTP_QUERY_PAIR_COUNT_MAX},"max_path_segments":{HTTP_PATH_SEGMENT_COUNT_MAX},"max_trailer_bytes":{HTTP_TRAILER_BYTES_MAX},"max_trailers":{HTTP_TRAILER_COUNT_MAX},"upstream_max_trailer_bytes":{HTTP_TRAILER_BYTES_MAX},"upstream_max_trailers":{HTTP_TRAILER_COUNT_MAX},"client_ip":{{"max_forwarded_for_bytes":{HTTP_FORWARDED_FOR_BYTES_MAX},"max_forwarded_for_hops":{HTTP_FORWARDED_FOR_HOPS_MAX}}}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_header_read_timeout_above_startup_ceiling() {
        let oversized = HTTP_HEADER_READ_TIMEOUT_MAX_MS + 1;
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","header_read_timeout_ms":{oversized}}}}}"#
        ))
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("http.header_read_timeout_ms"), "{err}");
        assert!(
            err.contains(&format!(
                "must be no higher than {HTTP_HEADER_READ_TIMEOUT_MAX_MS}"
            )),
            "{err}"
        );
    }

    #[test]
    fn app_config_accepts_header_read_timeout_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","header_read_timeout_ms":{HTTP_HEADER_READ_TIMEOUT_MAX_MS}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_http_stream_timeouts_above_startup_ceiling() {
        for (field, path, ceiling) in [
            (
                "downstream_write_timeout_ms",
                "http.downstream_write_timeout_ms",
                HTTP_DOWNSTREAM_WRITE_TIMEOUT_MAX_MS,
            ),
            (
                "request_body_idle_timeout_ms",
                "http.request_body_idle_timeout_ms",
                HTTP_BODY_IDLE_TIMEOUT_MAX_MS,
            ),
            (
                "upstream_body_idle_timeout_ms",
                "http.upstream_body_idle_timeout_ms",
                HTTP_BODY_IDLE_TIMEOUT_MAX_MS,
            ),
            (
                "request_body_min_rate_grace_ms",
                "http.request_body_min_rate_grace_ms",
                HTTP_BODY_MIN_RATE_GRACE_MAX_MS,
            ),
            (
                "upstream_body_min_rate_grace_ms",
                "http.upstream_body_min_rate_grace_ms",
                HTTP_BODY_MIN_RATE_GRACE_MAX_MS,
            ),
        ] {
            let oversized = ceiling + 1;
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","{field}":{oversized}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_http_stream_timeouts_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","downstream_write_timeout_ms":{HTTP_DOWNSTREAM_WRITE_TIMEOUT_MAX_MS},"request_body_idle_timeout_ms":{HTTP_BODY_IDLE_TIMEOUT_MAX_MS},"upstream_body_idle_timeout_ms":{HTTP_BODY_IDLE_TIMEOUT_MAX_MS},"request_body_min_rate_grace_ms":{HTTP_BODY_MIN_RATE_GRACE_MAX_MS},"upstream_body_min_rate_grace_ms":{HTTP_BODY_MIN_RATE_GRACE_MAX_MS}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_http_body_min_rates_above_startup_ceiling() {
        for (field, path) in [
            (
                "request_body_min_rate_bytes_per_second",
                "http.request_body_min_rate_bytes_per_second",
            ),
            (
                "upstream_body_min_rate_bytes_per_second",
                "http.upstream_body_min_rate_bytes_per_second",
            ),
        ] {
            let oversized = HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX + 1;
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","{field}":{oversized}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!(
                    "must be no higher than {HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX}"
                )),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_http_body_min_rates_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","request_body_min_rate_bytes_per_second":{HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX},"upstream_body_min_rate_bytes_per_second":{HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_body_size_caps_above_startup_ceiling() {
        for (field, path, ceiling) in [
            (
                "max_body_bytes",
                "http.max_body_bytes",
                HTTP_MAX_BODY_BYTES_MAX,
            ),
            (
                "max_upstream_body_bytes",
                "http.max_upstream_body_bytes",
                HTTP_MAX_UPSTREAM_BODY_BYTES_MAX,
            ),
        ] {
            let oversized = ceiling + 1;
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","{field}":{oversized}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_body_size_caps_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_body_bytes":{HTTP_MAX_BODY_BYTES_MAX},"max_upstream_body_bytes":{HTTP_MAX_UPSTREAM_BODY_BYTES_MAX}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_upstream_timeout_above_startup_ceiling() {
        let oversized = HTTP_UPSTREAM_TIMEOUT_MAX_MS + 1;
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_timeout_ms":{oversized}}}}}"#
        ))
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("http.upstream_timeout_ms"), "{err}");
        assert!(
            err.contains(&format!(
                "must be no higher than {HTTP_UPSTREAM_TIMEOUT_MAX_MS}"
            )),
            "{err}"
        );
    }

    #[test]
    fn app_config_accepts_upstream_timeout_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_timeout_ms":{HTTP_UPSTREAM_TIMEOUT_MAX_MS}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_upstream_failure_circuit_above_startup_ceiling() {
        for (raw, path, ceiling) in [
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_failure_threshold":{}}}}}"#,
                    HTTP_UPSTREAM_FAILURE_THRESHOLD_MAX + 1
                ),
                "http.upstream_failure_threshold",
                HTTP_UPSTREAM_FAILURE_THRESHOLD_MAX.to_string(),
            ),
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_failure_open_ms":{}}}}}"#,
                    HTTP_UPSTREAM_FAILURE_OPEN_MAX_MS + 1
                ),
                "http.upstream_failure_open_ms",
                HTTP_UPSTREAM_FAILURE_OPEN_MAX_MS.to_string(),
            ),
        ] {
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_upstream_failure_circuit_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_failure_threshold":{HTTP_UPSTREAM_FAILURE_THRESHOLD_MAX},"upstream_failure_open_ms":{HTTP_UPSTREAM_FAILURE_OPEN_MAX_MS}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_connect_timeout_above_startup_ceiling() {
        let http_oversized = HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS + 1;
        let tcp_oversized = TCP_CONNECT_TIMEOUT_MAX_MS + 1;
        for (raw, path, ceiling) in [
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_connect_timeout_ms":{http_oversized}}}}}"#
                ),
                "http.upstream_connect_timeout_ms",
                HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS,
            ),
            (
                format!(
                    r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:9000","upstream":"127.0.0.1:9001","connect_timeout_ms":{tcp_oversized}}}]}}"#
                ),
                "tcp[0].connect_timeout_ms",
                TCP_CONNECT_TIMEOUT_MAX_MS,
            ),
        ] {
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_connect_timeout_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_connect_timeout_ms":{HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS}}},"tcp":[{{"name":"tcp","listen":"127.0.0.1:9000","upstream":"127.0.0.1:9001","connect_timeout_ms":{TCP_CONNECT_TIMEOUT_MAX_MS}}}]}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_upstream_idle_pool_above_startup_ceiling() {
        for (raw, path, ceiling) in [
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_pool_idle_timeout_ms":{}}}}}"#,
                    HTTP_UPSTREAM_POOL_IDLE_TIMEOUT_MAX_MS + 1
                ),
                "http.upstream_pool_idle_timeout_ms",
                HTTP_UPSTREAM_POOL_IDLE_TIMEOUT_MAX_MS.to_string(),
            ),
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_pool_max_idle_per_host":{}}}}}"#,
                    HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST_MAX + 1
                ),
                "http.upstream_pool_max_idle_per_host",
                HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST_MAX.to_string(),
            ),
        ] {
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_upstream_idle_pool_at_startup_ceiling_and_zero_pool_disable() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_pool_idle_timeout_ms":{HTTP_UPSTREAM_POOL_IDLE_TIMEOUT_MAX_MS},"upstream_pool_max_idle_per_host":{HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST_MAX}}}}}"#
        ))
        .unwrap();
        cfg.validate().unwrap();

        let disabled_pool: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","upstream_pool_max_idle_per_host":0}}"#,
        )
        .unwrap();
        disabled_pool.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_connection_duration_above_startup_ceiling() {
        let http_oversized = HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS + 1;
        let tcp_oversized = TCP_MAX_CONNECTION_DURATION_MAX_SECONDS + 1;
        for (raw, path, ceiling) in [
            (
                format!(
                    r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_connection_duration_seconds":{http_oversized}}}}}"#
                ),
                "http.max_connection_duration_seconds",
                HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS,
            ),
            (
                format!(
                    r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:9000","upstream":"127.0.0.1:9001","max_connection_duration_seconds":{tcp_oversized}}}]}}"#
                ),
                "tcp[0].max_connection_duration_seconds",
                TCP_MAX_CONNECTION_DURATION_MAX_SECONDS,
            ),
        ] {
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!("must be no higher than {ceiling}")),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_connection_duration_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_connection_duration_seconds":{HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS}}},"tcp":[{{"name":"tcp","listen":"127.0.0.1:9000","upstream":"127.0.0.1:9001","max_connection_duration_seconds":{TCP_MAX_CONNECTION_DURATION_MAX_SECONDS}}}]}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_connection_request_count_above_startup_ceiling() {
        let oversized = HTTP_MAX_REQUESTS_PER_CONNECTION_MAX + 1;
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_requests_per_connection":{oversized}}}}}"#
        ))
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("http.max_requests_per_connection"), "{err}");
        assert!(
            err.contains(&format!(
                "must be no higher than {HTTP_MAX_REQUESTS_PER_CONNECTION_MAX}"
            )),
            "{err}"
        );
    }

    #[test]
    fn app_config_accepts_connection_request_count_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","max_requests_per_connection":{HTTP_MAX_REQUESTS_PER_CONNECTION_MAX}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_excessive_accept_shards() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{"http":{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","accept_shards":65}}"#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("http.accept_shards"), "{err}");
        assert!(err.contains("no higher than 64"), "{err}");
    }

    #[test]
    fn app_config_rejects_zero_http_limiter_capacity_limits() {
        for (field, path) in [
            ("per_ip_burst", "http.limits.per_ip_burst"),
            ("global_burst", "http.limits.global_burst"),
            ("trusted_proxy_burst", "http.limits.trusted_proxy_burst"),
            (
                "trusted_proxy_max_in_flight_requests",
                "http.limits.trusted_proxy_max_in_flight_requests",
            ),
            ("signature_burst", "http.limits.signature_burst"),
            (
                "max_tracked_signatures",
                "http.limits.max_tracked_signatures",
            ),
            ("path_shape_burst", "http.limits.path_shape_burst"),
            (
                "max_tracked_path_shapes",
                "http.limits.max_tracked_path_shapes",
            ),
            ("per_ip_connect_burst", "http.limits.per_ip_connect_burst"),
            ("global_connect_burst", "http.limits.global_connect_burst"),
            ("max_connections", "http.limits.max_connections"),
            (
                "max_connections_per_ip",
                "http.limits.max_connections_per_ip",
            ),
            (
                "max_in_flight_requests",
                "http.limits.max_in_flight_requests",
            ),
            (
                "max_in_flight_requests_per_ip",
                "http.limits.max_in_flight_requests_per_ip",
            ),
            ("max_tracked_ips", "http.limits.max_tracked_ips"),
        ] {
            let raw = format!(
                r#"{{"http":{{"listen":"127.0.0.1:8080","upstream":"http://127.0.0.1:1","limits":{{"{field}":0}}}}}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be greater than zero"), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_zero_tcp_capacity_limits() {
        for (snippet, path) in [
            (r#""listen_backlog":0"#, "tcp[0].listen_backlog"),
            (r#""accept_shards":0"#, "tcp[0].accept_shards"),
            (r#""connect_timeout_ms":0"#, "tcp[0].connect_timeout_ms"),
            (r#""idle_timeout_seconds":0"#, "tcp[0].idle_timeout_seconds"),
            (r#""min_rate_grace_ms":0"#, "tcp[0].min_rate_grace_ms"),
            (
                r#""max_connection_duration_seconds":0"#,
                "tcp[0].max_connection_duration_seconds",
            ),
        ] {
            let raw = format!(
                r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1",{snippet}}}]}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be greater than zero"), "{err}");
        }
    }

    #[test]
    fn app_config_rejects_tcp_min_rates_above_startup_ceiling() {
        for (field, path) in [
            (
                "downstream_min_rate_bytes_per_second",
                "tcp[0].downstream_min_rate_bytes_per_second",
            ),
            (
                "upstream_min_rate_bytes_per_second",
                "tcp[0].upstream_min_rate_bytes_per_second",
            ),
        ] {
            let oversized = TCP_MIN_RATE_BYTES_PER_SECOND_MAX + 1;
            let raw = format!(
                r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","{field}":{oversized}}}]}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(
                err.contains(&format!(
                    "must be no higher than {TCP_MIN_RATE_BYTES_PER_SECOND_MAX}"
                )),
                "{err}"
            );
        }
    }

    #[test]
    fn app_config_accepts_tcp_min_rates_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","downstream_min_rate_bytes_per_second":{TCP_MIN_RATE_BYTES_PER_SECOND_MAX},"upstream_min_rate_bytes_per_second":{TCP_MIN_RATE_BYTES_PER_SECOND_MAX}}}]}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_zero_tcp_limiter_capacity_limits() {
        for (field, path) in [
            ("per_ip_connect_burst", "tcp[0].limits.per_ip_connect_burst"),
            ("global_connect_burst", "tcp[0].limits.global_connect_burst"),
            ("max_connections", "tcp[0].limits.max_connections"),
            (
                "max_connections_per_ip",
                "tcp[0].limits.max_connections_per_ip",
            ),
            ("max_tracked_ips", "tcp[0].limits.max_tracked_ips"),
        ] {
            let raw = format!(
                r#"{{"tcp":[{{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","limits":{{"{field}":0}}}}]}}"#
            );
            let cfg: AppConfig = serde_json::from_str(&raw).unwrap();

            let err = cfg.validate().unwrap_err().to_string();

            assert!(err.contains(path), "{err}");
            assert!(err.contains("must be greater than zero"), "{err}");
        }
    }

    #[test]
    fn http_config_accepts_custom_upstream_header_caps() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","upstream_max_header_bytes":16384,"upstream_max_header_line_bytes":4096,"upstream_max_headers":32}"#,
        )
        .unwrap();

        assert_eq!(cfg.upstream_max_header_bytes, 16_384);
        assert_eq!(cfg.upstream_max_header_line_bytes, 4_096);
        assert_eq!(cfg.upstream_max_headers, 32);
    }

    #[test]
    fn http_config_accepts_custom_trailer_policy() {
        let cfg: HttpConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:0","upstream":"http://127.0.0.1:1","forward_request_trailers":true,"max_trailer_bytes":1024,"max_trailers":4,"forward_response_trailers":true,"upstream_max_trailer_bytes":2048,"upstream_max_trailers":8}"#,
        )
        .unwrap();

        assert!(cfg.forward_request_trailers);
        assert_eq!(cfg.max_trailer_bytes, 1_024);
        assert_eq!(cfg.max_trailers, 4);
        assert!(cfg.forward_response_trailers);
        assert_eq!(cfg.upstream_max_trailer_bytes, 2_048);
        assert_eq!(cfg.upstream_max_trailers, 8);
    }

    #[test]
    fn adaptive_config_accepts_custom_event_log_bounds() {
        let default_cfg: AdaptiveConfig = serde_json::from_str("{}").unwrap();
        let custom_cfg: AdaptiveConfig = serde_json::from_str(
            r#"{"event_log_flush_interval_ms":250,"event_log_max_bytes":4096,"event_log_backup_count":1,"event_log_queue_capacity":16,"max_signature_windows":128,"max_path_shape_windows":64}"#,
        )
        .unwrap();

        assert_eq!(default_cfg.event_log_flush_interval_ms, 100);
        assert_eq!(default_cfg.event_log_flush_interval().as_millis(), 100);
        assert_eq!(default_cfg.event_log_max_bytes, 64 * 1024 * 1024);
        assert_eq!(default_cfg.event_log_backup_count, 2);
        assert_eq!(default_cfg.event_log_queue_capacity, 4096);
        assert_eq!(default_cfg.max_signature_windows, 8_192);
        assert_eq!(default_cfg.max_path_shape_windows, 8_192);
        assert_eq!(custom_cfg.event_log_flush_interval_ms, 250);
        assert_eq!(custom_cfg.event_log_flush_interval().as_millis(), 250);
        assert_eq!(custom_cfg.event_log_max_bytes, 4096);
        assert_eq!(custom_cfg.event_log_backup_count, 1);
        assert_eq!(custom_cfg.event_log_queue_capacity, 16);
        assert_eq!(custom_cfg.max_signature_windows, 128);
        assert_eq!(custom_cfg.max_path_shape_windows, 64);
    }

    #[test]
    fn app_config_rejects_event_log_backup_count_above_startup_ceiling() {
        let oversized = EVENT_LOG_BACKUP_COUNT_MAX + 1;
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"adaptive":{{"event_log_backup_count":{oversized}}}}}"#
        ))
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("adaptive.event_log_backup_count"), "{err}");
        assert!(
            err.contains(&format!(
                "must be no higher than {EVENT_LOG_BACKUP_COUNT_MAX}"
            )),
            "{err}"
        );
    }

    #[test]
    fn app_config_accepts_event_log_backup_count_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"adaptive":{{"event_log_backup_count":{EVENT_LOG_BACKUP_COUNT_MAX}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_adaptive_activation_ttl_above_startup_ceiling() {
        let oversized = FILTER_TTL_MAX_SECONDS + 1;
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"adaptive":{{"activation_ttl_seconds":{oversized}}}}}"#
        ))
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("adaptive.activation_ttl_seconds"), "{err}");
        assert!(
            err.contains(&format!("must be no higher than {FILTER_TTL_MAX_SECONDS}")),
            "{err}"
        );
    }

    #[test]
    fn app_config_accepts_adaptive_activation_ttl_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"adaptive":{{"activation_ttl_seconds":{FILTER_TTL_MAX_SECONDS}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn app_config_rejects_event_log_queue_capacity_above_startup_ceiling() {
        let oversized = EVENT_LOG_QUEUE_CAPACITY_MAX + 1;
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"adaptive":{{"event_log_queue_capacity":{oversized}}}}}"#
        ))
        .unwrap();

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("adaptive.event_log_queue_capacity"), "{err}");
        assert!(
            err.contains(&format!(
                "must be no higher than {EVENT_LOG_QUEUE_CAPACITY_MAX}"
            )),
            "{err}"
        );
    }

    #[test]
    fn app_config_accepts_event_log_queue_capacity_at_startup_ceiling() {
        let cfg: AppConfig = serde_json::from_str(&format!(
            r#"{{"adaptive":{{"event_log_queue_capacity":{EVENT_LOG_QUEUE_CAPACITY_MAX}}}}}"#
        ))
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn tcp_config_defaults_and_accepts_custom_listen_backlog() {
        let default_cfg: super::TcpProxyConfig = serde_json::from_str(
            r#"{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1"}"#,
        )
        .unwrap();
        let custom_cfg: super::TcpProxyConfig = serde_json::from_str(
            r#"{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","listen_backlog":512}"#,
        )
        .unwrap();

        assert_eq!(default_cfg.listen_backlog, 4096);
        assert_eq!(custom_cfg.listen_backlog, 512);
        assert_eq!(default_cfg.accept_shards, 1);
        assert_eq!(default_cfg.downstream_min_rate_bytes_per_second, 512);
        assert_eq!(default_cfg.upstream_min_rate_bytes_per_second, 512);
        assert_eq!(default_cfg.min_rate_grace_ms, 10_000);
        assert_eq!(default_cfg.limits.ipv4_prefix_len, 32);
        assert_eq!(default_cfg.limits.ipv6_prefix_len, 64);
        assert_eq!(default_cfg.limits.global_connects_per_second, 20_000.0);
        assert_eq!(default_cfg.limits.global_connect_burst, 40_000);
    }

    #[test]
    fn tcp_config_accepts_custom_accept_shards() {
        let cfg: super::TcpProxyConfig = serde_json::from_str(
            r#"{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","accept_shards":4}"#,
        )
        .unwrap();

        assert_eq!(cfg.accept_shards, 4);
    }

    #[test]
    fn tcp_config_accepts_custom_min_rate_caps() {
        let cfg: super::TcpProxyConfig = serde_json::from_str(
            r#"{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","downstream_min_rate_bytes_per_second":32,"upstream_min_rate_bytes_per_second":64,"min_rate_grace_ms":500}"#,
        )
        .unwrap();

        assert_eq!(cfg.downstream_min_rate_bytes_per_second, 32);
        assert_eq!(cfg.upstream_min_rate_bytes_per_second, 64);
        assert_eq!(cfg.min_rate_grace_ms, 500);
    }

    #[test]
    fn tcp_config_accepts_custom_global_connection_rate_caps() {
        let cfg: super::TcpProxyConfig = serde_json::from_str(
            r#"{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","limits":{"global_connects_per_second":123.5,"global_connect_burst":17}}"#,
        )
        .unwrap();

        assert_eq!(cfg.limits.global_connects_per_second, 123.5);
        assert_eq!(cfg.limits.global_connect_burst, 17);
    }

    #[test]
    fn tcp_config_accepts_custom_ip_prefix_lengths() {
        let cfg: super::TcpProxyConfig = serde_json::from_str(
            r#"{"name":"tcp","listen":"127.0.0.1:0","upstream":"127.0.0.1:1","limits":{"ipv4_prefix_len":24,"ipv6_prefix_len":56}}"#,
        )
        .unwrap();

        assert_eq!(cfg.limits.ipv4_prefix_len, 24);
        assert_eq!(cfg.limits.ipv6_prefix_len, 56);
    }
}
