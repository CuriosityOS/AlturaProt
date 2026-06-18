use std::{fs, path::PathBuf, time::Duration};

use serde::Deserialize;

use crate::{filter::FilterRule, BoxError};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub http: Option<HttpConfig>,
    #[serde(default)]
    pub tcp: Vec<TcpProxyConfig>,
    #[serde(default)]
    pub filters: FilterConfig,
    #[serde(default)]
    pub adaptive: AdaptiveConfig,
}

impl AppConfig {
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, BoxError> {
        let path = path.into();
        let raw = fs::read_to_string(&path)?;
        let mut cfg: Self = serde_json::from_str(&raw)?;
        cfg.filters.resolve_relative_paths(path.parent().map(PathBuf::from));
        cfg.adaptive.resolve_relative_paths(path.parent().map(PathBuf::from));
        Ok(cfg)
    }
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
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default)]
    pub limits: HttpLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpLimitConfig {
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: f64,
    #[serde(default = "default_per_ip_burst")]
    pub per_ip_burst: u32,
    #[serde(default = "default_global_rps")]
    pub global_rps: f64,
    #[serde(default = "default_global_burst")]
    pub global_burst: u32,
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
}

impl Default for HttpLimitConfig {
    fn default() -> Self {
        Self {
            per_ip_rps: default_per_ip_rps(),
            per_ip_burst: default_per_ip_burst(),
            global_rps: default_global_rps(),
            global_burst: default_global_burst(),
            max_tracked_ips: default_max_tracked_ips(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpProxyConfig {
    pub name: String,
    pub listen: String,
    pub upstream: String,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_tcp_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
    #[serde(default)]
    pub limits: TcpLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpLimitConfig {
    #[serde(default = "default_tcp_connects_per_second")]
    pub per_ip_connects_per_second: f64,
    #[serde(default = "default_tcp_connect_burst")]
    pub per_ip_connect_burst: u32,
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
    #[serde(default)]
    pub static_rules: Vec<FilterRule>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            runtime_file: default_runtime_filter_file(),
            reload_seconds: default_reload_seconds(),
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
    #[serde(default = "default_event_cooldown_seconds")]
    pub event_cooldown_seconds: u64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            signature_threshold_per_second: default_signature_threshold(),
            activation_ttl_seconds: default_activation_ttl_seconds(),
            event_log: default_attack_event_log(),
            event_cooldown_seconds: default_event_cooldown_seconds(),
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
}

fn default_true() -> bool {
    true
}

fn default_admin_prefix() -> String {
    "/__altura".to_string()
}

fn default_max_header_bytes() -> usize {
    32 * 1024
}

fn default_per_ip_rps() -> f64 {
    200.0
}

fn default_per_ip_burst() -> u32 {
    400
}

fn default_global_rps() -> f64 {
    20_000.0
}

fn default_global_burst() -> u32 {
    40_000
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

fn default_tcp_max_connections_per_ip() -> usize {
    128
}

fn default_connect_timeout_ms() -> u64 {
    1000
}

fn default_tcp_idle_timeout_seconds() -> u64 {
    300
}

fn default_runtime_filter_file() -> PathBuf {
    PathBuf::from("runtime/filters.json")
}

fn default_reload_seconds() -> u64 {
    2
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

fn default_event_cooldown_seconds() -> u64 {
    5
}
