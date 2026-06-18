use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::BoxError;

#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    pub client_ip: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap<HeaderValue>,
    pub signature: String,
}

impl<'a> RequestContext<'a> {
    pub fn user_agent(&self) -> String {
        self.headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterFile {
    #[serde(default)]
    pub filters: Vec<FilterRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub adaptive: bool,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub expires_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub condition: FilterCondition,
    #[serde(default)]
    pub action: FilterAction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterCondition {
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_exact: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_contains: Option<String>,
    #[serde(default)]
    pub query_contains: Option<String>,
    #[serde(default)]
    pub user_agent_contains: Option<String>,
    #[serde(default)]
    pub headers: Vec<HeaderContains>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderContains {
    pub name: String,
    pub contains: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterAction {
    #[serde(default = "default_action_kind")]
    pub kind: String,
    #[serde(default = "default_block_status")]
    pub status: u16,
    #[serde(default = "default_block_body")]
    pub body: String,
}

impl Default for FilterAction {
    fn default() -> Self {
        Self {
            kind: default_action_kind(),
            status: default_block_status(),
            body: default_block_body(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterDecision {
    pub rule_id: String,
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone)]
struct RuntimeRule {
    rule: FilterRule,
    active_until: Option<Instant>,
}

impl RuntimeRule {
    fn new(rule: FilterRule, active_until: Option<Instant>) -> Self {
        Self { rule, active_until }
    }
}

#[derive(Debug)]
pub struct FilterEngine {
    static_rules: Vec<FilterRule>,
    runtime_file: PathBuf,
    default_activation_ttl: Duration,
    rules: RwLock<Vec<RuntimeRule>>,
}

impl FilterEngine {
    pub async fn new(
        static_rules: Vec<FilterRule>,
        runtime_file: PathBuf,
        default_activation_ttl: Duration,
    ) -> Arc<Self> {
        let engine = Arc::new(Self {
            static_rules,
            runtime_file,
            default_activation_ttl,
            rules: RwLock::new(Vec::new()),
        });
        if let Err(err) = engine.reload().await {
            eprintln!("filter reload failed: {err}");
        }
        engine
    }

    pub async fn reload(&self) -> Result<(), BoxError> {
        let now = Instant::now();
        let active_by_id: HashMap<String, Option<Instant>> = {
            let existing = match self.rules.read() {
                Ok(existing) => existing,
                Err(poisoned) => {
                    eprintln!("filter engine read lock poisoned during reload; recovering rules");
                    poisoned.into_inner()
                }
            };
            existing
                .iter()
                .map(|runtime| (runtime.rule.id.clone(), runtime.active_until))
                .collect()
        };

        let mut loaded = self.static_rules.clone();
        if tokio::fs::try_exists(&self.runtime_file).await? {
            let raw = tokio::fs::read_to_string(&self.runtime_file).await?;
            if !raw.trim().is_empty() {
                let file: FilterFile = serde_json::from_str(&raw)?;
                loaded.extend(file.filters);
            }
        }
        loaded.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

        let mut runtime_rules = Vec::with_capacity(loaded.len());
        for rule in loaded {
            let active_until = active_by_id
                .get(&rule.id)
                .copied()
                .flatten()
                .filter(|instant| *instant > now);
            runtime_rules.push(RuntimeRule::new(rule, active_until));
        }

        let mut rules = match self.rules.write() {
            Ok(rules) => rules,
            Err(poisoned) => {
                eprintln!("filter engine write lock poisoned during reload; recovering rules");
                poisoned.into_inner()
            }
        };
        *rules = runtime_rules;
        Ok(())
    }

    pub fn evaluate(&self, ctx: &RequestContext<'_>) -> Option<FilterDecision> {
        let now = Instant::now();
        let unix_ms = unix_time_ms();
        let rules = match self.rules.read() {
            Ok(rules) => rules,
            Err(poisoned) => {
                eprintln!("filter engine read lock poisoned during evaluate; recovering rules");
                poisoned.into_inner()
            }
        };
        for runtime in rules.iter() {
            let rule = &runtime.rule;
            if !rule.enabled || is_expired(rule, unix_ms) {
                continue;
            }
            if rule.adaptive && !runtime.active_until.is_some_and(|until| until > now) {
                continue;
            }
            if rule_matches(rule, ctx) {
                return Some(FilterDecision {
                    rule_id: rule.id.clone(),
                    status: rule.action.status,
                    body: rule.action.body.clone(),
                });
            }
        }
        None
    }

    pub fn activate_signature(&self, signature: &str, ttl: Option<Duration>) -> bool {
        let mut activated = false;
        let mut rules = match self.rules.write() {
            Ok(rules) => rules,
            Err(poisoned) => {
                eprintln!("filter engine write lock poisoned during activate; recovering rules");
                poisoned.into_inner()
            }
        };
        for runtime in rules.iter_mut() {
            if runtime.rule.enabled
                && runtime.rule.adaptive
                && runtime.rule.condition.signature.as_deref() == Some(signature)
            {
                let rule_ttl = runtime
                    .rule
                    .ttl_seconds
                    .map(Duration::from_secs)
                    .or(ttl)
                    .unwrap_or(self.default_activation_ttl);
                let active_until = Instant::now() + rule_ttl;
                runtime.active_until = Some(active_until);
                activated = true;
            }
        }
        activated
    }

    pub fn active_rule_count(&self) -> usize {
        let now = Instant::now();
        let rules = match self.rules.read() {
            Ok(rules) => rules,
            Err(poisoned) => {
                eprintln!("filter engine read lock poisoned during metrics; recovering rules");
                poisoned.into_inner()
            }
        };
        rules
            .iter()
            .filter(|rule| {
                !rule.rule.adaptive || rule.active_until.is_some_and(|until| until > now)
            })
            .count()
    }
}

pub fn request_signature(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap<HeaderValue>,
) -> String {
    let basis = signature_basis(method, path, query, headers);
    format!("{:016x}", fnv1a64(basis.as_bytes()))
}

pub fn signature_basis(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap<HeaderValue>,
) -> String {
    let ua = headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(user_agent_family)
        .unwrap_or_else(|| "empty".to_string());
    let accept = headers
        .get(http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(header_class)
        .unwrap_or_else(|| "empty".to_string());
    format!(
        "{}|{}|{}|{}|{}",
        method.to_ascii_uppercase(),
        normalize_path(path),
        query_shape(query.unwrap_or("")),
        ua,
        accept
    )
}

fn rule_matches(rule: &FilterRule, ctx: &RequestContext<'_>) -> bool {
    if !rule.condition.methods.is_empty()
        && !rule
            .condition
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(ctx.method))
    {
        return false;
    }
    if let Some(signature) = &rule.condition.signature {
        if signature != &ctx.signature {
            return false;
        }
    }
    if let Some(path_exact) = &rule.condition.path_exact {
        if ctx.path != path_exact {
            return false;
        }
    }
    if let Some(path_prefix) = &rule.condition.path_prefix {
        if !ctx.path.starts_with(path_prefix) {
            return false;
        }
    }
    if let Some(path_contains) = &rule.condition.path_contains {
        if !ctx.path.contains(path_contains) {
            return false;
        }
    }
    if let Some(query_contains) = &rule.condition.query_contains {
        if !ctx.query.unwrap_or("").contains(query_contains) {
            return false;
        }
    }
    if let Some(ua_contains) = &rule.condition.user_agent_contains {
        let ua = ctx
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !ua.contains(&ua_contains.to_ascii_lowercase()) {
            return false;
        }
    }
    for header in &rule.condition.headers {
        let Ok(name) = http::header::HeaderName::from_bytes(header.name.as_bytes()) else {
            return false;
        };
        let value = ctx
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !value.contains(&header.contains.to_ascii_lowercase()) {
            return false;
        }
    }
    true
}

fn is_expired(rule: &FilterRule, unix_ms: u64) -> bool {
    rule.expires_at_unix_ms
        .is_some_and(|expires_at| expires_at <= unix_ms)
}

fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for segment in path.split('/') {
        if segment.is_empty() {
            out.push('/');
            continue;
        }
        if !out.ends_with('/') {
            out.push('/');
        }
        if segment.bytes().all(|b| b.is_ascii_digit()) {
            out.push_str(":num");
        } else if is_uuid_segment(segment) {
            out.push_str(":uuid");
        } else if segment.len() >= 16 && segment.bytes().all(|b| b.is_ascii_hexdigit()) {
            out.push_str(":hex");
        } else {
            out.push_str(segment);
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        out
    }
}

fn is_uuid_segment(segment: &str) -> bool {
    if segment.len() != 36 {
        return false;
    }
    for (idx, byte) in segment.bytes().enumerate() {
        let expected_hyphen = matches!(idx, 8 | 13 | 18 | 23);
        if expected_hyphen {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn query_shape(query: &str) -> String {
    if query.is_empty() {
        return "none".to_string();
    }
    let mut keys: Vec<&str> = query
        .split('&')
        .filter_map(|pair| pair.split_once('=').map(|(key, _)| key).or(Some(pair)))
        .take(16)
        .collect();
    keys.sort_unstable();
    keys.join(",")
}

fn user_agent_family(ua: &str) -> String {
    let lower = ua.to_ascii_lowercase();
    for known in ["curl", "python", "wrk", "hey", "go-http", "java", "node", "mozilla"] {
        if lower.contains(known) {
            return known.to_string();
        }
    }
    lower
        .split(|c: char| c == '/' || c.is_whitespace() || c == ';')
        .next()
        .unwrap_or("unknown")
        .chars()
        .take(32)
        .collect()
}

fn header_class(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim()
        .chars()
        .take(32)
        .collect()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn default_true() -> bool {
    true
}

fn default_action_kind() -> String {
    "block".to_string()
}

fn default_block_status() -> u16 {
    403
}

fn default_block_body() -> String {
    "blocked\n".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_filter_matches_path() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "test".to_string(),
                enabled: true,
                adaptive: false,
                priority: 1,
                ttl_seconds: None,
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_prefix: Some("/bad".to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/bad/path",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "test");
    }

    #[tokio::test]
    async fn adaptive_filter_only_matches_when_active() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "adaptive".to_string(),
                enabled: true,
                adaptive: true,
                priority: 10,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    signature: Some("abc".to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: "abc".to_string(),
        };
        assert!(engine.evaluate(&ctx).is_none());
        assert!(engine.activate_signature("abc", None));
        assert!(engine.evaluate(&ctx).is_some());
    }

    #[test]
    fn signatures_normalize_numeric_paths() {
        let headers = HeaderMap::new();
        let a = signature_basis("GET", "/users/123/profile", None, &headers);
        let b = signature_basis("GET", "/users/456/profile", None, &headers);
        assert_eq!(a, b);
    }

    #[test]
    fn signatures_normalize_uuid_paths() {
        let headers = HeaderMap::new();
        let a = signature_basis(
            "GET",
            "/objects/8b5f10e8-daf8-4c78-9db2-6af2fc92cb01/detail",
            None,
            &headers,
        );
        let b = signature_basis(
            "GET",
            "/objects/0A7B0FA7-616C-49B3-9E63-F09284F59770/detail",
            None,
            &headers,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn signatures_keep_readable_slugs_distinct() {
        let headers = HeaderMap::new();
        let a = signature_basis("GET", "/products/iphone-16-pro", None, &headers);
        let b = signature_basis("GET", "/products/pixel-11-pro", None, &headers);
        assert_ne!(a, b);
    }

    #[test]
    fn signatures_sort_query_keys() {
        let headers = HeaderMap::new();
        let a = signature_basis("GET", "/search", Some("b=2&a=1"), &headers);
        let b = signature_basis("GET", "/search", Some("a=3&b=4"), &headers);
        assert_eq!(a, b);
    }
}
