use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::BoxError;

pub const DEFAULT_RUNTIME_FILTER_MAX_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_RUNTIME_FILTER_MAX_RULES: usize = 1024;
pub const DEFAULT_STATIC_FILTER_MAX_RULES: usize = DEFAULT_RUNTIME_FILTER_MAX_RULES;
pub const DEFAULT_FILTER_MAX_RULE_ID_BYTES: usize = 128;
pub const DEFAULT_FILTER_MAX_METHODS: usize = 16;
pub const DEFAULT_FILTER_MAX_METHOD_BYTES: usize = 32;
pub const DEFAULT_FILTER_MAX_HEADERS: usize = 16;
pub const DEFAULT_FILTER_MAX_MATCH_VALUE_BYTES: usize = 1024;
pub const DEFAULT_FILTER_MAX_ACTION_BODY_BYTES: usize = 1024;
pub const FILTER_TTL_MAX_SECONDS: u64 = 24 * 60 * 60;
const REQUEST_SIGNATURE_HASH_BYTES: usize = 16;

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
        combined_header_value(self.headers, &http::header::USER_AGENT)
            .unwrap_or(Cow::Borrowed(""))
            .into_owned()
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
    pub path_shape: Option<String>,
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

pub fn validate_filter_rules(
    source: &str,
    rules: &[FilterRule],
    max_rules: usize,
) -> Result<(), BoxError> {
    if max_rules == 0 {
        return Err(format!("{source} rule cap must be greater than zero").into());
    }
    if rules.len() > max_rules {
        return Err(format!(
            "{source} contains {} filters, above configured cap {max_rules}",
            rules.len()
        )
        .into());
    }
    validate_unique_filter_rule_ids(source, rules)?;
    for (idx, rule) in rules.iter().enumerate() {
        validate_filter_rule(&format!("{source}[{idx}]"), rule)?;
    }
    Ok(())
}

fn validate_unique_filter_rule_ids(source: &str, rules: &[FilterRule]) -> Result<(), BoxError> {
    let mut seen_ids = HashSet::new();
    for (idx, rule) in rules.iter().enumerate() {
        if !seen_ids.insert(rule.id.as_str()) {
            return Err(format!("{source}[{idx}].id duplicates rule id {:?}", rule.id).into());
        }
    }
    Ok(())
}

fn validate_filter_rule(path: &str, rule: &FilterRule) -> Result<(), BoxError> {
    validate_non_empty_bounded_string(
        &format!("{path}.id"),
        &rule.id,
        DEFAULT_FILTER_MAX_RULE_ID_BYTES,
    )?;
    if let Some(ttl_seconds) = rule.ttl_seconds {
        validate_filter_ttl(&format!("{path}.ttl_seconds"), ttl_seconds)?;
    }
    validate_filter_condition(path, &rule.condition)?;
    validate_filter_action(path, &rule.action)?;
    Ok(())
}

fn validate_filter_ttl(path: &str, ttl_seconds: u64) -> Result<(), BoxError> {
    if ttl_seconds == 0 {
        return Err(format!("{path} must be greater than zero").into());
    }
    if ttl_seconds > FILTER_TTL_MAX_SECONDS {
        return Err(format!("{path} must be no higher than {FILTER_TTL_MAX_SECONDS}").into());
    }
    Ok(())
}

fn validate_filter_condition(path: &str, condition: &FilterCondition) -> Result<(), BoxError> {
    let condition_path = format!("{path}.condition");
    if condition.methods.is_empty()
        && condition.path_exact.is_none()
        && condition.path_prefix.is_none()
        && condition.path_contains.is_none()
        && condition.query_contains.is_none()
        && condition.path_shape.is_none()
        && condition.user_agent_contains.is_none()
        && condition.headers.is_empty()
        && condition.signature.is_none()
    {
        return Err(format!("{condition_path} must include at least one matcher").into());
    }
    if condition.methods.len() > DEFAULT_FILTER_MAX_METHODS {
        return Err(format!(
            "{condition_path}.methods contains {} methods, above configured cap {}",
            condition.methods.len(),
            DEFAULT_FILTER_MAX_METHODS
        )
        .into());
    }
    for (idx, method) in condition.methods.iter().enumerate() {
        validate_method_token(&format!("{condition_path}.methods[{idx}]"), method)?;
    }
    for (field, value) in [
        ("path_exact", condition.path_exact.as_ref()),
        ("path_prefix", condition.path_prefix.as_ref()),
        ("path_contains", condition.path_contains.as_ref()),
        ("query_contains", condition.query_contains.as_ref()),
        ("path_shape", condition.path_shape.as_ref()),
        (
            "user_agent_contains",
            condition.user_agent_contains.as_ref(),
        ),
        ("signature", condition.signature.as_ref()),
    ] {
        if let Some(value) = value {
            validate_non_empty_bounded_string(
                &format!("{condition_path}.{field}"),
                value,
                DEFAULT_FILTER_MAX_MATCH_VALUE_BYTES,
            )?;
        }
    }
    if condition.path_prefix.as_deref() == Some("/") {
        return Err(format!("{condition_path}.path_prefix must be narrower than /").into());
    }
    if condition.headers.len() > DEFAULT_FILTER_MAX_HEADERS {
        return Err(format!(
            "{condition_path}.headers contains {} matchers, above configured cap {}",
            condition.headers.len(),
            DEFAULT_FILTER_MAX_HEADERS
        )
        .into());
    }
    for (idx, header) in condition.headers.iter().enumerate() {
        let header_path = format!("{condition_path}.headers[{idx}]");
        HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|err| format!("{header_path}.name is not a valid HTTP header name: {err}"))?;
        validate_non_empty_bounded_string(
            &format!("{header_path}.contains"),
            &header.contains,
            DEFAULT_FILTER_MAX_MATCH_VALUE_BYTES,
        )?;
    }
    Ok(())
}

fn validate_filter_action(path: &str, action: &FilterAction) -> Result<(), BoxError> {
    let action_path = format!("{path}.action");
    if action.kind != "block" {
        return Err(format!("{action_path}.kind must be \"block\"").into());
    }
    if !(400..=599).contains(&action.status) {
        return Err(format!("{action_path}.status must be an HTTP 4xx or 5xx status").into());
    }
    if action.body.len() > DEFAULT_FILTER_MAX_ACTION_BODY_BYTES {
        return Err(format!(
            "{action_path}.body is {} bytes, above configured cap {}",
            action.body.len(),
            DEFAULT_FILTER_MAX_ACTION_BODY_BYTES
        )
        .into());
    }
    Ok(())
}

fn validate_method_token(path: &str, value: &str) -> Result<(), BoxError> {
    validate_non_empty_bounded_string(path, value, DEFAULT_FILTER_MAX_METHOD_BYTES)?;
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(format!("{path} must not contain whitespace or control characters").into());
    }
    Ok(())
}

fn validate_non_empty_bounded_string(
    path: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), BoxError> {
    if value.is_empty() {
        return Err(format!("{path} must not be empty").into());
    }
    if value.len() > max_bytes {
        return Err(format!(
            "{path} is {} bytes, above configured cap {max_bytes}",
            value.len()
        )
        .into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterDecision {
    pub rule_id: String,
    pub status: u16,
    pub body: String,
}

#[derive(Debug)]
struct RuntimeRule {
    rule: FilterRule,
    condition: CompiledCondition,
    active_until_ms: AtomicU64,
}

impl RuntimeRule {
    fn new(rule: FilterRule, active_until_ms: u64) -> Self {
        let condition = CompiledCondition::from_filter(&rule.condition);
        Self {
            rule,
            condition,
            active_until_ms: AtomicU64::new(active_until_ms),
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledCondition {
    valid: bool,
    user_agent_contains: Option<Vec<u8>>,
    headers: Vec<CompiledHeaderContains>,
}

impl CompiledCondition {
    fn from_filter(condition: &FilterCondition) -> Self {
        let mut headers = Vec::with_capacity(condition.headers.len());
        for header in &condition.headers {
            let Ok(name) = HeaderName::from_bytes(header.name.as_bytes()) else {
                return Self {
                    valid: false,
                    user_agent_contains: None,
                    headers: Vec::new(),
                };
            };
            headers.push(CompiledHeaderContains {
                name,
                contains: header.contains.as_bytes().to_vec(),
            });
        }
        Self {
            valid: true,
            user_agent_contains: condition
                .user_agent_contains
                .as_ref()
                .map(|value| value.as_bytes().to_vec()),
            headers,
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledHeaderContains {
    name: HeaderName,
    contains: Vec<u8>,
}

#[derive(Debug, Default)]
struct FilterEvalScratch {
    path_shape: Option<String>,
    short_token_parent_shape: Option<Option<String>>,
    legacy_signature: Option<String>,
}

impl FilterEvalScratch {
    fn path_shape(&mut self, path: &str) -> &str {
        self.path_shape
            .get_or_insert_with(|| request_path_shape(path))
            .as_str()
    }

    fn matches_path_shape(&mut self, path: &str, expected: &str) -> bool {
        if self.path_shape(path) == expected {
            return true;
        }
        let parent = self
            .short_token_parent_shape
            .get_or_insert_with(|| short_token_parent_shape(path).map(|(shape, _)| shape));
        parent.as_deref() == Some(expected)
    }

    fn legacy_signature(&mut self, ctx: &RequestContext<'_>) -> &str {
        self.legacy_signature
            .get_or_insert_with(|| {
                legacy_request_signature(ctx.method, ctx.path, ctx.query, ctx.headers)
            })
            .as_str()
    }
}

#[derive(Debug)]
pub struct FilterEngine {
    static_rules: Vec<FilterRule>,
    runtime_file: PathBuf,
    default_activation_ttl: Duration,
    max_runtime_file_bytes: u64,
    max_runtime_filters: usize,
    rules: RwLock<Arc<Vec<RuntimeRule>>>,
    activation_deadlines: Mutex<HashMap<String, u64>>,
}

impl FilterEngine {
    pub async fn new(
        static_rules: Vec<FilterRule>,
        runtime_file: PathBuf,
        default_activation_ttl: Duration,
    ) -> Arc<Self> {
        Self::new_with_limits(
            static_rules,
            runtime_file,
            default_activation_ttl,
            DEFAULT_RUNTIME_FILTER_MAX_BYTES,
            DEFAULT_RUNTIME_FILTER_MAX_RULES,
        )
        .await
    }

    pub async fn new_with_limits(
        static_rules: Vec<FilterRule>,
        runtime_file: PathBuf,
        default_activation_ttl: Duration,
        max_runtime_file_bytes: u64,
        max_runtime_filters: usize,
    ) -> Arc<Self> {
        let engine = Arc::new(Self {
            static_rules,
            runtime_file,
            default_activation_ttl,
            max_runtime_file_bytes: max_runtime_file_bytes.max(1),
            max_runtime_filters: max_runtime_filters.max(1),
            rules: RwLock::new(Arc::new(Vec::new())),
            activation_deadlines: Mutex::new(HashMap::new()),
        });
        if let Err(err) = engine.reload().await {
            eprintln!("filter reload failed: {err}");
        }
        engine
    }

    pub async fn reload(&self) -> Result<(), BoxError> {
        let mut loaded = self.static_rules.clone();
        if let Some(file) = self.load_runtime_filter_file().await? {
            loaded.extend(file.filters);
        }
        validate_unique_filter_rule_ids("merged filters", &loaded)?;
        loaded.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

        let now_ms = unix_time_ms();
        let loaded_rule_ids = loaded
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<HashSet<_>>();
        let mut activation_deadlines =
            self.lock_activation_deadlines("reload activation state preservation");
        activation_deadlines.retain(|rule_id, active_until_ms| {
            *active_until_ms > now_ms && loaded_rule_ids.contains(rule_id.as_str())
        });
        let mut runtime_rules = Vec::with_capacity(loaded.len());
        for rule in loaded {
            let active_until_ms = activation_deadlines
                .get(&rule.id)
                .copied()
                .filter(|active_until_ms| *active_until_ms > now_ms)
                .unwrap_or(0);
            runtime_rules.push(RuntimeRule::new(rule, active_until_ms));
        }
        self.replace_rules(runtime_rules, "reload");
        Ok(())
    }

    fn rules_snapshot(&self, purpose: &str) -> Arc<Vec<RuntimeRule>> {
        let rules = match self.rules.read() {
            Ok(rules) => rules,
            Err(poisoned) => {
                eprintln!("filter engine read lock poisoned during {purpose}; recovering rules");
                poisoned.into_inner()
            }
        };
        Arc::clone(&rules)
    }

    fn replace_rules(&self, runtime_rules: Vec<RuntimeRule>, purpose: &str) {
        let mut rules = match self.rules.write() {
            Ok(rules) => rules,
            Err(poisoned) => {
                eprintln!("filter engine write lock poisoned during {purpose}; recovering rules");
                poisoned.into_inner()
            }
        };
        *rules = Arc::new(runtime_rules);
    }

    fn lock_activation_deadlines(
        &self,
        purpose: &str,
    ) -> std::sync::MutexGuard<'_, HashMap<String, u64>> {
        match self.activation_deadlines.lock() {
            Ok(deadlines) => deadlines,
            Err(poisoned) => {
                eprintln!("filter activation state lock poisoned during {purpose}; recovering");
                poisoned.into_inner()
            }
        }
    }

    async fn load_runtime_filter_file(&self) -> Result<Option<FilterFile>, BoxError> {
        let file = match tokio::fs::File::open(&self.runtime_file).await {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Box::new(err)),
        };

        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime filter path is not a regular file: {}",
                    self.runtime_file.display()
                ),
            )
            .into());
        }
        if metadata.len() > self.max_runtime_file_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime filter file {} is {} bytes, above configured cap {}",
                    self.runtime_file.display(),
                    metadata.len(),
                    self.max_runtime_file_bytes
                ),
            )
            .into());
        }

        let mut raw = String::new();
        let mut limited = file.take(self.max_runtime_file_bytes.saturating_add(1));
        limited.read_to_string(&mut raw).await?;
        if raw.len() as u64 > self.max_runtime_file_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime filter file {} exceeded configured read cap {}",
                    self.runtime_file.display(),
                    self.max_runtime_file_bytes
                ),
            )
            .into());
        }
        if raw.trim().is_empty() {
            return Ok(None);
        }

        let file: FilterFile = serde_json::from_str(&raw)?;
        if file.filters.len() > self.max_runtime_filters {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime filter file {} contains {} filters, above configured cap {}",
                    self.runtime_file.display(),
                    file.filters.len(),
                    self.max_runtime_filters
                ),
            )
            .into());
        }
        validate_filter_rules(
            &format!("runtime filter file {}", self.runtime_file.display()),
            &file.filters,
            self.max_runtime_filters,
        )?;
        Ok(Some(file))
    }

    pub fn evaluate(&self, ctx: &RequestContext<'_>) -> Option<FilterDecision> {
        let unix_ms = unix_time_ms();
        let rules = self.rules_snapshot("evaluate");
        let mut scratch = FilterEvalScratch::default();
        for runtime in rules.iter() {
            let rule = &runtime.rule;
            if !rule.enabled || is_expired(rule, unix_ms) {
                continue;
            }
            if rule.adaptive && runtime.active_until_ms.load(Ordering::Relaxed) <= unix_ms {
                continue;
            }
            if rule_matches(runtime, ctx, &mut scratch) {
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
        let unix_ms = unix_time_ms();
        let mut activation_deadlines = self.lock_activation_deadlines("signature activation");
        let rules = self.rules_snapshot("signature activation");
        for runtime in rules.iter() {
            if runtime.rule.enabled
                && runtime.rule.adaptive
                && !is_expired(&runtime.rule, unix_ms)
                && runtime.rule.condition.signature.as_deref() == Some(signature)
            {
                let rule_ttl = bounded_activation_ttl(
                    runtime.rule.ttl_seconds,
                    ttl,
                    self.default_activation_ttl,
                );
                let active_until_ms = active_until_ms_from_ttl(rule_ttl);
                runtime
                    .active_until_ms
                    .store(active_until_ms, Ordering::Relaxed);
                activation_deadlines.insert(runtime.rule.id.clone(), active_until_ms);
                activated = true;
            }
        }
        activated
    }

    pub fn activate_path_shape(&self, path_shape: &str, ttl: Option<Duration>) -> bool {
        let mut activated = false;
        let unix_ms = unix_time_ms();
        let mut activation_deadlines = self.lock_activation_deadlines("path-shape activation");
        let rules = self.rules_snapshot("path-shape activation");
        for runtime in rules.iter() {
            if runtime.rule.enabled
                && runtime.rule.adaptive
                && !is_expired(&runtime.rule, unix_ms)
                && runtime.rule.condition.path_shape.as_deref() == Some(path_shape)
            {
                let rule_ttl = bounded_activation_ttl(
                    runtime.rule.ttl_seconds,
                    ttl,
                    self.default_activation_ttl,
                );
                let active_until_ms = active_until_ms_from_ttl(rule_ttl);
                runtime
                    .active_until_ms
                    .store(active_until_ms, Ordering::Relaxed);
                activation_deadlines.insert(runtime.rule.id.clone(), active_until_ms);
                activated = true;
            }
        }
        activated
    }

    pub fn active_rule_count(&self) -> usize {
        let now_ms = unix_time_ms();
        let rules = self.rules_snapshot("metrics");
        rules
            .iter()
            .filter(|runtime| rule_is_active(runtime, now_ms))
            .count()
    }
}

fn bounded_activation_ttl(
    rule_ttl_seconds: Option<u64>,
    requested_ttl: Option<Duration>,
    default_ttl: Duration,
) -> Duration {
    let ttl_seconds = match rule_ttl_seconds {
        Some(seconds) => seconds,
        None => requested_ttl.unwrap_or(default_ttl).as_secs(),
    };
    Duration::from_secs(ttl_seconds.clamp(1, FILTER_TTL_MAX_SECONDS))
}

fn active_until_ms_from_ttl(ttl: Duration) -> u64 {
    let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
    unix_time_ms().saturating_add(ttl_ms)
}

pub fn request_signature(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap<HeaderValue>,
) -> String {
    let basis = signature_basis(method, path, query, headers);
    hex_prefix(
        blake3::hash(basis.as_bytes()).as_bytes(),
        REQUEST_SIGNATURE_HASH_BYTES,
    )
}

pub fn legacy_request_signature(
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
    let ua = combined_header_value(headers, &http::header::USER_AGENT)
        .map(|value| user_agent_family(value.as_ref()))
        .unwrap_or_else(|| "empty".to_string());
    let accept = combined_header_value(headers, &http::header::ACCEPT)
        .map(|value| header_class(value.as_ref()))
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

fn rule_matches(
    runtime: &RuntimeRule,
    ctx: &RequestContext<'_>,
    scratch: &mut FilterEvalScratch,
) -> bool {
    let rule = &runtime.rule;
    let compiled = &runtime.condition;
    if !compiled.valid {
        return false;
    }
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
        if signature != &ctx.signature && signature != scratch.legacy_signature(ctx) {
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
    if let Some(path_shape) = &rule.condition.path_shape {
        if !scratch.matches_path_shape(ctx.path, path_shape) {
            return false;
        }
    }
    if let Some(query_contains) = &rule.condition.query_contains {
        if !ctx.query.unwrap_or("").contains(query_contains) {
            return false;
        }
    }
    if let Some(needle) = &compiled.user_agent_contains {
        if !header_values_contain_ignore_case(ctx.headers, &http::header::USER_AGENT, needle) {
            return false;
        }
    }
    for header in &compiled.headers {
        if !header_values_contain_ignore_case(ctx.headers, &header.name, &header.contains) {
            return false;
        }
    }
    true
}

fn combined_header_value<'a>(
    headers: &'a HeaderMap<HeaderValue>,
    name: &HeaderName,
) -> Option<Cow<'a, str>> {
    let mut values = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok());
    let first = values.next()?;
    let Some(second) = values.next() else {
        return Some(Cow::Borrowed(first));
    };
    let mut combined = String::with_capacity(first.len() + second.len() + 2);
    combined.push_str(first);
    combined.push_str(", ");
    combined.push_str(second);
    for value in values {
        combined.push_str(", ");
        combined.push_str(value);
    }
    Some(Cow::Owned(combined))
}

fn header_values_contain_ignore_case(
    headers: &HeaderMap<HeaderValue>,
    name: &HeaderName,
    needle: &[u8],
) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| ascii_contains_ignore_case(value.as_bytes(), needle))
}

fn hex_prefix(bytes: &[u8], prefix_len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(prefix_len * 2);
    for byte in bytes.iter().take(prefix_len) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn ascii_contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn is_expired(rule: &FilterRule, unix_ms: u64) -> bool {
    rule.expires_at_unix_ms
        .is_some_and(|expires_at| expires_at <= unix_ms)
}

fn rule_is_active(runtime: &RuntimeRule, unix_ms: u64) -> bool {
    runtime.rule.enabled
        && !is_expired(&runtime.rule, unix_ms)
        && (!runtime.rule.adaptive || runtime.active_until_ms.load(Ordering::Relaxed) > unix_ms)
}

fn normalize_path(path: &str) -> String {
    normalize_path_with(path, false)
}

pub fn request_path_shape(path: &str) -> String {
    normalize_path_with(path, true)
}

pub fn short_token_parent_shape(path: &str) -> Option<(String, String)> {
    let mut out = String::with_capacity(path.len());
    let mut token = None;
    for segment in path.split('/') {
        if segment.is_empty() {
            out.push('/');
            continue;
        }
        let replace = token.is_none() && is_low_confidence_short_token_segment(segment);
        append_normalized_segment(&mut out, segment, true, replace);
        if replace {
            token = Some(segment.to_string());
        }
    }
    token.map(|token| {
        if out.is_empty() {
            ("/".to_string(), token)
        } else {
            (out, token)
        }
    })
}

fn normalize_path_with(path: &str, include_high_entropy_tokens: bool) -> String {
    let mut out = String::with_capacity(path.len());
    for segment in path.split('/') {
        if segment.is_empty() {
            out.push('/');
            continue;
        }
        append_normalized_segment(&mut out, segment, include_high_entropy_tokens, false);
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        out
    }
}

fn append_normalized_segment(
    out: &mut String,
    segment: &str,
    include_high_entropy_tokens: bool,
    force_short_token: bool,
) {
    if !out.ends_with('/') {
        out.push('/');
    }
    if force_short_token {
        out.push_str(":short-token");
    } else if segment.bytes().all(|b| b.is_ascii_digit()) {
        out.push_str(":num");
    } else if is_uuid_segment(segment) {
        out.push_str(":uuid");
    } else if segment.len() >= 16 && segment.bytes().all(|b| b.is_ascii_hexdigit()) {
        out.push_str(":hex");
    } else if include_high_entropy_tokens && is_long_token_segment(segment) {
        out.push_str(":token");
    } else if include_high_entropy_tokens && is_short_rotating_token_segment(segment) {
        out.push_str(":short-token");
    } else {
        out.push_str(segment);
    }
}

fn is_long_token_segment(segment: &str) -> bool {
    if segment.len() < 10 || !segment.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    if segment.bytes().any(|b| b.is_ascii_digit()) {
        return true;
    }
    if segment.bytes().any(|b| b.is_ascii_uppercase()) {
        return true;
    }
    !is_common_path_segment(segment)
}

fn is_short_rotating_token_segment(segment: &str) -> bool {
    if !(2..10).contains(&segment.len()) || !segment.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    if is_version_segment(segment) || is_common_path_segment(segment) {
        return false;
    }
    segment
        .bytes()
        .any(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

fn is_low_confidence_short_token_segment(segment: &str) -> bool {
    (2..=3).contains(&segment.len())
        && segment.bytes().all(|b| b.is_ascii_lowercase())
        && !is_version_segment(segment)
        && !is_common_path_segment(segment)
}

fn is_version_segment(segment: &str) -> bool {
    let Some(rest) = segment.strip_prefix('v') else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

fn is_common_path_segment(segment: &str) -> bool {
    const COMMON_SEGMENTS: &[&str] = &[
        "api",
        "app",
        "auth",
        "blog",
        "cart",
        "docs",
        "home",
        "jobs",
        "json",
        "login",
        "news",
        "oauth",
        "order",
        "price",
        "store",
        "users",
        "subscription",
        "membership",
        "onboarding",
        "authentication",
        "authorization",
        "notification",
        "notifications",
        "preferences",
        "marketplace",
        "integration",
        "integrations",
        "transaction",
        "transactions",
        "organization",
        "organizations",
        "certificate",
        "certificates",
        "configuration",
        "documentation",
        "catalog",
        "checkout",
        "dashboard",
        "inventory",
        "customers",
        "products",
        "settings",
        "profile",
        "profiles",
        "analytics",
        "warehouse",
        "fulfillment",
        "warehouses",
    ];
    COMMON_SEGMENTS.contains(&segment)
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
    for known in [
        "curl", "python", "wrk", "hey", "go-http", "java", "node", "mozilla",
    ] {
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

    fn temp_runtime_filter_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "altura-prot-{name}-{}-{nonce}.json",
            std::process::id()
        ))
    }

    fn path_rule(id: &str, path_exact: &str) -> FilterRule {
        FilterRule {
            id: id.to_string(),
            enabled: true,
            adaptive: false,
            priority: 1,
            ttl_seconds: None,
            expires_at_unix_ms: None,
            condition: FilterCondition {
                path_exact: Some(path_exact.to_string()),
                ..Default::default()
            },
            action: FilterAction::default(),
        }
    }

    fn runtime_filter_json(rules: &[FilterRule]) -> String {
        serde_json::to_string(&FilterFile {
            filters: rules.to_vec(),
        })
        .unwrap()
    }

    #[test]
    fn filter_rule_validation_rejects_zero_ttl() {
        let mut rule = path_rule("bad-ttl", "/blocked");
        rule.ttl_seconds = Some(0);

        let err = validate_filter_rules("filters.static_rules", &[rule], 4)
            .unwrap_err()
            .to_string();

        assert!(err.contains("filters.static_rules[0].ttl_seconds"), "{err}");
        assert!(err.contains("must be greater than zero"), "{err}");
    }

    #[test]
    fn filter_rule_validation_rejects_ttl_above_ceiling() {
        let mut rule = path_rule("bad-ttl", "/blocked");
        rule.ttl_seconds = Some(FILTER_TTL_MAX_SECONDS + 1);

        let err = validate_filter_rules("filters.static_rules", &[rule], 4)
            .unwrap_err()
            .to_string();

        assert!(err.contains("filters.static_rules[0].ttl_seconds"), "{err}");
        assert!(
            err.contains(&format!("must be no higher than {FILTER_TTL_MAX_SECONDS}")),
            "{err}"
        );
    }

    #[test]
    fn filter_rule_validation_rejects_duplicate_rule_ids() {
        let first = path_rule("duplicate", "/one");
        let second = path_rule("duplicate", "/two");

        let err = validate_filter_rules("filters.static_rules", &[first, second], 4)
            .unwrap_err()
            .to_string();

        assert!(err.contains("filters.static_rules[1].id"), "{err}");
        assert!(err.contains("duplicates rule id"), "{err}");
    }

    #[test]
    fn filter_rule_validation_rejects_root_path_prefix() {
        let mut rule = path_rule("catchall-prefix", "/blocked");
        rule.condition.path_exact = None;
        rule.condition.path_prefix = Some("/".to_string());

        let err = validate_filter_rules("filters.static_rules", &[rule], 4)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("filters.static_rules[0].condition.path_prefix"),
            "{err}"
        );
        assert!(err.contains("narrower than /"), "{err}");
    }

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
    async fn filter_signature_conditions_accept_legacy_fnv_signatures() {
        let headers = HeaderMap::new();
        let legacy_signature =
            legacy_request_signature("GET", "/api/users/123", Some("cachebust=1"), &headers);
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "legacy-signature".to_string(),
                enabled: true,
                adaptive: false,
                priority: 1,
                ttl_seconds: None,
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    signature: Some(legacy_signature),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-legacy-signature-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/users/123",
            query: Some("cachebust=1"),
            headers: &headers,
            signature: request_signature("GET", "/api/users/123", Some("cachebust=1"), &headers),
        };

        assert_eq!(
            engine.evaluate(&ctx).map(|decision| decision.rule_id),
            Some("legacy-signature".to_string())
        );
    }

    #[test]
    fn ascii_contains_ignore_case_matches_without_allocating_lowercase_strings() {
        assert!(ascii_contains_ignore_case(
            b"Legit MixedBot/1.0",
            b"mixedbot"
        ));
        assert!(ascii_contains_ignore_case(b"anything", b""));
        assert!(!ascii_contains_ignore_case(b"short", b"longer-needle"));
        assert!(!ascii_contains_ignore_case(b"mozilla", b"python"));
    }

    #[tokio::test]
    async fn filter_matches_compiled_user_agent_and_header_conditions_case_insensitively() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "compiled-header".to_string(),
                enabled: true,
                adaptive: false,
                priority: 1,
                ttl_seconds: None,
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    user_agent_contains: Some("MIXEDBOT".to_string()),
                    headers: vec![HeaderContains {
                        name: "X-Altura-Signal".to_string(),
                        contains: "FLOOD".to_string(),
                    }],
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static("legit mixedbot/1.0"),
        );
        headers.insert(
            HeaderName::from_static("x-altura-signal"),
            HeaderValue::from_static("prefix flood suffix"),
        );
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "compiled-header");
    }

    #[tokio::test]
    async fn filter_matches_duplicate_user_agent_and_header_values() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "duplicate-header-values".to_string(),
                enabled: true,
                adaptive: false,
                priority: 1,
                ttl_seconds: None,
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    user_agent_contains: Some("floodbot".to_string()),
                    headers: vec![HeaderContains {
                        name: "X-Altura-Signal".to_string(),
                        contains: "burst".to_string(),
                    }],
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-duplicate-header-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::USER_AGENT,
            HeaderValue::from_static("legit browser"),
        );
        headers.append(
            http::header::USER_AGENT,
            HeaderValue::from_static("floodbot/1.0"),
        );
        headers.append(
            HeaderName::from_static("x-altura-signal"),
            HeaderValue::from_static("warmup"),
        );
        headers.append(
            HeaderName::from_static("x-altura-signal"),
            HeaderValue::from_static("coordinated burst"),
        );
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };

        assert_eq!(
            engine.evaluate(&ctx).map(|decision| decision.rule_id),
            Some("duplicate-header-values".to_string())
        );
        assert_eq!(ctx.user_agent(), "legit browser, floodbot/1.0");
    }

    #[tokio::test]
    async fn filter_with_invalid_header_condition_never_matches() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "invalid-header".to_string(),
                enabled: true,
                adaptive: false,
                priority: 1,
                ttl_seconds: None,
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_exact: Some("/blocked".to_string()),
                    headers: vec![HeaderContains {
                        name: "bad header".to_string(),
                        contains: "anything".to_string(),
                    }],
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
            path: "/blocked",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert!(engine.evaluate(&ctx).is_none());
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

    #[tokio::test]
    async fn expired_adaptive_rules_do_not_activate_or_count_active() {
        let expired_at = unix_time_ms().saturating_sub(1);
        let engine = FilterEngine::new(
            vec![
                FilterRule {
                    id: "expired-signature".to_string(),
                    enabled: true,
                    adaptive: true,
                    priority: 10,
                    ttl_seconds: Some(30),
                    expires_at_unix_ms: Some(expired_at),
                    condition: FilterCondition {
                        signature: Some("expired".to_string()),
                        ..Default::default()
                    },
                    action: FilterAction::default(),
                },
                FilterRule {
                    id: "expired-shape".to_string(),
                    enabled: true,
                    adaptive: true,
                    priority: 10,
                    ttl_seconds: Some(30),
                    expires_at_unix_ms: Some(expired_at),
                    condition: FilterCondition {
                        path_shape: Some("/api/:token".to_string()),
                        ..Default::default()
                    },
                    action: FilterAction::default(),
                },
            ],
            PathBuf::from("/tmp/altura-prot-nonexistent-expired-adaptive-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/abcdefghij",
            query: None,
            headers: &headers,
            signature: "expired".to_string(),
        };

        assert!(!engine.activate_signature("expired", None));
        assert!(!engine.activate_path_shape("/api/:token", None));
        assert_eq!(engine.active_rule_count(), 0);
        assert!(engine.evaluate(&ctx).is_none());
    }

    #[tokio::test]
    async fn active_rule_count_matches_evaluation_gates() {
        let mut expired_static = path_rule("expired-static", "/expired");
        expired_static.expires_at_unix_ms = Some(unix_time_ms().saturating_sub(1));
        let mut disabled_static = path_rule("disabled-static", "/disabled");
        disabled_static.enabled = false;
        let engine = FilterEngine::new(
            vec![
                path_rule("static", "/blocked"),
                expired_static,
                disabled_static,
                FilterRule {
                    id: "inactive-adaptive".to_string(),
                    enabled: true,
                    adaptive: true,
                    priority: 10,
                    ttl_seconds: Some(30),
                    expires_at_unix_ms: None,
                    condition: FilterCondition {
                        signature: Some("adaptive".to_string()),
                        ..Default::default()
                    },
                    action: FilterAction::default(),
                },
            ],
            PathBuf::from("/tmp/altura-prot-nonexistent-active-count-filters.json"),
            Duration::from_secs(30),
        )
        .await;

        assert_eq!(engine.active_rule_count(), 1);
        assert!(engine.activate_signature("adaptive", None));
        assert_eq!(engine.active_rule_count(), 2);
    }

    #[tokio::test]
    async fn adaptive_activation_does_not_wait_for_rule_snapshot_readers() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "adaptive-nonblocking".to_string(),
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
        let held_snapshot_reader = engine.rules.read().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let engine_for_thread = Arc::clone(&engine);

        std::thread::spawn(move || {
            tx.send(engine_for_thread.activate_signature("abc", None))
                .unwrap();
        });

        assert!(rx.recv_timeout(Duration::from_millis(250)).unwrap());
        drop(held_snapshot_reader);

        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: "abc".to_string(),
        };
        assert_eq!(
            engine.evaluate(&ctx).map(|decision| decision.rule_id),
            Some("adaptive-nonblocking".to_string())
        );
    }

    #[tokio::test]
    async fn adaptive_activation_clamps_unvalidated_ttl_before_instant_math() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "adaptive-huge-ttl".to_string(),
                enabled: true,
                adaptive: true,
                priority: 10,
                ttl_seconds: Some(u64::MAX),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    signature: Some("huge".to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-filters.json"),
            Duration::from_secs(u64::MAX),
        )
        .await;
        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: "huge".to_string(),
        };

        assert!(engine.activate_signature("huge", Some(Duration::from_secs(u64::MAX))));
        assert!(engine.evaluate(&ctx).is_some());
    }

    #[tokio::test]
    async fn runtime_filter_reload_rejects_ttl_above_ceiling_and_preserves_last_good_rules() {
        let path = temp_runtime_filter_path("ttl-runtime-filters");
        std::fs::write(&path, runtime_filter_json(&[path_rule("good", "/blocked")])).unwrap();
        let engine = FilterEngine::new_with_limits(
            Vec::new(),
            path.clone(),
            Duration::from_secs(30),
            4096,
            4,
        )
        .await;

        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/blocked",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "good");

        let mut bad = path_rule("bad", "/bad");
        bad.ttl_seconds = Some(FILTER_TTL_MAX_SECONDS + 1);
        std::fs::write(&path, runtime_filter_json(&[bad])).unwrap();

        let err = engine.reload().await.unwrap_err().to_string();

        assert!(err.contains("[0].ttl_seconds"), "{err}");
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "good");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn runtime_filter_reload_prunes_activation_deadlines_for_removed_rules() {
        let path = temp_runtime_filter_path("activation-prune-runtime-filters");
        let mut first = path_rule("first", "/first");
        first.adaptive = true;
        first.ttl_seconds = Some(60);
        first.condition.signature = Some("sig-first".to_string());
        std::fs::write(&path, runtime_filter_json(&[first])).unwrap();
        let engine = FilterEngine::new_with_limits(
            Vec::new(),
            path.clone(),
            Duration::from_secs(60),
            4096,
            4,
        )
        .await;

        assert!(engine.activate_signature("sig-first", None));
        {
            let activation_deadlines =
                engine.lock_activation_deadlines("test activation deadline inserted");
            assert!(activation_deadlines.contains_key("first"));
        }

        let mut second = path_rule("second", "/second");
        second.adaptive = true;
        second.ttl_seconds = Some(60);
        second.condition.signature = Some("sig-second".to_string());
        std::fs::write(&path, runtime_filter_json(&[second])).unwrap();

        engine.reload().await.unwrap();

        let activation_deadlines =
            engine.lock_activation_deadlines("test activation deadline pruning");
        assert!(!activation_deadlines.contains_key("first"));
        assert!(activation_deadlines.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn runtime_filter_reload_rejects_oversized_file_and_preserves_last_good_rules() {
        let path = temp_runtime_filter_path("oversized-runtime-filters");
        std::fs::write(&path, runtime_filter_json(&[path_rule("good", "/blocked")])).unwrap();
        let engine = FilterEngine::new_with_limits(
            Vec::new(),
            path.clone(),
            Duration::from_secs(30),
            4096,
            4,
        )
        .await;

        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/blocked",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "good");

        std::fs::write(
            &path,
            format!(
                r#"{{"filters":[{{"id":"bad","condition":{{"path_exact":"/bad"}},"action":{{"kind":"block","status":403,"body":"{}"}}}}]}}"#,
                "x".repeat(8192)
            ),
        )
        .unwrap();

        assert!(engine.reload().await.is_err());
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "good");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn runtime_filter_reload_rejects_too_many_rules_and_preserves_last_good_rules() {
        let path = temp_runtime_filter_path("many-runtime-filters");
        std::fs::write(&path, runtime_filter_json(&[path_rule("good", "/blocked")])).unwrap();
        let engine = FilterEngine::new_with_limits(
            Vec::new(),
            path.clone(),
            Duration::from_secs(30),
            2048,
            1,
        )
        .await;

        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/blocked",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "good");

        std::fs::write(
            &path,
            runtime_filter_json(&[path_rule("one", "/one"), path_rule("two", "/two")]),
        )
        .unwrap();

        assert!(engine.reload().await.is_err());
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "good");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn runtime_filter_reload_rejects_invalid_rules_and_preserves_last_good_rules() {
        let path = temp_runtime_filter_path("invalid-runtime-filters");
        std::fs::write(&path, runtime_filter_json(&[path_rule("good", "/blocked")])).unwrap();
        let engine = FilterEngine::new_with_limits(
            Vec::new(),
            path.clone(),
            Duration::from_secs(30),
            2048,
            4,
        )
        .await;

        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/blocked",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "good");

        let mut invalid = path_rule("invalid-status", "/blocked");
        invalid.action.status = 200;
        std::fs::write(&path, runtime_filter_json(&[invalid])).unwrap();

        let err = engine.reload().await.unwrap_err().to_string();

        assert!(err.contains("action.status"), "{err}");
        assert_eq!(engine.evaluate(&ctx).unwrap().rule_id, "good");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn runtime_filter_reload_rejects_static_runtime_duplicate_ids_and_preserves_rules() {
        let path = temp_runtime_filter_path("duplicate-merged-runtime-filters");
        let static_rule = path_rule("shared-id", "/static-blocked");
        std::fs::write(
            &path,
            runtime_filter_json(&[path_rule("runtime-good", "/runtime-blocked")]),
        )
        .unwrap();
        let engine = FilterEngine::new_with_limits(
            vec![static_rule],
            path.clone(),
            Duration::from_secs(30),
            4096,
            4,
        )
        .await;

        let headers = HeaderMap::new();
        let static_ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/static-blocked",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        let runtime_ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/runtime-blocked",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert_eq!(engine.evaluate(&static_ctx).unwrap().rule_id, "shared-id");
        assert_eq!(
            engine.evaluate(&runtime_ctx).unwrap().rule_id,
            "runtime-good"
        );

        std::fs::write(
            &path,
            runtime_filter_json(&[path_rule("shared-id", "/runtime-shadow")]),
        )
        .unwrap();

        let err = engine.reload().await.unwrap_err().to_string();

        assert!(err.contains("merged filters[1].id"), "{err}");
        assert!(err.contains("duplicates rule id \"shared-id\""), "{err}");
        assert_eq!(engine.evaluate(&static_ctx).unwrap().rule_id, "shared-id");
        assert_eq!(
            engine.evaluate(&runtime_ctx).unwrap().rule_id,
            "runtime-good"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn runtime_filter_reload_rejects_non_regular_files() {
        let path = std::env::temp_dir().join(format!(
            "altura-prot-runtime-filter-dir-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        let engine = FilterEngine::new_with_limits(
            Vec::new(),
            path.clone(),
            Duration::from_secs(30),
            2048,
            4,
        )
        .await;

        assert!(engine.reload().await.is_err());
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn request_signature_uses_blake3_fingerprint_with_legacy_helper() {
        let headers = HeaderMap::new();
        let first = request_signature("GET", "/users/123/profile", None, &headers);
        let second = request_signature("GET", "/users/456/profile", None, &headers);
        let legacy = legacy_request_signature("GET", "/users/123/profile", None, &headers);

        assert_eq!(first, second);
        assert_eq!(first.len(), REQUEST_SIGNATURE_HASH_BYTES * 2);
        assert_eq!(legacy.len(), 16);
        assert_ne!(first, legacy);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(legacy.bytes().all(|byte| byte.is_ascii_hexdigit()));
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

    #[test]
    fn signatures_classify_combined_duplicate_header_values() {
        let mut first_only = HeaderMap::new();
        first_only.append(
            http::header::USER_AGENT,
            HeaderValue::from_static("randomized-browser"),
        );
        first_only.append(
            http::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        let mut duplicate_values = first_only.clone();
        duplicate_values.append(
            http::header::USER_AGENT,
            HeaderValue::from_static("Python-Requests/2.32"),
        );
        duplicate_values.append(http::header::ACCEPT, HeaderValue::from_static("text/html"));

        let baseline = signature_basis("GET", "/api/catalog", None, &first_only);
        let combined = signature_basis("GET", "/api/catalog", None, &duplicate_values);

        assert_ne!(baseline, combined);
        assert!(combined.contains("|python|"));
        assert!(combined.ends_with("|application/json"));
    }

    #[test]
    fn path_shape_generalizes_long_tokens_without_changing_signature_basis() {
        let headers = HeaderMap::new();
        assert_ne!(
            signature_basis("GET", "/api/abcdefghij/123", None, &headers),
            signature_basis("GET", "/api/klmnopqrst/456", None, &headers)
        );
        assert_eq!(
            request_path_shape("/api/abcdefghij/123"),
            request_path_shape("/api/klmnopqrst/456")
        );
        assert_eq!(request_path_shape("/api/catalog/123"), "/api/catalog/:num");
        assert_eq!(
            request_path_shape("/api/subscription/123"),
            "/api/subscription/:num"
        );
    }

    #[test]
    fn path_shape_preserves_short_words_but_exposes_short_sibling_parent_shape() {
        let headers = HeaderMap::new();
        assert_ne!(
            signature_basis("GET", "/api/ab", None, &headers),
            signature_basis("GET", "/api/cd", None, &headers)
        );
        assert_eq!(request_path_shape("/api/ab"), "/api/ab");
        assert_eq!(request_path_shape("/api/cd"), "/api/cd");
        assert_eq!(
            short_token_parent_shape("/api/ab"),
            Some(("/api/:short-token".to_string(), "ab".to_string()))
        );
        assert_eq!(
            short_token_parent_shape("/api/cd"),
            Some(("/api/:short-token".to_string(), "cd".to_string()))
        );
        assert_eq!(request_path_shape("/api/a1"), "/api/:short-token");
        assert_eq!(request_path_shape("/api/aB"), "/api/:short-token");
        assert_eq!(request_path_shape("/api/v1/users"), "/api/v1/users");
        assert_eq!(request_path_shape("/api/v2/users"), "/api/v2/users");
        assert!(short_token_parent_shape("/api/v1/users").is_none());
        assert!(short_token_parent_shape("/api/me").is_some());
    }

    #[tokio::test]
    async fn filter_matches_path_shape() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "shape".to_string(),
                enabled: true,
                adaptive: false,
                priority: 1,
                ttl_seconds: None,
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some("/api/:token/:num".to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let headers = HeaderMap::new();
        let matching = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/abcdefghij/123",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        let benign = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/catalog/123",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert!(engine.evaluate(&matching).is_some());
        assert!(engine.evaluate(&benign).is_none());
    }

    #[tokio::test]
    async fn filter_matches_short_token_parent_shape() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "short-shape".to_string(),
                enabled: true,
                adaptive: false,
                priority: 1,
                ttl_seconds: None,
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some("/api/:short-token".to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-short-shape-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let headers = HeaderMap::new();
        let matching = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/ef",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        let version = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/v1/users",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert!(engine.evaluate(&matching).is_some());
        assert!(engine.evaluate(&version).is_none());
    }

    #[tokio::test]
    async fn adaptive_path_shape_filter_activates() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "shape".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some("/api/:token/:num".to_string()),
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
            path: "/api/abcdefghij/123",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        assert!(engine.evaluate(&ctx).is_none());
        assert!(engine.activate_path_shape("/api/:token/:num", None));
        assert!(engine.evaluate(&ctx).is_some());
    }
}
