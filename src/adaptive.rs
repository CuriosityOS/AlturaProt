use std::{
    collections::{HashMap, VecDeque},
    hash::{Hash, Hasher},
    sync::Arc,
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{
    filter::{
        legacy_request_signature, request_path_shape, signature_basis, FilterEngine, RequestContext,
    },
    limiter::TokenBucket,
    telemetry::{unix_time_ms, AdaptiveWindowStats, AttackEvent, EventLogger},
};

const SHARDS: usize = 64;
const MAX_SHAPE_SAMPLES_PER_SECOND: u64 = 64;
const ADAPTIVE_WINDOW_IDLE_SECONDS: u64 = 120;
const ADAPTIVE_WINDOW_EVICTION_SCAN_LIMIT: usize = 32;
const TRUNCATED_MARKER: &str = "...[truncated]";
const MAX_EVENT_PATH_BYTES: usize = 1024;
const MAX_EVENT_PATH_SHAPE_BYTES: usize = 512;
const MAX_EVENT_QUERY_BYTES: usize = 1024;
const MAX_EVENT_QUERY_KEY_BYTES: usize = 128;
const MAX_EVENT_USER_AGENT_BYTES: usize = 512;
const MAX_EVENT_X_FORWARDED_FOR_BYTES: usize = 512;
const MAX_EVENT_HEADER_NAME_BYTES: usize = 128;
const MAX_EVENT_SIGNATURE_BASIS_BYTES: usize = 1024;

#[derive(Debug)]
struct SignatureWindow {
    bucket: TokenBucket,
    observed_count: u64,
    last_event: Option<Instant>,
    last_strong_event: Option<Instant>,
    last_seen: Instant,
}

#[derive(Debug)]
struct ShapeWindow {
    bucket: TokenBucket,
    strong_bucket: TokenBucket,
    observed_count: u64,
    strong_count: u64,
    sample_window_start: Instant,
    emitted_samples: u64,
    last_seen: Instant,
}

#[derive(Debug)]
struct WindowShard<T> {
    entries: HashMap<String, T>,
    order: VecDeque<String>,
}

impl<T> WindowShard<T> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

#[derive(Debug)]
struct Observation {
    count: u64,
    activate: bool,
    emit: bool,
}

#[derive(Debug)]
struct ShapeObservation {
    count: u64,
    activate: bool,
    emit: bool,
    reason: &'static str,
    shape: String,
}

#[derive(Debug, Clone, Copy)]
pub struct AdaptiveDetectorConfig {
    pub enabled: bool,
    pub threshold_per_second: u64,
    pub activation_ttl: Duration,
    pub event_cooldown: Duration,
    pub max_signature_windows: usize,
    pub max_path_shape_windows: usize,
}

#[derive(Debug)]
pub struct AdaptiveDetector {
    enabled: bool,
    threshold_per_second: u64,
    activation_ttl: Duration,
    event_cooldown: Duration,
    engine: Arc<FilterEngine>,
    logger: Arc<EventLogger>,
    max_signature_windows_per_shard: usize,
    max_path_shape_windows_per_shard: usize,
    windows: Vec<Mutex<WindowShard<SignatureWindow>>>,
    shape_windows: Vec<Mutex<WindowShard<ShapeWindow>>>,
}

impl AdaptiveDetector {
    pub fn new(
        cfg: AdaptiveDetectorConfig,
        engine: Arc<FilterEngine>,
        logger: Arc<EventLogger>,
    ) -> Arc<Self> {
        Arc::new(Self {
            enabled: cfg.enabled,
            threshold_per_second: cfg.threshold_per_second.max(1),
            activation_ttl: cfg.activation_ttl,
            event_cooldown: cfg.event_cooldown,
            engine,
            logger,
            max_signature_windows_per_shard: adaptive_shard_capacity(cfg.max_signature_windows),
            max_path_shape_windows_per_shard: adaptive_shard_capacity(cfg.max_path_shape_windows),
            windows: (0..SHARDS)
                .map(|_| Mutex::new(WindowShard::new()))
                .collect(),
            shape_windows: (0..SHARDS)
                .map(|_| Mutex::new(WindowShard::new()))
                .collect(),
        })
    }

    pub fn observe(&self, ctx: &RequestContext<'_>, reason: &str) {
        let path_shape = request_path_shape(ctx.path);
        self.observe_with_path_shape(ctx, reason, &path_shape);
    }

    pub fn observe_with_path_shape(
        &self,
        ctx: &RequestContext<'_>,
        reason: &str,
        path_shape: &str,
    ) {
        if !self.enabled {
            return;
        }

        let observation = self.observe_signature(&ctx.signature, reason);
        let shape_observation = if should_track_path_shape(reason) {
            self.observe_path_shape(path_shape, is_strong_reason(reason), reason)
        } else {
            None
        };

        if observation.activate {
            let _ = self
                .engine
                .activate_signature(&ctx.signature, Some(self.activation_ttl));
            let legacy_signature =
                legacy_request_signature(ctx.method, ctx.path, ctx.query, ctx.headers);
            if legacy_signature != ctx.signature {
                let _ = self
                    .engine
                    .activate_signature(&legacy_signature, Some(self.activation_ttl));
            }
        }
        if let Some(shape_observation) = &shape_observation {
            if shape_observation.activate {
                let _ = self
                    .engine
                    .activate_path_shape(&shape_observation.shape, Some(self.activation_ttl));
            }
            if shape_observation.emit && !observation.emit {
                self.log_event(
                    ctx,
                    shape_observation.reason,
                    shape_observation.count,
                    shape_observation.shape.clone(),
                );
            }
        }

        if observation.emit {
            self.log_event(ctx, reason, observation.count, path_shape.to_string());
        }
    }

    fn log_event(
        &self,
        ctx: &RequestContext<'_>,
        reason: &str,
        observed_count: u64,
        path_shape: String,
    ) {
        self.logger.log(AttackEvent {
            schema_version: 2,
            ts_unix_ms: unix_time_ms(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.to_string(),
            path: bounded_event_string(ctx.path, MAX_EVENT_PATH_BYTES),
            path_shape: bounded_event_string(&path_shape, MAX_EVENT_PATH_SHAPE_BYTES),
            query: ctx
                .query
                .map(|query| bounded_event_string(query, MAX_EVENT_QUERY_BYTES)),
            query_keys: query_keys(ctx.query.unwrap_or("")),
            user_agent: bounded_event_string(&ctx.user_agent(), MAX_EVENT_USER_AGENT_BYTES),
            x_forwarded_for: ctx
                .headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .map(|value| bounded_event_string(value, MAX_EVENT_X_FORWARDED_FOR_BYTES)),
            header_names: header_names(ctx),
            signature: ctx.signature.clone(),
            signature_basis: bounded_event_string(
                &signature_basis(ctx.method, ctx.path, ctx.query, ctx.headers),
                MAX_EVENT_SIGNATURE_BASIS_BYTES,
            ),
            reason: reason.to_string(),
            observed_count,
        });
    }

    fn observe_signature(&self, signature: &str, reason: &str) -> Observation {
        let now = Instant::now();
        let strong_reason = is_strong_reason(reason);
        let shard_idx = shard_for(signature);
        let mut windows = match self.windows[shard_idx].lock() {
            Ok(windows) => windows,
            Err(poisoned) => {
                eprintln!("adaptive detector shard mutex poisoned; recovering state");
                poisoned.into_inner()
            }
        };
        let window = if let Some(window) = windows.entries.get_mut(signature) {
            window
        } else {
            if !ensure_signature_window_capacity(
                &mut windows,
                self.max_signature_windows_per_shard,
                now,
            ) {
                return Observation {
                    count: 0,
                    activate: false,
                    emit: false,
                };
            }
            let signature_owned = signature.to_string();
            windows.order.push_back(signature_owned.clone());
            windows
                .entries
                .entry(signature_owned)
                .or_insert_with(|| SignatureWindow {
                    bucket: adaptive_bucket(self.threshold_per_second, now),
                    observed_count: 0,
                    last_event: None,
                    last_strong_event: None,
                    last_seen: now,
                })
        };
        window.last_seen = now;
        window.observed_count = window.observed_count.saturating_add(1);
        let count = window.observed_count;
        let activate = self.threshold_per_second == 1 || !window.bucket.allow(now, 1.0);
        let regular_emit = activate
            && window
                .last_event
                .is_none_or(|last| now.saturating_duration_since(last) >= self.event_cooldown);
        let strong_emit = strong_reason
            && activate
            && window
                .last_strong_event
                .is_none_or(|last| now.saturating_duration_since(last) >= self.event_cooldown);
        let emit = regular_emit || strong_emit;
        if regular_emit {
            window.last_event = Some(now);
        }
        if strong_emit {
            window.last_strong_event = Some(now);
        }
        Observation {
            count,
            activate,
            emit,
        }
    }

    fn observe_path_shape(
        &self,
        path_shape: &str,
        strong_evidence: bool,
        reason: &str,
    ) -> Option<ShapeObservation> {
        let now = Instant::now();
        let shard_idx = shard_for(path_shape);
        let mut windows = match self.shape_windows[shard_idx].lock() {
            Ok(windows) => windows,
            Err(poisoned) => {
                eprintln!("adaptive detector shape shard mutex poisoned; recovering state");
                poisoned.into_inner()
            }
        };
        let window = if let Some(window) = windows.entries.get_mut(path_shape) {
            window
        } else {
            if !ensure_shape_window_capacity(
                &mut windows,
                self.max_path_shape_windows_per_shard,
                now,
            ) {
                return None;
            }
            let path_shape_owned = path_shape.to_string();
            windows.order.push_back(path_shape_owned.clone());
            windows
                .entries
                .entry(path_shape_owned)
                .or_insert_with(|| ShapeWindow {
                    bucket: adaptive_bucket(self.threshold_per_second, now),
                    strong_bucket: adaptive_bucket(self.threshold_per_second, now),
                    observed_count: 0,
                    strong_count: 0,
                    sample_window_start: now,
                    emitted_samples: 0,
                    last_seen: now,
                })
        };
        window.last_seen = now;
        window.observed_count = window.observed_count.saturating_add(1);
        if now.saturating_duration_since(window.sample_window_start) >= Duration::from_secs(1) {
            window.sample_window_start = now;
            window.emitted_samples = 0;
        }
        let observed_count = window.observed_count;
        let observed_pressure = self.threshold_per_second == 1 || !window.bucket.allow(now, 1.0);
        let strong_pressure = if strong_evidence {
            window.strong_count = window.strong_count.saturating_add(1);
            self.threshold_per_second == 1 || !window.strong_bucket.allow(now, 1.0)
        } else {
            false
        };
        if observed_pressure || strong_pressure {
            let emit = window.emitted_samples < MAX_SHAPE_SAMPLES_PER_SECOND;
            if !emit && !strong_pressure {
                return None;
            }
            if emit {
                window.emitted_samples += 1;
            }
            return Some(ShapeObservation {
                count: if strong_pressure {
                    window.strong_count
                } else {
                    observed_count
                },
                activate: strong_pressure,
                emit,
                reason: if strong_pressure {
                    shape_reason(reason)
                } else {
                    "global_observed"
                },
                shape: path_shape.to_string(),
            });
        }
        None
    }

    pub fn window_stats(&self) -> AdaptiveWindowStats {
        AdaptiveWindowStats {
            signature_windows: self.window_count(&self.windows, "signature"),
            path_shape_windows: self.window_count(&self.shape_windows, "path-shape"),
            signature_window_capacity: self.max_signature_windows_per_shard * SHARDS,
            path_shape_window_capacity: self.max_path_shape_windows_per_shard * SHARDS,
        }
    }

    fn window_count<T>(&self, windows: &[Mutex<WindowShard<T>>], label: &str) -> usize {
        windows
            .iter()
            .map(|shard| match shard.lock() {
                Ok(shard) => shard.entries.len(),
                Err(poisoned) => {
                    eprintln!(
                        "adaptive detector {label} metrics shard mutex poisoned; recovering state"
                    );
                    poisoned.into_inner().entries.len()
                }
            })
            .sum()
    }
}

fn query_keys(query: &str) -> Vec<String> {
    if query.is_empty() {
        return Vec::new();
    }
    let mut keys: Vec<String> = query
        .split('&')
        .filter_map(|pair| pair.split_once('=').map(|(key, _)| key).or(Some(pair)))
        .take(16)
        .map(|key| bounded_event_string(key, MAX_EVENT_QUERY_KEY_BYTES))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn header_names(ctx: &RequestContext<'_>) -> Vec<String> {
    let mut names: Vec<String> = ctx
        .headers
        .keys()
        .take(32)
        .map(|name| bounded_event_string(name.as_str(), MAX_EVENT_HEADER_NAME_BYTES))
        .collect();
    names.sort_unstable();
    names
}

fn shard_for(signature: &str) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    signature.hash(&mut hasher);
    (hasher.finish() as usize) % SHARDS
}

fn is_strong_reason(reason: &str) -> bool {
    matches!(
        reason,
        "rate_limited"
            | "global_rate_limited"
            | "per_ip_rate_limited"
            | "signature_rate_limited"
            | "path_shape_rate_limited"
            | "trusted_proxy_rate_limited"
            | "filter_block"
            | "body_too_large"
    )
}

fn should_track_path_shape(reason: &str) -> bool {
    reason == "observed" || is_strong_reason(reason)
}

fn shape_reason(reason: &str) -> &'static str {
    match reason {
        "rate_limited" => "rate_limited",
        "global_rate_limited" => "global_rate_limited",
        "per_ip_rate_limited" => "per_ip_rate_limited",
        "signature_rate_limited" => "signature_rate_limited",
        "path_shape_rate_limited" => "path_shape_rate_limited",
        "trusted_proxy_rate_limited" => "trusted_proxy_rate_limited",
        "filter_block" => "filter_block",
        "body_too_large" => "body_too_large",
        _ => "path_shape_strong_evidence",
    }
}

fn adaptive_shard_capacity(max_windows: usize) -> usize {
    max_windows.max(1).div_ceil(SHARDS).max(1)
}

fn adaptive_bucket(threshold_per_second: u64, now: Instant) -> TokenBucket {
    TokenBucket::new(
        threshold_per_second as f64,
        adaptive_activation_burst(threshold_per_second),
        now,
    )
}

fn adaptive_activation_burst(threshold_per_second: u64) -> u32 {
    threshold_per_second
        .saturating_sub(1)
        .max(1)
        .min(u32::MAX as u64) as u32
}

fn adaptive_window_idle() -> Duration {
    Duration::from_secs(ADAPTIVE_WINDOW_IDLE_SECONDS)
}

fn ensure_signature_window_capacity(
    windows: &mut WindowShard<SignatureWindow>,
    capacity: usize,
    now: Instant,
) -> bool {
    ensure_window_capacity(windows, capacity, |window| {
        now.saturating_duration_since(window.last_seen) >= adaptive_window_idle()
    })
}

fn ensure_shape_window_capacity(
    windows: &mut WindowShard<ShapeWindow>,
    capacity: usize,
    now: Instant,
) -> bool {
    ensure_window_capacity(windows, capacity, |window| {
        now.saturating_duration_since(window.last_seen) >= adaptive_window_idle()
    })
}

fn ensure_window_capacity<T>(
    windows: &mut WindowShard<T>,
    capacity: usize,
    can_evict: impl Fn(&T) -> bool,
) -> bool {
    if windows.entries.len() < capacity {
        return true;
    }
    let scan = windows.order.len().min(ADAPTIVE_WINDOW_EVICTION_SCAN_LIMIT);
    for _ in 0..scan {
        let Some(oldest) = windows.order.pop_front() else {
            break;
        };
        let evict = windows.entries.get(&oldest).is_some_and(&can_evict);
        if evict {
            windows.entries.remove(&oldest);
            return windows.entries.len() < capacity;
        }
        if windows.entries.contains_key(&oldest) {
            windows.order.push_back(oldest);
        }
    }
    windows.entries.len() < capacity
}

fn bounded_event_string(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let marker_len = TRUNCATED_MARKER.len();
    if max_bytes <= marker_len {
        return value[..utf8_boundary_at_or_before(value, max_bytes)].to_string();
    }
    let keep = max_bytes - marker_len;
    let boundary = utf8_boundary_at_or_before(value, keep);
    format!("{}{}", &value[..boundary], TRUNCATED_MARKER)
}

fn utf8_boundary_at_or_before(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use http::{HeaderMap, HeaderName, HeaderValue};

    use crate::{
        filter::{FilterAction, FilterCondition, FilterRule},
        telemetry::EventLogger,
    };

    use super::*;

    #[test]
    fn trusted_proxy_rate_limited_is_strong_evidence() {
        assert!(is_strong_reason("trusted_proxy_rate_limited"));
    }

    #[tokio::test]
    async fn detector_activates_learned_signature() {
        let signature = "0123456789abcdef0123456789abcdef";
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "learned".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    signature: Some(signature.to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger = Arc::new(EventLogger::new("/tmp/altura-prot-test-events.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(2, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: signature.to_string(),
        };
        assert!(engine.evaluate(&ctx).is_none());
        detector.observe(&ctx, "test");
        assert!(engine.evaluate(&ctx).is_none());
        detector.observe(&ctx, "test");
        assert!(engine.evaluate(&ctx).is_some());
    }

    #[tokio::test]
    async fn detector_activates_legacy_learned_signature() {
        let headers = HeaderMap::new();
        let legacy_signature = legacy_request_signature("GET", "/api/orders/123", None, &headers);
        let current_signature =
            crate::filter::request_signature("GET", "/api/orders/123", None, &headers);
        assert_ne!(legacy_signature, current_signature);
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "legacy-learned".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    signature: Some(legacy_signature),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-legacy-adaptive-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-legacy-events.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(2, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/orders/123",
            query: None,
            headers: &headers,
            signature: current_signature,
        };

        assert!(engine.evaluate(&ctx).is_none());
        detector.observe(&ctx, "test");
        assert!(engine.evaluate(&ctx).is_none());
        detector.observe(&ctx, "test");
        assert_eq!(
            engine.evaluate(&ctx).map(|decision| decision.rule_id),
            Some("legacy-learned".to_string())
        );
    }

    #[tokio::test]
    async fn detector_keeps_distinct_signatures_below_threshold() {
        let signature_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let signature_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "learned".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    signature: Some(signature_a.to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-events-distinct.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(2, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let headers = HeaderMap::new();
        let ctx_a = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: signature_a.to_string(),
        };
        let ctx_b = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: signature_b.to_string(),
        };
        detector.observe(&ctx_a, "test");
        detector.observe(&ctx_b, "test");
        assert!(engine.evaluate(&ctx_a).is_none());
    }

    #[tokio::test]
    async fn detector_requires_strong_evidence_for_path_shape_activation() {
        let shape = "/api/:token/:num";
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "shape".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some(shape.to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-shape-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-shape-events.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(2, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let headers = HeaderMap::new();
        let ctx_a = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/abcdefghij/1",
            query: None,
            headers: &headers,
            signature: "sig-a".to_string(),
        };
        let ctx_b = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/klmnopqrst/2",
            query: None,
            headers: &headers,
            signature: "sig-b".to_string(),
        };
        assert!(engine.evaluate(&ctx_a).is_none());
        detector.observe(&ctx_a, "observed");
        detector.observe(&ctx_a, "rate_limited");
        assert!(engine.evaluate(&ctx_a).is_none());
        detector.observe(&ctx_b, "observed");
        assert!(engine.evaluate(&ctx_a).is_none());
        assert!(engine.evaluate(&ctx_b).is_none());
        detector.observe(&ctx_b, "rate_limited");
        assert!(engine.evaluate(&ctx_a).is_some());
        assert!(engine.evaluate(&ctx_b).is_some());
    }

    #[tokio::test]
    async fn detector_counts_path_shape_once_per_observed_request_without_activation() {
        let shape = "/api/:token/:num";
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "shape".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some(shape.to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-shape-count-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-shape-count-events.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(2, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/abcdefghij/1",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        detector.observe(&ctx, "observed");
        detector.observe(&ctx, "rate_limited");
        assert!(engine.evaluate(&ctx).is_none());
        detector.observe(&ctx, "observed");
        detector.observe(&ctx, "observed");
        assert!(engine.evaluate(&ctx).is_none());
    }

    #[tokio::test]
    async fn detector_activates_path_shape_after_repeated_strong_evidence() {
        let shape = "/api/:token/:num";
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "shape".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some(shape.to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-shape-strong-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-shape-strong-events.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(2, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let headers = HeaderMap::new();
        let ctx_a = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/abcdefghij/1",
            query: None,
            headers: &headers,
            signature: "sig-a".to_string(),
        };
        let ctx_b = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/klmnopqrst/2",
            query: None,
            headers: &headers,
            signature: "sig-b".to_string(),
        };

        detector.observe(&ctx_a, "signature_rate_limited");
        assert!(engine.evaluate(&ctx_a).is_none());
        detector.observe(&ctx_b, "signature_rate_limited");
        assert!(engine.evaluate(&ctx_a).is_some());
        assert!(engine.evaluate(&ctx_b).is_some());
    }

    #[tokio::test]
    async fn detector_activates_path_shape_when_sample_cap_is_full() {
        let shape = "/api/:token/:num";
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "shape-sample-cap".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some(shape.to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-shape-sample-cap-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger = Arc::new(
            EventLogger::new("/tmp/altura-prot-test-shape-sample-cap-events.jsonl").unwrap(),
        );
        let detector = AdaptiveDetector::new(
            test_detector_config(1, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/abcdefghij/1",
            query: None,
            headers: &headers,
            signature: "shape-sample-cap".to_string(),
        };

        for idx in 0..MAX_SHAPE_SAMPLES_PER_SECOND {
            let observed = RequestContext {
                signature: format!("shape-sample-cap-observed-{idx}"),
                ..ctx.clone()
            };
            detector.observe(&observed, "observed");
        }
        assert!(engine.evaluate(&ctx).is_none());

        detector.observe(&ctx, "path_shape_rate_limited");

        assert!(engine.evaluate(&ctx).is_some());
    }

    #[tokio::test]
    async fn detector_uses_overridden_path_shape_for_short_sibling_evidence() {
        let shape = "/api/:short-token";
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "short-shape".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some(shape.to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-short-shape-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-short-shape-events.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(2, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let headers = HeaderMap::new();
        let ctx_a = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/ef",
            query: None,
            headers: &headers,
            signature: "short-sig-a".to_string(),
        };
        let ctx_b = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/gh",
            query: None,
            headers: &headers,
            signature: "short-sig-b".to_string(),
        };

        assert!(engine.evaluate(&ctx_a).is_none());
        detector.observe_with_path_shape(&ctx_a, "path_shape_rate_limited", shape);
        assert!(engine.evaluate(&ctx_a).is_none());
        detector.observe_with_path_shape(&ctx_b, "path_shape_rate_limited", shape);
        assert!(engine.evaluate(&ctx_a).is_some());
        assert!(engine.evaluate(&ctx_b).is_some());
    }

    #[tokio::test]
    async fn detector_does_not_activate_catalog_shape_from_observed_only_traffic() {
        let shape = "/api/catalog/:num";
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "shape".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    path_shape: Some(shape.to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-benign-shape-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-benign-shape-events.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(2, 8_192, 8_192),
            Arc::clone(&engine),
            logger,
        );
        let headers = HeaderMap::new();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/api/catalog/42",
            query: None,
            headers: &headers,
            signature: "sig".to_string(),
        };
        for _ in 0..4 {
            detector.observe(&ctx, "observed");
        }
        assert!(engine.evaluate(&ctx).is_none());
    }

    #[tokio::test]
    async fn detector_preserves_recent_signature_window_at_capacity() {
        let engine = FilterEngine::new(
            Vec::new(),
            PathBuf::from("/tmp/altura-prot-nonexistent-signature-cap-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-signature-cap-events.jsonl").unwrap());
        let detector =
            AdaptiveDetector::new(test_detector_config(100, SHARDS, 8_192), engine, logger);
        let signatures = same_signature_shard_keys("sig-cap", 3);
        let shard_idx = shard_for(&signatures[0]);
        let headers = HeaderMap::new();

        for signature in &signatures {
            let ctx = RequestContext {
                client_ip: "127.0.0.1".parse().unwrap(),
                method: "GET",
                path: "/",
                query: None,
                headers: &headers,
                signature: signature.clone(),
            };
            detector.observe(&ctx, "test");
        }

        let windows = detector.windows[shard_idx].lock().unwrap();
        assert_eq!(windows.entries.len(), 1);
        assert!(windows.entries.contains_key(&signatures[0]));
        assert!(!windows.entries.contains_key(signatures.last().unwrap()));
    }

    #[tokio::test]
    async fn detector_preserves_recent_path_shape_window_at_capacity() {
        let engine = FilterEngine::new(
            Vec::new(),
            PathBuf::from("/tmp/altura-prot-nonexistent-shape-cap-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::new("/tmp/altura-prot-test-shape-cap-events.jsonl").unwrap());
        let detector =
            AdaptiveDetector::new(test_detector_config(100, 8_192, SHARDS), engine, logger);
        let shapes = same_path_shape_shard_keys("shape-cap", 3);
        let shard_idx = shard_for(&shapes[0]);
        let headers = HeaderMap::new();

        for (idx, shape) in shapes.iter().enumerate() {
            let ctx = RequestContext {
                client_ip: "127.0.0.1".parse().unwrap(),
                method: "GET",
                path: shape,
                query: None,
                headers: &headers,
                signature: format!("shape-cap-sig-{idx}"),
            };
            detector.observe(&ctx, "observed");
        }

        let windows = detector.shape_windows[shard_idx].lock().unwrap();
        assert_eq!(windows.entries.len(), 1);
        assert!(windows.entries.contains_key(&shapes[0]));
        assert!(!windows.entries.contains_key(shapes.last().unwrap()));
    }

    #[tokio::test]
    async fn detector_evicts_idle_signature_window_at_capacity() {
        let engine = FilterEngine::new(
            Vec::new(),
            PathBuf::from("/tmp/altura-prot-nonexistent-signature-idle-cap-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger = Arc::new(
            EventLogger::new("/tmp/altura-prot-test-signature-idle-cap-events.jsonl").unwrap(),
        );
        let detector =
            AdaptiveDetector::new(test_detector_config(100, SHARDS, 8_192), engine, logger);
        let signatures = same_signature_shard_keys("sig-idle-cap", 2);
        let shard_idx = shard_for(&signatures[0]);
        let headers = HeaderMap::new();
        let first = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: signatures[0].clone(),
        };
        detector.observe(&first, "test");
        {
            let mut windows = detector.windows[shard_idx].lock().unwrap();
            windows.entries.get_mut(&signatures[0]).unwrap().last_seen = Instant::now()
                .checked_sub(adaptive_window_idle() + Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }

        let second = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: signatures[1].clone(),
        };
        detector.observe(&second, "test");

        let windows = detector.windows[shard_idx].lock().unwrap();
        assert_eq!(windows.entries.len(), 1);
        assert!(!windows.entries.contains_key(&signatures[0]));
        assert!(windows.entries.contains_key(&signatures[1]));
    }

    #[tokio::test]
    async fn detector_evicts_idle_path_shape_window_at_capacity() {
        let engine = FilterEngine::new(
            Vec::new(),
            PathBuf::from("/tmp/altura-prot-nonexistent-shape-idle-cap-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger = Arc::new(
            EventLogger::new("/tmp/altura-prot-test-shape-idle-cap-events.jsonl").unwrap(),
        );
        let detector =
            AdaptiveDetector::new(test_detector_config(100, 8_192, SHARDS), engine, logger);
        let shapes = same_path_shape_shard_keys("shape-idle-cap", 2);
        let shard_idx = shard_for(&shapes[0]);
        let headers = HeaderMap::new();
        let first = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: &shapes[0],
            query: None,
            headers: &headers,
            signature: "shape-idle-cap-sig-0".to_string(),
        };
        detector.observe(&first, "observed");
        {
            let mut windows = detector.shape_windows[shard_idx].lock().unwrap();
            windows.entries.get_mut(&shapes[0]).unwrap().last_seen = Instant::now()
                .checked_sub(adaptive_window_idle() + Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }

        let second = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: &shapes[1],
            query: None,
            headers: &headers,
            signature: "shape-idle-cap-sig-1".to_string(),
        };
        detector.observe(&second, "observed");

        let windows = detector.shape_windows[shard_idx].lock().unwrap();
        assert_eq!(windows.entries.len(), 1);
        assert!(!windows.entries.contains_key(&shapes[0]));
        assert!(windows.entries.contains_key(&shapes[1]));
    }

    #[tokio::test]
    async fn attack_events_bound_user_controlled_fields_before_queueing() {
        let event_path = PathBuf::from("/tmp/altura-prot-test-bounded-events.jsonl");
        let _ = std::fs::remove_file(&event_path);
        let engine = FilterEngine::new(
            Vec::new(),
            PathBuf::from("/tmp/altura-prot-nonexistent-bounded-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger =
            Arc::new(EventLogger::with_flush_interval(&event_path, Duration::ZERO).unwrap());
        let detector = AdaptiveDetector::new(
            test_detector_config(1, 8_192, 8_192),
            engine,
            Arc::clone(&logger),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_str(&"u".repeat(MAX_EVENT_USER_AGENT_BYTES + 200)).unwrap(),
        );
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&"203.0.113.1, ".repeat(100)).unwrap(),
        );
        let long_header_name =
            HeaderName::from_bytes(format!("x-{}", "a".repeat(200)).as_bytes()).unwrap();
        headers.insert(long_header_name.clone(), HeaderValue::from_static("1"));
        let path = format!("/api/{}", "p".repeat(MAX_EVENT_PATH_BYTES + 200));
        let long_key = "k".repeat(MAX_EVENT_QUERY_KEY_BYTES + 200);
        let query = format!("{}={}", long_key, "v".repeat(MAX_EVENT_QUERY_BYTES + 200));
        let ctx = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: &path,
            query: Some(&query),
            headers: &headers,
            signature: "sig".to_string(),
        };

        detector.observe(&ctx, "observed");
        logger.flush();

        let line = std::fs::read_to_string(&event_path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        let event: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_bounded_field(&event, "path", MAX_EVENT_PATH_BYTES);
        assert_bounded_field(&event, "query", MAX_EVENT_QUERY_BYTES);
        assert_bounded_field(&event, "user_agent", MAX_EVENT_USER_AGENT_BYTES);
        assert_bounded_field(&event, "x_forwarded_for", MAX_EVENT_X_FORWARDED_FOR_BYTES);
        assert_bounded_field(&event, "signature_basis", MAX_EVENT_SIGNATURE_BASIS_BYTES);
        let first_query_key = event["query_keys"].as_array().unwrap()[0].as_str().unwrap();
        assert!(first_query_key.len() <= MAX_EVENT_QUERY_KEY_BYTES);
        assert!(first_query_key.ends_with(TRUNCATED_MARKER));
        let logged_header_name = event["header_names"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .find(|name| name.starts_with("x-"))
            .unwrap();
        assert!(logged_header_name.len() <= MAX_EVENT_HEADER_NAME_BYTES);
        assert!(logged_header_name.ends_with(TRUNCATED_MARKER));
        let _ = std::fs::remove_file(event_path);
    }

    fn assert_bounded_field(event: &serde_json::Value, field: &str, max_bytes: usize) {
        let value = event[field].as_str().unwrap();
        assert!(
            value.len() <= max_bytes,
            "{field} was {} bytes",
            value.len()
        );
        assert!(
            value.ends_with(TRUNCATED_MARKER),
            "{field} should be marked truncated"
        );
    }

    fn test_detector_config(
        threshold_per_second: u64,
        max_signature_windows: usize,
        max_path_shape_windows: usize,
    ) -> AdaptiveDetectorConfig {
        AdaptiveDetectorConfig {
            enabled: true,
            threshold_per_second,
            activation_ttl: Duration::from_secs(30),
            event_cooldown: Duration::from_secs(1),
            max_signature_windows,
            max_path_shape_windows,
        }
    }

    fn same_signature_shard_keys(prefix: &str, count: usize) -> Vec<String> {
        let mut selected = Vec::new();
        let mut target_shard = None;
        for idx in 0..10_000 {
            let key = format!("{prefix}-{idx}");
            let shard = shard_for(&key);
            if target_shard.is_none() {
                target_shard = Some(shard);
            }
            if Some(shard) == target_shard {
                selected.push(key);
                if selected.len() == count {
                    return selected;
                }
            }
        }
        panic!("could not find {count} keys in one adaptive shard");
    }

    fn same_path_shape_shard_keys(prefix: &str, count: usize) -> Vec<String> {
        let mut selected = Vec::new();
        let mut target_shard = None;
        for idx in 0..10_000 {
            let path = format!("/{prefix}-{idx}");
            let shape = request_path_shape(&path);
            let shard = shard_for(&shape);
            if target_shard.is_none() {
                target_shard = Some(shard);
            }
            if Some(shard) == target_shard {
                selected.push(shape);
                if selected.len() == count {
                    return selected;
                }
            }
        }
        panic!("could not find {count} path shapes in one adaptive shard");
    }
}
