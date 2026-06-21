use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::Arc,
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{
    filter::{request_path_shape, signature_basis, FilterEngine, RequestContext},
    telemetry::{unix_time_ms, AttackEvent, EventLogger},
};

const SHARDS: usize = 64;
const MAX_SHAPE_SAMPLES_PER_SECOND: u64 = 64;

#[derive(Debug)]
struct SignatureWindow {
    window_start: Instant,
    count: u64,
    last_event: Option<Instant>,
    last_strong_event: Option<Instant>,
}

#[derive(Debug)]
struct ShapeWindow {
    window_start: Instant,
    count: u64,
    emitted_samples: u64,
}

#[derive(Debug)]
struct Observation {
    count: u64,
    activate: bool,
    emit: bool,
}

#[derive(Debug)]
pub struct AdaptiveDetector {
    enabled: bool,
    threshold_per_second: u64,
    activation_ttl: Duration,
    event_cooldown: Duration,
    engine: Arc<FilterEngine>,
    logger: Arc<EventLogger>,
    windows: Vec<Mutex<HashMap<String, SignatureWindow>>>,
    shape_windows: Vec<Mutex<HashMap<String, ShapeWindow>>>,
}

impl AdaptiveDetector {
    pub fn new(
        enabled: bool,
        threshold_per_second: u64,
        activation_ttl: Duration,
        event_cooldown: Duration,
        engine: Arc<FilterEngine>,
        logger: Arc<EventLogger>,
    ) -> Arc<Self> {
        Arc::new(Self {
            enabled,
            threshold_per_second: threshold_per_second.max(1),
            activation_ttl,
            event_cooldown,
            engine,
            logger,
            windows: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            shape_windows: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        })
    }

    pub fn observe(&self, ctx: &RequestContext<'_>, reason: &str) {
        if !self.enabled {
            return;
        }

        let path_shape = request_path_shape(ctx.path);
        let observation = self.observe_signature(&ctx.signature, reason);
        let shape_observed_count = if reason == "observed" {
            self.observe_path_shape(&path_shape)
        } else {
            None
        };

        if observation.activate {
            let _ = self
                .engine
                .activate_signature(&ctx.signature, Some(self.activation_ttl));
        }
        if let Some((count, shape)) = &shape_observed_count {
            let _ = self
                .engine
                .activate_path_shape(shape, Some(self.activation_ttl));
            if !observation.emit {
                self.log_event(ctx, "global_observed", *count, shape.clone());
            }
        }

        if observation.emit {
            self.log_event(ctx, reason, observation.count, path_shape);
        }
    }

    fn log_event(&self, ctx: &RequestContext<'_>, reason: &str, observed_count: u64, path_shape: String) {
        self.logger.log(&AttackEvent {
            schema_version: 2,
            ts_unix_ms: unix_time_ms(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.to_string(),
            path: ctx.path.to_string(),
            path_shape,
            query: ctx.query.map(ToString::to_string),
            query_keys: query_keys(ctx.query.unwrap_or("")),
            user_agent: ctx.user_agent(),
            x_forwarded_for: ctx
                .headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string),
            header_names: header_names(ctx),
            signature: ctx.signature.clone(),
            signature_basis: signature_basis(ctx.method, ctx.path, ctx.query, ctx.headers),
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
        let window = windows
            .entry(signature.to_string())
            .or_insert_with(|| SignatureWindow {
                window_start: now,
                count: 0,
                last_event: None,
                last_strong_event: None,
            });
        if now.saturating_duration_since(window.window_start) >= Duration::from_secs(1) {
            window.window_start = now;
            window.count = 0;
        }
        window.count += 1;
        let count = window.count;
        let regular_emit = count == self.threshold_per_second
            || (count > self.threshold_per_second
                && window
                    .last_event
                    .is_none_or(|last| now.saturating_duration_since(last) >= self.event_cooldown));
        let strong_emit = strong_reason
            && count >= self.threshold_per_second
            && window.last_strong_event.is_none_or(|last| {
                now.saturating_duration_since(last) >= self.event_cooldown
            });
        let emit = regular_emit || strong_emit;
        if regular_emit {
            window.last_event = Some(now);
        }
        if strong_emit {
            window.last_strong_event = Some(now);
        }
        if windows.len() > 8192 / SHARDS + 128 {
            windows.retain(|_, window| {
                now.saturating_duration_since(window.window_start) < Duration::from_secs(10)
            });
        }
        Observation {
            count,
            activate: count >= self.threshold_per_second,
            emit,
        }
    }

    fn observe_path_shape(&self, path_shape: &str) -> Option<(u64, String)> {
        let now = Instant::now();
        let shard_idx = shard_for(path_shape);
        let mut windows = match self.shape_windows[shard_idx].lock() {
            Ok(windows) => windows,
            Err(poisoned) => {
                eprintln!("adaptive detector shape shard mutex poisoned; recovering state");
                poisoned.into_inner()
            }
        };
        if windows.len() > 8192 / SHARDS + 128 {
            windows.retain(|_, window| {
                now.saturating_duration_since(window.window_start) < Duration::from_secs(10)
            });
        }
        let window = windows
            .entry(path_shape.to_string())
            .or_insert_with(|| ShapeWindow {
                window_start: now,
                count: 0,
                emitted_samples: 0,
            });
        if now.saturating_duration_since(window.window_start) >= Duration::from_secs(1) {
            window.window_start = now;
            window.count = 0;
            window.emitted_samples = 0;
        }
        window.count += 1;
        let count = window.count;
        if count >= self.threshold_per_second
            && count % self.threshold_per_second == 0
            && window.emitted_samples < MAX_SHAPE_SAMPLES_PER_SECOND
        {
            window.emitted_samples += 1;
            return Some((count, path_shape.to_string()));
        }
        None
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
        .map(ToString::to_string)
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
        .map(|name| name.as_str().to_string())
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
        "rate_limited" | "global_rate_limited" | "per_ip_rate_limited" | "filter_block"
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use http::HeaderMap;

    use crate::{
        filter::{FilterAction, FilterCondition, FilterRule},
        telemetry::EventLogger,
    };

    use super::*;

    #[tokio::test]
    async fn detector_activates_learned_signature() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "learned".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    signature: Some("sig".to_string()),
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
            true,
            2,
            Duration::from_secs(30),
            Duration::from_secs(1),
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
            signature: "sig".to_string(),
        };
        assert!(engine.evaluate(&ctx).is_none());
        detector.observe(&ctx, "test");
        assert!(engine.evaluate(&ctx).is_none());
        detector.observe(&ctx, "test");
        assert!(engine.evaluate(&ctx).is_some());
    }

    #[tokio::test]
    async fn detector_keeps_distinct_signatures_below_threshold() {
        let engine = FilterEngine::new(
            vec![FilterRule {
                id: "learned".to_string(),
                enabled: true,
                adaptive: true,
                priority: 1,
                ttl_seconds: Some(30),
                expires_at_unix_ms: None,
                condition: FilterCondition {
                    signature: Some("sig-a".to_string()),
                    ..Default::default()
                },
                action: FilterAction::default(),
            }],
            PathBuf::from("/tmp/altura-prot-nonexistent-filters.json"),
            Duration::from_secs(30),
        )
        .await;
        let logger = Arc::new(EventLogger::new("/tmp/altura-prot-test-events-distinct.jsonl").unwrap());
        let detector = AdaptiveDetector::new(
            true,
            2,
            Duration::from_secs(30),
            Duration::from_secs(1),
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
            signature: "sig-a".to_string(),
        };
        let ctx_b = RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/",
            query: None,
            headers: &headers,
            signature: "sig-b".to_string(),
        };
        detector.observe(&ctx_a, "test");
        detector.observe(&ctx_b, "test");
        assert!(engine.evaluate(&ctx_a).is_none());
    }

    #[tokio::test]
    async fn detector_activates_path_shape_from_distinct_signatures() {
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
        let logger = Arc::new(
            EventLogger::new("/tmp/altura-prot-test-shape-events.jsonl").unwrap(),
        );
        let detector = AdaptiveDetector::new(
            true,
            2,
            Duration::from_secs(30),
            Duration::from_secs(1),
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
        assert!(engine.evaluate(&ctx_a).is_some());
        assert!(engine.evaluate(&ctx_b).is_some());
    }

    #[tokio::test]
    async fn detector_counts_path_shape_once_per_observed_request() {
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
        let logger = Arc::new(
            EventLogger::new("/tmp/altura-prot-test-shape-count-events.jsonl").unwrap(),
        );
        let detector = AdaptiveDetector::new(
            true,
            2,
            Duration::from_secs(30),
            Duration::from_secs(1),
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
        assert!(engine.evaluate(&ctx).is_some());
    }
}
