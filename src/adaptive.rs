use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use crate::{
    filter::{signature_basis, FilterEngine, RequestContext},
    telemetry::{unix_time_ms, AttackEvent, EventLogger},
};

#[derive(Debug)]
struct SignatureWindow {
    window_start: Instant,
    count: u64,
    last_event: Option<Instant>,
}

#[derive(Debug)]
pub struct AdaptiveDetector {
    enabled: bool,
    threshold_per_second: u64,
    activation_ttl: Duration,
    event_cooldown: Duration,
    engine: Arc<FilterEngine>,
    logger: Arc<EventLogger>,
    windows: Mutex<HashMap<String, SignatureWindow>>,
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
            windows: Mutex::new(HashMap::new()),
        })
    }

    pub async fn observe(&self, ctx: &RequestContext<'_>, reason: &str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let mut windows = self.windows.lock().await;
        let window = windows
            .entry(ctx.signature.clone())
            .or_insert_with(|| SignatureWindow {
                window_start: now,
                count: 0,
                last_event: None,
            });
        if now.saturating_duration_since(window.window_start) >= Duration::from_secs(1) {
            window.window_start = now;
            window.count = 0;
        }
        window.count += 1;
        let count = window.count;
        let should_emit = count == self.threshold_per_second
            || (count > self.threshold_per_second
                && window
                    .last_event
                    .is_none_or(|last| now.saturating_duration_since(last) >= self.event_cooldown));
        if should_emit {
            window.last_event = Some(now);
        }
        if windows.len() > 8192 {
            windows.retain(|_, window| {
                now.saturating_duration_since(window.window_start) < Duration::from_secs(10)
            });
        }
        drop(windows);

        if count >= self.threshold_per_second {
            let _ = self
                .engine
                .activate_signature(&ctx.signature, Some(self.activation_ttl))
                .await;
        }

        if should_emit {
            self.logger.log(&AttackEvent {
                ts_unix_ms: unix_time_ms(),
                client_ip: ctx.client_ip.to_string(),
                method: ctx.method.to_string(),
                path: ctx.path.to_string(),
                query: ctx.query.map(ToString::to_string),
                user_agent: ctx.user_agent(),
                signature: ctx.signature.clone(),
                signature_basis: signature_basis(ctx.method, ctx.path, ctx.query, ctx.headers),
                reason: reason.to_string(),
                observed_count: count,
            });
        }
    }
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
        assert!(engine.evaluate(&ctx).await.is_none());
        detector.observe(&ctx, "test").await;
        assert!(engine.evaluate(&ctx).await.is_none());
        detector.observe(&ctx, "test").await;
        assert!(engine.evaluate(&ctx).await.is_some());
    }
}
