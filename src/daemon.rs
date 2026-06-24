use std::{path::Path, sync::Arc, time::Duration};

use crate::{
    adaptive::{AdaptiveDetector, AdaptiveDetectorConfig},
    config::AppConfig,
    filter::FilterEngine,
    http_proxy::run_http_proxy,
    resource_limits::{apply_runtime_limits, validate_nofile_capacity},
    tcp_proxy::run_tcp_proxy,
    telemetry::{EventLogger, Stats},
    BoxError,
};
use tokio::{
    sync::{oneshot, watch},
    task::JoinSet,
};

pub async fn run(config_path: impl AsRef<Path>) -> Result<(), BoxError> {
    let config_path = config_path.as_ref();
    let cfg = AppConfig::from_path(config_path)?;
    let runtime_status = apply_runtime_limits(&cfg.runtime)?;
    if let Some(status) = runtime_status.as_ref() {
        eprintln!(
            "runtime nofile limit soft={} hard={} target={} changed={}",
            status.soft, status.hard, status.target, status.changed
        );
    }
    if let Some(estimate) = validate_nofile_capacity(&cfg, runtime_status.as_ref())? {
        eprintln!(
            "runtime nofile capacity required={} soft={} reserve={} listeners={} http_downstream={} http_upstream_in_flight={} http_upstream_idle_pool={} tcp_downstream={} tcp_upstream={}",
            estimate.required,
            estimate.soft_limit,
            estimate.reserve,
            estimate.listeners,
            estimate.http_downstream,
            estimate.http_upstream_in_flight,
            estimate.http_upstream_idle_pool,
            estimate.tcp_downstream,
            estimate.tcp_upstream,
        );
    }

    let stats = Arc::new(Stats::default());
    let logger = Arc::new(EventLogger::with_options_and_queue(
        &cfg.adaptive.event_log,
        cfg.adaptive.event_log_flush_interval(),
        cfg.adaptive.event_log_max_bytes,
        cfg.adaptive.event_log_backup_count,
        cfg.adaptive.event_log_queue_capacity,
    )?);
    let engine = FilterEngine::new_with_limits(
        cfg.filters.static_rules.clone(),
        cfg.filters.runtime_file.clone(),
        cfg.adaptive.activation_ttl(),
        cfg.filters.max_runtime_file_bytes,
        cfg.filters.max_runtime_filters,
    )
    .await;
    let detector = AdaptiveDetector::new(
        AdaptiveDetectorConfig {
            enabled: cfg.adaptive.enabled,
            threshold_per_second: cfg.adaptive.signature_threshold_per_second,
            activation_ttl: cfg.adaptive.activation_ttl(),
            event_cooldown: cfg.adaptive.event_cooldown(),
            max_signature_windows: cfg.adaptive.max_signature_windows,
            max_path_shape_windows: cfg.adaptive.max_path_shape_windows,
        },
        Arc::clone(&engine),
        Arc::clone(&logger),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut startup_checks = Vec::new();
    let mut listener_tasks = JoinSet::new();
    if let Some(http_cfg) = cfg.http.clone() {
        let (startup_tx, startup_rx) = oneshot::channel();
        startup_checks.push(("http".to_string(), startup_rx));
        let engine = Arc::clone(&engine);
        let detector = Arc::clone(&detector);
        let stats = Arc::clone(&stats);
        let shutdown = shutdown_rx.clone();
        listener_tasks.spawn(async move {
            run_http_proxy(
                http_cfg,
                engine,
                detector,
                stats,
                Arc::clone(&logger),
                Some(startup_tx),
                shutdown,
            )
            .await
        });
    }

    for tcp_cfg in cfg.tcp.clone() {
        let name = format!("tcp:{}", tcp_cfg.name);
        let (startup_tx, startup_rx) = oneshot::channel();
        startup_checks.push((name, startup_rx));
        let stats = Arc::clone(&stats);
        let shutdown = shutdown_rx.clone();
        listener_tasks
            .spawn(async move { run_tcp_proxy(tcp_cfg, stats, Some(startup_tx), shutdown).await });
    }

    if startup_checks.is_empty() {
        return Err("configuration has no listeners".into());
    }

    for (name, rx) in startup_checks {
        if let Err(err) = wait_for_listener_startup(&name, rx).await {
            let _ = shutdown_tx.send(true);
            listener_tasks.shutdown().await;
            return Err(err);
        }
    }

    let reload_task = {
        let engine = Arc::clone(&engine);
        let interval = cfg.filters.reload_interval();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(err) = engine.reload().await {
                    eprintln!("filter reload failed: {err}");
                }
            }
        })
    };

    let shutdown_result = tokio::select! {
        signal = shutdown_signal() => {
            let signal = signal?;
            eprintln!("shutdown signal received: {signal}");
            Ok(())
        }
        result = listener_tasks.join_next() => {
            let _ = shutdown_tx.send(true);
            match result {
                Some(Ok(Ok(()))) => Err("listener exited before shutdown signal".into()),
                Some(Ok(Err(err))) => Err(err),
                Some(Err(join_err)) => Err(join_err.into()),
                None => Err("no listeners running".into()),
            }
        }
    };

    reload_task.abort();
    let _ = reload_task.await;
    let _ = shutdown_tx.send(true);

    if let Err(err) = shutdown_result {
        listener_tasks.shutdown().await;
        return Err(err);
    }

    if cfg.runtime.shutdown_grace_ms > 0 {
        let shutdown_grace = Duration::from_millis(cfg.runtime.shutdown_grace_ms);
        if tokio::time::timeout(shutdown_grace, listener_tasks.join_all())
            .await
            .is_err()
        {
            eprintln!("shutdown grace period elapsed before all listener tasks stopped");
        }
    } else {
        listener_tasks.shutdown().await;
    }
    Ok(())
}

async fn wait_for_listener_startup(
    name: &str,
    rx: oneshot::Receiver<Result<(), String>>,
) -> Result<(), BoxError> {
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(err))) => Err(format!("{name} startup failed: {err}").into()),
        Ok(Err(_)) => Err(format!("{name} startup task exited before reporting readiness").into()),
        Err(_) => Err(format!("{name} startup timed out").into()),
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<&'static str, BoxError> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok("SIGINT")
        }
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<&'static str, BoxError> {
    tokio::signal::ctrl_c().await?;
    Ok("SIGINT")
}
