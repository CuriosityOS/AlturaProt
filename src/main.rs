use std::{env, sync::Arc, time::Duration};

use altura_prot::{
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
    task::JoinHandle,
};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let config_path = config_path_from_args();
    let cfg = AppConfig::from_path(&config_path)?;
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

    {
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
        });
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut startup_checks = Vec::new();
    let mut listener_tasks: Vec<JoinHandle<()>> = Vec::new();
    if let Some(http_cfg) = cfg.http.clone() {
        let (startup_tx, startup_rx) = oneshot::channel();
        startup_checks.push(("http".to_string(), startup_rx));
        let engine = Arc::clone(&engine);
        let detector = Arc::clone(&detector);
        let stats = Arc::clone(&stats);
        let shutdown = shutdown_rx.clone();
        listener_tasks.push(tokio::spawn(async move {
            if let Err(err) = run_http_proxy(
                http_cfg,
                engine,
                detector,
                stats,
                Arc::clone(&logger),
                Some(startup_tx),
                shutdown,
            )
            .await
            {
                eprintln!("http proxy stopped: {err}");
            }
        }));
    }

    for tcp_cfg in cfg.tcp.clone() {
        let name = format!("tcp:{}", tcp_cfg.name);
        let (startup_tx, startup_rx) = oneshot::channel();
        startup_checks.push((name, startup_rx));
        let stats = Arc::clone(&stats);
        let shutdown = shutdown_rx.clone();
        listener_tasks.push(tokio::spawn(async move {
            if let Err(err) = run_tcp_proxy(tcp_cfg, stats, Some(startup_tx), shutdown).await {
                eprintln!("tcp proxy stopped: {err}");
            }
        }));
    }

    if startup_checks.is_empty() {
        return Err("configuration has no listeners".into());
    }

    for (name, rx) in startup_checks {
        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => return Err(format!("{name} startup failed: {err}").into()),
            Ok(Err(_)) => {
                return Err(format!("{name} startup task exited before reporting readiness").into())
            }
            Err(_) => return Err(format!("{name} startup timed out").into()),
        }
    }

    let signal_name = shutdown_signal().await?;
    eprintln!("shutdown signal received: {signal_name}");
    let _ = shutdown_tx.send(true);
    if cfg.runtime.shutdown_grace_ms > 0 {
        let shutdown_grace = Duration::from_millis(cfg.runtime.shutdown_grace_ms);
        let wait_for_listeners = async {
            for task in listener_tasks {
                let _ = task.await;
            }
        };
        if tokio::time::timeout(shutdown_grace, wait_for_listeners)
            .await
            .is_err()
        {
            eprintln!("shutdown grace period elapsed before all listener tasks stopped");
        }
    }
    Ok(())
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

fn config_path_from_args() -> String {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(path) = args.next() {
                return path;
            }
        }
    }
    "configs/example.json".to_string()
}
