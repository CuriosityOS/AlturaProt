use std::{env, sync::Arc};

use altura_prot::{
    adaptive::AdaptiveDetector,
    config::AppConfig,
    filter::FilterEngine,
    http_proxy::run_http_proxy,
    tcp_proxy::run_tcp_proxy,
    telemetry::{EventLogger, Stats},
    BoxError,
};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let config_path = config_path_from_args();
    let cfg = AppConfig::from_path(&config_path)?;

    let stats = Arc::new(Stats::default());
    let logger = Arc::new(EventLogger::new(&cfg.adaptive.event_log)?);
    let engine = FilterEngine::new(
        cfg.filters.static_rules.clone(),
        cfg.filters.runtime_file.clone(),
        cfg.adaptive.activation_ttl(),
    )
    .await;
    let detector = AdaptiveDetector::new(
        cfg.adaptive.enabled,
        cfg.adaptive.signature_threshold_per_second,
        cfg.adaptive.activation_ttl(),
        cfg.adaptive.event_cooldown(),
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

    let mut listeners = 0;
    if let Some(http_cfg) = cfg.http.clone() {
        listeners += 1;
        let engine = Arc::clone(&engine);
        let detector = Arc::clone(&detector);
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            if let Err(err) = run_http_proxy(http_cfg, engine, detector, stats).await {
                eprintln!("http proxy stopped: {err}");
            }
        });
    }

    for tcp_cfg in cfg.tcp.clone() {
        listeners += 1;
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            if let Err(err) = run_tcp_proxy(tcp_cfg, stats).await {
                eprintln!("tcp proxy stopped: {err}");
            }
        });
    }

    if listeners == 0 {
        return Err("configuration has no listeners".into());
    }

    tokio::signal::ctrl_c().await?;
    eprintln!("shutdown signal received");
    Ok(())
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
