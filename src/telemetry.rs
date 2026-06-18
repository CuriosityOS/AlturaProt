use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::BoxError;

#[derive(Debug, Default)]
pub struct Stats {
    pub http_total: AtomicU64,
    pub http_proxied: AtomicU64,
    pub http_blocked: AtomicU64,
    pub http_rate_limited: AtomicU64,
    pub http_upstream_errors: AtomicU64,
    pub tcp_accepted: AtomicU64,
    pub tcp_rejected: AtomicU64,
    pub tcp_upstream_errors: AtomicU64,
}

impl Stats {
    pub fn render_prometheus(&self, active_filters: usize) -> String {
        format!(
            concat!(
                "altura_http_total {}\n",
                "altura_http_proxied {}\n",
                "altura_http_blocked {}\n",
                "altura_http_rate_limited {}\n",
                "altura_http_upstream_errors {}\n",
                "altura_tcp_accepted {}\n",
                "altura_tcp_rejected {}\n",
                "altura_tcp_upstream_errors {}\n",
                "altura_active_filters {}\n"
            ),
            self.http_total.load(Ordering::Relaxed),
            self.http_proxied.load(Ordering::Relaxed),
            self.http_blocked.load(Ordering::Relaxed),
            self.http_rate_limited.load(Ordering::Relaxed),
            self.http_upstream_errors.load(Ordering::Relaxed),
            self.tcp_accepted.load(Ordering::Relaxed),
            self.tcp_rejected.load(Ordering::Relaxed),
            self.tcp_upstream_errors.load(Ordering::Relaxed),
            active_filters,
        )
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Serialize)]
pub struct AttackEvent {
    pub ts_unix_ms: u64,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub user_agent: String,
    pub signature: String,
    pub signature_basis: String,
    pub reason: String,
    pub observed_count: u64,
}

#[derive(Debug)]
pub struct EventLogger {
    writer: Mutex<BufWriter<File>>,
}

impl EventLogger {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, BoxError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn log(&self, event: &AttackEvent) {
        let Ok(line) = serde_json::to_string(event) else {
            return;
        };
        let mut writer = self.writer.lock().expect("event logger poisoned");
        let _ = writer.write_all(line.as_bytes());
        let _ = writer.write_all(b"\n");
        let _ = writer.flush();
    }
}

pub fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
