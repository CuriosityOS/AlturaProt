use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    log_limiter::{log_limited, LogLimiter, HOT_PATH_LOG_INTERVAL},
    BoxError,
};

static EVENT_LOGGER_WRITE_FAILED_LOG: LogLimiter = LogLimiter::new();
static EVENT_LOGGER_NEWLINE_FAILED_LOG: LogLimiter = LogLimiter::new();
static EVENT_LOGGER_FLUSH_FAILED_LOG: LogLimiter = LogLimiter::new();
static EVENT_LOGGER_OPEN_FAILED_LOG: LogLimiter = LogLimiter::new();
static EVENT_LOGGER_ROTATE_FAILED_LOG: LogLimiter = LogLimiter::new();
static EVENT_LOGGER_QUEUE_FULL_LOG: LogLimiter = LogLimiter::new();
static EVENT_LOGGER_QUEUE_CLOSED_LOG: LogLimiter = LogLimiter::new();
static SYSTEM_TIME_BEFORE_EPOCH_LOG: LogLimiter = LogLimiter::new();

pub const DEFAULT_EVENT_LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(100);
pub const DEFAULT_EVENT_LOG_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_EVENT_LOG_BACKUP_COUNT: u32 = 2;
pub const DEFAULT_EVENT_LOG_QUEUE_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Copy, Default)]
pub struct AdaptiveWindowStats {
    pub signature_windows: usize,
    pub path_shape_windows: usize,
    pub signature_window_capacity: usize,
    pub path_shape_window_capacity: usize,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub http_total: AtomicU64,
    pub http_proxied: AtomicU64,
    pub http_blocked: AtomicU64,
    pub http_rate_limited: AtomicU64,
    pub http_trusted_proxy_rate_limited: AtomicU64,
    pub http_signature_rate_limited: AtomicU64,
    pub http_path_shape_rate_limited: AtomicU64,
    pub http_connections_rejected: AtomicU64,
    pub http_request_limited: AtomicU64,
    pub http_method_rejected: AtomicU64,
    pub http_host_rejected: AtomicU64,
    pub http_framing_rejected: AtomicU64,
    pub http_header_line_rejected: AtomicU64,
    pub http_initial_header_too_large: AtomicU64,
    pub http_initial_header_timeouts: AtomicU64,
    pub http_initial_headers_too_many: AtomicU64,
    pub http_forwarded_sanitized: AtomicU64,
    pub http_forwarded_rejected: AtomicU64,
    pub http_content_encoding_rejected: AtomicU64,
    pub http_expect_rejected: AtomicU64,
    pub http_range_rejected: AtomicU64,
    pub http_accept_encoding_stripped: AtomicU64,
    pub http_uri_rejected: AtomicU64,
    pub http_initial_request_target_rejected: AtomicU64,
    pub http_body_rejected: AtomicU64,
    pub http_body_timeouts: AtomicU64,
    pub http_body_too_slow: AtomicU64,
    pub http_request_trailers_dropped: AtomicU64,
    pub http_request_trailers_rejected: AtomicU64,
    pub http_downstream_write_timeouts: AtomicU64,
    pub http_upstream_errors: AtomicU64,
    pub http_upstream_timeouts: AtomicU64,
    pub http_upstream_circuit_open: AtomicU64,
    pub http_upstream_in_flight_rejected: AtomicU64,
    pub http_trusted_proxy_in_flight_rejected: AtomicU64,
    pub http_upstream_header_rejected: AtomicU64,
    pub http_upstream_body_rejected: AtomicU64,
    pub http_upstream_body_timeouts: AtomicU64,
    pub http_upstream_body_too_slow: AtomicU64,
    pub http_upstream_trailers_dropped: AtomicU64,
    pub http_upstream_trailers_rejected: AtomicU64,
    pub tcp_accepted: AtomicU64,
    pub tcp_rejected: AtomicU64,
    pub tcp_global_connect_rate_limited: AtomicU64,
    pub tcp_idle_timeouts: AtomicU64,
    pub tcp_downstream_too_slow: AtomicU64,
    pub tcp_upstream_too_slow: AtomicU64,
    pub tcp_upstream_errors: AtomicU64,
}

impl Stats {
    pub fn render_prometheus(
        &self,
        active_filters: usize,
        event_log_dropped: u64,
        adaptive_windows: AdaptiveWindowStats,
    ) -> String {
        format!(
            concat!(
                "altura_http_total {}\n",
                "altura_http_proxied {}\n",
                "altura_http_blocked {}\n",
                "altura_http_rate_limited {}\n",
                "altura_http_trusted_proxy_rate_limited {}\n",
                "altura_http_signature_rate_limited {}\n",
                "altura_http_path_shape_rate_limited {}\n",
                "altura_http_connections_rejected {}\n",
                "altura_http_request_limited {}\n",
                "altura_http_method_rejected {}\n",
                "altura_http_host_rejected {}\n",
                "altura_http_framing_rejected {}\n",
                "altura_http_header_line_rejected {}\n",
                "altura_http_initial_header_too_large {}\n",
                "altura_http_initial_header_timeouts {}\n",
                "altura_http_initial_headers_too_many {}\n",
                "altura_http_forwarded_sanitized {}\n",
                "altura_http_forwarded_rejected {}\n",
                "altura_http_content_encoding_rejected {}\n",
                "altura_http_expect_rejected {}\n",
                "altura_http_range_rejected {}\n",
                "altura_http_accept_encoding_stripped {}\n",
                "altura_http_uri_rejected {}\n",
                "altura_http_initial_request_target_rejected {}\n",
                "altura_http_body_rejected {}\n",
                "altura_http_body_timeouts {}\n",
                "altura_http_body_too_slow {}\n",
                "altura_http_request_trailers_dropped {}\n",
                "altura_http_request_trailers_rejected {}\n",
                "altura_http_downstream_write_timeouts {}\n",
                "altura_http_upstream_errors {}\n",
                "altura_http_upstream_timeouts {}\n",
                "altura_http_upstream_circuit_open {}\n",
                "altura_http_upstream_in_flight_rejected {}\n",
                "altura_http_trusted_proxy_in_flight_rejected {}\n",
                "altura_http_upstream_header_rejected {}\n",
                "altura_http_upstream_body_rejected {}\n",
                "altura_http_upstream_body_timeouts {}\n",
                "altura_http_upstream_body_too_slow {}\n",
                "altura_http_upstream_trailers_dropped {}\n",
                "altura_http_upstream_trailers_rejected {}\n",
                "altura_tcp_accepted {}\n",
                "altura_tcp_rejected {}\n",
                "altura_tcp_global_connect_rate_limited {}\n",
                "altura_tcp_idle_timeouts {}\n",
                "altura_tcp_downstream_too_slow {}\n",
                "altura_tcp_upstream_too_slow {}\n",
                "altura_tcp_upstream_errors {}\n",
                "altura_event_log_dropped {}\n",
                "altura_active_filters {}\n",
                "altura_adaptive_signature_windows {}\n",
                "altura_adaptive_signature_window_capacity {}\n",
                "altura_adaptive_path_shape_windows {}\n",
                "altura_adaptive_path_shape_window_capacity {}\n"
            ),
            self.http_total.load(Ordering::Relaxed),
            self.http_proxied.load(Ordering::Relaxed),
            self.http_blocked.load(Ordering::Relaxed),
            self.http_rate_limited.load(Ordering::Relaxed),
            self.http_trusted_proxy_rate_limited.load(Ordering::Relaxed),
            self.http_signature_rate_limited.load(Ordering::Relaxed),
            self.http_path_shape_rate_limited.load(Ordering::Relaxed),
            self.http_connections_rejected.load(Ordering::Relaxed),
            self.http_request_limited.load(Ordering::Relaxed),
            self.http_method_rejected.load(Ordering::Relaxed),
            self.http_host_rejected.load(Ordering::Relaxed),
            self.http_framing_rejected.load(Ordering::Relaxed),
            self.http_header_line_rejected.load(Ordering::Relaxed),
            self.http_initial_header_too_large.load(Ordering::Relaxed),
            self.http_initial_header_timeouts.load(Ordering::Relaxed),
            self.http_initial_headers_too_many.load(Ordering::Relaxed),
            self.http_forwarded_sanitized.load(Ordering::Relaxed),
            self.http_forwarded_rejected.load(Ordering::Relaxed),
            self.http_content_encoding_rejected.load(Ordering::Relaxed),
            self.http_expect_rejected.load(Ordering::Relaxed),
            self.http_range_rejected.load(Ordering::Relaxed),
            self.http_accept_encoding_stripped.load(Ordering::Relaxed),
            self.http_uri_rejected.load(Ordering::Relaxed),
            self.http_initial_request_target_rejected
                .load(Ordering::Relaxed),
            self.http_body_rejected.load(Ordering::Relaxed),
            self.http_body_timeouts.load(Ordering::Relaxed),
            self.http_body_too_slow.load(Ordering::Relaxed),
            self.http_request_trailers_dropped.load(Ordering::Relaxed),
            self.http_request_trailers_rejected.load(Ordering::Relaxed),
            self.http_downstream_write_timeouts.load(Ordering::Relaxed),
            self.http_upstream_errors.load(Ordering::Relaxed),
            self.http_upstream_timeouts.load(Ordering::Relaxed),
            self.http_upstream_circuit_open.load(Ordering::Relaxed),
            self.http_upstream_in_flight_rejected
                .load(Ordering::Relaxed),
            self.http_trusted_proxy_in_flight_rejected
                .load(Ordering::Relaxed),
            self.http_upstream_header_rejected.load(Ordering::Relaxed),
            self.http_upstream_body_rejected.load(Ordering::Relaxed),
            self.http_upstream_body_timeouts.load(Ordering::Relaxed),
            self.http_upstream_body_too_slow.load(Ordering::Relaxed),
            self.http_upstream_trailers_dropped.load(Ordering::Relaxed),
            self.http_upstream_trailers_rejected.load(Ordering::Relaxed),
            self.tcp_accepted.load(Ordering::Relaxed),
            self.tcp_rejected.load(Ordering::Relaxed),
            self.tcp_global_connect_rate_limited.load(Ordering::Relaxed),
            self.tcp_idle_timeouts.load(Ordering::Relaxed),
            self.tcp_downstream_too_slow.load(Ordering::Relaxed),
            self.tcp_upstream_too_slow.load(Ordering::Relaxed),
            self.tcp_upstream_errors.load(Ordering::Relaxed),
            event_log_dropped,
            active_filters,
            adaptive_windows.signature_windows,
            adaptive_windows.signature_window_capacity,
            adaptive_windows.path_shape_windows,
            adaptive_windows.path_shape_window_capacity,
        )
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Serialize)]
pub struct AttackEvent {
    pub schema_version: u32,
    pub ts_unix_ms: u64,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub path_shape: String,
    pub query: Option<String>,
    pub query_keys: Vec<String>,
    pub user_agent: String,
    pub x_forwarded_for: Option<String>,
    pub header_names: Vec<String>,
    pub signature: String,
    pub signature_basis: String,
    pub reason: String,
    pub observed_count: u64,
}

#[derive(Debug)]
pub struct EventLogger {
    sender: SyncSender<EventLogCommand>,
    dropped_events: Arc<AtomicU64>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug)]
enum EventLogCommand {
    Event {
        event: Box<AttackEvent>,
        now_ms: u64,
    },
    Flush {
        ack: mpsc::Sender<()>,
    },
    Shutdown {
        ack: mpsc::Sender<()>,
    },
}

#[derive(Debug)]
struct EventLogWorker {
    state: EventLoggerState,
    dropped_events: Arc<AtomicU64>,
    flush_interval_ms: u64,
    max_bytes: u64,
    backup_count: u32,
    path: PathBuf,
}

#[derive(Debug)]
struct EventLoggerState {
    writer: Option<BufWriter<File>>,
    bytes_written: u64,
    next_flush_ms: u64,
}

impl EventLogger {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, BoxError> {
        Self::with_flush_interval(path, DEFAULT_EVENT_LOG_FLUSH_INTERVAL)
    }

    pub fn with_flush_interval(
        path: impl AsRef<Path>,
        flush_interval: Duration,
    ) -> Result<Self, BoxError> {
        Self::with_options(
            path,
            flush_interval,
            DEFAULT_EVENT_LOG_MAX_BYTES,
            DEFAULT_EVENT_LOG_BACKUP_COUNT,
        )
    }

    pub fn with_options(
        path: impl AsRef<Path>,
        flush_interval: Duration,
        max_bytes: u64,
        backup_count: u32,
    ) -> Result<Self, BoxError> {
        Self::with_options_and_queue(
            path,
            flush_interval,
            max_bytes,
            backup_count,
            DEFAULT_EVENT_LOG_QUEUE_CAPACITY,
        )
    }

    pub fn with_options_and_queue(
        path: impl AsRef<Path>,
        flush_interval: Duration,
        max_bytes: u64,
        backup_count: u32,
        queue_capacity: usize,
    ) -> Result<Self, BoxError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = open_event_log_file(path)?;
        let bytes_written = file.metadata()?.len();
        let dropped_events = Arc::new(AtomicU64::new(0));
        let worker = EventLogWorker {
            state: EventLoggerState {
                writer: Some(BufWriter::new(file)),
                bytes_written,
                next_flush_ms: 0,
            },
            dropped_events: Arc::clone(&dropped_events),
            flush_interval_ms: duration_millis(flush_interval),
            max_bytes,
            backup_count,
            path: path.to_path_buf(),
        };
        let (sender, receiver) = mpsc::sync_channel(queue_capacity.max(1));
        let worker_handle = thread::Builder::new()
            .name("altura-event-log".to_string())
            .spawn(move || worker.run(receiver))?;
        Ok(Self {
            sender,
            dropped_events,
            worker: Mutex::new(Some(worker_handle)),
        })
    }

    pub fn log(&self, event: AttackEvent) {
        self.log_at(event, unix_time_ms());
    }

    fn log_at(&self, event: AttackEvent, now_ms: u64) {
        match self.sender.try_send(EventLogCommand::Event {
            event: Box::new(event),
            now_ms,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
                log_limited(
                    &EVENT_LOGGER_QUEUE_FULL_LOG,
                    HOT_PATH_LOG_INTERVAL,
                    |suppressed| {
                        eprintln!("attack event log queue full; dropping event{suppressed}");
                    },
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
                log_limited(
                    &EVENT_LOGGER_QUEUE_CLOSED_LOG,
                    HOT_PATH_LOG_INTERVAL,
                    |suppressed| {
                        eprintln!("attack event log worker stopped; dropping event{suppressed}");
                    },
                );
            }
        }
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub fn flush(&self) {
        let (ack_tx, ack_rx) = mpsc::channel();
        if send_control_with_retry(&self.sender, EventLogCommand::Flush { ack: ack_tx }) {
            let _ = ack_rx.recv_timeout(Duration::from_secs(5));
        }
    }
}

impl Drop for EventLogger {
    fn drop(&mut self) {
        let (ack_tx, ack_rx) = mpsc::channel();
        let shutdown_acked =
            send_control_with_retry(&self.sender, EventLogCommand::Shutdown { ack: ack_tx })
                && ack_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        let worker = match self.worker.get_mut() {
            Ok(worker) => worker.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if shutdown_acked {
            if let Some(worker) = worker {
                let _ = worker.join();
            }
        }
    }
}

impl EventLogWorker {
    fn run(mut self, receiver: mpsc::Receiver<EventLogCommand>) {
        loop {
            let command = if self.flush_interval_ms == 0 {
                receiver.recv().map_err(|_| RecvTimeoutError::Disconnected)
            } else {
                receiver.recv_timeout(Duration::from_millis(self.flush_interval_ms))
            };
            match command {
                Ok(EventLogCommand::Event { event, now_ms }) => self.write_event(&event, now_ms),
                Ok(EventLogCommand::Flush { ack }) => {
                    self.flush_writer();
                    let _ = ack.send(());
                }
                Ok(EventLogCommand::Shutdown { ack }) => {
                    self.flush_writer();
                    let _ = ack.send(());
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.flush_writer();
                }
                Err(RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }
        self.flush_writer();
    }

    fn write_event(&mut self, event: &AttackEvent, now_ms: u64) {
        let Ok(line) = serde_json::to_vec(event) else {
            self.drop_event();
            return;
        };
        if let Err(err) = self.ensure_writer() {
            log_limited(
                &EVENT_LOGGER_OPEN_FAILED_LOG,
                HOT_PATH_LOG_INTERVAL,
                |suppressed| {
                    eprintln!("failed to open attack event log: {err}{suppressed}");
                },
            );
            self.drop_event();
            return;
        }
        let line_bytes = line.len().saturating_add(1) as u64;
        if self.should_rotate(line_bytes) {
            if let Err(err) = self.rotate() {
                log_limited(
                    &EVENT_LOGGER_ROTATE_FAILED_LOG,
                    HOT_PATH_LOG_INTERVAL,
                    |suppressed| {
                        eprintln!("failed to rotate attack event log: {err}{suppressed}");
                    },
                );
                self.drop_event();
                return;
            }
        }
        let write_result = {
            let Some(writer) = self.state.writer.as_mut() else {
                self.drop_event();
                return;
            };
            writer.write_all(&line)
        };
        if let Err(err) = write_result {
            log_limited(
                &EVENT_LOGGER_WRITE_FAILED_LOG,
                HOT_PATH_LOG_INTERVAL,
                |suppressed| {
                    eprintln!("failed to write attack event: {err}{suppressed}");
                },
            );
            self.drop_event();
            return;
        }
        self.state.bytes_written = self.state.bytes_written.saturating_add(line.len() as u64);
        let newline_result = {
            let Some(writer) = self.state.writer.as_mut() else {
                self.drop_event();
                return;
            };
            writer.write_all(b"\n")
        };
        if let Err(err) = newline_result {
            log_limited(
                &EVENT_LOGGER_NEWLINE_FAILED_LOG,
                HOT_PATH_LOG_INTERVAL,
                |suppressed| {
                    eprintln!("failed to write attack event newline: {err}{suppressed}");
                },
            );
            self.drop_event();
            return;
        }
        self.state.bytes_written = self.state.bytes_written.saturating_add(1);
        if !self.should_flush(now_ms) {
            return;
        }
        self.flush_writer();
    }

    fn ensure_writer(&mut self) -> io::Result<()> {
        if self.state.writer.is_some() {
            return Ok(());
        }
        let file = open_event_log_file(&self.path)?;
        self.state.bytes_written = file.metadata()?.len();
        self.state.writer = Some(BufWriter::new(file));
        self.state.next_flush_ms = 0;
        Ok(())
    }

    fn should_rotate(&self, incoming_bytes: u64) -> bool {
        self.max_bytes > 0
            && self.state.bytes_written > 0
            && self.state.bytes_written.saturating_add(incoming_bytes) > self.max_bytes
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut writer) = self.state.writer.take() {
            writer.flush()?;
        }
        if self.backup_count == 0 {
            remove_if_exists(&self.path)?;
        } else {
            remove_if_exists(&rotated_event_log_path(&self.path, self.backup_count))?;
            for idx in (1..self.backup_count).rev() {
                let from = rotated_event_log_path(&self.path, idx);
                if from.exists() {
                    fs::rename(&from, rotated_event_log_path(&self.path, idx + 1))?;
                }
            }
            if self.path.exists() {
                fs::rename(&self.path, rotated_event_log_path(&self.path, 1))?;
            }
        }
        let file = open_event_log_file(&self.path)?;
        self.state.bytes_written = file.metadata()?.len();
        self.state.writer = Some(BufWriter::new(file));
        self.state.next_flush_ms = 0;
        Ok(())
    }

    fn flush_writer(&mut self) {
        let Some(writer) = self.state.writer.as_mut() else {
            return;
        };
        if let Err(err) = writer.flush() {
            log_limited(
                &EVENT_LOGGER_FLUSH_FAILED_LOG,
                HOT_PATH_LOG_INTERVAL,
                |suppressed| {
                    eprintln!("failed to flush attack event: {err}{suppressed}");
                },
            );
        }
    }

    fn should_flush(&mut self, now_ms: u64) -> bool {
        if self.flush_interval_ms == 0 {
            return true;
        }
        if now_ms < self.state.next_flush_ms {
            return false;
        }
        self.state.next_flush_ms = now_ms.saturating_add(self.flush_interval_ms);
        true
    }

    fn drop_event(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
    }
}

fn open_event_log_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let file = options.open(path)?;
        let mut permissions = file.metadata()?.permissions();
        if permissions.mode() & 0o077 != 0 {
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        options.open(path)
    }
}

fn send_control_with_retry(sender: &SyncSender<EventLogCommand>, command: EventLogCommand) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut command = command;
    loop {
        match sender.try_send(command) {
            Ok(()) => return true,
            Err(TrySendError::Full(returned)) => {
                if Instant::now() >= deadline {
                    return false;
                }
                command = returned;
                thread::sleep(Duration::from_millis(10));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

fn rotated_event_log_path(path: &Path, index: u32) -> PathBuf {
    let mut rotated = path.as_os_str().to_os_string();
    rotated.push(format!(".{index}"));
    PathBuf::from(rotated)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn unix_time_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as u64,
        Err(err) => {
            log_limited(
                &SYSTEM_TIME_BEFORE_EPOCH_LOG,
                HOT_PATH_LOG_INTERVAL,
                |suppressed| {
                    eprintln!("system clock is before UNIX_EPOCH: {err}{suppressed}");
                },
            );
            0
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    if millis > u64::MAX as u128 {
        u64::MAX
    } else {
        millis as u64
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;

    #[test]
    fn event_logger_flushes_first_event_and_batches_burst() {
        let path = temp_event_log_path("batched");
        let logger = EventLogger::with_flush_interval(&path, Duration::from_millis(100)).unwrap();

        logger.log_at(event(1), 1);
        wait_for_line_count(&path, 1);

        logger.log_at(event(2), 50);
        assert_eq!(line_count(&path), 1);

        logger.log_at(event(3), 101);
        wait_for_line_count(&path, 3);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn event_logger_flushes_batched_event_after_idle_interval() {
        let path = temp_event_log_path("idle-flush");
        let logger = EventLogger::with_flush_interval(&path, Duration::from_millis(25)).unwrap();

        logger.log_at(event(1), 1);
        wait_for_line_count(&path, 1);
        logger.log_at(event(2), 2);

        wait_for_line_count(&path, 2);
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn event_log_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_event_log_path("permissions");
        let logger = EventLogger::with_flush_interval(&path, Duration::ZERO).unwrap();

        logger.log_at(event(1), 1);
        wait_for_line_count(&path, 1);

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn zero_flush_interval_preserves_flush_every_event_behavior() {
        let path = temp_event_log_path("immediate");
        let logger = EventLogger::with_flush_interval(&path, Duration::ZERO).unwrap();

        logger.log_at(event(1), 1);
        logger.log_at(event(2), 1);

        wait_for_line_count(&path, 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn event_logger_flushes_buffer_on_drop() {
        let path = temp_event_log_path("drop");
        {
            let logger = EventLogger::with_flush_interval(&path, Duration::from_secs(60)).unwrap();
            logger.log_at(event(1), 1);
            logger.log_at(event(2), 2);
            wait_for_line_count(&path, 1);
        }

        assert_eq!(line_count(&path), 2);
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn event_logger_drops_when_worker_queue_is_full() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt, time::Instant};

        let path = temp_event_log_path("blocked-fifo");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        unsafe {
            assert_eq!(libc::mkfifo(c_path.as_ptr(), 0o600), 0);
        }
        let reader_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(reader_fd >= 0);

        let logger = EventLogger::with_options_and_queue(&path, Duration::ZERO, 0, 0, 1).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut idx = 0;
        while logger.dropped_events() == 0 && Instant::now() < deadline {
            logger.log_at(event(idx), idx);
            idx += 1;
        }
        assert!(
            logger.dropped_events() > 0,
            "expected the bounded event-log queue to drop under a blocked sink"
        );

        drop(logger);
        unsafe {
            libc::close(reader_fd);
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn event_logger_rotates_when_byte_cap_is_reached() {
        let path = temp_event_log_path("rotate");
        let max_bytes = serialized_line_len(&event(1)) as u64 + 8;
        let logger = EventLogger::with_options(&path, Duration::ZERO, max_bytes, 1).unwrap();

        logger.log_at(event(1), 1);
        logger.log_at(event(2), 2);
        logger.log_at(event(3), 3);
        logger.flush();

        let current = fs::read_to_string(&path).unwrap();
        let previous = fs::read_to_string(rotated_event_log_path(&path, 1)).unwrap();
        assert_eq!(current.lines().count(), 1);
        assert_eq!(previous.lines().count(), 1);
        assert!(current.contains("sig-3"));
        assert!(previous.contains("sig-2"));
        assert!(!rotated_event_log_path(&path, 2).exists());

        remove_event_logs(&path, 2);
    }

    #[test]
    fn event_logger_respects_existing_file_size_on_startup() {
        let path = temp_event_log_path("existing-rotate");
        let first_line = serde_json::to_string(&event(1)).unwrap() + "\n";
        fs::write(&path, &first_line).unwrap();
        let logger =
            EventLogger::with_options(&path, Duration::ZERO, first_line.len() as u64 + 8, 1)
                .unwrap();

        logger.log_at(event(2), 2);
        logger.flush();

        let current = fs::read_to_string(&path).unwrap();
        let previous = fs::read_to_string(rotated_event_log_path(&path, 1)).unwrap();
        assert!(current.contains("sig-2"));
        assert!(previous.contains("sig-1"));

        remove_event_logs(&path, 1);
    }

    fn line_count(path: &Path) -> usize {
        fs::read_to_string(path).unwrap_or_default().lines().count()
    }

    fn wait_for_line_count(path: &Path, expected: usize) {
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            if line_count(path) >= expected {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(line_count(path), expected);
    }

    fn serialized_line_len(event: &AttackEvent) -> usize {
        serde_json::to_string(event).unwrap().len() + 1
    }

    fn remove_event_logs(path: &Path, backup_count: u32) {
        let _ = fs::remove_file(path);
        for idx in 1..=backup_count {
            let _ = fs::remove_file(rotated_event_log_path(path, idx));
        }
    }

    fn temp_event_log_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "altura-prot-{name}-{}-{}.jsonl",
            std::process::id(),
            unix_time_ms()
        ))
    }

    fn event(idx: u64) -> AttackEvent {
        AttackEvent {
            schema_version: 2,
            ts_unix_ms: idx,
            client_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: format!("/api/{idx}"),
            path_shape: "/api/:num".to_string(),
            query: None,
            query_keys: Vec::new(),
            user_agent: "test".to_string(),
            x_forwarded_for: None,
            header_names: Vec::new(),
            signature: format!("sig-{idx}"),
            signature_basis: format!("basis-{idx}"),
            reason: "observed".to_string(),
            observed_count: idx,
        }
    }
}
