use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const HOT_PATH_LOG_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct LogLimiter {
    next_allowed_ms: AtomicU64,
    suppressed: AtomicU64,
}

impl LogLimiter {
    pub const fn new() -> Self {
        Self {
            next_allowed_ms: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    pub fn should_log(&self, interval: Duration) -> Option<u64> {
        self.should_log_at(now_ms(), interval_ms(interval))
    }

    fn should_log_at(&self, now_ms: u64, interval_ms: u64) -> Option<u64> {
        let next_allowed_ms = self.next_allowed_ms.load(Ordering::Relaxed);
        if now_ms < next_allowed_ms {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let new_next_allowed_ms = now_ms.saturating_add(interval_ms.max(1));
        match self.next_allowed_ms.compare_exchange(
            next_allowed_ms,
            new_next_allowed_ms,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => Some(self.suppressed.swap(0, Ordering::AcqRel)),
            Err(_) => {
                self.suppressed.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

impl Default for LogLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn log_limited<F>(limiter: &'static LogLimiter, interval: Duration, log: F)
where
    F: FnOnce(SuppressedLogCount),
{
    if let Some(suppressed) = limiter.should_log(interval) {
        log(SuppressedLogCount(suppressed));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuppressedLogCount(u64);

impl fmt::Display for SuppressedLogCount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return Ok(());
        }
        write!(formatter, " (suppressed {} similar messages)", self.0)
    }
}

fn interval_ms(interval: Duration) -> u64 {
    let millis = interval.as_millis();
    if millis > u64::MAX as u128 {
        u64::MAX
    } else {
        millis as u64
    }
}

fn now_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => interval_ms(duration),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_log_is_allowed_and_burst_is_suppressed() {
        let limiter = LogLimiter::new();

        assert_eq!(limiter.should_log_at(0, 100), Some(0));
        assert_eq!(limiter.should_log_at(10, 100), None);
        assert_eq!(limiter.should_log_at(50, 100), None);
        assert_eq!(limiter.should_log_at(100, 100), Some(2));
    }

    #[test]
    fn zero_interval_still_advances_one_millisecond() {
        let limiter = LogLimiter::new();

        assert_eq!(limiter.should_log_at(10, 0), Some(0));
        assert_eq!(limiter.should_log_at(10, 0), None);
        assert_eq!(limiter.should_log_at(11, 0), Some(1));
    }

    #[test]
    fn suppressed_suffix_is_empty_without_suppressed_logs() {
        assert_eq!(SuppressedLogCount(0).to_string(), "");
        assert_eq!(
            SuppressedLogCount(7).to_string(),
            " (suppressed 7 similar messages)"
        );
    }
}
