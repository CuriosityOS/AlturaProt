use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::config::{HttpLimitConfig, TcpLimitConfig};

const SHARDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitReason {
    GlobalRate,
    PerIpRate,
    PerIpConnections,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitDecision {
    pub allowed: bool,
    pub reason: Option<LimitReason>,
}

impl LimitDecision {
    fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }

    fn deny(reason: LimitReason) -> Self {
        Self {
            allowed: false,
            reason: Some(reason),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_second: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(refill_per_second: f64, capacity: u32, now: Instant) -> Self {
        let capacity = capacity.max(1) as f64;
        Self {
            capacity,
            tokens: capacity,
            refill_per_second: refill_per_second.max(0.0),
            last: now,
        }
    }

    pub fn allow(&mut self, now: Instant, cost: f64) -> bool {
        self.refill(now);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
            self.last = now;
        }
    }

    fn stale(&self, now: Instant, max_idle: Duration) -> bool {
        now.saturating_duration_since(self.last) > max_idle
    }
}

#[derive(Debug)]
struct IpBucket {
    bucket: TokenBucket,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    per_ip_rps: f64,
    per_ip_burst: u32,
    max_tracked_ips: usize,
    global: Option<Mutex<TokenBucket>>,
    shards: Vec<Mutex<HashMap<IpAddr, IpBucket>>>,
}

impl RateLimiter {
    pub fn new(cfg: &HttpLimitConfig) -> Self {
        let now = Instant::now();
        let global = if cfg.global_rps > 0.0 {
            Some(Mutex::new(TokenBucket::new(
                cfg.global_rps,
                cfg.global_burst,
                now,
            )))
        } else {
            None
        };
        Self {
            per_ip_rps: cfg.per_ip_rps,
            per_ip_burst: cfg.per_ip_burst,
            max_tracked_ips: cfg.max_tracked_ips.max(1),
            global,
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    pub fn check(&self, ip: IpAddr) -> LimitDecision {
        let now = Instant::now();
        if let Some(global) = &self.global {
            let mut global = global.lock().expect("global rate limiter poisoned");
            if !global.allow(now, 1.0) {
                return LimitDecision::deny(LimitReason::GlobalRate);
            }
        }

        if self.per_ip_rps <= 0.0 {
            return LimitDecision::allow();
        }

        let shard_idx = shard_for(ip);
        let mut shard = self.shards[shard_idx]
            .lock()
            .expect("ip rate limiter poisoned");
        if shard.len() > self.max_tracked_ips / SHARDS + 128 {
            shard.retain(|_, entry| !entry.bucket.stale(now, Duration::from_secs(120)));
        }
        let entry = shard.entry(ip).or_insert_with(|| IpBucket {
            bucket: TokenBucket::new(self.per_ip_rps, self.per_ip_burst, now),
            last_seen: now,
        });
        entry.last_seen = now;
        if entry.bucket.allow(now, 1.0) {
            LimitDecision::allow()
        } else {
            LimitDecision::deny(LimitReason::PerIpRate)
        }
    }
}

#[derive(Debug)]
struct ConnEntry {
    bucket: TokenBucket,
    active: usize,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct ConnectionLimiter {
    per_ip_connects_per_second: f64,
    per_ip_connect_burst: u32,
    max_connections_per_ip: usize,
    max_tracked_ips: usize,
    shards: Vec<Mutex<HashMap<IpAddr, ConnEntry>>>,
}

impl ConnectionLimiter {
    pub fn new(cfg: &TcpLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            per_ip_connects_per_second: cfg.per_ip_connects_per_second,
            per_ip_connect_burst: cfg.per_ip_connect_burst,
            max_connections_per_ip: cfg.max_connections_per_ip.max(1),
            max_tracked_ips: cfg.max_tracked_ips.max(1),
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionPermit, LimitReason> {
        let now = Instant::now();
        let shard_idx = shard_for(ip);
        let mut shard = self.shards[shard_idx]
            .lock()
            .expect("tcp connection limiter poisoned");
        if shard.len() > self.max_tracked_ips / SHARDS + 128 {
            shard.retain(|_, entry| {
                entry.active > 0 || !entry.bucket.stale(now, Duration::from_secs(120))
            });
        }
        let entry = shard.entry(ip).or_insert_with(|| ConnEntry {
            bucket: TokenBucket::new(
                self.per_ip_connects_per_second,
                self.per_ip_connect_burst,
                now,
            ),
            active: 0,
            last_seen: now,
        });

        if entry.active >= self.max_connections_per_ip {
            return Err(LimitReason::PerIpConnections);
        }
        if self.per_ip_connects_per_second > 0.0 && !entry.bucket.allow(now, 1.0) {
            return Err(LimitReason::PerIpRate);
        }
        entry.active += 1;
        entry.last_seen = now;
        Ok(ConnectionPermit {
            ip,
            limiter: Arc::clone(self),
        })
    }

    fn release(&self, ip: IpAddr) {
        let shard_idx = shard_for(ip);
        let mut shard = self.shards[shard_idx]
            .lock()
            .expect("tcp connection limiter poisoned");
        if let Some(entry) = shard.get_mut(&ip) {
            entry.active = entry.active.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }
}

#[derive(Debug)]
pub struct ConnectionPermit {
    ip: IpAddr,
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

fn shard_for(ip: IpAddr) -> usize {
    let hash = match ip {
        IpAddr::V4(v4) => u32::from(v4) as u64,
        IpAddr::V6(v6) => v6
            .segments()
            .iter()
            .fold(0xcbf29ce484222325_u64, |acc, segment| {
                (acc ^ (*segment as u64)).wrapping_mul(0x100000001b3)
            }),
    };
    (hash as usize) % SHARDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_refills_over_time() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(10.0, 2, start);
        assert!(bucket.allow(start, 1.0));
        assert!(bucket.allow(start, 1.0));
        assert!(!bucket.allow(start, 1.0));
        assert!(bucket.allow(start + Duration::from_millis(110), 1.0));
    }

    #[test]
    fn rate_limiter_denies_after_burst() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 0.1,
            per_ip_burst: 2,
            global_rps: 0.0,
            global_burst: 1,
            max_tracked_ips: 64,
        };
        let limiter = RateLimiter::new(&cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.check(ip).allowed);
        assert!(limiter.check(ip).allowed);
        let denied = limiter.check(ip);
        assert!(!denied.allowed);
        assert_eq!(denied.reason, Some(LimitReason::PerIpRate));
    }

    #[test]
    fn connection_limiter_tracks_active_connections() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 100.0,
            per_ip_connect_burst: 100,
            max_connections_per_ip: 1,
            max_tracked_ips: 64,
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let permit = limiter.try_acquire(ip).unwrap();
        assert_eq!(
            limiter.try_acquire(ip).unwrap_err(),
            LimitReason::PerIpConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(ip).is_ok());
    }
}
