use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use crate::config::{HttpLimitConfig, TcpLimitConfig};

const SHARDS: usize = 64;
const TRACKED_IP_IDLE_SECONDS: u64 = 120;
const TRACKED_SIGNATURE_IDLE_SECONDS: u64 = 120;
const EVICTION_SCAN_LIMIT: usize = 32;
const SHORT_TOKEN_SIBLING_DISTINCT_THRESHOLD: usize = 3;
const SHORT_TOKEN_SIBLING_DISTINCT_CAP: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitReason {
    GlobalRate,
    GlobalConnections,
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

    fn has_tokens(&mut self, now: Instant, cost: f64) -> bool {
        self.refill(now);
        self.tokens >= cost
    }

    fn consume(&mut self, cost: f64) {
        self.tokens -= cost;
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
    ipv4_prefix_len: u8,
    ipv6_prefix_len: u8,
    max_tracked_ips: usize,
    global: Option<Mutex<TokenBucket>>,
    shards: Vec<Mutex<LimiterShard<IpAddr, IpBucket>>>,
}

#[derive(Debug)]
struct KeyBucket {
    bucket: TokenBucket,
    last_seen: Instant,
}

#[derive(Debug)]
struct LimiterShard<K, T> {
    entries: HashMap<K, T>,
    order: VecDeque<K>,
}

impl<K, T> LimiterShard<K, T> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

#[derive(Debug)]
struct KeyRateLimiter {
    rps: f64,
    burst: u32,
    max_tracked_keys: usize,
    shards: Vec<Mutex<LimiterShard<String, KeyBucket>>>,
}

impl KeyRateLimiter {
    fn new(rps: f64, burst: u32, max_tracked_keys: usize) -> Self {
        Self {
            rps,
            burst,
            max_tracked_keys: max_tracked_keys.max(1),
            shards: (0..SHARDS)
                .map(|_| Mutex::new(LimiterShard::new()))
                .collect(),
        }
    }

    fn check(&self, key: &str) -> bool {
        if self.rps <= 0.0 {
            return true;
        }

        let now = Instant::now();
        let shard_idx = shard_for_key(key);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "key rate limiter");
        if let Some(entry) = shard.entries.get_mut(key) {
            entry.last_seen = now;
            return entry.bucket.allow(now, 1.0);
        }
        if !ensure_key_shard_capacity(&mut shard, self.max_tracked_keys, now) {
            return false;
        }
        let key_owned = key.to_string();
        shard.order.push_back(key_owned.clone());
        let entry = shard.entries.entry(key_owned).or_insert_with(|| KeyBucket {
            bucket: TokenBucket::new(self.rps, self.burst, now),
            last_seen: now,
        });
        entry.last_seen = now;
        entry.bucket.allow(now, 1.0)
    }
}

#[derive(Debug)]
pub struct SignatureRateLimiter {
    inner: KeyRateLimiter,
}

impl SignatureRateLimiter {
    pub fn new(cfg: &HttpLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            inner: KeyRateLimiter::new(
                cfg.signature_rps,
                cfg.signature_burst,
                cfg.max_tracked_signatures,
            ),
        })
    }

    pub fn check(&self, signature: &str) -> bool {
        self.inner.check(signature)
    }
}

#[derive(Debug)]
pub struct PathShapeRateLimiter {
    inner: KeyRateLimiter,
}

impl PathShapeRateLimiter {
    pub fn new(cfg: &HttpLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            inner: KeyRateLimiter::new(
                cfg.path_shape_rps,
                cfg.path_shape_burst,
                cfg.max_tracked_path_shapes,
            ),
        })
    }

    pub fn check(&self, path_shape: &str) -> bool {
        self.inner.check(path_shape)
    }
}

#[derive(Debug)]
struct ShortTokenSiblingEntry {
    bucket: TokenBucket,
    distinct_tokens: HashSet<String>,
    token_order: VecDeque<String>,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct ShortTokenSiblingRateLimiter {
    rps: f64,
    burst: u32,
    max_tracked_parents: usize,
    shards: Vec<Mutex<LimiterShard<String, ShortTokenSiblingEntry>>>,
}

impl ShortTokenSiblingRateLimiter {
    pub fn new(cfg: &HttpLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            rps: cfg.path_shape_rps,
            burst: cfg.path_shape_burst,
            max_tracked_parents: cfg.max_tracked_path_shapes.max(1),
            shards: (0..SHARDS)
                .map(|_| Mutex::new(LimiterShard::new()))
                .collect(),
        })
    }

    pub fn check(&self, parent_shape: &str, token: &str) -> bool {
        if self.rps <= 0.0 {
            return true;
        }

        let now = Instant::now();
        let shard_idx = shard_for_key(parent_shape);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "short-token sibling limiter");
        let entry = if let Some(entry) = shard.entries.get_mut(parent_shape) {
            entry
        } else {
            if !ensure_short_token_parent_shard_capacity(&mut shard, self.max_tracked_parents, now)
            {
                return false;
            }
            let parent_owned = parent_shape.to_string();
            shard.order.push_back(parent_owned.clone());
            shard
                .entries
                .entry(parent_owned)
                .or_insert_with(|| ShortTokenSiblingEntry {
                    bucket: TokenBucket::new(self.rps, self.burst, now),
                    distinct_tokens: HashSet::new(),
                    token_order: VecDeque::new(),
                    last_seen: now,
                })
        };
        entry.last_seen = now;
        if !entry.distinct_tokens.contains(token) {
            let token_owned = token.to_string();
            entry.distinct_tokens.insert(token_owned.clone());
            entry.token_order.push_back(token_owned);
            while entry.distinct_tokens.len() > SHORT_TOKEN_SIBLING_DISTINCT_CAP {
                let Some(oldest) = entry.token_order.pop_front() else {
                    break;
                };
                entry.distinct_tokens.remove(&oldest);
            }
        }
        let has_budget = entry.bucket.allow(now, 1.0);
        has_budget || entry.distinct_tokens.len() < SHORT_TOKEN_SIBLING_DISTINCT_THRESHOLD
    }
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
            ipv4_prefix_len: cfg.ipv4_prefix_len,
            ipv6_prefix_len: cfg.ipv6_prefix_len,
            max_tracked_ips: cfg.max_tracked_ips.max(1),
            global,
            shards: (0..SHARDS)
                .map(|_| Mutex::new(LimiterShard::new()))
                .collect(),
        }
    }

    pub fn trusted_proxy_aggregate(cfg: &HttpLimitConfig) -> Self {
        Self {
            per_ip_rps: cfg.trusted_proxy_rps,
            per_ip_burst: cfg.trusted_proxy_burst,
            ipv4_prefix_len: 32,
            ipv6_prefix_len: 128,
            max_tracked_ips: cfg.max_tracked_ips.max(1),
            global: None,
            shards: (0..SHARDS)
                .map(|_| Mutex::new(LimiterShard::new()))
                .collect(),
        }
    }

    pub fn check(&self, ip: IpAddr) -> LimitDecision {
        let now = Instant::now();
        if let Some(global) = self.global.as_ref() {
            if !bucket_has_tokens(global, "global rate limiter", now) {
                return LimitDecision::deny(LimitReason::GlobalRate);
            }
        }

        if self.per_ip_rps <= 0.0 {
            if let Some(global) = self.global.as_ref() {
                if !bucket_try_consume(global, "global rate limiter", now) {
                    return LimitDecision::deny(LimitReason::GlobalRate);
                }
            }
            return LimitDecision::allow();
        }

        let key = normalize_ip(ip, self.ipv4_prefix_len, self.ipv6_prefix_len);
        let shard_idx = shard_for(key);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "ip rate limiter");
        if !shard.entries.contains_key(&key)
            && !ensure_rate_shard_capacity(&mut shard, self.max_tracked_ips, now)
        {
            return LimitDecision::deny(LimitReason::PerIpRate);
        }
        let inserted = !shard.entries.contains_key(&key);
        if inserted {
            shard.order.push_back(key);
        }
        {
            let entry = shard.entries.entry(key).or_insert_with(|| IpBucket {
                bucket: TokenBucket::new(self.per_ip_rps, self.per_ip_burst, now),
                last_seen: now,
            });
            entry.last_seen = now;
            if !entry.bucket.has_tokens(now, 1.0) {
                return LimitDecision::deny(LimitReason::PerIpRate);
            }
        }
        if let Some(global) = self.global.as_ref() {
            if !bucket_try_consume(global, "global rate limiter", now) {
                if inserted {
                    remove_shard_entry(&mut shard, &key);
                }
                return LimitDecision::deny(LimitReason::GlobalRate);
            }
        }
        if !consume_rate_bucket(&mut shard, &key) {
            eprintln!("rate limiter bucket missing after successful admission; denying request");
            return LimitDecision::deny(LimitReason::PerIpRate);
        }
        LimitDecision::allow()
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
    ipv4_prefix_len: u8,
    ipv6_prefix_len: u8,
    max_connections: usize,
    max_connections_per_ip: usize,
    max_tracked_ips: usize,
    global_connects: Option<Mutex<TokenBucket>>,
    global_active: AtomicUsize,
    shards: Vec<Mutex<LimiterShard<IpAddr, ConnEntry>>>,
}

impl ConnectionLimiter {
    pub fn new(cfg: &TcpLimitConfig) -> Arc<Self> {
        let now = Instant::now();
        let global_connects = if cfg.global_connects_per_second > 0.0 {
            Some(Mutex::new(TokenBucket::new(
                cfg.global_connects_per_second,
                cfg.global_connect_burst,
                now,
            )))
        } else {
            None
        };
        Arc::new(Self {
            per_ip_connects_per_second: cfg.per_ip_connects_per_second,
            per_ip_connect_burst: cfg.per_ip_connect_burst,
            ipv4_prefix_len: cfg.ipv4_prefix_len,
            ipv6_prefix_len: cfg.ipv6_prefix_len,
            max_connections: cfg.max_connections,
            max_connections_per_ip: cfg.max_connections_per_ip.max(1),
            max_tracked_ips: cfg.max_tracked_ips.max(1),
            global_connects,
            global_active: AtomicUsize::new(0),
            shards: (0..SHARDS)
                .map(|_| Mutex::new(LimiterShard::new()))
                .collect(),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionPermit, LimitReason> {
        let now = Instant::now();
        if let Some(global_connects) = self.global_connects.as_ref() {
            if !bucket_has_tokens(global_connects, "tcp global connection-rate limiter", now) {
                return Err(LimitReason::GlobalRate);
            }
        }
        if self.max_connections > 0
            && self.global_active.load(Ordering::Relaxed) >= self.max_connections
        {
            return Err(LimitReason::GlobalConnections);
        }

        let key = normalize_ip(ip, self.ipv4_prefix_len, self.ipv6_prefix_len);
        let shard_idx = shard_for(key);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "tcp connection limiter");
        if !shard.entries.contains_key(&key)
            && !ensure_connection_shard_capacity(&mut shard, self.max_tracked_ips, now)
        {
            return Err(LimitReason::GlobalConnections);
        }
        if !shard.entries.contains_key(&key) {
            shard.order.push_back(key);
        }
        let entry = shard.entries.entry(key).or_insert_with(|| ConnEntry {
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
        if self.per_ip_connects_per_second > 0.0 && !entry.bucket.has_tokens(now, 1.0) {
            return Err(LimitReason::PerIpRate);
        }
        if self.max_connections > 0 {
            let mut active = self.global_active.load(Ordering::Relaxed);
            loop {
                if active >= self.max_connections {
                    return Err(LimitReason::GlobalConnections);
                }
                match self.global_active.compare_exchange_weak(
                    active,
                    active + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(current) => active = current,
                }
            }
        }
        if let Some(global_connects) = self.global_connects.as_ref() {
            if !bucket_try_consume(global_connects, "tcp global connection-rate limiter", now) {
                self.release_global();
                return Err(LimitReason::GlobalRate);
            }
        }
        if self.per_ip_connects_per_second > 0.0 {
            entry.bucket.consume(1.0);
        }
        entry.active += 1;
        entry.last_seen = now;
        Ok(ConnectionPermit {
            ip: key,
            limiter: Arc::clone(self),
        })
    }

    fn release(&self, ip: IpAddr) {
        self.release_global();
        let shard_idx = shard_for(ip);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "tcp connection limiter");
        if let Some(entry) = shard.entries.get_mut(&ip) {
            entry.active = entry.active.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }

    fn release_global(&self) {
        if self.max_connections > 0 {
            self.global_active.fetch_sub(1, Ordering::AcqRel);
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

#[derive(Debug)]
struct HttpConnEntry {
    bucket: TokenBucket,
    active: usize,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct HttpConnectionLimiter {
    per_ip_connects_per_second: f64,
    per_ip_connect_burst: u32,
    ipv4_prefix_len: u8,
    ipv6_prefix_len: u8,
    max_connections: usize,
    max_connections_per_ip: usize,
    max_tracked_ips: usize,
    global_connects: Option<Mutex<TokenBucket>>,
    global_active: AtomicUsize,
    shards: Vec<Mutex<LimiterShard<IpAddr, HttpConnEntry>>>,
}

impl HttpConnectionLimiter {
    pub fn new(cfg: &HttpLimitConfig) -> Arc<Self> {
        let now = Instant::now();
        let global_connects = if cfg.global_connects_per_second > 0.0 {
            Some(Mutex::new(TokenBucket::new(
                cfg.global_connects_per_second,
                cfg.global_connect_burst,
                now,
            )))
        } else {
            None
        };
        Arc::new(Self {
            per_ip_connects_per_second: cfg.per_ip_connects_per_second,
            per_ip_connect_burst: cfg.per_ip_connect_burst,
            ipv4_prefix_len: cfg.ipv4_prefix_len,
            ipv6_prefix_len: cfg.ipv6_prefix_len,
            max_connections: cfg.max_connections,
            max_connections_per_ip: cfg.max_connections_per_ip,
            max_tracked_ips: cfg.max_tracked_ips.max(1),
            global_connects,
            global_active: AtomicUsize::new(0),
            shards: (0..SHARDS)
                .map(|_| Mutex::new(LimiterShard::new()))
                .collect(),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<HttpConnectionPermit, LimitReason> {
        let now = Instant::now();
        if let Some(global_connects) = self.global_connects.as_ref() {
            if !bucket_has_tokens(global_connects, "http global connection-rate limiter", now) {
                return Err(LimitReason::GlobalRate);
            }
        }
        if self.max_connections > 0
            && self.global_active.load(Ordering::Relaxed) >= self.max_connections
        {
            return Err(LimitReason::GlobalConnections);
        }

        let key = normalize_ip(ip, self.ipv4_prefix_len, self.ipv6_prefix_len);
        let shard_idx = shard_for(key);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "http connection limiter");
        if !shard.entries.contains_key(&key)
            && !ensure_http_connection_shard_capacity(&mut shard, self.max_tracked_ips, now)
        {
            return Err(LimitReason::GlobalConnections);
        }
        if !shard.entries.contains_key(&key) {
            shard.order.push_back(key);
        }
        let entry = shard.entries.entry(key).or_insert_with(|| HttpConnEntry {
            bucket: TokenBucket::new(
                self.per_ip_connects_per_second,
                self.per_ip_connect_burst,
                now,
            ),
            active: 0,
            last_seen: now,
        });
        if self.per_ip_connects_per_second > 0.0 && !entry.bucket.has_tokens(now, 1.0) {
            return Err(LimitReason::PerIpRate);
        }
        if self.max_connections_per_ip > 0 && entry.active >= self.max_connections_per_ip {
            return Err(LimitReason::PerIpConnections);
        }
        if self.max_connections > 0 {
            let mut active = self.global_active.load(Ordering::Relaxed);
            loop {
                if active >= self.max_connections {
                    return Err(LimitReason::GlobalConnections);
                }
                match self.global_active.compare_exchange_weak(
                    active,
                    active + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(current) => active = current,
                }
            }
        }
        if let Some(global_connects) = self.global_connects.as_ref() {
            if !bucket_try_consume(global_connects, "http global connection-rate limiter", now) {
                if self.max_connections > 0 {
                    self.global_active.fetch_sub(1, Ordering::AcqRel);
                }
                return Err(LimitReason::GlobalRate);
            }
        }
        if self.per_ip_connects_per_second > 0.0 {
            entry.bucket.consume(1.0);
        }
        entry.active += 1;
        entry.last_seen = now;
        Ok(HttpConnectionPermit {
            ip: key,
            limiter: Arc::clone(self),
        })
    }

    fn release(&self, ip: IpAddr) {
        if self.max_connections > 0 {
            self.global_active.fetch_sub(1, Ordering::AcqRel);
        }
        let shard_idx = shard_for(ip);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "http connection limiter");
        if let Some(entry) = shard.entries.get_mut(&ip) {
            entry.active = entry.active.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }
}

#[derive(Debug)]
pub struct HttpConnectionPermit {
    ip: IpAddr,
    limiter: Arc<HttpConnectionLimiter>,
}

impl Drop for HttpConnectionPermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

#[derive(Debug)]
struct RequestEntry {
    active: usize,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct RequestConcurrencyLimiter {
    max_in_flight: usize,
    max_in_flight_per_ip: usize,
    ipv4_prefix_len: u8,
    ipv6_prefix_len: u8,
    max_tracked_ips: usize,
    global_active: AtomicUsize,
    shards: Vec<Mutex<LimiterShard<IpAddr, RequestEntry>>>,
}

impl RequestConcurrencyLimiter {
    pub fn new(cfg: &HttpLimitConfig) -> Arc<Self> {
        Self::with_limits(
            cfg.max_in_flight_requests,
            cfg.max_in_flight_requests_per_ip,
            cfg.max_tracked_ips,
            cfg.ipv4_prefix_len,
            cfg.ipv6_prefix_len,
        )
    }

    pub fn trusted_proxy_aggregate(cfg: &HttpLimitConfig) -> Arc<Self> {
        Self::with_limits(
            0,
            cfg.trusted_proxy_max_in_flight_requests,
            cfg.max_tracked_ips,
            32,
            128,
        )
    }

    fn with_limits(
        max_in_flight: usize,
        max_in_flight_per_ip: usize,
        max_tracked_ips: usize,
        ipv4_prefix_len: u8,
        ipv6_prefix_len: u8,
    ) -> Arc<Self> {
        Arc::new(Self {
            max_in_flight,
            max_in_flight_per_ip,
            ipv4_prefix_len,
            ipv6_prefix_len,
            max_tracked_ips: max_tracked_ips.max(1),
            global_active: AtomicUsize::new(0),
            shards: (0..SHARDS)
                .map(|_| Mutex::new(LimiterShard::new()))
                .collect(),
        })
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
    ) -> Result<RequestConcurrencyPermit, LimitReason> {
        if self.max_in_flight > 0
            && self.global_active.load(Ordering::Relaxed) >= self.max_in_flight
        {
            return Err(LimitReason::GlobalConnections);
        }

        let now = Instant::now();
        let key = normalize_ip(ip, self.ipv4_prefix_len, self.ipv6_prefix_len);
        let shard_idx = shard_for(key);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "request concurrency limiter");
        if !shard.entries.contains_key(&key)
            && !ensure_request_shard_capacity(&mut shard, self.max_tracked_ips, now)
        {
            return Err(LimitReason::GlobalConnections);
        }
        if !shard.entries.contains_key(&key) {
            shard.order.push_back(key);
        }
        let entry = shard.entries.entry(key).or_insert_with(|| RequestEntry {
            active: 0,
            last_seen: now,
        });
        if self.max_in_flight_per_ip > 0 && entry.active >= self.max_in_flight_per_ip {
            return Err(LimitReason::PerIpConnections);
        }
        if self.max_in_flight > 0 {
            let mut active = self.global_active.load(Ordering::Relaxed);
            loop {
                if active >= self.max_in_flight {
                    return Err(LimitReason::GlobalConnections);
                }
                match self.global_active.compare_exchange_weak(
                    active,
                    active + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(current) => active = current,
                }
            }
        }
        entry.active += 1;
        entry.last_seen = now;
        Ok(RequestConcurrencyPermit {
            ip: key,
            limiter: Arc::clone(self),
        })
    }

    fn release(&self, ip: IpAddr) {
        self.release_global();
        let shard_idx = shard_for(ip);
        let mut shard = lock_or_recover(&self.shards[shard_idx], "request concurrency limiter");
        if let Some(entry) = shard.entries.get_mut(&ip) {
            entry.active = entry.active.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }

    fn release_global(&self) {
        if self.max_in_flight > 0 {
            self.global_active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug)]
pub struct RequestConcurrencyPermit {
    ip: IpAddr,
    limiter: Arc<RequestConcurrencyLimiter>,
}

impl Drop for RequestConcurrencyPermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

fn shard_for(ip: IpAddr) -> usize {
    hashed_shard(&ip)
}

fn normalize_ip(ip: IpAddr, ipv4_prefix_len: u8, ipv6_prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let prefix = ipv4_prefix_len.min(32);
            if prefix == 0 {
                IpAddr::V4(0_u32.into())
            } else if prefix == 32 {
                IpAddr::V4(v4)
            } else {
                let mask = u32::MAX << (32 - prefix);
                IpAddr::V4((u32::from(v4) & mask).into())
            }
        }
        IpAddr::V6(v6) => {
            let prefix = ipv6_prefix_len.min(128);
            if prefix == 0 {
                IpAddr::V6(0_u128.into())
            } else if prefix == 128 {
                IpAddr::V6(v6)
            } else {
                let mask = u128::MAX << (128 - prefix);
                IpAddr::V6((u128::from(v6) & mask).into())
            }
        }
    }
}

fn shard_for_key(key: &str) -> usize {
    hashed_shard(key)
}

fn hashed_shard<T: Hash + ?Sized>(value: &T) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % SHARDS
}

fn tracked_ip_idle() -> Duration {
    Duration::from_secs(TRACKED_IP_IDLE_SECONDS)
}

fn tracked_signature_idle() -> Duration {
    Duration::from_secs(TRACKED_SIGNATURE_IDLE_SECONDS)
}

fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, label: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            eprintln!("{label} poisoned; recovering state");
            poisoned.into_inner()
        }
    }
}

fn bucket_has_tokens(bucket: &Mutex<TokenBucket>, label: &str, now: Instant) -> bool {
    lock_or_recover(bucket, label).has_tokens(now, 1.0)
}

fn bucket_try_consume(bucket: &Mutex<TokenBucket>, label: &str, now: Instant) -> bool {
    let mut bucket = lock_or_recover(bucket, label);
    if !bucket.has_tokens(now, 1.0) {
        return false;
    }
    bucket.consume(1.0);
    true
}

fn shard_capacity(max_tracked_ips: usize) -> usize {
    let max_tracked_ips = max_tracked_ips.max(1);
    max_tracked_ips.div_ceil(SHARDS).max(1)
}

fn ensure_key_shard_capacity(
    shard: &mut LimiterShard<String, KeyBucket>,
    max_tracked_keys: usize,
    now: Instant,
) -> bool {
    let capacity = shard_capacity(max_tracked_keys);
    if shard.entries.len() < capacity {
        return true;
    }
    evict_stale_or_oldest(shard, |entry| {
        entry.bucket.stale(now, tracked_signature_idle())
    });
    if shard.entries.len() < capacity {
        return true;
    }
    false
}

fn ensure_short_token_parent_shard_capacity(
    shard: &mut LimiterShard<String, ShortTokenSiblingEntry>,
    max_tracked_parents: usize,
    now: Instant,
) -> bool {
    let capacity = shard_capacity(max_tracked_parents);
    if shard.entries.len() < capacity {
        return true;
    }
    evict_stale_or_oldest(shard, |entry| {
        now.saturating_duration_since(entry.last_seen) >= tracked_signature_idle()
    });
    if shard.entries.len() < capacity {
        return true;
    }
    false
}

fn ensure_rate_shard_capacity(
    shard: &mut LimiterShard<IpAddr, IpBucket>,
    max_tracked_ips: usize,
    now: Instant,
) -> bool {
    let capacity = shard_capacity(max_tracked_ips);
    if shard.entries.len() < capacity {
        return true;
    }
    evict_stale_or_oldest(shard, |entry| entry.bucket.stale(now, tracked_ip_idle()));
    if shard.entries.len() < capacity {
        return true;
    }
    false
}

fn ensure_connection_shard_capacity(
    shard: &mut LimiterShard<IpAddr, ConnEntry>,
    max_tracked_ips: usize,
    now: Instant,
) -> bool {
    let capacity = shard_capacity(max_tracked_ips);
    if shard.entries.len() < capacity {
        return true;
    }
    evict_stale_or_oldest(shard, |entry| {
        entry.active == 0 && entry.bucket.stale(now, tracked_ip_idle())
    });
    if shard.entries.len() < capacity {
        return true;
    }
    evict_one(shard, |entry| entry.active == 0);
    shard.entries.len() < capacity
}

fn ensure_http_connection_shard_capacity(
    shard: &mut LimiterShard<IpAddr, HttpConnEntry>,
    max_tracked_ips: usize,
    now: Instant,
) -> bool {
    let capacity = shard_capacity(max_tracked_ips);
    if shard.entries.len() < capacity {
        return true;
    }
    evict_stale_or_oldest(shard, |entry| {
        entry.active == 0 && entry.bucket.stale(now, tracked_ip_idle())
    });
    if shard.entries.len() < capacity {
        return true;
    }
    evict_one(shard, |entry| entry.active == 0);
    shard.entries.len() < capacity
}

fn ensure_request_shard_capacity(
    shard: &mut LimiterShard<IpAddr, RequestEntry>,
    max_tracked_ips: usize,
    now: Instant,
) -> bool {
    let capacity = shard_capacity(max_tracked_ips);
    if shard.entries.len() < capacity {
        return true;
    }
    evict_stale_or_oldest(shard, |entry| {
        entry.active == 0 && now.saturating_duration_since(entry.last_seen) >= tracked_ip_idle()
    });
    if shard.entries.len() < capacity {
        return true;
    }
    evict_one(shard, |entry| entry.active == 0);
    shard.entries.len() < capacity
}

fn evict_stale_or_oldest<K, T>(
    shard: &mut LimiterShard<K, T>,
    is_stale: impl Fn(&T) -> bool,
) -> bool
where
    K: Eq + Hash + Clone,
{
    let scan = shard.order.len().min(EVICTION_SCAN_LIMIT);
    for _ in 0..scan {
        let Some(key) = shard.order.pop_front() else {
            break;
        };
        let stale = shard.entries.get(&key).is_some_and(&is_stale);
        if stale {
            shard.entries.remove(&key);
            return true;
        }
        if shard.entries.contains_key(&key) {
            shard.order.push_back(key);
        }
    }
    false
}

fn evict_one<K, T>(shard: &mut LimiterShard<K, T>, can_evict: impl Fn(&T) -> bool) -> bool
where
    K: Eq + Hash + Clone,
{
    let scan = shard.order.len().min(EVICTION_SCAN_LIMIT);
    for _ in 0..scan {
        let Some(key) = shard.order.pop_front() else {
            break;
        };
        let evict = shard.entries.get(&key).is_some_and(&can_evict);
        if evict {
            shard.entries.remove(&key);
            return true;
        }
        if shard.entries.contains_key(&key) {
            shard.order.push_back(key);
        }
    }
    false
}

fn remove_shard_entry<K, T>(shard: &mut LimiterShard<K, T>, key: &K)
where
    K: Eq + Hash + Clone,
{
    shard.entries.remove(key);
    if let Some(pos) = shard.order.iter().position(|candidate| candidate == key) {
        shard.order.remove(pos);
    }
}

fn consume_rate_bucket(shard: &mut LimiterShard<IpAddr, IpBucket>, key: &IpAddr) -> bool {
    let Some(entry) = shard.entries.get_mut(key) else {
        return false;
    };
    entry.bucket.consume(1.0);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn same_shard_ips(count: usize) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        let target_shard = shard_for("10.0.0.1".parse().unwrap());
        let mut value = 1_u32;
        while ips.len() < count {
            let ip = IpAddr::V4(value.into());
            if shard_for(ip) == target_shard {
                ips.push(ip);
            }
            value += 1;
        }
        ips
    }

    fn same_shard_signatures(count: usize) -> Vec<String> {
        let mut signatures = Vec::new();
        let target_shard = shard_for_key("sig-0");
        let mut value = 0_u64;
        while signatures.len() < count {
            let signature = format!("sig-{value}");
            if shard_for_key(&signature) == target_shard {
                signatures.push(signature);
            }
            value += 1;
        }
        signatures
    }

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
    fn normalize_ip_masks_configured_prefix_bits() {
        assert_eq!(
            normalize_ip("198.51.100.42".parse().unwrap(), 24, 64),
            "198.51.100.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            normalize_ip("2001:db8:abcd:1234::42".parse().unwrap(), 32, 64),
            "2001:db8:abcd:1234::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn normalized_ipv4_prefixes_are_sharded_by_hash_not_low_bits() {
        let shards: HashSet<usize> = (0_u8..64)
            .map(|third_octet| {
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, third_octet, 42));
                shard_for(normalize_ip(ip, 24, 64))
            })
            .collect();

        assert!(
            shards.len() > 1,
            "normalized /24 IPv4 keys must not all collapse into one limiter shard"
        );
    }

    #[test]
    fn signature_rate_limiter_denies_after_burst_without_cross_signature_tokens() {
        let cfg = HttpLimitConfig {
            signature_rps: 0.000001,
            signature_burst: 2,
            max_tracked_signatures: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = SignatureRateLimiter::new(&cfg);

        assert!(limiter.check("hot-signature"));
        assert!(limiter.check("hot-signature"));
        assert!(!limiter.check("hot-signature"));
        assert!(limiter.check("other-signature"));
    }

    #[test]
    fn signature_rate_limiter_can_be_disabled() {
        let cfg = HttpLimitConfig {
            signature_rps: 0.0,
            signature_burst: 1,
            max_tracked_signatures: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = SignatureRateLimiter::new(&cfg);

        for _ in 0..10 {
            assert!(limiter.check("hot-signature"));
        }
    }

    #[test]
    fn signature_rate_limiter_denies_new_active_key_at_tracked_signature_cap() {
        let cfg = HttpLimitConfig {
            signature_rps: 100.0,
            signature_burst: 100,
            max_tracked_signatures: SHARDS,
            ..HttpLimitConfig::default()
        };
        let limiter = SignatureRateLimiter::new(&cfg);
        let signatures = same_shard_signatures(2);

        assert!(limiter.check(&signatures[0]));
        assert!(!limiter.check(&signatures[1]));

        let shard = limiter.inner.shards[shard_for_key(&signatures[0])]
            .lock()
            .unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert!(shard.entries.contains_key(&signatures[0]));
        assert!(!shard.entries.contains_key(&signatures[1]));
    }

    #[test]
    fn path_shape_rate_limiter_denies_after_burst_without_cross_shape_tokens() {
        let cfg = HttpLimitConfig {
            path_shape_rps: 0.000001,
            path_shape_burst: 2,
            max_tracked_path_shapes: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = PathShapeRateLimiter::new(&cfg);

        assert!(limiter.check("/api/:token/:num"));
        assert!(limiter.check("/api/:token/:num"));
        assert!(!limiter.check("/api/:token/:num"));
        assert!(limiter.check("/api/catalog/:num"));
    }

    #[test]
    fn path_shape_rate_limiter_denies_new_active_key_at_tracked_shape_cap() {
        let cfg = HttpLimitConfig {
            path_shape_rps: 100.0,
            path_shape_burst: 100,
            max_tracked_path_shapes: SHARDS,
            ..HttpLimitConfig::default()
        };
        let limiter = PathShapeRateLimiter::new(&cfg);
        let shapes = same_shard_signatures(2);

        assert!(limiter.check(&shapes[0]));
        assert!(!limiter.check(&shapes[1]));

        let shard = limiter.inner.shards[shard_for_key(&shapes[0])]
            .lock()
            .unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert!(shard.entries.contains_key(&shapes[0]));
        assert!(!shard.entries.contains_key(&shapes[1]));
    }

    #[test]
    fn short_token_sibling_limiter_allows_one_short_route_without_budget() {
        let cfg = HttpLimitConfig {
            path_shape_rps: 0.000001,
            path_shape_burst: 2,
            max_tracked_path_shapes: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = ShortTokenSiblingRateLimiter::new(&cfg);

        for _ in 0..10 {
            assert!(
                limiter.check("/api/:short-token", "me"),
                "one stable short route must not be limited by the sibling-churn guard"
            );
        }
    }

    #[test]
    fn short_token_sibling_limiter_denies_distinct_short_sibling_churn() {
        let cfg = HttpLimitConfig {
            path_shape_rps: 0.000001,
            path_shape_burst: 2,
            max_tracked_path_shapes: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = ShortTokenSiblingRateLimiter::new(&cfg);

        assert!(limiter.check("/api/:short-token", "ab"));
        assert!(limiter.check("/api/:short-token", "cd"));
        assert!(!limiter.check("/api/:short-token", "ef"));
        assert!(!limiter.check("/api/:short-token", "gh"));
    }

    #[test]
    fn short_token_sibling_limiter_denies_new_recent_parent_at_cap() {
        let cfg = HttpLimitConfig {
            path_shape_rps: 100.0,
            path_shape_burst: 100,
            max_tracked_path_shapes: SHARDS,
            ..HttpLimitConfig::default()
        };
        let limiter = ShortTokenSiblingRateLimiter::new(&cfg);
        let parents = same_shard_signatures(2);

        assert!(limiter.check(&parents[0], "ab"));
        assert!(!limiter.check(&parents[1], "ab"));

        let shard = limiter.shards[shard_for_key(&parents[0])].lock().unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert!(shard.entries.contains_key(&parents[0]));
        assert!(!shard.entries.contains_key(&parents[1]));
    }

    #[test]
    fn limiter_eviction_scan_is_bounded_per_insert_attempt() {
        let now = Instant::now();
        let stale_at = EVICTION_SCAN_LIMIT + 4;
        let mut shard = LimiterShard::new();

        for idx in 0..=stale_at {
            let key = format!("key-{idx}");
            shard.order.push_back(key.clone());
            shard.entries.insert(
                key,
                KeyBucket {
                    bucket: TokenBucket::new(1.0, 1, now),
                    last_seen: now,
                },
            );
        }

        let calls = Cell::new(0);
        let evicted = evict_stale_or_oldest(&mut shard, |entry: &KeyBucket| {
            calls.set(calls.get() + 1);
            entry.bucket.stale(
                now + tracked_signature_idle() + Duration::from_secs(1),
                tracked_signature_idle(),
            ) && calls.get() > EVICTION_SCAN_LIMIT
        });

        assert!(!evicted);
        assert_eq!(calls.get(), EVICTION_SCAN_LIMIT);
        assert_eq!(shard.entries.len(), stale_at + 1);
    }

    #[test]
    fn inactive_connection_eviction_scan_is_bounded_per_insert_attempt() {
        let now = Instant::now();
        let inactive_at = EVICTION_SCAN_LIMIT + 4;
        let mut shard = LimiterShard::new();

        for idx in 0..=inactive_at {
            let key = IpAddr::V4((idx as u32 + 1).into());
            shard.order.push_back(key);
            shard.entries.insert(
                key,
                ConnEntry {
                    bucket: TokenBucket::new(1.0, 1, now),
                    active: 1,
                    last_seen: now,
                },
            );
        }
        shard
            .entries
            .get_mut(&IpAddr::V4((inactive_at as u32 + 1).into()))
            .unwrap()
            .active = 0;

        let calls = Cell::new(0);
        let evicted = evict_one(&mut shard, |entry: &ConnEntry| {
            calls.set(calls.get() + 1);
            entry.active == 0
        });

        assert!(!evicted);
        assert_eq!(calls.get(), EVICTION_SCAN_LIMIT);
        assert_eq!(shard.entries.len(), inactive_at + 1);
    }

    #[test]
    fn rate_limiter_denies_after_burst() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 0.1,
            per_ip_burst: 2,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 1024,
            ..HttpLimitConfig::default()
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
    fn rate_limiter_bucket_consume_fails_closed_when_entry_missing() {
        let mut shard = LimiterShard::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        assert!(!consume_rate_bucket(&mut shard, &ip));

        shard.entries.insert(
            ip,
            IpBucket {
                bucket: TokenBucket::new(1.0, 1, Instant::now()),
                last_seen: Instant::now(),
            },
        );

        assert!(consume_rate_bucket(&mut shard, &ip));
    }

    #[test]
    fn rate_limiter_aggregates_ipv6_prefix_by_default() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 0.000001,
            per_ip_burst: 1,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 1024,
            ..HttpLimitConfig::default()
        };
        let limiter = RateLimiter::new(&cfg);
        let first: IpAddr = "2001:db8:1::1".parse().unwrap();
        let same_prefix: IpAddr = "2001:db8:1::2".parse().unwrap();
        let different_prefix: IpAddr = "2001:db8:2::1".parse().unwrap();

        assert!(limiter.check(first).allowed);
        let denied = limiter.check(same_prefix);
        assert!(!denied.allowed);
        assert_eq!(denied.reason, Some(LimitReason::PerIpRate));
        assert!(limiter.check(different_prefix).allowed);
    }

    #[test]
    fn rate_limiter_keeps_ipv4_exact_by_default() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 0.000001,
            per_ip_burst: 1,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 1024,
            ..HttpLimitConfig::default()
        };
        let limiter = RateLimiter::new(&cfg);
        let first: IpAddr = "198.51.100.1".parse().unwrap();
        let neighbor: IpAddr = "198.51.100.2".parse().unwrap();

        assert!(limiter.check(first).allowed);
        assert!(limiter.check(neighbor).allowed);
    }

    #[test]
    fn rate_limiter_aggregates_configured_ipv4_prefix() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 0.000001,
            per_ip_burst: 1,
            ipv4_prefix_len: 24,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 1024,
            ..HttpLimitConfig::default()
        };
        let limiter = RateLimiter::new(&cfg);
        let first: IpAddr = "198.51.100.1".parse().unwrap();
        let same_prefix: IpAddr = "198.51.100.2".parse().unwrap();
        let different_prefix: IpAddr = "198.51.101.1".parse().unwrap();

        assert!(limiter.check(first).allowed);
        assert_eq!(
            limiter.check(same_prefix).reason,
            Some(LimitReason::PerIpRate)
        );
        assert!(limiter.check(different_prefix).allowed);
    }

    #[test]
    fn per_ip_denied_requests_do_not_consume_global_tokens() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 0.000001,
            per_ip_burst: 1,
            global_rps: 0.000001,
            global_burst: 2,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RateLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        assert!(limiter.check(first_ip).allowed);
        let denied = limiter.check(first_ip);
        assert!(!denied.allowed);
        assert_eq!(denied.reason, Some(LimitReason::PerIpRate));

        let second = limiter.check(second_ip);
        assert!(
            second.allowed,
            "a per-IP-denied request must not burn the remaining global token"
        );
    }

    #[test]
    fn rate_limiter_denies_new_active_bucket_at_tracked_ip_cap() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: SHARDS,
            ..HttpLimitConfig::default()
        };
        let limiter = RateLimiter::new(&cfg);
        let ips = same_shard_ips(2);

        assert!(limiter.check(ips[0]).allowed);
        let denied = limiter.check(ips[1]);
        assert!(!denied.allowed);
        assert_eq!(denied.reason, Some(LimitReason::PerIpRate));

        let shard = limiter.shards[shard_for(ips[0])].lock().unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert!(shard.entries.contains_key(&ips[0]));
        assert!(!shard.entries.contains_key(&ips[1]));
    }

    #[test]
    fn trusted_proxy_aggregate_limiter_uses_dedicated_threshold_without_global_tokens() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 0.000001,
            per_ip_burst: 1,
            global_rps: 0.000001,
            global_burst: 1,
            trusted_proxy_rps: 0.000001,
            trusted_proxy_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RateLimiter::trusted_proxy_aggregate(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        assert!(limiter.check(first_ip).allowed);
        assert_eq!(limiter.check(first_ip).reason, Some(LimitReason::PerIpRate));
        assert!(
            limiter.check(second_ip).allowed,
            "trusted-proxy aggregate limiter must not consume normal global tokens"
        );
    }

    #[test]
    fn trusted_proxy_aggregate_rate_limiter_keeps_ipv6_peers_exact() {
        let cfg = HttpLimitConfig {
            trusted_proxy_rps: 0.000001,
            trusted_proxy_burst: 1,
            ipv6_prefix_len: 64,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RateLimiter::trusted_proxy_aggregate(&cfg);
        let first_proxy: IpAddr = "2001:db8:1::1".parse().unwrap();
        let second_proxy_same_prefix: IpAddr = "2001:db8:1::2".parse().unwrap();

        assert!(limiter.check(first_proxy).allowed);
        assert!(
            limiter.check(second_proxy_same_prefix).allowed,
            "trusted-proxy aggregate rate limits must key exact immediate peer IPs"
        );
    }

    #[test]
    fn connection_limiter_tracks_active_connections() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 100.0,
            per_ip_connect_burst: 100,
            max_connections: 10,
            max_connections_per_ip: 1,
            max_tracked_ips: 64,
            ..TcpLimitConfig::default()
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

    #[test]
    fn connection_limiter_aggregates_ipv6_prefix_by_default() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 100.0,
            per_ip_connect_burst: 100,
            max_connections: 10,
            max_connections_per_ip: 1,
            max_tracked_ips: 64,
            ..TcpLimitConfig::default()
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let first: IpAddr = "2001:db8:1::1".parse().unwrap();
        let same_prefix: IpAddr = "2001:db8:1::2".parse().unwrap();
        let permit = limiter.try_acquire(first).unwrap();

        assert_eq!(
            limiter.try_acquire(same_prefix).unwrap_err(),
            LimitReason::PerIpConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(same_prefix).is_ok());
    }

    #[test]
    fn connection_limiter_evicts_inactive_entry_at_tracked_ip_cap() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 100.0,
            per_ip_connect_burst: 100,
            max_connections: 10,
            max_connections_per_ip: 10,
            max_tracked_ips: SHARDS,
            ..TcpLimitConfig::default()
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let ips = same_shard_ips(2);

        drop(limiter.try_acquire(ips[0]).unwrap());
        assert!(limiter.try_acquire(ips[1]).is_ok());

        let shard = limiter.shards[shard_for(ips[0])].lock().unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert!(!shard.entries.contains_key(&ips[0]));
        assert!(shard.entries.contains_key(&ips[1]));
    }

    #[test]
    fn connection_limiter_denies_new_entry_when_shard_is_full_of_active_entries() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 100.0,
            per_ip_connect_burst: 100,
            max_connections: 10,
            max_connections_per_ip: 10,
            max_tracked_ips: SHARDS,
            ..TcpLimitConfig::default()
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let ips = same_shard_ips(2);

        let permit = limiter.try_acquire(ips[0]).unwrap();
        assert_eq!(
            limiter.try_acquire(ips[1]).unwrap_err(),
            LimitReason::GlobalConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(ips[1]).is_ok());
    }

    #[test]
    fn connection_limiter_enforces_global_connections() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 100.0,
            per_ip_connect_burst: 100,
            max_connections: 1,
            max_connections_per_ip: 10,
            max_tracked_ips: 64,
            ..TcpLimitConfig::default()
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();
        let permit = limiter.try_acquire(first_ip).unwrap();
        assert_eq!(
            limiter.try_acquire(second_ip).unwrap_err(),
            LimitReason::GlobalConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(second_ip).is_ok());
    }

    #[test]
    fn connection_limiter_enforces_global_connect_rate() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 0.0,
            per_ip_connect_burst: 1,
            global_connects_per_second: 0.000001,
            global_connect_burst: 1,
            max_connections: 10,
            max_connections_per_ip: 10,
            max_tracked_ips: 64,
            ..TcpLimitConfig::default()
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        drop(limiter.try_acquire(first_ip).unwrap());
        assert_eq!(
            limiter.try_acquire(second_ip).unwrap_err(),
            LimitReason::GlobalRate
        );
    }

    #[test]
    fn per_ip_denied_tcp_connections_do_not_consume_global_connect_tokens() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 0.000001,
            per_ip_connect_burst: 1,
            global_connects_per_second: 0.000001,
            global_connect_burst: 2,
            max_connections: 10,
            max_connections_per_ip: 10,
            max_tracked_ips: 64,
            ..TcpLimitConfig::default()
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        drop(limiter.try_acquire(first_ip).unwrap());
        assert_eq!(
            limiter.try_acquire(first_ip).unwrap_err(),
            LimitReason::PerIpRate
        );
        assert!(limiter.try_acquire(second_ip).is_ok());
    }

    #[test]
    fn globally_full_tcp_connections_do_not_consume_per_ip_connect_tokens() {
        let cfg = TcpLimitConfig {
            per_ip_connects_per_second: 0.000001,
            per_ip_connect_burst: 1,
            global_connects_per_second: 0.0,
            global_connect_burst: 1,
            max_connections: 1,
            max_connections_per_ip: 10,
            max_tracked_ips: 64,
            ..TcpLimitConfig::default()
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        let permit = limiter.try_acquire(first_ip).unwrap();
        assert_eq!(
            limiter.try_acquire(second_ip).unwrap_err(),
            LimitReason::GlobalConnections
        );
        drop(permit);
        assert!(
            limiter.try_acquire(second_ip).is_ok(),
            "a globally-denied TCP open must not burn that client's per-IP token"
        );
    }

    #[test]
    fn http_connection_limiter_enforces_per_ip_connections() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 10,
            max_connections_per_ip: 1,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = HttpConnectionLimiter::new(&cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let permit = limiter.try_acquire(ip).unwrap();
        assert_eq!(
            limiter.try_acquire(ip).unwrap_err(),
            LimitReason::PerIpConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(ip).is_ok());
    }

    #[test]
    fn http_connection_limiter_aggregates_ipv6_prefix_by_default() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 10,
            max_connections_per_ip: 1,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = HttpConnectionLimiter::new(&cfg);
        let first: IpAddr = "2001:db8:1::1".parse().unwrap();
        let same_prefix: IpAddr = "2001:db8:1::2".parse().unwrap();
        let permit = limiter.try_acquire(first).unwrap();

        assert_eq!(
            limiter.try_acquire(same_prefix).unwrap_err(),
            LimitReason::PerIpConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(same_prefix).is_ok());
    }

    #[test]
    fn http_connection_limiter_evicts_inactive_entry_at_tracked_ip_cap() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 10,
            max_connections_per_ip: 10,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: SHARDS,
            ..HttpLimitConfig::default()
        };
        let limiter = HttpConnectionLimiter::new(&cfg);
        let ips = same_shard_ips(2);

        drop(limiter.try_acquire(ips[0]).unwrap());
        assert!(limiter.try_acquire(ips[1]).is_ok());

        let shard = limiter.shards[shard_for(ips[0])].lock().unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert!(!shard.entries.contains_key(&ips[0]));
        assert!(shard.entries.contains_key(&ips[1]));
    }

    #[test]
    fn http_connection_limiter_enforces_global_connections() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 1,
            max_connections_per_ip: 10,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = HttpConnectionLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();
        let permit = limiter.try_acquire(first_ip).unwrap();
        assert_eq!(
            limiter.try_acquire(second_ip).unwrap_err(),
            LimitReason::GlobalConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(second_ip).is_ok());
    }

    #[test]
    fn globally_full_http_connections_do_not_track_denied_clients() {
        let cfg = HttpLimitConfig {
            per_ip_connects_per_second: 100.0,
            per_ip_connect_burst: 100,
            global_connects_per_second: 0.0,
            global_connect_burst: 1,
            max_connections: 1,
            max_connections_per_ip: 10,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = HttpConnectionLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        let permit = limiter.try_acquire(first_ip).unwrap();
        assert_eq!(
            limiter.try_acquire(second_ip).unwrap_err(),
            LimitReason::GlobalConnections
        );

        let second_key = normalize_ip(second_ip, cfg.ipv4_prefix_len, cfg.ipv6_prefix_len);
        let shard = limiter.shards[shard_for(second_key)].lock().unwrap();
        assert!(
            !shard.entries.contains_key(&second_key),
            "globally-denied HTTP opens should not create per-client state"
        );
        drop(shard);
        drop(permit);
    }

    #[test]
    fn http_connection_limiter_enforces_per_ip_connect_rate() {
        let cfg = HttpLimitConfig {
            per_ip_connects_per_second: 0.000001,
            per_ip_connect_burst: 1,
            global_connects_per_second: 0.0,
            global_connect_burst: 1,
            max_connections: 10,
            max_connections_per_ip: 10,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = HttpConnectionLimiter::new(&cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        drop(limiter.try_acquire(ip).unwrap());
        assert_eq!(limiter.try_acquire(ip).unwrap_err(), LimitReason::PerIpRate);
    }

    #[test]
    fn http_connection_limiter_enforces_global_connect_rate() {
        let cfg = HttpLimitConfig {
            per_ip_connects_per_second: 0.0,
            per_ip_connect_burst: 1,
            global_connects_per_second: 0.000001,
            global_connect_burst: 1,
            max_connections: 10,
            max_connections_per_ip: 10,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = HttpConnectionLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        drop(limiter.try_acquire(first_ip).unwrap());
        assert_eq!(
            limiter.try_acquire(second_ip).unwrap_err(),
            LimitReason::GlobalRate
        );
    }

    #[test]
    fn per_ip_denied_http_connections_do_not_consume_global_connect_tokens() {
        let cfg = HttpLimitConfig {
            per_ip_connects_per_second: 0.000001,
            per_ip_connect_burst: 1,
            global_connects_per_second: 0.000001,
            global_connect_burst: 2,
            max_connections: 10,
            max_connections_per_ip: 10,
            max_in_flight_requests: 0,
            max_in_flight_requests_per_ip: 0,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = HttpConnectionLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        drop(limiter.try_acquire(first_ip).unwrap());
        assert_eq!(
            limiter.try_acquire(first_ip).unwrap_err(),
            LimitReason::PerIpRate
        );
        assert!(limiter.try_acquire(second_ip).is_ok());
    }

    #[test]
    fn request_concurrency_limiter_enforces_per_ip_in_flight() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 10,
            max_in_flight_requests_per_ip: 1,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RequestConcurrencyLimiter::new(&cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let permit = limiter.try_acquire(ip).unwrap();
        assert_eq!(
            limiter.try_acquire(ip).unwrap_err(),
            LimitReason::PerIpConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(ip).is_ok());
    }

    #[test]
    fn request_concurrency_limiter_aggregates_ipv6_prefix_by_default() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 10,
            max_in_flight_requests_per_ip: 1,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RequestConcurrencyLimiter::new(&cfg);
        let first: IpAddr = "2001:db8:1::1".parse().unwrap();
        let same_prefix: IpAddr = "2001:db8:1::2".parse().unwrap();
        let permit = limiter.try_acquire(first).unwrap();

        assert_eq!(
            limiter.try_acquire(same_prefix).unwrap_err(),
            LimitReason::PerIpConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(same_prefix).is_ok());
    }

    #[test]
    fn request_concurrency_limiter_evicts_inactive_entry_at_tracked_ip_cap() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 10,
            max_in_flight_requests_per_ip: 10,
            max_tracked_ips: SHARDS,
            ..HttpLimitConfig::default()
        };
        let limiter = RequestConcurrencyLimiter::new(&cfg);
        let ips = same_shard_ips(2);

        drop(limiter.try_acquire(ips[0]).unwrap());
        assert!(limiter.try_acquire(ips[1]).is_ok());

        let shard = limiter.shards[shard_for(ips[0])].lock().unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert!(!shard.entries.contains_key(&ips[0]));
        assert!(shard.entries.contains_key(&ips[1]));
    }

    #[test]
    fn request_concurrency_limiter_enforces_global_in_flight() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 1,
            max_in_flight_requests_per_ip: 10,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RequestConcurrencyLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();
        let permit = limiter.try_acquire(first_ip).unwrap();
        assert_eq!(
            limiter.try_acquire(second_ip).unwrap_err(),
            LimitReason::GlobalConnections
        );
        drop(permit);
        assert!(limiter.try_acquire(second_ip).is_ok());
    }

    #[test]
    fn globally_full_request_concurrency_does_not_track_denied_clients() {
        let cfg = HttpLimitConfig {
            per_ip_rps: 100.0,
            per_ip_burst: 100,
            global_rps: 0.0,
            global_burst: 1,
            max_connections: 0,
            max_connections_per_ip: 0,
            max_in_flight_requests: 1,
            max_in_flight_requests_per_ip: 10,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RequestConcurrencyLimiter::new(&cfg);
        let first_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let second_ip: IpAddr = "127.0.0.2".parse().unwrap();

        let permit = limiter.try_acquire(first_ip).unwrap();
        assert_eq!(
            limiter.try_acquire(second_ip).unwrap_err(),
            LimitReason::GlobalConnections
        );

        let second_key = normalize_ip(second_ip, cfg.ipv4_prefix_len, cfg.ipv6_prefix_len);
        let shard = limiter.shards[shard_for(second_key)].lock().unwrap();
        assert!(
            !shard.entries.contains_key(&second_key),
            "globally-denied in-flight requests should not create per-client state"
        );
        drop(shard);
        drop(permit);
    }

    #[test]
    fn trusted_proxy_concurrency_limiter_tracks_peer_without_global_cap() {
        let cfg = HttpLimitConfig {
            max_in_flight_requests: 1,
            max_in_flight_requests_per_ip: 10,
            trusted_proxy_max_in_flight_requests: 1,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RequestConcurrencyLimiter::trusted_proxy_aggregate(&cfg);
        let first_proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let second_proxy: IpAddr = "127.0.0.2".parse().unwrap();

        let permit = limiter.try_acquire(first_proxy).unwrap();
        assert_eq!(
            limiter.try_acquire(first_proxy).unwrap_err(),
            LimitReason::PerIpConnections
        );
        assert!(
            limiter.try_acquire(second_proxy).is_ok(),
            "trusted-proxy in-flight cap must be per peer, not process-global"
        );
        drop(permit);
        assert!(limiter.try_acquire(first_proxy).is_ok());
    }

    #[test]
    fn trusted_proxy_concurrency_limiter_keeps_ipv6_peers_exact() {
        let cfg = HttpLimitConfig {
            max_in_flight_requests: 1,
            max_in_flight_requests_per_ip: 10,
            trusted_proxy_max_in_flight_requests: 1,
            ipv6_prefix_len: 64,
            max_tracked_ips: 64,
            ..HttpLimitConfig::default()
        };
        let limiter = RequestConcurrencyLimiter::trusted_proxy_aggregate(&cfg);
        let first_proxy: IpAddr = "2001:db8:1::1".parse().unwrap();
        let second_proxy_same_prefix: IpAddr = "2001:db8:1::2".parse().unwrap();

        let permit = limiter.try_acquire(first_proxy).unwrap();
        assert!(
            limiter.try_acquire(second_proxy_same_prefix).is_ok(),
            "trusted-proxy aggregate concurrency must key exact immediate peer IPs"
        );
        drop(permit);
        assert!(limiter.try_acquire(first_proxy).is_ok());
    }
}
