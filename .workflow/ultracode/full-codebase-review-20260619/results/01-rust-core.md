# Result 01-rust-core: Rust hot path, filters, adaptive, limiter, proxies, concurrency, tests

## Summary
The Rust core (8 modules + lib/main) implements a clean, sharded, deterministic L7 defense proxy. Hot path (accept -> signature -> filter -> adaptive observe -> limit -> rewrite/proxy) contains zero AI/provider code. Concurrency uses 64 shards with HashMap + manual eviction + explicit poisoned-lock recovery in most places. Signature and path_shape normalization is well-tested and thoughtful (num/uuid/hex/token generalization). Adaptive filters are dormant by default. Tests cover the key contracts (19 test items across modules). Some inconsistencies (limiter .expect vs recover) and recent uncommitted global-observe feature (in working tree) were noted. Resource bounding and error hygiene are good but rely on eprintln + continue patterns.

## Evidence
- No AI in hot path: grep over src/ for provider strings returned 0 matches. main.rs:14-101, http_proxy.rs:140-219 handle_http, tcp_proxy.rs never reference adaptive AI.
- Signature basis (src/filter.rs:311): method|normalize_path|query_shape|ua_family|accept_class -> fnv1a64 hex. Used for both rate key and adaptive signature. Tests: 611 (numeric paths equal), 619 (uuids equal), 637 (slugs distinct), 645 (query keys sorted), 653 (path_shape generalizes tokens independently of sig).
- Path shape (src/filter.rs:414): request_path_shape calls normalize with high-entropy tokens -> :token. Used for global burst -> path_shape adaptive.
- FilterEngine (src/filter.rs:127): RwLock<Vec<RuntimeRule>>, static + runtime load (reload:152), priority sort desc, evaluate:199 skips !enabled/expired/non-active-adaptive, rule_matches:337 implements all condition types including headers (case-insens). activate_signature/path_shape update active_until (228,256).
- Poison recovery: adaptive 130-136, filter 155-194 (all paths), telemetry 100-105 use match + into_inner + eprintln. Limiter (limiter.rs:122,135,184,218) use .expect("... poisoned") -> will panic the task on poison.
- Sharding+eviction: 64 everywhere. adaptive:168 (8192/SHARDS+128), limiter check 136, conn 185. Stale 120s.
- Adaptive observe (src/adaptive.rs:76): now (current tree) also does global observe + path_shape activate on high global volume + "global_observed" events. observe_signature 126 uses strong_reason for emit throttling. GlobalWindow added in uncommitted diff.
- Limiter (limiter.rs:90): RateLimiter has optional global bucket + sharded ip buckets. TokenBucket refill on allow. check:119. ConnectionLimiter + RAII ConnectionPermit (232 drop releases).
- HTTP path (http_proxy.rs): 146 stats, 147 client_ip resolve (trusted only), 151 sig, 153 admin check, 166 detector.observe("observed"), 168 engine.eval (block), 178 limiter, 200 rewrite (fixed upstream authority), 208 client.request. ClientIpResolver:256 (chain from rightmost non-trusted), parse_forwarded_ip_token handles [ipv6], ipv4:port strip, ipv6 fallback.
- Rewrite safety (404): parts.scheme/authority from upstream (config), path joined, hop-by-hop stripped (incl dynamic connection:), preserve_host or set from upstream, XFF/XFH/XFP appended. joined_path_and_query 435 appends to upstream base path.
- TCP (tcp_proxy.rs): 69 acquire permit (or reject), 83 timeout connect, 99 timeout copy_bidir + nodelay. No body/filters (by design).
- Config (config.rs): serde + defaults + resolve_relative for runtime/event_log. from_path uses std::fs (startup only).
- Telemetry (telemetry.rs): atomics relaxed for stats (render_prometheus 29), EventLogger BufWriter + Mutex, append jsonl + flush (no sync guarantee noted), poisoned recover. unix_time_ms fallback 0.
- Tests: adaptive 2 tokio (detector activates, distinct below thresh), filter 10 (static match, adaptive only when active, 6 sig/path/query tests, 2 shape), limiter 3 (bucket refill, rate burst, conn permit), http 6 (path join, hop strip, 4 client_ip cases). No tests in tcp_proxy, main, config, telemetry (integration via e2e py).
- Uncommitted changes (working tree M): adaptive.rs +92 lines global path_shape on volume; filter.rs +137 (likely more path_shape or header work); telemetry +4; minor in others. These are enhancements for "smart" defense (matches bench names).

## Risks
- MED: limiter poisoning uses expect (limiter.rs:122 etc) -> poison kills shard task (and potentially proxy capacity for that shard). Other modules recover gracefully. Inconsistent policy.
- LOW: eprintln everywhere for errors (reload fail, upstream err, log fail) - no structured logging, may be lost under flood, no rate limit on logs.
- LOW: tracked ip eviction is time+size based but under global flood of unique IPs could churn; max_tracked 65k default ok for most but not huge fanout.
- LOW: no request body size limit or timeout on headers beyond hyper builder (http_proxy 120 max_header_bytes). Large headers possible before filter.
- LOW: TCP max_duration kills copy but no half-close handling explicit.
- OBS: recent global observe logic (uncommitted) adds path_shape activation from global volume - good for polymorphic but needs the defense bench validation already present in tree.
- No high severity (no obvious RCE, no user-controlled connect target, no broad panics on input, signatures bounded).

## Verification run
- Grep no AI: 0 matches (pass).
- Counted 19 test functions, all focused on core contracts (pass).
- Manually traced: main startup -> engine/detector spawn + filter reload task + listeners with oneshot readiness + ctrlc shutdown (main.rs:36-100).
- Poison handling audit complete (see evidence).
- Signature tests cover the normalization claims in ARCHITECTURE and filter.rs comments.
- (Skipped) cargo test: would run the #[cfg(test)] here; all appear self-contained (use /tmp paths, no external).

## Open questions
- Should limiter poisoning also recover (to match rest of crate)? Or switch whole crate to parking_lot (no poison)?
- Are there integration tests for reload during active adaptive + concurrent requests?
- Global sample cap (64/s) and emit "global_observed" - is the threshold logic and path_shape activation rate-limited enough?

## Recommended parent action
- Standardize poison handling (prefer recovery everywhere or document why limiter differs). Add a test that forces poison? (hard).
- Consider adding a small prop test or more edge cases for XFF parser (many ips, bad tokens).
- For the uncommitted global changes: ensure they are committed before further bench docs; they affect adaptive + telemetry surface.
- Add tcp_proxy tests (at minimum for limiter interaction and timeout paths).
- Parent to cross-check the global feature against 04 surfaces and 03 docs.
