# AlturaProt

AlturaProt is a Rust Layer 7 reverse proxy prototype for defensive HTTP and raw TCP service protection. It keeps deterministic mitigation in the hot path and treats AI/Codex analysis as an optional out-of-band filter generator.

## What It Does

- HTTP/1 reverse proxy with per-client prefix, per-signature, per-path-shape route-family, trusted-proxy aggregate, and global token-bucket limits.
- Bounded rate-limiter state that evicts stale buckets but denies new active keys when a shard is full, so high-cardinality rotation cannot reset existing hot IP, signature, or path-shape buckets.
- HTTP method allowlist, Host header validation, bounded trusted `X-Forwarded-For` parsing, forwarded-header/client-IP spoof sanitization, normalized request-signature and path-shape rate caps that collapse long dynamic tokens plus high-confidence short tokens without merging version segments such as `/api/v1` and `/api/v2`, bounded sibling-churn limiting for short lowercase token rotation under one parent route, trusted-proxy aggregate rate and in-flight caps, downstream keep-alive disabled by default, downstream write timeout for slow readers, raw initial HTTP/1 header/framing validation with incremental delimiter scanning plus hard byte, per-field, and count caps, request framing validation, request content-encoding policy, default chunked request-body rejection with opt-in, default `Expect` rejection with opt-in `100-continue`, bounded `Range` request policy, default origin `Accept-Encoding` stripping with opt-in passthrough, connection-open rate caps, active connection caps, sharded `SO_REUSEPORT` accept sockets, in-flight upstream request caps, upstream connect timeout, path-shape-scoped passive upstream failure circuit breaker, per-connection request caps, request and upstream response header byte/field/count caps and timeouts, default-stripped HTTP trailers with opt-in capped forwarding, request/upstream body recent-window minimum data-rate guards, request body guardrails, and upstream response body guardrails.
- Rate-limited admin health checks and token-protected Prometheus metrics.
- Raw TCP proxy with per-client-prefix and global connection-rate limits, global/per-client-prefix concurrent-connection caps, sharded `SO_REUSEPORT` accept sockets, outbound connect timeout, idle timeout, optional per-direction minimum data-rate guard, and max connection duration.
- Runtime `RLIMIT_NOFILE` preflight and capacity validation so configured connection caps are backed by an explicit file-descriptor floor.
- Config preflight for the config file itself, DDoS-critical HTTP/TCP rate knobs, positive resource-capacity ceilings, Hyper HTTP/1 header-buffer floors and startup ceilings, header field-line ceilings, request metadata ceilings, trailer ceilings, forwarded-header parse ceilings, body-size ceilings, minimum data-rate byte-floor ceilings, header-read, HTTP stream/body, upstream connect, upstream idle-pool, TCP connect, and upstream response timeout ceilings, connection lifetime and per-connection request-count ceilings, event-log queue, rotation, backup-count, adaptive-window, filter TTL, runtime/static-filter, and limiter tracked-state ceilings, upstream failure circuit settings and ceilings, the HTTP method and Host allowlists, client-IP trusted-proxy settings, and admin control-plane settings, so oversized/non-regular config inputs or malformed values fail startup instead of exhausting startup memory, silently disabling protection, removing socket/metadata/concurrency bounds, silently raising too-low header byte caps, body byte caps, or accepting excessive header byte/field/count caps, accidentally stretching slowloris protection, slow upload/download protections, origin connect attempts, origin response waits, origin idle keep-alive retention, TCP upstream connect attempts, connection permit lifetimes, persistent-connection request budgets, or learned-filter activations into minutes, hours, days, or effectively unlimited work, turning event-log buffering or rotation, runtime filter reloads, learned-rule counts, adaptive detector windows, or tracked limiter state into excessive memory/filesystem/hot-path work, repeatedly hammering a failing origin path without a local shed window, making the failure circuit effectively unreachable, shedding origin-bound traffic for excessive open windows, generating malformed or huge `Allow` responses, doing unbounded request-target, trailer, Host, or trusted-proxy scans, silently falling back to weaker client-IP identity, moving control-plane endpoints, or accepting blank or oversized metrics tokens; `0` remains the explicit per-rate-bucket disable value and can disable optional minimum data-rate guards and the upstream idle connection pool.
- SIGINT/SIGTERM shutdown handling so service-manager stops enter the same listener-drain path as Ctrl-C.
- Static JSON filters for known bad HTTP patterns, plus bounded and validated static/runtime filter rules with compiled header/user-agent match data and snapshot-based rule evaluation on the request path.
- Adaptive learned filters that stay dormant, activate during matching floods through rolling token-bucket counters, reclaim idle signature/path-shape windows under capacity pressure, preserve recent evidence, and stop admitting fresh detector keys when a shard is full of recent windows.
- JSONL attack event logs for offline/nearline analysis, with bounded user-controlled fields, a bounded nonblocking queue capped at `8192` owned events, worker-side JSON serialization, bounded flush cadence, and byte/backup-count-capped rotation so event logging does not become request-path JSON formatting, backpressure, a high-rate disk flush, unbounded memory or disk growth, or excessive per-rotation filesystem work during floods.
- Optional CodexSDGate analyzer that converts attack logs into constrained adaptive filter rules using Codex SDK, OpenAI, Anthropic, or OpenRouter.
- Host-edge nftables/sysctl/systemd templates plus a validation preflight for L3/L4
  and service-manager backstops, including explicit size bounds on dynamic
  nftables SYN-rate and connection-limit sets and exemptions for essential
  ICMPv4/ICMPv6 control traffic.
- Local-only benchmark/flood script that refuses non-loopback targets by default.

## Quick Start

```bash
cargo test
cargo run --release -- --config configs/example.json
```

In another terminal, run an upstream:

```bash
python3 -m http.server 9000 --bind 127.0.0.1
```

Then test through the proxy:

```bash
curl http://127.0.0.1:8080/
python3 tools/run_local_bench.py --duration 10 --workers 64
```

## Codex Analyzer

The proxy never calls an AI provider on the request path. Adaptive signature and path-shape tracking windows are capped by `adaptive.max_signature_windows` and `adaptive.max_path_shape_windows`. Static filters are capped by `filters.max_static_filters`, and runtime filter reloads reject non-regular files while enforcing `filters.max_runtime_file_bytes` plus `filters.max_runtime_filters`, preserving the last good rules when a bad analyzer output appears. `adaptive.activation_ttl_seconds` and per-rule `ttl_seconds` must stay within `1..=86400`; activation also clamps unvalidated in-memory TTLs before `Instant` arithmetic. Static and runtime rules must have a bounded, non-empty matcher and a bounded `block` action with a 4xx/5xx status; root-wide `path_prefix: "/"` filters are rejected because they are too easy to fat-finger into a full-site block. Adaptive path-shape learning has no hardcoded benign route-family exemptions: catalog, login, product, and other common-looking routes use the same bounded windows as every other route family. Observed-only route-family pressure can emit bounded analyzer samples, but broad path-shape filter activation requires strong evidence such as deterministic rate-limit, trusted-proxy aggregate, filter, or body-guard denial. Loaded filters precompile header names and byte needles for case-insensitive user-agent/header checks, and each request computes derived path shape at most once while rules are evaluated. Request workers clone an immutable rule snapshot before scanning; adaptive activation updates per-rule atomic deadlines and reload swaps the snapshot, so learned-filter activation does not wait on long-running rule scans. The proxy truncates user-controlled attack-event fields before enqueueing, then queues owned events to a dedicated JSONL writer thread that performs serialization, file writes, flushes, and rotation; `adaptive.event_log_queue_capacity` must be `1..=8192`, and `altura_event_log_dropped` reports events discarded when the queue is saturated instead of blocking request workers. The first event is flushed immediately, burst flushes are bounded by positive `adaptive.event_log_flush_interval_ms` (`100` ms by default), and disk growth plus rotation work are bounded by positive `adaptive.event_log_max_bytes` plus `1..=128` `adaptive.event_log_backup_count` numbered backups. CodexSDGate reads the active log plus rotated backups and writes `runtime/filters.json`.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install openai-codex
python3 tools/ai_provider_cli.py login codex
python3 tools/codexsdgate.py --events runtime/attack_events.jsonl --filters runtime/filters.json --once
```

If the selected provider is unavailable, the analyzer falls back to a deterministic signature-based rule generator. See [AI providers](docs/AI_PROVIDERS.md) for OpenAI, Anthropic, and OpenRouter setup.

## Mitigation Model

Availability is protected by deterministic controls first: token buckets, static filters, and learned adaptive signatures/path shapes. On normal HTTP traffic, exhausted request-rate buckets shed with `429` before static/runtime filter scans, while in-budget requests still reach the filter layer. Those controls run in the proxy and can start dropping matching traffic without depending on a wall-clock tumbling boundary. CodexSDGate is the precision layer: it learns narrow filters from telemetry so repeat attacks can be blocked quickly with fewer false positives.

For true volumetric attacks that saturate the network before the proxy can inspect traffic, use upstream/provider blackholing, scrubbing, CDN/anycast protection, or router ACLs. AlturaProt includes host-edge templates for smaller L3/L4 floods, but provider-side mitigation is still required when the link itself is saturated.

## Safety Notes

This is defensive software. The included flood script defaults to loopback-only targets; its non-loopback override is limited to owned private-LAN or link-local targets, and public IPs are refused. It is meant for local validation and capacity benchmarking, not internet traffic generation.

## More Docs

- [Architecture](docs/ARCHITECTURE.md)
- [AI providers and CodexSDGate](docs/AI_PROVIDERS.md)
- [Benchmarks](docs/BENCHMARKS.md)
- [Operations](docs/OPERATIONS.md)
- [Edge protection](docs/EDGE_PROTECTION.md)
