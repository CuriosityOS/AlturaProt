# Packet 01-rust-core: Rust hot path, filters, adaptive, limiter, proxies, concurrency, tests

## Objective
Inspect the Rust implementation for correctness of the defense mechanisms, concurrency safety (sharded mutexes, poisoning), signature/path normalization fidelity, filter evaluation and adaptive activation, rate/connection limiting, proxy request handling (HTTP + TCP), telemetry emission points, admin surface, and coverage/quality of inline tests. Verify the architectural invariant that AI never executes in the request hot path. Identify any bugs, races, resource leaks, or robustness gaps.

## Context
- Hot path must stay deterministic and fast (token buckets + filters in <1s window).
- Sharding (64) + per-shard HashMap + manual eviction for bounded memory.
- Consistent recovery from poisoned Mutex/RwLock (some .expect, some into_inner).
- Signature basis includes method|normalized_path|query_shape|ua_family|accept_class ; used for both rate and adaptive.
- Path shape generalizes high-entropy for adaptive without polluting signatures.
- Filters support static + runtime (reloaded) + dormant adaptive (activated on threshold).
- TCP path is simpler (no filters, only connection limiter).

## Sources
Inspect ONLY these unless one nearby hop needed for a call/trace:
- src/main.rs (entire)
- src/lib.rs (entire)
- src/filter.rs (entire, focus lines 199-403 rule_matches/evaluate/activate, 301-516 signatures/normalize)
- src/adaptive.rs (entire, focus 76-104 observe, 126-178 observe_signature, 245-353 tests)
- src/limiter.rs (entire, focus 119-149 check, 179-212 try_acquire, 251-301 tests)
- src/http_proxy.rs (entire, focus 140-219 handle_http, 256-281 resolve, 376-402 maybe_admin, 404-433 rewrite, 526-end tests)
- src/tcp_proxy.rs (entire)
- src/config.rs (entire)
- src/telemetry.rs (entire)
- Cargo.toml (deps + profiles)

One-hop allowed for: any direct use of http::*, tokio::*, serde in context of above.

## Ownership
read-only (no writes)

## Do
- Trace one full HTTP request from accept through filter -> detector -> limiter -> upstream rewrite -> response.
- Trace TCP accept through limiter permit -> connect -> copy.
- Audit all lock acquisitions for poisoning handling and deadlock potential.
- Audit signature_basis, request_path_shape, normalize_path_with for correctness on edge paths (/, /num, uuid, hex, long alnum, query, empty).
- Verify adaptive activation only happens for adaptive:true rules, on threshold, with TTL.
- Check test coverage: list every #[test] and what it asserts; note missing cases (e.g. global rate, XFF, shutdown, reload race).
- Look for panics, unwraps on user data, unbounded growth, integer overflow.
- Confirm zero provider/AI/LLM code paths reachable from main or handle_http / run_tcp_proxy.
- Note any use of unsafe, raw pointers, or FFI.

## Do not
- Edit any files.
- Run cargo/build that mutates (ok to note commands).
- Duplicate work of other packets (e.g. do not deep dive docs or py analyzer internals beyond cross calls).
- Exercise flood tools (parent will run targeted local checks).

## Expected output
- Summary of architecture fidelity to ARCHITECTURE.md.
- Evidence list: "src/foo.rs:123: <finding>"
- Risks (severity: low/med/high): races, correctness bugs, perf, security (e.g. header smuggling, IP spoof via XFF misconfig, path traversal in upstream rewrite?).
- Test gaps and recommended additional tests.
- Recommended parent action (e.g. "add test for global limiter eviction", "consider parking_lot or better poisoning policy").

## Verification
- Parent will re-read cited lines.
- Grep in parent for AI strings in src/.
- Re-run relevant unit tests via inspection (since no cargo); note any that would fail.

## Handoff format
N/A (independent review packet)
