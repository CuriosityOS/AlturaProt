# Integration

## Accepted
- **Critical/High — Limiter eviction resets burst tokens** (01): Confirmed `evict_one(shard, |_| true)` at `src/limiter.rs:820-821`, `837-838`. Affects IP, signature, and path-shape limiters.
- **High — Filter before rate limits** (01): Confirmed ordering at `src/http_proxy.rs:1131` vs `1141-1168`.
- **High — Path-shape FP on observed traffic** (03): Confirmed `reason == "observed"` path at `src/adaptive.rs:120-134`; test at `adaptive.rs:600-640`.
- **High — Filter RwLock write contention** (03): Confirmed activation/reload write locks at `src/filter.rs:439-446`, `550-600`.
- **High — TasksMax vs connection caps** (02): Confirmed `TasksMax=4096` vs example 10k+10k connections.
- **High — TCP slow-trickle bypass** (02): Default min rate 0 confirmed; idle-only defense insufficient.
- **High — No CI defense gate** (04): No `.github/` workflows; manual bench runs only.
- **Medium findings** from all packets accepted with spot-checks.

## Rejected
- None — all explorer findings had file/line evidence.

## Conflicts
- None between packets.

## Decisions
1. Rank limiter eviction + filter ordering as top engineering fixes
2. Rank path-shape activation gating as top operational/tuning fix
3. Rank ops/systemd alignment as top deployment fix
4. Benchmark coverage is strong; gaps are operational (CI, edge live tests)

## Final changes
Read-only audit — no code changes.

## Verification still needed
- Load test: concurrent filter activation + reload with 512+ rules
- Edge integration test on `core` (optional, root-required)

## Remaining risks
- Link saturation before any host rules matter (acknowledged in ARCHITECTURE.md)
- Novel signature defense lag until codex writes templates (by design)
- Provider/CDN scrubbing not bench'd (operational layer)