# Final report — DDoS Protection Review

## Outcome
**AlturaProt has a mature, defense-in-depth DDoS architecture** with layered HTTP/TCP controls, adaptive learning, bounded control path, and strong benchmark coverage. The system is production-viable behind edge controls, but has **three high-priority engineering gaps** (limiter eviction bypass, filter-before-rate-limit ordering, filter write-lock contention) and **deployment alignment issues** (systemd TasksMax, edge connlimit skew, TCP min-rate defaults).

## What changed
- Created workflow artifacts at `.workflow/ultracode/ddos-protection-review-20260622/`
- No source code changes (read-only audit)

## Verification
| Check | Status | Evidence |
|-------|--------|----------|
| `cargo test --lib` | **pass** | 294 passed, 0 failed |
| Architecture cross-check | **pass** | Findings align with `docs/ARCHITECTURE.md` |
| Spot-check top findings | **pass** | limiter.rs:820-838, http_proxy.rs:1131-1168, systemd:19 |
| Defense bench re-run | **skipped** | Heavy; relied on recent artifacts + explorer analysis |
| Live edge flood test | **skipped** | Requires root; template validation only |

## Final audit

### Critical / High findings (prioritized)

| # | Severity | Finding | Location |
|---|----------|---------|----------|
| 1 | **Critical** | Tracked-key eviction resets rate-limit buckets — rotation bypass | `src/limiter.rs:820-838` |
| 2 | **High** | Filter evaluation before per-request rate limits — CPU flood vector | `src/http_proxy.rs:1131-1168` |
| 3 | **High** | Path-shape adaptive activation on benign `observed` traffic | `src/adaptive.rs:120-134` |
| 4 | **High** | Filter `RwLock` write during activation/reload stalls evaluation | `src/filter.rs:439-446, 550-600` |
| 5 | **High** | `TasksMax=4096` undercuts configured 10k+ connection caps | `ops/systemd/altura-prot.service:19` |
| 6 | **High** | TCP default min data-rate disabled — slow-trickle holds slots | `src/config.rs:1802-1804` |
| 7 | **High** | No CI gate on deterministic defense benchmarks | No `.github/` workflows |

### Strengths
- Layered limits: connection-open → framing → signature/path-shape → per-IP/global → in-flight → upstream circuits
- Trusted-proxy aggregate caps prevent XFF rotation bypass (recent fix validated in benches)
- Last-good filter reload; bounded adaptive telemetry; hot path isolated from AI
- 60+ guardrail probes + 17 defense scenarios + 294 unit tests
- Edge templates (nftables/sysctl) align IPv6 `/64` with userspace

### Medium findings
- Keep-alive amplifies connection defenses when enabled
- IPv6 /64 aggregation causes shared-bucket false positives
- Body min-rate (512 B/s) can reject slow legitimate uploads
- Accept-then-reject burns FDs on connect floods
- Edge per-source connlimit (512) looser than userspace (128)
- Novel signatures cannot be filter-blocked until codex writes templates
- Benchmark `target_score` false negatives — use `effective_target_score`

## Skipped checks
- Full `run_defense_bench.py --preset all` re-run (time; recent artifacts sufficient)
- Live edge SYN/ICMP flood integration (root-required)

## Remaining risks
- Bandwidth exhaustion before userspace/edge rules matter
- Defense lag for novel attack shapes (seconds to minutes)
- Historical bench JSON pre-trusted-proxy-aggregate can mislead if not labeled

## Next useful step
1. Fix limiter eviction to not reset active buckets (or deny new keys when shard full)
2. Move lightweight rate limits before filter evaluation
3. Decouple `active_until` from filter rule-list write lock
4. Raise `TasksMax`; align edge connlimit; enable TCP min-rate on exposed services
5. Add CI job: `cargo test` + `test_ai_tools.py` + deterministic defense bench with `effective_target_score` assertions