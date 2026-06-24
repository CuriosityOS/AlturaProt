# Orchestration

## Parent critical path
Create workflow artifacts → spawn 4 read-only explorers in parallel → integrate findings → run targeted verification → write final report

## Packets
| ID | Owner | Scope |
|----|-------|-------|
| 01-http-hot-path | read-only-agent | `src/http_proxy.rs`, `src/limiter.rs`, `src/listener.rs`, `src/resource_limits.rs` |
| 02-tcp-edge | read-only-agent | `src/tcp_proxy.rs`, `ops/`, listener/config |
| 03-adaptive-filters | read-only-agent | `src/adaptive.rs`, `src/filter.rs`, `src/config.rs`, control path |
| 04-benchmark-gaps | read-only-agent | `tools/`, `benchmark_results/`, `docs/BENCHMARKS.md` |

## Delegation
Native Task subagents, 4 parallel read-only explorers, wave 1 only

## Agents
- `[explorer] http-hot-path`
- `[explorer] tcp-edge`
- `[explorer] adaptive-filters`
- `[explorer] benchmark-gaps`

## Delegation limits
4 agents, 1 wave, no write-capable agents

## Wait points
After all 4 explorers return before integration

## Fallback
If delegation unavailable, execute packets sequentially in parent session

## Verification order
1. Integrate explorer findings
2. `cargo test` (lib modules)
3. Spot-check top 3 critical findings in source