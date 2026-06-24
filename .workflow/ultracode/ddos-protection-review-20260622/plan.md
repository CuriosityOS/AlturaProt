# DDoS Protection Review

## Goal
Audit AlturaProt's DDoS protection across HTTP hot path, TCP proxy, adaptive detection, edge ops, and benchmark coverage. Produce evidence-based findings with severity-ranked risks and actionable recommendations.

## Success criteria
- Map all rate-limit, connection-cap, framing, filter, and upstream-guard layers with file/line evidence
- Identify bypass vectors, false-positive risks, and config footguns
- Cross-check docs/benchmarks against implementation
- Deliver integrated final report with prioritized findings

## Current context
- Rust reverse proxy (AlturaProt) with HTTP/TCP paths, adaptive learning, static/runtime filters, CodexSDGate control loop
- Recent extensive defense benchmarks in `benchmark_results/`
- Prior full codebase review exists at `.workflow/ultracode/full-codebase-review-20260619/`

## Constraints
- Read-only audit; no code changes unless critical bug found
- No production deploy or external flood traffic
- Follow AGENTS.md: local/loopback benchmarks only

## Risk level
High — security-critical availability surface

## Approval gates
None required for read-only review

## Mode
Delegated — 4 parallel read-only explorers + parent integration

## Work packets
1. `01-http-hot-path` — HTTP accept, framing, rate limits, upstream guards
2. `02-tcp-edge` — TCP proxy, listener sharding, ops/ edge templates
3. `03-adaptive-filters` — adaptive detector, filter safety, control path
4. `04-benchmark-gaps` — bench harness coverage vs documented defenses

## Eval contract
- Outcome: Integrated DDoS protection audit with severity-ranked findings
- Shared surfaces: `src/http_proxy.rs`, `src/limiter.rs`, `src/filter.rs`, `src/adaptive.rs`, `src/tcp_proxy.rs`, `src/config.rs`, `ops/`, `tools/`
- Required checks: `cargo test` (targeted), cross-reference ARCHITECTURE.md
- Blocking conditions: None for read-only
- Handoff evidence: File paths, line numbers, benchmark result references

## Integration policy
Parent reconciles overlapping findings, dedupes, ranks by exploitability/impact, validates claims against source

## Verification plan
- Run `cargo test` on core modules
- Spot-check key guard implementations cited by explorers
- Compare findings against `docs/ARCHITECTURE.md` and `docs/BENCHMARKS.md`

## Completion criteria
- All 4 packet results integrated
- `final-report.md` with outcome, findings, verification, remaining risks