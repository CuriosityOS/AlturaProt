# Result 04-benchmark-gaps: Benchmark Coverage

## Summary
Strong layered coverage: 60+ local guardrails, 17 defense scenarios, 294 Rust unit tests. Gaps: no CI gate, edge defenses template-only, pre-trusted-proxy-aggregate XFF artifacts misleading, runtime max-connection-duration untested.

## Evidence
- Guardrails: `tools/run_local_bench.py:9916-10150`
- Pre-fix XFF 100% pass: `benchmark_results/defense_bench_advanced_codex_20260621_v2.json`
- Post-fix path-shape 98% limited: `defense_bench_path_shape_layer_20260622.json`
- `cargo test --lib`: 294 passed

## Handoff
- Summary: Add CI on deterministic defense bench; use effective_target_score for reporting
- Gaps: Live edge tests, CI gate, runtime duration probes