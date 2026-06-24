# Result 03-adaptive-filters: Adaptive + Filters

## Summary
Two-loop model is sound with last-good reload and bounded telemetry. Primary risks: path-shape activation on benign observed traffic, filter RwLock write contention during activation/reload, defense lag until codex writes rule templates.

## Evidence
- Path-shape activates on observed only: `src/adaptive.rs:120-134`
- Filter write lock on activation: `src/filter.rs:550-600`
- Reload every 2s: `src/main.rs:73-84`
- Per-request observe on all allowed requests: `src/http_proxy.rs:1121`

## Handoff
- Summary: Decouple activation from rule-list write lock; gate path-shape activation on strong evidence
- Risks: Benign route FP (high), hot-path lock stalls (high)