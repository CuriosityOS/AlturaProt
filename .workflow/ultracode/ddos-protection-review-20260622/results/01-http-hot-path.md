# Result 01-http-hot-path: HTTP Hot Path

## Summary
HTTP hot path has layered defenses from accept through upstream proxying. Primary weaknesses: tracked-key eviction resets rate buckets (rotation bypass), filter evaluation before rate limits (CPU flood), keep-alive amplifying connection defenses.

## Evidence
- Filter before rate limits: `src/http_proxy.rs:1131-1168`
- Eviction resets buckets: `src/limiter.rs:820-821`, `837-838`
- Connection-open limits at accept: `src/http_proxy.rs:354-377`
- In-flight permits held until body drop: `src/http_proxy.rs:2430-2459`

## Handoff
- Summary: Strong framing/upstream guards; fix limiter eviction and rate-limit ordering
- Changed surfaces: none (read-only)
- Risks: Cardinality rotation bypass (high), CPU exhaustion before rate limits (high)