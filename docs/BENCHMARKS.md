# Benchmarks

Benchmarks are loopback-only on `core` using the release binary, a local fixed-response upstream, and `tools/local_http_flood.py`.

Run:

```bash
cargo build --release
python3 tools/run_local_bench.py --duration 8 --workers 128
```

Latest measured snapshot on 2026-06-18:

| Scenario | RPS | Statuses | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed upstream, pre-sync-lock removal | 12034.99 | `204: 96407` | 0 | 31.282 ms |
| admin health, pre-sync-lock removal | 11708.52 | `200: 93800` | 0 | 31.936 ms |
| proxied fixed upstream, sharded + sync hot path | 12070.70 | `204: 96693` | 0 | 30.994 ms |
| admin health, sharded + sync hot path | 11852.77 | `200: 94956` | 0 | 31.811 ms |

The Python flood client and Python upstream become bottlenecks around this range, so these numbers are useful for regression checks, not maximum capacity claims.
