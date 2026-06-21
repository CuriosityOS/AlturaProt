# Defense Benchmark 2026-06-18

Run target: `core` (`ubuntu-server`), loopback only.

Command:

```bash
.venv/bin/python tools/run_defense_bench.py --duration 2.0 --workers 48 --analyzer-wait 60 --json-only
```

Full JSON artifact: `benchmark_results/defense_bench_codex_20260618_interpreted.json`.

Safety model: no external targets and no packet-level source spoofing. Spoof cases use trusted-proxy `X-Forwarded-For` simulation from localhost, matching how the proxy consumes forwarded client IPs.

## Important Caveat

The CodexSDGate timing is for a temporary benchmark event log, not a huge production history. In this run each analyzer pass read a small local JSONL event file emitted by the active scenario and an empty temporary filter file, then wrote constrained filter JSON.

Codex was not allowed to emit commands, firewall rules, IP bans, or arbitrary code. It could only emit sanitized AlturaProt filter rules.

## Layer Scores

| Scenario | Direct RPS | Proxy-open RPS | Rate-limit allowed | Rate-limit 429 | Static blocked | Codex filters | Detect | Filter write | Replay blocked | Bypass allowed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| basic | 9384.15 | 9256.96 | 1.03% | 98.97% | 100.00% | 1 | 0.009s | 10.018s | 99.74% | 100.00% |
| cachebuster | 9374.22 | 9193.88 | 1.06% | 98.94% | 100.00% | 1 | 0.010s | 10.769s | 99.73% | 100.00% |
| mixed-user-agent | 9511.15 | 9288.35 | 1.04% | 98.96% | 100.00% | 4 | 0.016s | 14.024s | 99.29% | 100.00% |
| rotating-path | 9413.10 | 9075.37 | 1.03% | 98.97% | 100.00% | 1 | 0.010s | 12.020s | 99.74% | 100.00% |
| uuid-path | 9169.09 | 8865.63 | 1.07% | 98.93% | 100.00% | 1 | 0.010s | 11.521s | 99.73% | 100.00% |
| xff-rotating strict | 9333.46 | 9139.70 | 100.00% | 0.00% | 100.00% | 0 | 0.009s | n/a | 0.00% | n/a |
| xff-rotating observed-learning | 9333.46 | 9139.70 | 100.00% | 0.00% | 100.00% | 1 | 0.009s | 10.865s | 99.74% | 100.00% |
| xff-single strict | 9439.60 | 9135.74 | 1.05% | 98.95% | 100.00% | 1 | 0.009s | 8.514s | 99.74% | 100.00% |

## Learned Filters

None of the learned filters were IP-based. They were adaptive signature filters. A signature is AlturaProt's normalized request-shape fingerprint, derived from method, normalized path, query-key shape, user-agent family, and accept class.

| Scenario | Filter kind | Normalized basis |
| --- | --- | --- |
| basic | exact request shape | `GET|/api/login|none|curl|*/*` |
| cachebuster | normalized pattern | `GET|/api/search|cachebust,id|curl|*/*` |
| mixed-user-agent | exact request shape | `GET|/api/login|none|mozilla|*/*` |
| mixed-user-agent | exact request shape | `GET|/api/login|none|python|*/*` |
| mixed-user-agent | exact request shape | `GET|/api/login|none|node|*/*` |
| mixed-user-agent | exact request shape | `GET|/api/login|none|curl|*/*` |
| rotating-path | normalized pattern | `GET|/api/item/:num|view|curl|*/*` |
| uuid-path | normalized pattern | `GET|/api/object/:uuid|view|curl|*/*` |
| xff-rotating observed-learning | exact request shape | `GET|/api/login|none|curl|*/*` |
| xff-single strict | exact request shape | `GET|/api/login|none|curl|*/*` |

## Findings

- Proxy-open overhead was small in this Python-driven benchmark: roughly 2-3% below direct upstream for most scenarios.
- Deterministic per-IP limiting blocks normal single-source floods quickly, allowing about 1% through after burst.
- Rotating trusted `X-Forwarded-For` defeats per-IP rate limiting, as expected, because every request appears to come from a different client IP.
- Strict CodexSDGate does not learn from observed-only rotating-XFF floods. That is conservative and avoids teaching filters from normal high-volume traffic with no strong signal.
- `--learn-observed` lets CodexSDGate mitigate rotating-XFF spoof simulation by request pattern instead of IP address, blocking 99.74% on replay.
- Bypass probes with different benign request shapes were 100% allowed after learned filters, so these learned filters did not act as broad `/api/` blocks.

## Interpretation

Codex did not perform broad semantic malware analysis here. It recognized high-confidence telemetry groups and emitted narrow adaptive signature filters. The deeper part is mostly in AlturaProt's signature design: numeric IDs, UUIDs, and query values are normalized before hashing, so one filter covers a rotating-path/cachebuster pattern without blocking every path or IP.
