# AlturaProt

AlturaProt is a Rust Layer 7 reverse proxy prototype for defensive HTTP and raw TCP service protection. It keeps deterministic mitigation in the hot path and treats AI/Codex analysis as an optional out-of-band filter generator.

## What It Does

- HTTP/1 reverse proxy with per-IP and global token-bucket limits.
- Raw TCP proxy with connection-rate and concurrent-connection limits.
- Static JSON filters for known bad HTTP patterns.
- Adaptive learned filters that stay dormant, activate during matching floods, then expire.
- JSONL attack event logs for offline/nearline analysis.
- Optional CodexSDGate analyzer that converts attack logs into constrained adaptive filter rules using Codex SDK, OpenAI, Anthropic, or OpenRouter.
- Local-only benchmark/flood script that refuses non-loopback targets by default.

## Quick Start

```bash
cargo test
cargo run --release -- --config configs/example.json
```

In another terminal, run an upstream:

```bash
python3 -m http.server 9000 --bind 127.0.0.1
```

Then test through the proxy:

```bash
curl http://127.0.0.1:8080/
python3 tools/local_http_flood.py --url http://127.0.0.1:8080/ --duration 10 --workers 64
```

## Codex Analyzer

The proxy never calls an AI provider on the request path. It writes attack events to `runtime/attack_events.jsonl`. CodexSDGate reads those logs and writes `runtime/filters.json`.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install openai-codex
python3 tools/ai_provider_cli.py login codex
python3 tools/codexsdgate.py --events runtime/attack_events.jsonl --filters runtime/filters.json --once
```

If the selected provider is unavailable, the analyzer falls back to a deterministic signature-based rule generator. See [AI providers](docs/AI_PROVIDERS.md) for OpenAI, Anthropic, and OpenRouter setup.

## Mitigation Model

Availability is protected by deterministic controls first: token buckets, static filters, and learned adaptive signatures. Those controls run in the proxy and can start dropping matching traffic in the same one-second detection window. CodexSDGate is the precision layer: it learns narrow filters from telemetry so repeat attacks can be blocked quickly with fewer false positives.

For true volumetric attacks that saturate the network before the proxy can inspect traffic, use upstream/provider blackholing or scrubbing. A blackhole is cheaper than host firewall rules, but it is also blunt because it drops the blackholed traffic entirely.

## Safety Notes

This is defensive software. The included flood script defaults to loopback-only targets and should be used only against systems you own or are authorized to test. It is meant for local validation and capacity benchmarking, not internet traffic generation.

## More Docs

- [Architecture](docs/ARCHITECTURE.md)
- [AI providers and CodexSDGate](docs/AI_PROVIDERS.md)
- [Benchmarks](docs/BENCHMARKS.md)
- [Operations](docs/OPERATIONS.md)
