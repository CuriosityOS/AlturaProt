# AI Providers And CodexSDGate

CodexSDGate is the control-plane analyzer. It reads `runtime/attack_events.jsonl` and writes `runtime/filters.json`.

## Configure Providers

```bash
python3 tools/ai_provider_cli.py init
python3 tools/ai_provider_cli.py status
python3 tools/ai_provider_cli.py login codex
python3 tools/ai_provider_cli.py select codex
```

Config is stored in `~/.config/altura-prot/providers.json`. Optional local secrets are stored in `~/.config/altura-prot/secrets.json` with mode `0600`. For public or server deployments, environment variables are preferred.

## Providers

Codex SDK:

```bash
pip install openai-codex
python3 tools/ai_provider_cli.py login codex
python3 tools/codexsdgate.py --once
```

The default Codex provider uses `gpt-5.5`, `reasoning_effort=high`, and `service_tier=fast`. The SDK maps `service_tier=fast` to Codex fast mode where the account/model supports it.

OpenAI API:

```bash
export OPENAI_API_KEY=...
python3 tools/ai_provider_cli.py login openai
python3 tools/codexsdgate.py --provider openai --once
```

Anthropic API:

```bash
export ANTHROPIC_API_KEY=...
python3 tools/ai_provider_cli.py login anthropic
python3 tools/codexsdgate.py --provider anthropic --once
```

OpenRouter API:

```bash
export OPENROUTER_API_KEY=...
python3 tools/ai_provider_cli.py login openrouter
python3 tools/codexsdgate.py --provider openrouter --once
```

## Runtime Contract

Providers can only suggest this sanitized filter shape:

```json
{
  "id": "codex-learned-example",
  "enabled": true,
  "adaptive": true,
  "priority": 100,
  "ttl_seconds": 60,
  "condition": {
    "signature": "request-signature"
  },
  "action": {
    "kind": "block",
    "status": 403,
    "body": "blocked by adaptive filter\n"
  }
}
```

The proxy ignores unsupported behavior. Providers cannot execute commands, change networking, or install firewall rules through this filter file.

## False Positive Controls

CodexSDGate defaults to high-confidence learning. Deterministic fallback rules are created from strong evidence such as `per_ip_rate_limited`, `global_rate_limited`, `signature_rate_limited`, `path_shape_rate_limited`, `trusted_proxy_rate_limited`, `rate_limited`, or `filter_block` events. Observed-only high volume is treated as weak evidence because legitimate traffic can also be bursty.

Provider output is also merged with deterministic coverage. In strict mode this adds high-confidence strong-signal signatures. When `--learn-observed` is explicitly enabled, it also adds deterministic observed-learning coverage so a model omission does not leave a known high-volume path shape unprotected. Use `--disable-strong-coverage` only when evaluating raw provider behavior.

Learned adaptive filters are preserved in `runtime/filters.json` even when there are no new attack events. This lets the proxy keep a dormant library of previous attack signatures and reactivate the same filter quickly when the pattern returns. Use `--max-filters` to cap the retained filter library size; the proxy also enforces `filters.max_runtime_file_bytes` and `filters.max_runtime_filters` during reload.

To intentionally learn from observed-only bursts during a controlled test, pass:

```bash
python3 tools/codexsdgate.py --learn-observed --once
```

## End-To-End Mitigation Test

Run loopback-only real-time scenarios with CodexSDGate in the control loop:

```bash
cargo build --release
python3 tools/run_codexsdgate_e2e.py --provider codex
```

For deterministic fallback testing without an AI provider:

```bash
python3 tools/run_codexsdgate_e2e.py --no-codex
```

To verify repeat-attack persistence, add `--verify-persistence`. The runner clears the event log after a filter is learned, lets CodexSDGate process a quiet interval, then replays the same attack pattern to confirm the dormant filter still reactivates.

The scenario runner tests a basic flood, cache-busting query flood, rotating numeric path flood, rotating UUID path flood, and mixed user-agent flood. It reports collection-phase statuses, replay-phase statuses, learned filters, event reasons, and the analyzer log tail.

Latest Codex SDK persistence run on `core` used `gpt-5.5`, `reasoning_effort=high`, and `service_tier=fast` with `--verify-persistence`.

| Scenario | Learned filters | Initial replay | Quiet repeated replay |
| --- | ---: | --- | --- |
| basic `/api/login` flood | 1 | `403: 5231`, `429: 11543`, `204: 135` | `403: 16673` |
| cachebuster query flood | 1 | `403: 10597`, `429: 4838`, `204: 102` | `403: 13089` |
| mixed user-agent flood | 4 | `403: 9464`, `429: 7588`, `204: 115` | `403: 16914` |
| rotating numeric path flood | 1 | `403: 10415`, `429: 5426`, `204: 108` | `403: 17062` |
