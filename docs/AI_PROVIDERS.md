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

CodexSDGate defaults to high-confidence learning. Deterministic fallback rules are created from strong evidence such as `per_ip_rate_limited`, `global_rate_limited`, `rate_limited`, or `filter_block` events. Observed-only high volume is treated as weak evidence because legitimate traffic can also be bursty.

Provider output is also merged with deterministic high-confidence signature coverage. This prevents a model from omitting a strong attack signature during a short real-time mitigation window. Use `--disable-strong-coverage` only when evaluating raw provider behavior.

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

The scenario runner tests a basic flood, cache-busting query flood, rotating numeric path flood, and mixed user-agent flood. It reports collection-phase statuses, replay-phase statuses, learned filters, event reasons, and the analyzer log tail.

Latest Codex SDK run on `core` used `gpt-5.5`, `reasoning_effort=high`, and `service_tier=fast`.

| Scenario | Learned filters | Replay result |
| --- | ---: | --- |
| basic `/api/login` flood | 1 | `403: 18200`, `429: 8624`, `204: 135` |
| cachebuster query flood | 1 | `403: 20438`, `429: 6489`, `204: 117` |
| mixed user-agent flood | 4 | `403: 18635`, `429: 6999`, `204: 123` |
| rotating numeric path flood | 1 | `403: 24290`, `429: 3204`, `204: 100` |
