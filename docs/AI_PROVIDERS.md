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

To intentionally learn from observed-only bursts during a controlled test, pass:

```bash
python3 tools/codexsdgate.py --learn-observed --once
```
