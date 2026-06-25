# Agent Notes

## Installing AlturaProt non-interactively

`install.sh` is fully scriptable — every prompt has a flag and it auto-skips the
interactive AI step when there is no TTY. To install and wire AI in one command:

```bash
# install for the current user and auto-select whatever AI CLI/key is present
curl -fsSL https://raw.githubusercontent.com/CuriosityOS/AlturaProt/main/install.sh \
  | bash -s -- --user --ai auto --non-interactive
```

Use `--ai <provider>` to force one (`codex`/`claude`/`opencode`/`cursor`/`grok`
use that CLI's existing login; `openai`/`anthropic`/`gemini`/`openrouter` read
the matching `*_API_KEY` env var unless `--ai-key` is given). System install:
`sudo bash -s -- --start --ai auto --non-interactive`. See README "Install with
an agent" and docs/OPERATIONS.md.

## Benchmarks and safety

- Heavy AlturaProt benchmarks should run on the `core` server (`ssh core`) when feasible.
- Keep flood and spoof benchmarks local-only: use loopback targets or controlled Core LAN-owned targets only.
- Do not generate real spoofed internet traffic. Simulate spoof behavior with trusted-proxy/X-Forwarded-For headers and local test configs.
- Prefer extending the existing `tools/run_local_bench.py`, `tools/local_http_flood.py`, and `tools/run_codexsdgate_e2e.py` harnesses before adding new tooling.
