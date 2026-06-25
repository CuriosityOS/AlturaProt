# Contributing to AlturaProt

Thanks for your interest in improving AlturaProt! This document covers how to set
up, test, and submit changes.

## Development setup

You need a stable Rust toolchain (2021 edition) and Python 3 for the analyzer
tooling.

```bash
git clone https://github.com/CuriosityOS/AlturaProt
cd AlturaProt
cargo build
```

## Before you open a PR

Run the same checks CI runs and keep them green:

```bash
cargo fmt --check                              # formatting
cargo clippy --all-targets -- -D warnings      # lints (warnings are errors)
cargo test                                     # Rust unit/integration tests
PYTHONPATH=tools python3 tools/test_ai_tools.py  # analyzer + tooling tests
```

Guidelines:

- **Add or update tests** for any behavior you change — unit tests for the
  changed path, and end-to-end coverage when a change crosses runtime boundaries.
- Keep it **KISS and DRY**; match the style of the surrounding code.
- Update the relevant docs in [`docs/`](docs/) and the `README` when behavior or
  flags change.
- Open PRs against `main` as **ready for review** (not draft).
- Never commit secrets, tokens, or real attack telemetry.

## Safety rules for benchmarks and floods

This is defensive tooling. When working on the load/flood harnesses:

- Keep flood and spoof benchmarks **local-only** — loopback targets, or owned
  private-LAN / link-local hosts only. Public IPs are refused by design; do not
  remove that guard.
- Do not generate real spoofed internet traffic. Simulate spoofing with
  trusted-proxy / `X-Forwarded-For` headers and local test configs.
- Prefer extending the existing `tools/run_local_bench.py`,
  `tools/local_http_flood.py`, and `tools/run_codexsdgate_e2e.py` harnesses
  before adding new tooling.

## Reporting bugs and security issues

- Functional bugs: open an [issue](https://github.com/CuriosityOS/AlturaProt/issues/new/choose).
- Security vulnerabilities: follow [SECURITY.md](SECURITY.md) — please do not
  file them as public issues.

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
