# Agent Notes

- Heavy AlturaProt benchmarks should run on the `core` server (`ssh core`) when feasible.
- Keep flood and spoof benchmarks local-only: use loopback targets or controlled Core LAN-owned targets only.
- Do not generate real spoofed internet traffic. Simulate spoof behavior with trusted-proxy/X-Forwarded-For headers and local test configs.
- Prefer extending the existing `tools/run_local_bench.py`, `tools/local_http_flood.py`, and `tools/run_codexsdgate_e2e.py` harnesses before adding new tooling.
