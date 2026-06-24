# Packet 02-python-tools: Benchmark harness, flood client, CodexSDGate analyzer, provider CLI, e2e, tests

## Objective
Review all Python code for safety (especially loopback enforcement), correctness of deterministic fallback + AI filter generation, sanitization strength, merging/upsert logic for filters, provider abstraction, CLI usability, and quality of unit tests. Confirm the control plane never affects hot-path availability. Identify maintenance, security (key handling, prompt injection surface), or robustness issues.

## Context
- CodexSDGate (thin wrapper) + codex_analyzer.py is the only place that talks to AI providers.
- Runs out-of-band, reads attack_events.jsonl, writes filters.json (reloaded by Rust every N sec).
- Strong preference for narrow signature or path_shape adaptive filters; fallback deterministic.
- Sanitize aggressively; only allow listed condition keys + safe methods + bounded strings.
- Bench and flood scripts are the primary local validation tools; must stay safe by default.
- Provider config/secrets use 0600 files + env fallback.

## Sources
Inspect ONLY:
- tools/codexsdgate.py (entire - tiny)
- tools/codex_analyzer.py (entire, focus: 111-151 deterministic, 427-473 sanitize_filter, 476-493 merge_strong_coverage, 528-548 merge_existing, 551-582 analyze_once, 96-108 read_events, SYSTEM_PROMPT, post_json + response extractors)
- tools/ai_provider_cli.py (entire)
- tools/local_http_flood.py (entire, focus 43-66 assert_loopback, 84-117 worker, 126-170 main)
- tools/run_local_bench.py (entire)
- tools/run_codexsdgate_e2e.py (if exists; confirm)
- tools/run_defense_bench.py (if exists)
- tools/test_ai_tools.py (entire - 9 tests)

Nearby hops: only for imported stdlib or the exact functions called from these.

## Ownership
read-only

## Do
- Audit assert_loopback: does it catch all DNS, IPv6, non-loop, and require explicit flag? Any bypasses?
- Audit sanitize_filter: all attack surfaces (long strings, weird headers, injection in id, unicode, control chars).
- Audit merge logic: does it preserve old dormant rules, replace correctly, cap at max_filters, prefer recent?
- Verify deterministic fallback always produces adaptive signature rules (or path_shape) and never broad blocks.
- Check provider HTTP paths: auth, error handling, timeout, json extract robustness (markdown fences etc).
- Confirm no shell execution of untrusted data; no network in hot tools except provider calls (expected).
- Review test_ai_tools: coverage of merge, sanitize, observed vs strong, config; note any missing (e.g. path_shape in det, header sanitize).
- Trace e2e runner if present (run_codexsdgate_e2e.py) for how it drives full loop without real attacks.
- Check for secrets leakage in logs or error messages.

## Do not
- Call any AI provider or perform network logins.
- Run floods (even local) unless parent explicitly asks for a tiny verification.
- Edit code or provider configs.
- Review Rust or docs (defer to sibling packets).

## Expected output
- Summary of safety posture in tooling.
- Evidence: "tools/codex_analyzer.py:427: sanitize allows ... but misses X"
- Risks: prompt injection via events? key storage? filter merge causing priority inversion or filter exhaustion? loopback bypass?
- Gaps in unit tests.
- Recommended parent actions (e.g. "add test for long path_shape in sanitize", "harden error messages").

## Verification
Parent will:
- Re-execute the 9 unit tests.
- Grep for dangerous patterns (eval, exec, os.system, subprocess with unsanitized).
- Manually exercise sanitize via python one-liner for edge cases.

## Handoff format
N/A
