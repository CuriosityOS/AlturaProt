# Packet 03-config-docs: Configuration, documentation, README, architecture, benchmarks, agents notes

## Objective
Verify that documentation accurately describes implemented behavior, that example config is valid and safe-by-default, that AGENTS.md and safety notes are followed in code, and that benchmark claims are reproducible from the harnesses. Find drift between docs and code, missing operational guidance, or outdated benchmark data.

## Context
- README claims specific quickstart and Codex flow.
- ARCHITECTURE.md defines the two-loop model and filter safety.
- OPERATIONS has hardening checklist.
- BENCHMARKS + dated defense md files record numbers from local runs.
- configs/example.json is the reference and default fallback.
- AGENTS.md constrains where heavy work runs and forbids real spoof traffic.

## Sources
- README.md (entire)
- configs/example.json (entire)
- docs/ARCHITECTURE.md (entire)
- docs/OPERATIONS.md (entire)
- docs/AI_PROVIDERS.md (entire)
- docs/BENCHMARKS.md (entire)
- docs/DEFENSE_BENCHMARK_20260618.md (scan for key claims + links)
- docs/SMART_DEFENSE_BENCHMARK_20260618.md (scan)
- AGENTS.md (entire)
- Any other *.md in docs/ or root.

## Ownership
read-only

## Do
- Parse example.json against config.rs deserialization rules (note defaults, aliases, relative paths).
- Walk every claim in ARCHITECTURE.md and OPERATIONS.md and cite code locations that implement (or contradict).
- Check README quickstart commands for accuracy (cargo run, python -m http.server, flood cmd).
- Verify benchmark harness numbers could be reproduced (see run_local_bench defaults vs recorded RPS).
- Check that dated defense bench docs reference the correct tools (run_defense_bench etc) and respect local-only.
- Confirm AGENTS.md rules are reflected in code (e.g. loopback asserts, no new bench tools without extending existing).
- Note any broken links, outdated versions (gpt-5.5 etc), or security advice not enforced in code.
- Look for "TODO", "FIXME", "XXX" in docs.

## Do not
- Deep dive implementation internals (that's 01/02/04).
- Run long benchmarks.
- Assume docs are source of truth; always prefer code.

## Expected output
- Table or list: doc section -> code support / drift / gap (with :line cites where possible).
- Risks: e.g. "OPERATIONS says X but code at Y allows Z".
- Completeness: missing sections (TLS example? production config template?).
- Recommended updates or clarifications.

## Verification
Parent will sample 5-10 claims with direct read_file + grep cross-check.

## Handoff format
N/A
