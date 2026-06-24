# Full Codebase Review

## Goal
Perform a comprehensive, evidence-based review of the entire AlturaProt codebase (Rust proxy core, Python tools and analyzers, configuration, documentation, benchmarks, and integration surfaces) to identify correctness, safety, security, maintainability, architectural fidelity, and test coverage issues. Prioritize hot-path safety, defense correctness, loopback-only discipline, and separation of AI from critical path.

## Success criteria
- All source areas covered by dedicated packets with cited evidence (file:line).
- Key invariants verified (e.g., no AI in hot path, strict client IP handling, filter sanitization, loopback guards).
- Tests exercised where runnable; gaps identified.
- Risks, bugs, improvement opportunities documented with severity.
- Final report actionable, with prioritized recommendations.
- No workflow files committed; all artifacts local under .workflow/

## Current context
- Rust binary "altura-prot": hyper+tokio L7 reverse proxy + TCP proxy with token-bucket limits, static+adaptive filters, sharded state, JSONL telemetry.
- Python control plane: codexsdgate/analyzer for AI (or deterministic) generated filters from events.
- Strong safety culture in docs and code (loopback flood guards, out-of-band AI).
- Recent benchmarks and defense docs from 2026-06-18.
- Inline Rust tests + Python unittest for analyzer.
- Git baseline captured at start of run; local shell has no cargo/rustc toolchain (must use core server or local dev for full Rust verification).

## Constraints
- Cargo/rustc not available in this Grok Build shell env (limited PATH); heavy benches and `cargo test` / `cargo check` must be run on the `core` server (`ssh core`) per AGENTS.md or a machine with rustup.
- Python3 + unittest available.
- Do not generate real spoofed internet traffic or flood non-authorized targets. Local/loopback only.
- Review is strictly read-only; no source edits in this run. Any fix work requires new approval + separate packets.
- Respect project Agents.md: prefer extending existing bench/e2e harnesses.

## Risk level
medium (repo-wide audit of security-sensitive DDoS/L7 defense code with external AI provider surface, flood tooling, and telemetry; findings may surface recommendations that touch hot path or filter schema)

## Approval gates
None required for this read-only review pass (all packets are read-only inspection + local artifacts only). 
If follow-up implementation or codemod packets arise from findings, apply full approval gate policy before any destructive/broad change.

## Mode
delegated

## Work packets
- `01-rust-core`: read-only explorer packet covering Rust sources, hot path, sharded concurrency, filter/adaptive logic, proxies, signature/path handling, limiter, telemetry hooks, inline tests.
- `02-python-tools`: read-only explorer packet covering all Python tools (bench harness, flood client, analyzer/CodexSDGate, provider CLI, e2e runner), their safety logic, sanitization, tests.
- `03-config-docs`: read-only explorer packet covering example config, all documentation, README, AGENTS.md, and cross-checks against implemented behavior.
- `04-surfaces-risks`: read-only explorer packet covering attack surfaces, admin endpoints, client-IP/XFF parsing robustness, error paths, JSON/JSONL handling, dependency surface, runtime artifacts, benchmark results, and false-positive / completeness risks.

## Eval contract
Eval contract:
- Outcome: Evidence-backed review findings and actionable report. No behavioral changes or file mutations in this run.
- Shared surfaces: FilterRule/condition/action JSON schema (filter.rs + codex_analyzer.py), AttackEvent JSONL (telemetry.rs + analyzer), admin /__altura/{health,metrics} responses, client IP resolution contract (http_proxy), request_signature / path_shape, limit decisions.
- Required checks: Python analyzer tests must pass; hot-path contains zero AI/provider calls; loopback guards present and enforced in flood/bench scripts; mutex poisoning handled consistently; signature normalization and filter matching tests exist and cover key cases.
- Blocking conditions: N/A (read-only; parent will manually cross-verify high-claims via source reads).
- Handoff evidence: N/A for pure review packets.

## Integration policy
Parent owns:
- Read every results/*.md
- Re-inspect cited files/lines with read_file + grep to validate claims (reject evidence-free assertions).
- Cross-reference shared surfaces (schemas, contracts) across packets.
- Collate into integration.md (accepted/rejected findings, decisions).
- Produce final-report.md + update state.json.
- Run local verification (py tests, manual checklist from OPERATIONS hardening).
- Explicitly call out any files/areas not covered and why.
- Never paste raw subagent output as final answer.

## Verification plan
Low/medium risk checks:
- Run `PYTHONPATH=tools python3 -m unittest tools.test_ai_tools -v` (must pass).
- Grep/read for "AI", "codex", "openai", provider calls inside src/ (must find zero in hot path).
- Grep for loopback / assert_loopback / non-loopback guard in tools/.
- Inspect all #[test] / unittest coverage and gaps.
- Read OPERATIONS.md hardening checklist and manually map to code locations.
- cargo test / cargo check / cargo build --release: skipped in this env (toolchain absent); document command to run on core or dev rust machine. Optional: if ssh core succeeds non-interactively, attempt remote verification (non-blocking).
- For high-risk claims (e.g. header parsing, path shape edge cases), re-execute the relevant unit tests manually via code inspection or targeted python if applicable.
- Final audit: re-read plan.md, orchestration.md, state.json, all packet results; confirm deliverables; mark checks pass/fail/skipped with reason.

## Completion criteria
- 4 packets reach "complete" status with concrete evidence (paths + line numbers or command output).
- integration.md and final-report.md exist and are non-empty.
- state.json status=complete, verification.checks populated.
- Python tests verified locally.
- Remaining risks + next steps listed.
- All source tree files accounted for (or explicitly scoped out).

## Native subagent outcome (post-planning)
4 explore subagents were spawned in parallel (background) per delegated mode:
- task_ids: 019edc28-d343-..., 019edc28-e7ce-..., 019edc28-f902-..., 019edc29-0b8c-...
All 4 returned status "cancelled" after 34-51s runtime with no result files produced (tool calls ~17 for first). 
Concrete no-delegation reason: Native subagent primitive available and used, but all delegated explore packets were cancelled by the host/harness before completing (possible internal timeout, tool budget, or long-running read-only explorer limits in current Grok Build env). 
Fallback executed: parent session performed all packet work sequentially using native tools (read_file, grep, run_terminal_command with shell for any writes, list_dir). All workflow mutation continued to use only run_terminal_command (no write/search_replace). 
This is recorded here and in orchestration.md + state.json per skill rules.
