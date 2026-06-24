# Result 03-config-docs: Configuration, documentation, README, architecture, benchmarks, agents notes

## Summary
Docs are high-quality, tightly coupled to the code, and emphasize safety. ARCHITECTURE.md is an accurate executive summary of the two-loop model and exactly matches implemented hot path (hyper accept, trusted XFF only, signature from 5 fields, 1s adaptive, dormant adaptive, token buckets, rewrite, tokio tcp copy+limits, sanitize allowlist). OPERATIONS hardening checklist is actionable and largely enforced by code/config defaults (explicit 127 listeners, admin token, trusted_proxies empty by default, SIGINT graceful, narrow static example). README quickstart is executable. BENCHMARKS + dated defense docs correctly describe the harnesses (run_local_bench, run_defense_bench) and stress loopback + "not maximum capacity". AGENTS.md rules are reflected in the py guards and preference for extending existing tools. Minor drifts: TLS is called out as missing (correctly); some dated bench numbers reference "pre-sync-lock removal" and "sharded + sync hot path" (aligns with current uncommitted M changes in filter/adaptive); no production config template or TLS example; "gpt-5.5" etc are forward-looking model names in defaults.

## Evidence
- Two loops (docs/ARCHITECTURE.md:3): exactly main.rs + codex_analyzer loop; hot path never calls AI (grep confirmed).
- HTTP bullet list (10-18): matches http_proxy:54 bind, 147 client_ip (XFF only if trusted, 257), 151 request_signature (filter), 166 observe, 168 evaluate, 178 limiter.check, 200 rewrite + 208 proxy.
- TCP (20-25): tcp_proxy:30 bind, 69 limiter try_acquire (conn rate + concurrent), 83 connect, 99 copy_bidir + timeout.
- Filter safety (27-31): py sanitize (codex_analyzer:427), Rust only implements the fields (rule_matches 337 lists exactly the condition keys), adaptive dormant until activate (filter:214, adaptive:85).
- False pos (33-39): signature preference in analyzer SYSTEM_PROMPT + det, static only wp in example, dormant, TTL, event log, blackhole as upstream.
- Hardening checklist (OPERATIONS:45-53) cross-map:
  - TLS: code has none (hyper http1 only, no tls feature); ops correctly says "add before internet".
  - Metrics admin token: http_proxy:386 checks x-altura-admin-token vs cfg.
  - Listeners explicit: example 127.0.0.1:*, code requires parse, default config fallback.
  - trusted_proxies before XFF: resolver 257 if not trusted return peer; default [] in ClientIpConfig + example.
  - Tune rps/thresh: defaults in config + example high for bench; adaptive 300.
  - TCP max dur: config + tcp_proxy:99.
  - SIGINT: main:93 tokio::signal::ctrl_c, shutdown watch to listeners (grace 5s + sleep2).
  - Static narrow: example has one /wp-login exact.
  - Review runtime after: docs say so; code writes them.
- Example.json (configs/): matches AppConfig (http optional, tcp vec, filters, adaptive); relative runtime resolved in from_path; admin_token present; trusted empty (good default).
- README quickstart: cargo run -- --config ..., python -m http.server 127, flood with loopback url. Matches code paths.
- Benchmarks run cmd: exactly matches run_local_bench.py:49-54 args + 148 Popen binary. Numbers note "python flood + upstream are bottlenecks" (honest).
- Defense docs: use run_defense_bench, local, XFF sim only, "Codex was not allowed to emit commands..."; matches analyzer SYSTEM_PROMPT and sanitize.
- AGENTS.md: "keep flood/spoof local", "prefer extending run_local_bench / local_http_flood / run_codexsdgate_e2e". Code: all py respect it; there are run_defense + e2e extensions. No new tooling added that bypasses.
- Untracked in git but present: AGENTS.md, some dated docs, run_defense_bench.py, benchmark_results/ - all reviewed here or in 04.

## Risks
- LOW: docs reference specific future models ("gpt-5.5", "claude-sonnet-4-6") in AI_PROVIDERS and defaults; if providers change names, drift. (Defaults are in code too.)
- LOW: no end-to-end "production deploy" example (TLS termination + private metrics + tuned limits + logrotate for jsonl + codexsdgate as systemd). OPERATIONS is local-focused.
- OBS: BENCHMARKS table has rows for "pre-sync-lock removal" and "sharded + sync hot path" - these describe states before/after the uncommitted M changes in this tree (filter/adaptive). Good that numbers are historical snapshots.
- No med/high: no false claims, no unsafe advice (blackhole correctly scoped to upstream).

## Verification run
- Example fields validated via python parse (listen 127, admin present, trusted=[], adaptive on, 1 static wp rule, runtime relative).
- 9 hardening items manually mapped to code locations (all supported or correctly caveated).
- Sampled defense/smart md:  loopback/XFF counts high; safety text present.
- Grep in docs for "TODO|FIXME|drift" : none critical.

## Open questions
- Should there be a configs/production.example.json with TLS comment, lower defaults, trusted_proxies placeholder, and notes on log management?
- Add a "TLS termination" section to OPERATIONS or AI_PROVIDERS with example nginx/caddy snippet + forward IP config?
- Version the model names or make them more abstract in docs?

## Recommended parent action
- Add a short "Production considerations" subsection to OPERATIONS or README (TLS, log rotation for jsonl/events, running codexsdgate as a service, capacity planning for tracked_ips).
- Consider git commit of the current uncommitted src/ + docs/BENCHMARKS changes (or .gitignore the workflow/ + results if intentional) before PRs; the sharded/sync and global observe are material to the latest bench snapshots.
- No urgent doc fixes; fidelity is excellent. Parent to ensure any follow-up code changes also update the matching doc bullets.
