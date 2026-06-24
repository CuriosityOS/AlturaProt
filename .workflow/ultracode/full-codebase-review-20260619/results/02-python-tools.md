# Result 02-python-tools: Benchmark harness, flood client, CodexSDGate analyzer, provider CLI, e2e, tests

## Summary
Python tooling (8 scripts) is safety-first and well-structured. The crown jewel is codex_analyzer.py + its 9 unit tests: strict schema enforcement, aggressive sanitize (length caps, allowlists, no broad actions), deterministic fallback always available, merge that preserves history while preferring new, atomic write. Flood and bench tools default to loopback (DNS-resolved) with explicit --allow flag and error messages. Harness (run_*) use tempdirs, high-limit configs for measurement, subprocess management with terminate+kill, no internet by construction. Provider CLI manages 0600 secrets + env. No exec of untrusted data. e2e and defense_bench extend the local-only model (XFF spoof sims only, explicit comments). Minor gaps: sanitize can emit "custom" sig if all conditions stripped; limited coverage of provider error paths and very long event files; no property tests on sanitize.

## Evidence
- Loopback enforcement (tools/local_http_flood.py:43): parses url, getaddrinfo + ipaddress.ip_address, refuses any !is_loopback unless flag; also in run_local_bench:119 (config always 127), run_codexsdgate_e2e:172, run_defense_bench:343 (and safety note at 773: "loopback-only; spoof cases use X-Forwarded-For headers from trusted localhost, not packet spoofing").
- Sanitize (codex_analyzer.py:427): only 7 condition keys (sig, paths, query, ua, headers); methods upper+whitelist to 6 verbs max8; headers max8, name<=64, contains<=256; strings <=512; always forces adaptive+block 403. If sig>512 dropped -> falls to "custom" (line 460).
- My verification run (python -c): long sig (>512) -> 0 length (dropped); bad methods filtered to GET/POST; bad header entry (empty name) dropped; observed-only skipped unless learn_observed=True (matches test); safe_id strips to alnum-.: .
- Deterministic (111): groups by signature, counts strong reasons only by default; requires min_count strong (or learn+total); emits adaptive sig rule + metadata.
- Merge strong coverage (476): runs provider then adds any missed strong sigs from det (unless --disable). Prevents provider from "forgetting" high-confidence.
- Merge existing (528): key by signature (or id), last-wins for dups, keeps old, caps by taking tail after upsert (prefers new when over max).
- Extract json (415): strips ```json fences, takes first { to last } . Used for all 4 providers + codex sdk.
- Post / providers (215-289): urllib, explicit headers, timeouts 60s default, error body truncated on HTTPError. No auth leakage in exceptions (provider_api_key raises before).
- CLI (ai_provider_cli.py): interactive only, chmod 0600 on write, never prints keys, subprocess only for "codex --version".
- Tests (test_ai_tools.py): 9 tests cover det+learn, merge_strong, merge_existing (preserve/replace/cap), provider config merge, defaults for codex, api_key env. All pass (ran twice).
- Harness safety: all use TemporaryDirectory + Popen(..., stdout=DEVNULL/PIPE, env copy with RUST_BACKTRACE=0), terminate + wait(5) or kill, upstream threads daemon. run_local_bench 104 checks binary exists.
- run_defense_bench + e2e: large files (~180k lines json for one), drive full Codex or det loop + flood scenarios including XFF poly for "smart" attacks. Explicitly local.

## Risks
- LOW: if provider returns empty condition after sanitize, filter with signature:"custom" + path? may be created (broad-ish). Mitigated by merge and max_filters, but could bloat.
- LOW: no size limit on events read (max_events=200 default caps); very large jsonl could OOM analyzer (but offline tool).
- LOW: subprocess in harnesses could leave zombies if kill fails, but try/finally + kill present.
- LOW-MED: provider response extractors are heuristic (first/last braces, specific keys); a malicious or broken model could cause extract_json to parse partial or wrong JSON (but sanitize + schema guard downstream).
- OBS: Codex SDK path uses read_only sandbox; other providers are direct REST (no sandbox).
- No high: no credential exfil, no command injection, no way to target non-local from default, no silent broad filters.

## Verification run
- PYTHONPATH=tools python3 -m unittest ... : 9/9 OK (pre and during).
- python -c sanitize/det edges: as above, all expected behaviors (long drop, filter methods, observed gate, safe_id).
- Grep for exec patterns: only controlled harness Popen/check_output for local children + one codex --version + lazy __import__ for os (no risk).
- Read of run_codexsdgate_e2e.py + run_defense_bench.py: confirmed loopback + XFF-only spoof sims + safety strings.

## Open questions
- Should sanitize reject a rule that ends up with no condition keys at all (instead of "custom")?
- Add roundtrip property test or hypothesis for sanitize (valid in -> valid out, no expansion of power)?
- Error taxonomy for provider failures (transient vs auth vs bad json) to decide fallback vs backoff?

## Recommended parent action
- Consider making "empty condition after sanitize" an error or skip (add guard in sanitize or analyze_once).
- Expand test_ai_tools with: header sanitization cases, long path_shape, fence+partial json in extract, very large events (mock).
- Document in AI_PROVIDERS or OPERATIONS the analyzer resource use (max_events).
- Parent cross-link with 04 (any prompt injection via event fields into SYSTEM_PROMPT or build_prompt? fields are in "events" JSON, model instructed to treat as data).
