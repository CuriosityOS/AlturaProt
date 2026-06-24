# Packet 04-surfaces-risks: Attack surfaces, telemetry, admin, parsing, JSON, deps, runtime, benchmark data, completeness

## Objective
Identify and assess all external input surfaces (requests, headers, XFF, JSON configs/filters/events, CLI args, provider responses), error handling, logging of sensitive data, resource exhaustion vectors, admin exposure, dependency attack surface, and any gaps in the reviewed tree. Cross-check runtime/ and benchmark_results/ for PII or sensitive content. Evaluate overall attack surface given the defensive purpose.

## Context
- Proxy accepts untrusted HTTP/TCP from internet (in prod).
- Trusts XFF only from configured trusted_proxies (default empty).
- Admin metrics protected by optional token.
- Filters JSON written by analyzer (or manually); runtime reload.
- Event log is append-only JSONL for offline use (may contain real client IPs/paths/UAs during incidents).
- No auth on the proxied path itself (by design; upstream does).
- Python tools run with user privileges for bench/analysis.

## Sources
- src/http_proxy.rs (admin, XFF, rewrite, header stripping, client_ip resolver - cross ref 01)
- src/filter.rs (rule_matches, header parsing)
- src/telemetry.rs (entire, esp. log, AttackEvent)
- src/config.rs (from_path, relative resolution)
- runtime/filters.json
- runtime/attack_events.jsonl (if present; size + sample)
- benchmark_results/*.json (scan 1-2 recent for structure/sensitive)
- Cargo.toml + Cargo.lock (top-level deps + notable versions)
- Any .env, secrets, or config in home that may be referenced (note only; do not cat secrets)
- root-level files not covered elsewhere: .gitignore (if visible), any CI, Makefile etc via list_dir if needed.
- Full dir tree summary for unmentioned files.

## Ownership
read-only

## Do
- Map every untrusted input: method, path (length?), query, all headers (incl. XFF, host, ua, accept, connection), body (streamed?), TCP bytes.
- Analyze XFF parsing (parse_forwarded_ip_token, chain logic) for spoofing, IPv6 bracket, multiple colons, malicious commas.
- Analyze upstream rewrite (joined_path_and_query, preserve_host): can a malicious path cause open proxy or SSRF against internal? (note: no, because upstream authority is fixed from config, path is just appended).
- Check for log injection / JSONL poisoning via crafted paths/UAs (serde will escape?).
- Review admin token check (constant time? header only on metrics).
- Review rate limiter tracking: max_tracked_ips, eviction, memory under millions of IPs.
- Review filter reload: file read every 2s, potential TOCTOU or large file DoS.
- Check for secrets in code, hardcoded tokens, or example.json admin_token.
- Inspect Cargo deps: any old hyper/tokio/serde? known vulns? (use knowledge + note commands for cargo audit).
- Scan runtime/ and benchmark jsons for real IPs or long event data.
- List every file in tree not mentioned in any packet and justify.
- Note any use of temp files, /tmp paths in tests that could collide.

## Do not
- Perform actual attacks or send malicious traffic.
- Read private ~/.config/altura-prot/secrets.json content (just note existence/permissions).
- Execute cargo-audit unless toolchain present.

## Expected output
- Surface inventory with severity (e.g. "XFF parsing: MED - accepts junk but falls back to peer").
- Evidence citations.
- Any PII/sensitive findings in runtime or results (redact in report).
- Dependency observations.
- "Unknown files" list.
- High-value recommendations (e.g. "add request size limits", "use constant-time compare for admin token", "add cargo-deny or audit in CI").

## Verification
Parent + cross-packet: re-inspect cited parsing code; run python snippet for sanitize edges if relevant; ls runtime/.

## Handoff format
N/A
