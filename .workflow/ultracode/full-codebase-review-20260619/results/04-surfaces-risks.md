# Result 04-surfaces-risks: Attack surfaces, telemetry, admin, parsing, JSON, deps, runtime, benchmark data, completeness

## Summary
Attack surface is appropriately narrow for a defensive L7 proxy: all untrusted input (method, path, query, headers incl XFF/UA/Accept/Connection, TCP bytes) is parsed defensively; client identity only from peer or XFF when peer explicitly trusted (default empty list = always peer); upstream authority is config-only (no SSRF via Host/path); rewrite only appends path; hop-by-hop stripped; filters are allowlisted + sanitized on write. Telemetry is one-way JSONL (IPs/paths/UAs logged on threshold - expected for defense audit). Admin surface (/health open, /metrics token optional) is small and documented. No secrets in source. Runtime/ currently clean (empty filters). Benchmark JSONs are large regression artifacts (local only, no PII apparent). Deps are current major versions (hyper1/tokio1). All tree files accounted for in the 4 packets. Minor risks around resource (large filter file, many unique IPs, jsonl growth, reload cpu) and the inconsistent poison panic in limiter. No critical vulns (no command inj, no arbitrary connect, no obvious log poisoning to RCE, XFF parse fails safe to peer).

## Evidence
- Untrusted inputs mapped: http_proxy handle 148-162 (method/path/query/headers -> sig), 263 (XFF header split), tcp 69 (peer ip only for limit). Body is streamed via hyper Incoming, never fully buffered in hot path.
- XFF parse (http_proxy:355): trims, [v6] strip, plain parse, single-: v4:port hack (for :port), final v6. Tests 553 (ignores from untrusted), 565 (rightmost non-trusted wins), 585/589 (port and [v6] tokens). Falls back to peer_ip on any failure or untrusted. Good.
- Rewrite safety (404): upstream from cfg (validated at start 61-71 has scheme+auth), joined only base+ incoming_pq (435), never takes authority from client Host. preserve_host only re-uses original Host value for header. append always adds client-derived XFF (from resolved ip). No user-controlled destination.
- Hop removal (449): removes Connection-listed + known list (incl dynamic). Good.
- Admin (376): /__altura/health always 200 (no token); /metrics requires token only if cfg.admin_token set (386 exact == , not constant time but for admin ok); returns active_filters + stats. Prefix configurable (default /__altura).
- Filter reload surface (filter.rs:169): tokio::fs::try_exists + read_to_string of runtime_file (every reload_seconds, default 2). Then full serde of FilterFile. If file is GBs or 1M rules, reload task (main:38 spawn) will cpu/ram spike and block other reloads. No size guard.
- Telemetry log (telemetry:96): every emit does full serde + write + flush on the mutexed BufWriter. Event contains client_ip, path, ua, xff, headers list (32), sig, basis, query_keys(16). Expected for defense (to feed analyzer), but jsonl grows forever; no rotation or PII redaction in core. log poisoned recovers.
- Limiter memory: max_tracked_ips (default 65k) per shard +128 headroom + 120s stale eviction. Under intentional unique-IP flood will drop old; global + per-ip still apply to new.
- Deps (Cargo.toml): bytes1, http1, hyper1 (http1/client/server), serde1+json, tokio1 (full rt). Lock shows recent (bytes 1.11, etc). No obvious outdated. Release profile abort+strip good for prod size.
- Runtime current: filters.json = {"filters":[]} (empty, safe). No attack_events.jsonl present in this tree (good, no sample PII).
- Benchmark results: 4 large json (up to 180k lines), keys include duration, per_ip_rps, provider, safety note, scenarios (7-9), workdir. No raw client data apparent from structure; they are measurement outputs.
- Git state: 5 M (src/adaptive +filter +telemetry + codex_analyzer + docs/BENCHMARKS) + untracked .workflow/ + some docs/ + run_defense + benchmark_results/ + AGENTS.md + .DS_Store. The M are enhancements (global observe etc) covered in 01/02.
- Full tree accounting (from find): all 8 .rs (01), 8 .py (02: ai, codex*, local_flood, run_local, run_codex_e2e, run_defense, test), configs/example (03), 6 docs+README+AGENTS (03), Cargo* (01+04), runtime/filters (04), 4 bench_results (04). Extras: .workflow (this run artifact), .DS_Store (ignore). No other .rs .py .json .md or Cargo outside packets.

## Risks
- MED-LOW: filter reload (single task, full read+parse+sort every 2s) is a cpu DoS / latency vector if adversary or misconfig makes runtime/filters.json huge or many rules. Reload errors only eprintln (engine keeps old rules).
- LOW: jsonl event log unbounded; in long incident can fill disk. Analyzer caps read (max_events). No size limit on logged header_names/query_keys beyond take(32/16).
- LOW: admin token compare is == str (not constant-time); timing side-channel possible but admin token is not high-entropy secret in threat model (ops says put behind private net).
- LOW: XFF parser "single colon = possible v4:port" heuristic could misparse weird IPv6 or future, but final v6 parse fallback + always + peer makes fail-closed for trust.
- LOW: many eprintln under load (accept err, upstream err, log fail, reload fail) could themselves become a problem if stderr is a pipe or console.
- OBS: panic=abort in release means any panic (e.g. poison expect in limiter, or hyper bug) takes whole process down (no recovery). Fits "availability via restart" but worth noting.
- No critical: no arbitrary code, no SSRF to user hosts, no filter bypass via path encoding (normalize + exact/prefix/contains/shape all covered), no secret material in logs by default (ips/paths are the point), no deserialization of untrusted into executable (serde only on our FilterFile/AttackEvent and provider json which is sanitized or det).

## Verification run
- Grep XFF/trusted/admin/rewrite: all paths lead to peer fallback or config-only upstream.
- ls runtime/: only empty filters.json.
- Sample bench json structure: no raw events, only agg + safety strings.
- Tree file list: 100% of non-artifact source covered by one of the 4 packets.
- (parent pre-grep) no AI strings in src.

## Open questions
- Should reload task have a size guard or background parse + swap with timeout?
- Add log rotation advice or built-in size-based truncate for attack_events.jsonl?
- Constant-time token compare (subtle, but easy win)?
- Monitor for poison panics in limiter under weird mutex contention?

## Recommended parent action
- Add a max filter file size check or at least a warning + truncate guidance in reload or analyzer write.
- Document jsonl growth / logrotate in OPERATIONS (or add a small tool).
- Standardize poison handling (see 01 result) to avoid surprise panic on one shard.
- For any production use, pair with proper TLS terminator (as ops already says) and place metrics endpoint on a separate listener or with strong auth.
- The current surfaces are reasonable for the stated threat model (L7 defense, not volumetric at pipe level). No immediate security patches required from this review.
