# Benchmarks

Benchmarks are loopback-only on `core` using the release binary, a local
fixed-response upstream, `tools/run_local_bench.py`, and
`tools/run_defense_bench.py`.

Run:

```bash
cargo build --release
python3 tools/run_local_bench.py --duration 8 --workers 128
```

Latest measured snapshot on 2026-06-18:

| Scenario | RPS | Statuses | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed upstream, pre-sync-lock removal | 12034.99 | `204: 96407` | 0 | 31.282 ms |
| admin health, pre-sync-lock removal | 11708.52 | `200: 93800` | 0 | 31.936 ms |
| proxied fixed upstream, sharded + sync hot path | 12070.70 | `204: 96693` | 0 | 30.994 ms |
| admin health, sharded + sync hot path | 11852.77 | `200: 94956` | 0 | 31.811 ms |

The Python flood client and Python upstream become bottlenecks around this range, so these numbers are useful for regression checks, not maximum capacity claims.

Defense-layer/CodexSDGate flood benchmark snapshot: [Defense Benchmark 2026-06-18](DEFENSE_BENCHMARK_20260618.md).

Smarter rotating-XFF/polymorphic flood snapshot: [Smart Defense Benchmark 2026-06-18](SMART_DEFENSE_BENCHMARK_20260618.md).

## 2026-06-23 Edge Namespace Smoke

Artifacts:

- `.github/workflows/ci.yml`
- `tools/run_edge_namespace_smoke.py`
- `benchmark_results/edge_namespace_smoke_core_20260623.json`
- `benchmark_results/edge_namespace_smoke_core_expanded_20260623.json`
- `benchmark_results/edge_namespace_smoke_core_current_20260623.json`
- `benchmark_results/edge_namespace_smoke_core_latest_20260623.json`
- `benchmark_results/edge_namespace_smoke_current_audit_20260623.json`

This snapshot adds a Linux-only edge-template smoke probe that applies
`ops/nftables/altura-prot-edge.nft` inside a temporary network namespace and
lists the resulting nftables table back from the kernel. The latest smoke also
supports a packet probe: it creates isolated victim and attacker namespaces
joined by a veth pair, serves clean IPv4 and IPv6 TCP on a protected port,
verifies clean TCP connections are still allowed, and verifies IPv4 and IPv6 UDP
sent to that protected TCP port is silently dropped instead of escaping to the
host or returning a port unreachable. It also opens 140 TCP connections per
family from the attacker namespace and requires the protected-port
connection-count rules to cap accepted connections at the template's `ct count
over 128` threshold, including the IPv6 `/64` key path. The strict packet probe
also crafts an IPv6 Hop-by-Hop Options packet carrying UDP to a protected TCP
port and verifies the nftables raw hook silently drops it instead of letting the
kernel return ICMPv6 port unreachable. It does not touch the host firewall
ruleset and sends no public traffic. The probe is skip-safe on
non-Linux hosts or machines without `nft`, `unshare`, or `ip`; use `--require`
and `--require-packet-probe` on `core` or another prepared Linux host when the
edge check must be enforced. CI now installs `nftables`, `iproute2`, and
`util-linux` on the standard Ubuntu runner, marks the checkout as a root-safe
Git directory for the sudo smoke process, and runs `sudo python3
tools/run_edge_namespace_smoke.py --require --require-provenance
--require-packet-probe`, so edge-template kernel loadability and protected-port
packet behavior are no longer only manual artifacts, and the report proves which
checkout produced them.

Reference checks used for the probe:

- [GitHub-hosted runner docs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges) document passwordless `sudo` on Linux virtual-machine runners; the workflow uses a standard Ubuntu runner, not `ubuntu-slim`.
- [Netfilter nft man page](https://www.netfilter.org/projects/nftables/manpage.html) documents `nft` as the userspace tool for maintaining nftables rules in the Linux kernel.
- [Debian nft man page](https://manpages.debian.org/testing/nftables/nft.8.en.html) documents `nft -c` as syntax-only validation; this smoke test goes one step further by loading and listing the ruleset in an isolated namespace.
- [nftables Netfilter hooks](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks) documents where raw-priority and input-priority hooks run in the packet path; the smoke result checks both chains are present after kernel load.
- [Linux namespaces man page](https://man7.org/linux/man-pages/man7/namespaces.7.html) documents that namespaces isolate global system resources for the member processes; this is why the probe can load nftables in a disposable network namespace.
- [Linux `unshare` man page](https://man7.org/linux/man-pages/man1/unshare.1.html) documents executing a command in new namespaces.
- [Ubuntu nftables security docs](https://documentation.ubuntu.com/security/security-features/network/firewall/nftables/) note that nftables hooks and rules are managed independently per network namespace.
- [Linux `ip-netns(8)`](https://man7.org/linux/man-pages/man8/ip-netns.8.html) documents named network namespace creation, execution, and cleanup.
- [Linux `veth(4)`](https://man7.org/linux/man-pages/man4/veth.4.html) documents virtual Ethernet pairs and using one endpoint in each namespace for cross-namespace packet probes.
- [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) document isolation for firewall rules, devices, routing tables, and sockets.
- [Linux `udp(7)`](https://man7.org/linux/man-pages/man7/udp.7.html) and [Python `socket`](https://docs.python.org/3/library/socket.html) docs were checked for the connected UDP timeout/port-unreachable behavior used by the protected-port drop probe.
- [nftables connlimits](https://wiki.nftables.org/wiki-nftables/index.php/Connlimits) and [Ubuntu nftables docs](https://documentation.ubuntu.com/security/security-features/network/firewall/nftables/) document `ct count over` connection limits; the packet probe verifies the shipped protected-port connlimit rule with live TCP sockets.
- [Linux `listen(2)`](https://man7.org/linux/man-pages/man2/listen.2.html) documents that the listen backlog covers completed sockets waiting for accept; the probe uses a larger backlog and accepts/holds connections so the nft connlimit, not the application backlog, is the tested limit.
- [Linux `ip-address(8)`](https://man7.org/linux/man-pages/man8/ip-address.8.html) documents IPv6 `nodad`, which keeps temporary namespace addresses immediately usable for deterministic local probes.
- [Linux `ipv6(7)`](https://man7.org/linux/man-pages/man7/ipv6.7.html) and [Python `socket`](https://docs.python.org/3/library/socket.html) document `AF_INET6` sockets; the smoke uses explicit numeric IPv6 addresses rather than DNS resolution.
- [nftables packet-header matching](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers) documents that `meta l4proto` matches the real transport protocol and skips IPv6 extension headers; the smoke now pairs that static rule validation with live IPv6 TCP/UDP packet behavior.
- [RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200) documents the IPv6 Hop-by-Hop Options header format and that it immediately follows the IPv6 header when present.
- [Linux `packet(7)`](https://man7.org/linux/man-pages/man7/packet.7.html) and [Python `socket`](https://docs.python.org/3/library/socket.html) document raw `AF_PACKET` sockets; the Hop-by-Hop probe uses them only inside the isolated attacker namespace to generate one local veth frame.

`core` isolated Linux namespace result:

| Probe | Result |
| --- | --- |
| nftables template loaded in temporary netns | `true` |
| `table inet altura_prot_edge` listed back | `true` |
| protected TCP port set present | `true` |
| IPv4 and IPv6 connlimit sets present | `true` |
| bounded IPv4 and IPv6 SYN-rate sets present | `true` |
| invalid TCP null-flag drop present | `true` |
| invalid TCP XMAS drop present | `true` |
| IPv4 protected-port SYN-rate rule present | `true` |
| global protected-port SYN-rate backstop present | `true` |
| `ct state invalid` drop present | `true` |
| new protected-port non-SYN TCP drop present | `true` |
| IPv4 and IPv6 connlimit rules present | `true` |
| IPv6 `/64` SYN-rate backstop present | `true` |
| IPv6 `/64` connlimit backstop present | `true` |
| protected-port UDP drop present | `true` |
| protected-port UDP drop source uses `meta l4proto udp` | `true` |
| clean TCP connection on protected port allowed | `true` |
| UDP packet to protected TCP port silently dropped | `true` |
| protected-port TCP connlimit enforced | `true` |
| IPv6 clean TCP connection on protected port allowed | `true` |
| IPv6 UDP packet to protected TCP port silently dropped | `true` |
| IPv6 `/64` protected-port TCP connlimit enforced | `true` |
| IPv6 Hop-by-Hop UDP packet to protected TCP port sent | `true` |
| IPv6 Hop-by-Hop UDP packet to protected TCP port silently dropped | `true` |
| ICMPv4 and ICMPv6 control exemptions present | `true` |
| ICMPv4 and ICMPv6 flood drops present | `true` |

Current-tree follow-up on 2026-06-23 copied the working tree to
`/tmp/altura-prot-current-edge-20260623-101037` on `core`, excluding `.git`,
`target`, and historical benchmark artifacts. `python3
tools/validate_edge_templates.py --config configs/example.json` passed on
Linux, then `python3 tools/run_edge_namespace_smoke.py --require` produced
`benchmark_results/edge_namespace_smoke_core_current_20260623.json` with
`returncode: 0`, `skipped: false`, `nft_loaded: true`,
`listed_edge_table: true`, protected TCP ports present, IPv6 `/64` SYN and
connlimit backstops present, and ICMPv4/ICMPv6 control exemptions present.
The latest smoke harness also emits `generated_at_utc` and `source_tree`
metadata, and `--require-provenance` makes missing or stale Git metadata a
failing check for current CI evidence.

Strict packet-probe follow-up on 2026-06-23 copied the current working tree to
`/root/altura-prot-codex-packet` on `core`, marked that temporary checkout as a
Git safe directory, and ran `python3 tools/run_edge_namespace_smoke.py
--require --require-provenance --require-packet-probe`. The resulting
`benchmark_results/edge_namespace_smoke_core_latest_20260623.json` records
`nft_loaded: true`, `listed_edge_table: true`, current source-tree provenance,
`packet_probe.tcp_clean_connect_allowed: true`, and
`packet_probe.udp_protected_port_silently_dropped: true`. The same strict
artifact now records `packet_probe.tcp_connlimit_enforced: true` after 140
local attacker-namespace connection attempts, with accepted connections capped
at 128 and the excess attempts timing out behind the nftables connlimit. The
artifact also records the matching IPv6 live-packet checks:
`packet_probe.ipv6_tcp_clean_connect_allowed: true`,
`packet_probe.ipv6_udp_protected_port_silently_dropped: true`, and
`packet_probe.ipv6_tcp_connlimit_enforced: true`. The strict artifact also
records `packet_probe.ipv6_hop_by_hop_udp_packet_sent: true`,
`packet_probe.ipv6_hop_by_hop_udp_protected_port_silently_dropped: true`, and
an empty `packet_probe.ipv6_hop_by_hop_udp_port_unreachable_replies` list,
proving a protected-port UDP packet behind an IPv6 extension header did not
escape to the kernel's closed-port path.

Current audit follow-up on 2026-06-23 copied the dirty worktree to
`/tmp/altura-prot-edge-audit-20260623` on `core`, excluding `target`,
`.DS_Store`, and historical benchmark artifacts. `python3
tools/validate_edge_templates.py --config configs/example.json` passed on
Linux, then `python3 tools/run_edge_namespace_smoke.py --require
--require-provenance --require-packet-probe` generated
`benchmark_results/edge_namespace_smoke_current_audit_20260623.json` with
`generated_at_utc: 2026-06-23T06:04:44Z`, git commit
`38213a0e4262d5879bd080885b67b8b9c03baa2d`, `git_dirty: true`,
`skipped: false`, `nft_loaded: true`, and `listed_edge_table: true`. The packet
probe preserved the strict edge contract: clean IPv4 and IPv6 TCP were allowed,
IPv4 and IPv6 UDP sent to a protected TCP port were silently dropped, IPv4 and
IPv6 protected-port connlimits capped 140 attempts at 128 accepted sockets with
12 failures, and the IPv6 Hop-by-Hop UDP probe was sent and silently dropped
with no port-unreachable replies.

Validation commands:

```bash
python3 -m py_compile tools/run_edge_namespace_smoke.py tools/test_ai_tools.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/run_edge_namespace_smoke.py
sudo git config --global --add safe.directory "$PWD"
sudo python3 tools/run_edge_namespace_smoke.py --require --require-provenance --require-packet-probe
rsync -az --delete --exclude target --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-edge-smoke-20260623/
ssh core 'cd /root/altura-prot-edge-smoke-20260623 && python3 tools/run_edge_namespace_smoke.py --require --require-provenance --require-packet-probe > edge-namespace-smoke.json'
rsync -az core:/root/altura-prot-edge-smoke-20260623/edge-namespace-smoke.json /Users/core/AlturaProt/benchmark_results/edge_namespace_smoke_core_20260623.json
rsync -az tools/run_edge_namespace_smoke.py core:/tmp/altura-prot-edge-smoke-expanded-20260623/tools/run_edge_namespace_smoke.py
rsync -az ops/nftables/altura-prot-edge.nft core:/tmp/altura-prot-edge-smoke-expanded-20260623/ops/nftables/altura-prot-edge.nft
ssh core 'cd /tmp/altura-prot-edge-smoke-expanded-20260623 && python3 tools/run_edge_namespace_smoke.py --require --require-packet-probe > edge-namespace-smoke-expanded.json'
rsync -az core:/tmp/altura-prot-edge-smoke-expanded-20260623/edge-namespace-smoke-expanded.json /Users/core/AlturaProt/benchmark_results/edge_namespace_smoke_core_expanded_20260623.json
```

## 2026-06-23 Local Guardrail CI Gate

Artifacts:

- `.github/workflows/ci.yml`
- `tools/assert_local_bench.py`
- `tools/bench_provenance.py`
- `benchmark_results/local_bench_ci_guardrails_20260623.json`
- `benchmark_results/local_bench_ci_guardrails_post_grace_min_rate_20260623.json`
- `benchmark_results/local_bench_ci_guardrails_coderabbit_followups_20260623.json`
- `benchmark_results/local_bench_ci_guardrails_tcp_relay_full_duplex_20260623.json`
- `benchmark_results/local_bench_current_audit_20260623.json`
- `benchmark_results/cargo_audit_current_20260623.json`
- `benchmark_results/defense_bench_all_deterministic_current_audit_20260623.json`

The GitHub Actions workflow now runs the local loopback benchmark after the
release build and asserts the security guardrail contract with
`tools/assert_local_bench.py`. This keeps review-driven protections from being
manual-only checks: HTTP and TCP endpoint startup validation, path-shape
short-token sibling churn, signature limiting, TCP and HTTP minimum rates,
maximum connection duration, rate-limit-before-filter ordering, bounded tracked
state, path-shape adaptive evidence, nonblocking filter activation and runtime
reload, event-log queue behavior, runtime-filter bounds, trusted-proxy
aggregate limiting, trusted duplicate-XFF canonicalization, clean XFF synthesis
when a non-XFF trusted identity header is configured, singleton validation for
non-XFF trusted identity headers, absolute-form request-target scheme rejection
for non-HTTP schemes, request content-encoding, `Expect`, and `Range`
rejections, origin `Accept-Encoding` stripping, framing/header timeout and
header-size guards, upstream connect/header/response timeout and body guards,
upstream in-flight overload headers, default downstream keep-alive closure, TCP
global active/rate/idle guards, startup rejection of unsupported
tunnel/diagnostic allowed-method names, default rejection of method-override
headers before origin work, upstream circuit scoping, and edge/systemd template
validation must all remain true for CI to pass. Metrics admin-token startup
validation is also
asserted, including rejection of tokens above the 256-byte bounded comparison
budget and fail-closed behavior for duplicate metrics-token headers. The
assertion intentionally
checks guardrail booleans and zero benchmark-surface errors, not absolute
throughput floors, so runner variance does not turn the security gate flaky.
Fresh CI local-benchmark reports must also include `generated_at_utc` and
`source_tree` provenance. The local assertion uses `--require-provenance` in CI
so stale or copied guardrail JSON cannot silently stand in for a current
checkout run, while older artifacts remain inspectable without that flag. The
CI workflow also uploads `edge-namespace-smoke.json`, `local-bench.json`, and
`defense-bench.json` with the official `actions/upload-artifact@v4` action under
`altura-prot-ci-benchmark-reports`, using `if: ${{ always() }}` so partial
reports survive later assertion failures for debugging. `if-no-files-found: warn`
keeps earlier setup failures visible without masking the original failing step.
The same assertion also checks the CI-sized run strength: at least 1 second, 8 HTTP
workers, 4 TCP workers, and the release binary path. TCP min-rate evidence is
checked at byte level: both the explicit and default slow-drip probes must close
before the second and third post-grace bytes can be echoed, so an eventual-only
rejection no longer satisfies the gate. TCP relay evidence also includes a
full-duplex head-of-line probe: a loopback upstream sends a response while its
read side is deliberately not drained and the client floods the opposite
direction; the response must still reach the client promptly.

A 2026-06-23 current-tree audit run generated
`benchmark_results/local_bench_current_audit_20260623.json` from
`target/release/altura-prot` at git commit
`38213a0e4262d5879bd080885b67b8b9c03baa2d` with a dirty worktree, then passed
the same provenance-aware local assertion. The run preserved the screenshot
follow-up guarantees: short-token sibling churn and direct short-token
path-shape limiting both passed while normal versioned API routes remained
allowed; banked pre-grace HTTP request body bytes were still rejected after the
post-grace slow byte (`http_body_banked_too_slow_delta: 1`); TCP explicit and
default min-rate slow-drip probes were rejected; rate limiting preceded filter
evaluation; active tracked-IP capacity failed closed for a new client; adaptive
signature windows stayed at `64 / 64`, path-shape windows stayed at `1 / 64`;
and adaptive activation plus runtime reload completed without blocking 6544
control requests, with maximum control latency `4.962` ms. CodeRabbit completed
the current uncommitted `src`, `ops`, `.github`, and `tools` reviews with
`findings: 0`.
The first `configs` review found that `configs/example.json` set the HTTP
per-source connection-open rate and burst equal to the global connection-open
budget; the example now uses `per_ip_connects_per_second: 100` and
`per_ip_connect_burst: 200`, with a regression test asserting the example
per-source budget stays below the global budget, and the follow-up `configs`
review completed with `findings: 0`. A follow-up scoped `tools` review was
rerun with a longer window after the earlier wrapper timeout and completed with
`findings: 0`.

A follow-up hardening pass also changed the Rust HTTP defaults so
`http.limits.per_ip_connects_per_second` and `per_ip_connect_burst` follow the
default per-client request bucket (`200/s`, burst `400`) instead of matching the
service-wide connection-open bucket (`20000/s`, burst `40000`). Synthetic
benchmarks that intentionally open thousands of loopback connections now lift
their benchmark-only connection-open buckets explicitly, so they continue to
measure the intended L7 layer rather than accidentally scoring the accept-path
guard.

The patched local guardrail run generated
`benchmark_results/local_bench_http_connect_defaults_20260623.json` at
`2026-06-23T07:23:19Z` from the dirty main worktree and passed the same
provenance-aware local assertion with 1 second, 8 HTTP workers, 4 TCP workers,
and `target/release/altura-prot`. This confirms the lower production HTTP
connection-open defaults while preserving the local guardrails, including
path-shape/short-token limiting, body/TCP min-rate rejection,
rate-limit-before-filter ordering, active tracked-IP fail-closed behavior,
adaptive window bounds,
and nonblocking adaptive activation/reload behavior.

The same current audit pass also ran `cargo audit --json` into
`benchmark_results/cargo_audit_current_20260623.json`. RustSec loaded 1137
advisories, scanned 43 locked crate dependencies, and reported zero
vulnerabilities and no warnings.

The final current-tree defense audit generated
`benchmark_results/defense_bench_all_deterministic_current_audit_20260623.json`
on `core` with `generated_at_utc: 2026-06-23T06:53:21Z`, git commit
`38213a0e4262d5879bd080885b67b8b9c03baa2d`, and `git_dirty: true`. The
artifact passed the strict deterministic all-scenario assertion with
`--require-provenance`, the exact 18-scenario set, exact common layer coverage,
direct-upstream baselines, layer traffic, open-proxy negative controls,
score-consistency checks, and measured benign allowance. Every scenario had at
least one automated passing layer: attacker traffic was stopped at or above the
90% target and benign bypass probes stayed at 100% allowed on the selected
passing layers. The lowest passing attacker-stop score in the full run was
94.88% on the slow-XFF polymorphic rate-limit layer, and each `proxy_open`
negative control allowed at least 99.92% of the same attack workload.

During that audit, the defense benchmark harness was tightened rather than
weakening assertions. Phase summaries now include bounded `error_samples`, and
assertion failures print those samples. The harness also explicitly enables
downstream keep-alive in benchmark configs and raises all unrelated request-rate
buckets on `proxy_open` and static-filter layers, while the path-shape layer
leaves only the path-shape bucket low. A follow-up harness patch also lifts
connection-open token buckets in the synthetic L7 benchmark configs, so the
lower production HTTP connection-open defaults do not convert intended L7
denials into accept-path disconnects. This keeps the full deterministic defense
benchmark focused on request-layer DDoS behavior; connection-open and closed
downstream-socket behavior remain covered by the local guardrail and edge smoke
benches.

After the HTTP connection-open default hardening, the final deterministic
defense rerun generated
`benchmark_results/defense_bench_all_deterministic_http_connect_defaults_20260623.json`
on `core` with `generated_at_utc: 2026-06-23T07:41:26Z`, git commit
`38213a0e4262d5879bd080885b67b8b9c03baa2d`, and `git_dirty: true`. It passed
the same strict all-scenario assertion with provenance, exact 18-scenario
coverage, exact common layer coverage, observed-learning scenario checks,
direct-upstream baselines, layer traffic, open-proxy negative controls,
score-consistency checks, and measured benign allowance. Every scenario had an
automated passing layer; the lowest passing attacker-stop scores were 94.87% on
`slow-xff-polymorphic` path-shape limiting, 94.95% on the same scenario's
rate-limit layer, 95.73% on `legit-interleave-xff` path-shape limiting, and
100% benign allowance on those selected layers.

The follow-up artifact also covers review-driven hardening after the min-rate
fix: normalized client-prefix keys are hash-sharded before limiter shard
selection; tracked-IP cap probing no longer assumes a particular shard hash;
strong adaptive path-shape evidence can activate even when sample events are
throttled; forwarded client-IP tokens reject invalid port/suffix text;
absolute-form request-target authority bytes count against `max_uri_bytes`;
oversized upstream `Content-Length` is rejected before recording upstream
success; filter validation rejects duplicate rule IDs and ignores expired rules
during adaptive activation/active counts; event logs use owner-only Unix file
permissions and flush batched events after idle intervals; `runtime.shutdown_grace_ms`
defaults to `2000` ms and is the single listener-drain deadline. The latest
artifact additionally covers the raw TCP relay refactor: each direction runs
independently so one write-backpressured direction does not block reads and
writes in the other direction.

Reference checks used for the CI gate:

- [GitHub Actions workflow syntax](https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions) documents that a `run` step reports failure when the command exits non-zero.
- [GitHub Actions workflow artifacts](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts) was considered for retaining CI reports; no artifact dependency was added because the existing local JSON artifact flow and pass/fail assertion are enough for this gate.
- [Google SRE testing reliability guidance](https://sre.google/sre-book/testing-reliability/) frames stress-style tests as a way to quantify release confidence; here the CI gate uses short loopback stress probes to preserve specific DDoS contracts.
- [RFC 9110](https://datatracker.ietf.org/doc/html/rfc9110#section-5.2) documents that same-name HTTP field lines are combined in order when the field's grammar allows a list.
- [MDN X-Forwarded-For guidance](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For) documents the comma-separated proxy chain convention.
- [Cloudflare HTTP header docs](https://developers.cloudflare.com/fundamentals/reference/http-headers/) document `CF-Connecting-IP` as a separate original-client-IP header sent from Cloudflare to an origin.
- [RFC 9112 absolute-form request-target handling](https://datatracker.ietf.org/doc/html/rfc9112#section-3.2.2) documents that origin servers must accept absolute-form while using its authority.
- [MDN request target forms](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages#request_targets) describes absolute-form as the complete URL form used with proxies.
- [MDN CONNECT method reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/CONNECT) documents that `CONNECT` asks a proxy to establish a tunnel and warns that loose proxy support can be abused.
- [MDN TRACE method reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/TRACE) documents `TRACE` as a diagnostic loopback method that owners have historically disabled for security reasons.
- [OWASP WSTG HTTP methods testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods) calls out `TRACE`/`TRACK`, `CONNECT`, and `X-HTTP-Method`/`X-HTTP-Method-Override`/`X-Method-Override` workarounds as hardening concerns and recommends allowing only required methods.
- [hyper-util `HttpConnector` docs](https://docs.rs/hyper-util/latest/hyper_util/client/legacy/connect/struct.HttpConnector.html) document it as a connector for the `http` scheme.
- [Hyper connector guide](https://hyper.rs/guides/1/client/connectors/) documents that HTTPS support requires choosing a TLS connector such as `hyper-tls` or `hyper-rustls`.
- [Tokio `TcpStream::connect` docs](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.connect) document that connect accepts any `ToSocketAddrs` value and attempts resolved addresses.
- [Rust `std::net::ToSocketAddrs` docs](https://doc.rust-lang.org/std/net/trait.ToSocketAddrs.html) document that string addresses must be a socket address or `<host>:<port>` pair with a `u16` port.
- [`http::uri::Authority` docs](https://docs.rs/http/latest/http/uri/struct.Authority.html) document host and port extraction from an authority without adding a new parser dependency.
- [Kestrel server limits](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/options?view=aspnetcore-10.0) document minimum data-rate checks after a grace period.
- [NGINX `client_body_timeout`](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_timeout) documents body-read timeout as an inter-read timeout, so low-rate drip protection still needs a separate minimum-rate contract.
- [Rust `DefaultHasher`](https://doc.rust-lang.org/std/collections/hash_map/struct.DefaultHasher.html) and [`IpAddr`](https://doc.rust-lang.org/std/net/enum.IpAddr.html) docs were checked before using the standard `Hash` implementation for normalized client-prefix shard selection.
- [OWASP secure-by-default guidance](https://devguide.owasp.org/en/02-foundations/03-security-principles/) was checked before choosing fail-closed duplicate/expired filter handling.
- [Tokio `copy_bidirectional`](https://docs.rs/tokio/latest/tokio/io/fn.copy_bidirectional.html) documents concurrent bidirectional copying and EOF shutdown behavior; AlturaProt keeps those semantics while retaining custom idle and min-rate guards.
- [Tokio `split`](https://docs.rs/tokio/latest/tokio/io/fn.split.html) documents splitting one `AsyncRead + AsyncWrite` stream into independent read/write halves.
- [Tokio `select!` cancellation safety](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety) and [`AsyncWriteExt::write_all`](https://docs.rs/tokio/latest/tokio/io/trait.AsyncWriteExt.html#method.write_all) document why the relay avoids selecting directly on `write_all`.

CI-sized local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9506.10 RPS | `204: 9511` | 0 | 1.345 ms |
| admin health | 9596.55 RPS | `200: 9601` | 0 | 1.379 ms |
| raw TCP persistent echo | 36248.16 msg/s | `36261` echoed messages | 0 | 0.177 ms |

TCP relay full-duplex head-of-line probe:

| Probe | Result |
| --- | --- |
| upstream response while downstream write is blocked | `pong` |
| response bytes delivered | `4` |
| response elapsed | `0.222` seconds |
| client flood send completed during probe | `false` |
| full-duplex relay contract | `true` |

TCP min-rate post-grace probe:

| Probe | Result |
| --- | --- |
| explicit slow-drip first byte echo | `1` byte |
| explicit slow-drip second byte echo | `0` bytes |
| explicit slow-drip third byte echo | `0` bytes |
| default-floor slow-drip first byte echo | `1` byte |
| default-floor slow-drip second byte echo | `0` bytes |
| default-floor slow-drip third byte echo | `0` bytes |
| explicit/default downstream too-slow metric deltas | `1` / `1` |

Tracked-IP cap probe:

| Probe | Result |
| --- | --- |
| first trusted XFF client | `204` |
| repeated first trusted XFF client | `429` |
| first new client denied after bounded state filled | `429` |
| first client still rate-limited after cap pressure | `429` |
| admitted new clients before cap denial | `10` |

Host/request-target guard probe:

| Probe | Result |
| --- | --- |
| absolute-form `ftp://good.local/` status | `400` |
| absolute-form unsupported scheme response no-store | `true` |
| host rejection metric delta | `7` |

HTTP endpoint startup guard probe:

| Probe | Result |
| --- | --- |
| invalid `http.listen` | startup exited before binding |
| missing `http.upstream` scheme | startup exited before binding |
| `https://` `http.upstream` without TLS connector | startup exited before binding |
| `http.upstream` URI userinfo | startup exited before binding |
| `http.upstream` query string | startup exited before binding |

TCP endpoint startup guard probe:

| Probe | Result |
| --- | --- |
| invalid `tcp[0].listen` | startup exited before binding |
| missing `tcp[0].upstream` port | startup exited before binding |
| URL-shaped `tcp[0].upstream` with scheme | startup exited before binding |
| `tcp[0].upstream` URI userinfo | startup exited before binding |
| `tcp[0].upstream` path suffix | startup exited before binding |
| `tcp[0].upstream` port `0` | startup exited before binding |

Allowed-method startup guard probe:

| Probe | Result |
| --- | --- |
| configured `CONNECT` method | startup exited before binding |
| configured `TRACE` method | startup exited before binding |
| configured `TRACK` method | startup exited before binding |

Method-override header guard probe:

| Probe | Result |
| --- | --- |
| `GET` with `X-HTTP-Method: DELETE` | `400`, no-store, connection close |
| `GET` with `X-HTTP-Method-Override: DELETE` | `400`, no-store, connection close |
| `GET` with `X-Method-Override: DELETE` | `400`, no-store, connection close |
| method rejection metric delta | `3` |

Trusted-proxy duplicate-XFF probe:

| Probe | Result |
| --- | --- |
| origin-visible `X-Forwarded-For` | `203.0.113.200, 198.51.100.77, 127.0.0.1` |
| origin-visible `X-Real-IP` | `198.51.100.77` |
| duplicate XFF chain preserved and canonicalized | `true` |
| custom `CF-Connecting-IP` identity produced clean XFF | `203.0.113.203, 127.0.0.1` |
| custom identity XFF synthesized instead of preserving spoofed XFF | `true` |
| duplicate `CF-Connecting-IP` singleton identity rejected | `400` |
| comma-list `CF-Connecting-IP` singleton identity rejected | `400` |
| custom identity rejection metric delta | `2` |
| untrusted direct spoofed XFF overwritten | `127.0.0.1` |

Validation commands:

```bash
cargo fmt --check
cargo test -- --nocapture
cargo clippy --all-targets -- -D warnings
python3 -m py_compile tools/assert_local_bench.py tools/bench_provenance.py tools/test_ai_tools.py tools/run_local_bench.py tools/assert_defense_bench.py tools/run_defense_bench.py tools/codex_analyzer.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 8 --tcp-workers 4 > benchmark_results/local_bench_ci_guardrails_coderabbit_followups_20260623.json
python3 tools/assert_local_bench.py \
  benchmark_results/local_bench_ci_guardrails_coderabbit_followups_20260623.json \
  --require-provenance \
  --min-duration 1 \
  --min-workers 8 \
  --min-tcp-workers 4 \
  --expect-binary target/release/altura-prot
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 8 --tcp-workers 4 > benchmark_results/local_bench_current_audit_20260623.json
python3 tools/assert_local_bench.py \
  benchmark_results/local_bench_current_audit_20260623.json \
  --require-provenance \
  --min-duration 1 \
  --min-workers 8 \
  --min-tcp-workers 4 \
  --expect-binary target/release/altura-prot
coderabbit review --agent --type uncommitted --dir /Users/core/AlturaProt/src
coderabbit review --agent --type uncommitted --dir /Users/core/AlturaProt/.github
coderabbit review --agent --type uncommitted --dir /Users/core/AlturaProt/ops
coderabbit review --agent --type uncommitted --dir /Users/core/AlturaProt/configs
cargo audit --json > benchmark_results/cargo_audit_current_20260623.json
ssh core 'cd /tmp/altura-prot-defense-debug-20260623 && python3 tools/run_defense_bench.py --binary target/release/altura-prot --no-codex --duration 1 --workers 8 --preset all --json-only > defense_bench_all_deterministic_current_audit_20260623.json'
rsync -az core:/tmp/altura-prot-defense-debug-20260623/defense_bench_all_deterministic_current_audit_20260623.json benchmark_results/defense_bench_all_deterministic_current_audit_20260623.json
python3 tools/assert_defense_bench.py \
  benchmark_results/defense_bench_all_deterministic_current_audit_20260623.json \
  --require-provenance \
  --expect-provider deterministic \
  --expect-preset all \
  --min-duration 1 \
  --min-workers 8 \
  --expect-scenario-set basic,cachebuster,rotating-path,uuid-path,mixed-user-agent,smart-api-mix,xff-single,xff-rotating,xff-polymorphic,catalog-mimic-xff,dictionary-slug-xff,hex-slug-xff,v2-polymorphic-xff,method-spray-xff,accept-spray-xff,legit-interleave-xff,slow-xff-polymorphic,mozilla-polymorphic-xff \
  --expect-common-layer-set direct_upstream,proxy_open,rate_limit,path_shape_rate_limit,static_filter,learned_filter_strict \
  --expect-observed-learning-scenarios smart-api-mix,xff-single,xff-rotating,xff-polymorphic,catalog-mimic-xff,dictionary-slug-xff,hex-slug-xff,v2-polymorphic-xff,method-spray-xff,accept-spray-xff,legit-interleave-xff,slow-xff-polymorphic,mozilla-polymorphic-xff \
  --expect-static-only-scenarios '' \
  --require-direct-baseline \
  --require-layer-traffic \
  --require-open-proxy-negative-control \
  --require-score-consistency \
  --require-measured-benign
git diff --check
```

## 2026-06-22 Short-Token Sibling-Churn Snapshot

Artifacts:

- `benchmark_results/local_bench_short_token_sibling_churn_20260622.json`

This snapshot tightens the path-shape precision/recall tradeoff for short API
segments. High-confidence short tokens with digits or mixed case still collapse
directly into the normalized path shape. All-lowercase two- and
three-character segments now stay distinct for normal routing precision, while a
bounded sibling-churn limiter uses the same path-shape RPS, burst, and tracked
state cap to shed many distinct short siblings under one parent route. When that
sibling-churn limiter fires, adaptive/event evidence is recorded under the same
parent path-shape descriptor (`/api/:short-token`) so learned filters and offline
analysis see the route family rather than only the final exact short segment.

Reference checks used for the change:

- [OWASP API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) recommends rate limits tuned to individual API operations.
- [Cloudflare WAF rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) and [Envoy local rate limit descriptors](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter) both model rate limits with request characteristics/descriptors rather than a single global bucket.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8863.17 RPS | `204: 8882` | 0 | 6.490 ms |
| admin health | 9278.11 RPS | `200: 9298` | 0 | 5.957 ms |
| raw TCP persistent echo | 17461.53 msg/s | `17482` echoed messages | 0 | 1.677 ms |

Guardrails:

| Probe | Result |
| --- | --- |
| long-token path-shape burst returned `204,204,429,429` | `true` |
| short-token sibling-churn burst returned `204,204,429,429` | `true` |
| short-token sibling-churn event recorded `/api/:short-token` | `true` |
| version route shape `/api/v1/users` remained allowed | `true` |
| path-shape and aggregate rate-limit counters increased by 4 | `true` |
| generated 429 responses carried `Retry-After: 1` and `Cache-Control: no-store` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/run_defense_bench.py tools/assert_defense_bench.py tools/codex_analyzer.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
cargo test -- --nocapture
cargo clippy -- -D warnings
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 32 --tcp-workers 16 > benchmark_results/local_bench_short_token_sibling_churn_20260622.json
jq -e '.guardrails.path_shape_rate.short_token_sibling_churn_limited == true and .guardrails.path_shape_rate.short_token_path_shape_limited == true and .guardrails.path_shape_rate.short_token_sibling_event_shape_recorded == true and .guardrails.path_shape_rate.hot_path_shape_limited == true and .guardrails.path_shape_rate.version_shape_allowed == true and .guardrails.path_shape_rate.path_shape_metric_matches == true and .guardrails.path_shape_rate.rate_limited_metric_includes_path_shape_limit == true' benchmark_results/local_bench_short_token_sibling_churn_20260622.json
```

## 2026-06-22 Ops Alignment Snapshot

Artifacts:

- `ops/systemd/altura-prot.service`
- `ops/nftables/altura-prot-edge.nft`
- `configs/example.json`
- `benchmark_results/local_bench_ops_alignment_20260622.json`

This snapshot aligns the shipped deployment templates with the userspace DDoS
caps. The systemd unit now uses bounded `TasksMax=32768` instead of `4096`,
preserving a service-manager task ceiling without sitting below the example
connection budget. The nftables protected-port connection-count backstop now
uses `ct count over 128`, matching the example raw TCP per-IP connection cap
instead of remaining looser at `512`. Raw TCP services now default to `512` B/s
downstream and upstream minimum data-rate guards after the existing 10-second
grace window; `0` remains the explicit opt-out for measured quiet protocols.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8876.67 RPS | `204` responses | 0 | 13.735 ms |
| admin health | 8482.05 RPS | `200` responses | 0 | 14.204 ms |
| raw TCP persistent echo | 18680.73 msg/s | echoed messages | 0 | 1.491 ms |

Ops guardrails from the same run:

| Probe | Result |
| --- | --- |
| edge template port coverage | passed |
| connlimit set sizes | passed |
| systemd unit guardrails | passed |
| weak systemd sandbox rejected | passed |
| excessive systemd capabilities rejected | passed |
| TCP slow-drip min-rate rejection | passed |

Validation commands:

```bash
python3 -m py_compile tools/test_ai_tools.py tools/run_local_bench.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_ops_alignment_20260622.json
jq -e '.guardrails.edge_template_port_coverage.systemd_unit_allowed == true and .guardrails.edge_template_port_coverage.connlimit_set_sizes_allowed == true and .guardrails.edge_template_port_coverage.covered_public_ports_allowed == true and .guardrails.edge_template_port_coverage.insufficient_systemd_nofile_rejected == true and .guardrails.edge_template_port_coverage.weak_systemd_sandbox_rejected == true and .guardrails.edge_template_port_coverage.excessive_systemd_capabilities_rejected == true and .guardrails.tcp_min_rate.tcp_min_rate_rejected == true' benchmark_results/local_bench_ops_alignment_20260622.json
```

## 2026-06-22 CI Deterministic Defense Gate Snapshot

Artifacts:

- `.github/workflows/ci.yml`
- `tools/assert_defense_bench.py`
- `benchmark_results/defense_artifacts_manifest.json`
- `benchmark_results/defense_bench_ci_deterministic_20260622.json`
- `benchmark_results/defense_bench_ci_deterministic_20260623.json`
- `benchmark_results/defense_bench_ci_deterministic_20260623_current.json`
- `benchmark_results/defense_bench_ci_deterministic_20260623_distributed_slow.json`
- `benchmark_results/defense_bench_ci_deterministic_20260623_fresh.json`
- `benchmark_results/defense_bench_ci_deterministic_20260623_measured_benign.json`
- `benchmark_results/defense_bench_core_ci_deterministic_20260622.json`

This snapshot adds a GitHub Actions CI gate for deterministic defense
coverage. The workflow runs formatting, Clippy across all Cargo targets, Rust
tests, a RustSec dependency audit, Python tool tests, edge-template validation,
release build, then a loopback-only deterministic defense benchmark. The
benchmark assertion requires
loopback-only/XFF simulation safety metadata, the expected 18 scenarios, zero
hung workers, zero metrics scrape errors, and at least one defense layer per
scenario whose `effective_target_score` meets both attacker block and benign
allowance targets. The scenario check is exact, so dropping one attack family
and replacing it with another cannot pass by preserving the same scenario count.
Layer coverage is exact too: every scenario must include the direct-upstream
baseline plus proxy-open, per-IP rate-limit, path-shape rate-limit,
static-filter, and strict learned-filter layers, while the observed-learning
layer is required only for scenarios that exercise observed-learning behavior.
The static-filter layer is a manual-rule smoke test, not evidence that automated
mitigation worked. CI therefore requires the exact static-only passing set to be
empty: every scenario must have a passing automated layer in addition to the
broad benchmark static rule.
CI also requires every scored layer to show real phase traffic: collect phases
must have requests with zero errors and zero hung workers, learned-filter layers
must include replay traffic, and every scored layer must include bypass-probe
traffic. The open-proxy layer is also treated as a
negative control: it must carry the same attack workload with at least `95%`
allowed responses and must not meet the attacker-block target, proving later
passing layers are defense effects rather than a broken generator. Score
booleans are also cross-checked against the numeric target percentages, so a
scorer regression cannot mark a below-threshold layer as passing. A layer whose
benign allowance is unmeasured no longer counts as meeting the benign target.
The direct-upstream baseline is the only unscored layer; a legacy-only
`target_score` is ignored so stale artifacts cannot satisfy the CI gate. CI also
requires each scenario's direct-upstream baseline to show real traffic
generation before the proxy is involved: `requests > 0`, `errors = 0`,
`hung_workers = 0`, and at least `95%` allowed responses. Attack-side connection
errors count as stopped attack attempts in the score, while benign bypass errors
still fail the selected layer.

The Clippy step intentionally uses `cargo clippy --all-targets -- -D warnings`
instead of the default target set. This matches the local validation command and
keeps test, example, and future bench targets under the same warning-as-error
gate. Reference checks: [Clippy usage](https://doc.rust-lang.org/clippy/usage.html)
documents CI `-D warnings`, [Cargo target selection](https://doc.rust-lang.org/cargo/commands/cargo-check.html#target-selection)
documents `--all-targets`, and [rustup components](https://rust-lang.github.io/rustup/concepts/components.html)
documents `clippy` as an installable toolchain component.

The dependency audit step installs `cargo-audit` with Cargo's lockfile
resolution and runs `cargo audit` against `Cargo.lock`. The
[cargo-audit README](https://github.com/rustsec/rustsec/blob/main/cargo-audit/README.md)
documents it as a scanner for vulnerabilities reported to the RustSec Advisory
Database, and [RustSec](https://rustsec.org/) documents the advisory database as
the source of those Rust crate vulnerability records.

Local release build, loopback only:

```bash
python3 tools/run_defense_bench.py \
  --preset all \
  --no-codex \
  --duration 1 \
  --workers 8 \
  --analyzer-wait 8 \
  --json-only > /tmp/altura-defense-ci-check.json
expected_scenarios=basic,cachebuster,rotating-path,uuid-path,mixed-user-agent,smart-api-mix,xff-single,xff-rotating,xff-polymorphic,catalog-mimic-xff,dictionary-slug-xff,hex-slug-xff,v2-polymorphic-xff,method-spray-xff,accept-spray-xff,legit-interleave-xff,slow-xff-polymorphic,mozilla-polymorphic-xff
expected_common_layers=direct_upstream,proxy_open,rate_limit,path_shape_rate_limit,static_filter,learned_filter_strict
expected_observed_learning_scenarios=smart-api-mix,xff-single,xff-rotating,xff-polymorphic,catalog-mimic-xff,dictionary-slug-xff,hex-slug-xff,v2-polymorphic-xff,method-spray-xff,accept-spray-xff,legit-interleave-xff,slow-xff-polymorphic,mozilla-polymorphic-xff
expected_static_only_scenarios=
python3 tools/assert_defense_bench.py \
  /tmp/altura-defense-ci-check.json \
  --expect-scenarios 18 \
  --require-provenance \
  --expect-provider deterministic \
  --expect-preset all \
  --expect-scenario-set "$expected_scenarios" \
  --expect-common-layer-set "$expected_common_layers" \
  --expect-observed-learning-scenarios "$expected_observed_learning_scenarios" \
  --expect-static-only-scenarios "$expected_static_only_scenarios" \
  --min-duration 1 \
  --min-workers 8 \
  --min-analyzer-wait 8 \
  --expect-per-ip-rps 80 \
  --expect-path-shape-rps 80 \
  --expect-signature-threshold 60 \
  --require-direct-baseline \
  --require-layer-traffic \
  --require-open-proxy-negative-control \
  --require-score-consistency \
  --require-measured-benign
```

Local result: all 18 scenarios passed the assertion with `0` metrics scrape
errors and `0` hung workers. The lowest passing attacker blocked-or-limited
rates were `mixed-user-agent` at `95.87%`, `mozilla-polymorphic-xff` at
`97.74%`, `method-spray-xff` at `97.77%`, and `v2-polymorphic-xff` at `97.77%`.
Passing benign probes were at least `95.0%` where the selected layer included a
bypass probe.

Current-tree local rerun on 2026-06-23 with the stricter assertion also passed
all 18 scenarios with `0` metrics scrape errors and `0` hung workers. The lowest
selected passing attacker blocked-or-limited rates were `method-spray-xff` at
`97.70%`, `accept-spray-xff` at `97.73%`, `v2-polymorphic-xff` at `97.83%`,
`mozilla-polymorphic-xff` at `97.87%`, and `xff-polymorphic` at `97.89%`.
Passing benign probes were at least `95.0%` where the selected layer included a
bypass probe. A 2026-06-23 assertion-only hardening pass kept the same artifact
valid while adding unit coverage that rejects reports with only the legacy
`target_score` field.

A follow-up 2026-06-23 rerun models `slow-xff-polymorphic` as a distributed
low-rate flood: each attack worker still sleeps `40 ms` between requests, but
the scenario uses at least 128 attack workers so the aggregate route-family
pressure exceeds the configured path-shape and learned-filter thresholds during
the short CI window. The empty static-only expectation passed for all 18
scenarios. `slow-xff-polymorphic` selected `learned_filter_observed` at `93.75%`
attacker blocked-or-limited and `100.0%` benign allowed, so the broad static
benchmark rule no longer masks that scenario's automated coverage.

A later 2026-06-23 measured-benign rerun tightens the score contract: every
defense layer now runs a benign bypass probe after a short token-bucket refill
pause, and `meets_benign_allow_target` is false unless the probe reports at
least `95%` allowed responses with zero bypass errors. The strict assertion
passed for all 18 scenarios with an empty static-only selected set. Every
selected passing layer reported measured benign allowance at `100.0%`; the
lowest selected attacker stopped rates were `slow-xff-polymorphic` at `93.93%`,
`xff-polymorphic` at `97.86%`, `method-spray-xff` at `97.90%`,
`accept-spray-xff` at `97.91%`, `mozilla-polymorphic-xff` at `97.92%`, and
`v2-polymorphic-xff` at `97.94%`. This closes the prior proof gap where coarse
rate/path-shape layers could pass on attack shedding while `benign_allowed` was
`null`.

A current-tree 2026-06-23 rerun after the TCP full-duplex and CodeRabbit tool
follow-ups also passed the strict assertion for all 18 scenarios:
`benchmark_results/defense_bench_ci_deterministic_20260623_current.json`. The
lowest selected passing attacker blocked-or-limited rates were
`legit-interleave-xff` at `95.92%`, `xff-polymorphic` at `97.88%`,
`method-spray-xff` at `97.91%`, `accept-spray-xff` at `97.94%`,
`catalog-mimic-xff` at `98.02%`, and `dictionary-slug-xff` at `98.03%`.
Every selected passing layer reported measured benign allowance at `100.0%`.

A later current-tree 2026-06-23 rerun after the HTTP body minimum-rate bank
guard and adaptive-window local-bench assertion follow-up also passed the same
strict assertion for all 18 scenarios:
`benchmark_results/defense_bench_ci_deterministic_20260623_fresh.json`. The
strict checker's passing-layer summary reported selected attacker
blocked-or-limited rates as low as
`legit-interleave-xff` at `95.94%`, `accept-spray-xff` at `97.88%`,
`xff-polymorphic` at `97.91%`, `method-spray-xff` at `97.94%`,
`catalog-mimic-xff` at `98.01%`, and `dictionary-slug-xff` at `98.02%`.
Every selected passing layer again reported measured benign allowance at
`100.0%`.

New defense-benchmark reports also include `generated_at_utc` and a
`source_tree` object with the current working directory plus best-effort Git
root, branch, commit, short commit, and dirty-state fields. Trees copied without
`.git`, such as some `core` benchmark workdirs, keep those Git fields `null`
instead of failing the run; that makes historical JSON easier to classify
without adding a hard Git dependency to local-only benchmark execution. CI runs
`tools/assert_defense_bench.py --require-provenance` so fresh benchmark reports
must carry a parseable UTC generation timestamp and non-null Git source
identity; old or copied artifacts can still be inspected manually without that
flag. CI also asserts that the deterministic defense report came from the
intended all-scenario run: provider `deterministic`, preset `all`, at least 1
second, 8 workers, 8 seconds of analyzer wait, `per_ip_rps=80`,
`path_shape_rps=80`, and signature threshold `60`.

CI also audits source-controlled defense benchmark artifacts with
`tools/assert_defense_bench.py --audit-tracked-artifacts benchmark_results`.
The audit uses `git ls-files` to check only tracked `defense_bench*.json`
files, so local scratch runs under `benchmark_results/` do not affect the gate.
Any tracked artifact that cannot pass the current provenance/schema assertion
must be explicitly listed in
`benchmark_results/defense_artifacts_manifest.json` with a historical reason.
The manifest currently labels the tracked 2026-06-18 Codex snapshots as
historical pre-provenance evidence rather than current CI proof.

Reference checks used for the artifact audit:

- [Google SRE handling overload](https://sre.google/sre-book/handling-overload/) frames overload handling around maintaining useful service under excess demand, which is why the gate now requires measured benign availability as well as attack shedding.
- [Envoy local rate limit docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter) model rate limits with token buckets and descriptors; the benchmark keeps descriptor-like scenario dimensions while verifying allowed benign traffic.
- [NGINX `limit_req` docs](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) describe rate limiting as delaying or rejecting excess requests, reinforcing that configured limits need a measured non-excess path.
- [OWASP Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service) defines the risk as loss of availability for legitimate users; the measured-benign assertion directly checks that side of the DDoS contract.
- [Python argparse docs](https://docs.python.org/3/library/argparse.html) document optional positional arguments and option parsing used for the report-or-audit command mode.
- [Python json docs](https://docs.python.org/3/library/json.html) document built-in JSON parsing/validation without a new package dependency.
- [Git `ls-files` docs](https://git-scm.com/docs/git-ls-files) document listing files tracked in the index; the audit relies on this to avoid untracked local benchmark output.

`core` release build, loopback only, using the same command and artifact path
under `/root/altura-prot-ci-gate-20260622`: all 18 scenarios passed the
assertion with `0` metrics scrape errors and `0` hung workers. The lowest
passing attacker blocked-or-limited rates were `mozilla-polymorphic-xff` at
`97.78%`, `xff-rotating` at `97.87%`, `legit-interleave-xff` at `98.34%`, and
`catalog-mimic-xff` at `98.47%`. Passing benign probes were at least `96.0%`
where the selected layer included a bypass probe.

## 2026-06-22 Adaptive Window Preservation Follow-Up

Artifacts:

- `benchmark_results/local_bench_adaptive_window_preserve_20260622.json`

This follow-up hardens adaptive detector capacity behavior under
high-cardinality churn. Signature and path-shape detector shards now preserve
recent windows, reclaim idle windows, and stop admitting new detector keys when a
full shard has no idle candidate. That prevents fresh unique signatures or path
shapes from resetting hot learned evidence while keeping detector maps inside
their configured caps.

Local release build, loopback only, short guardrail run:

| Probe | Result |
| --- | --- |
| high-cardinality adaptive probe requests | `512` requests, all `204` |
| signature windows after probe | `64` of `64` capacity |
| path-shape windows after probe | `1` of `64` capacity |
| bounded checks | `signature_windows_bounded: true`, `path_shape_windows_bounded: true` |

Validation commands:

```bash
cargo fmt --check
cargo test adaptive -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py tools/run_defense_bench.py tools/assert_defense_bench.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 32 --tcp-workers 16 > benchmark_results/local_bench_adaptive_window_preserve_20260622.json
jq -e '.guardrails.adaptive_window_cap.signature_windows_bounded == true and .guardrails.adaptive_window_cap.path_shape_windows_bounded == true and .guardrails.adaptive_window_cap.all_requests_ok == true' benchmark_results/local_bench_adaptive_window_preserve_20260622.json
```

## 2026-06-22 Limiter Admission Follow-Up

Artifacts:

- `benchmark_results/local_bench_limiter_admission_20260622.json`

This follow-up tightens limiter admission ordering. Global request and
connection-open token buckets are no longer held across per-client shard cleanup,
and per-client request/TCP/HTTP connection-open tokens are consumed only after
the other relevant global and per-client gates admit the attempt. Obvious global
connection or in-flight saturation is rejected before creating avoidable
per-client limiter state.

Local release build, loopback only, short guardrail run:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8899.02 RPS | `204: 8917` | 0 | 6.376 ms |
| admin health | 9117.98 RPS | `200: 9153` | 0 | 6.232 ms |
| raw TCP persistent echo | 17709.86 msg/s | `17731` echoed messages | 0 | 1.651 ms |

Guardrail checks from the same artifact:

| Probe | Result |
| --- | --- |
| tracked-IP active-shard fail-closed | passed |
| request rate limiting before filter evaluation | passed |
| HTTP connection-open rate limiting | passed |
| adaptive signature/path-shape windows bounded | passed |
| upstream failure circuit opens and stays path-shape scoped | passed |

Validation commands:

```bash
cargo fmt --check
cargo test limiter -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py tools/run_defense_bench.py tools/assert_defense_bench.py tools/codex_analyzer.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 32 --tcp-workers 16 > benchmark_results/local_bench_limiter_admission_20260622.json
jq -e '.guardrails.tracked_ip_cap.new_client_denied_when_active_shard_full == true and .guardrails.rate_limit_before_filter.rate_limit_precedes_filter == true and .guardrails.http_connection_rate.connection_rate_limited == true and .guardrails.adaptive_window_cap.signature_windows_bounded == true and .guardrails.adaptive_window_cap.path_shape_windows_bounded == true and .guardrails.upstream_failure_circuit.circuit_opened_after_consecutive_failures == true and .guardrails.upstream_failure_circuit.circuit_scoped_to_path_shape == true' benchmark_results/local_bench_limiter_admission_20260622.json
```

## 2026-06-22 Connection Duration Runtime Follow-Up

Artifacts:

- `benchmark_results/local_bench_connection_duration_runtime_20260622.json`

This follow-up closes the benchmark gap around runtime max-connection-duration
enforcement. Startup validation already rejects excessive HTTP/TCP max duration
values; the local harness now also starts a one-second HTTP keep-alive proxy and
a one-second raw TCP proxy, holds each connection beyond the configured duration,
and asserts that the next use observes a closed/reset connection instead of more
work being accepted.

Reference checks used for the change:

- [NGINX stream proxy docs](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html) expose TCP stream timeouts and upload/download rate knobs as configurable per deployment.
- [Envoy TCP proxy docs](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto) document idle timeout and max downstream connection duration as explicit TCP proxy controls.

Local release build, loopback only, short guardrail run:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8895.99 RPS | `204: 8917` | 0 | 6.369 ms |
| admin health | 9333.03 RPS | `200: 9350` | 0 | 5.966 ms |
| raw TCP persistent echo | 17478.58 msg/s | `17499` echoed messages | 0 | 1.675 ms |

Runtime duration guardrails:

| Probe | Result |
| --- | --- |
| HTTP keep-alive first response | `204` |
| HTTP second request after one-second max duration | closed/reset before response |
| TCP first echo before one-second max duration | `12` bytes echoed |
| TCP second write/read after one-second max duration | closed/reset before echo |

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 32 --tcp-workers 16 > benchmark_results/local_bench_connection_duration_runtime_20260622.json
jq -e '.guardrails.connection_duration_runtime.http_max_connection_duration_enforced == true and .guardrails.connection_duration_runtime.tcp_max_connection_duration_enforced == true and .guardrails.connection_duration_ceiling_startup.http_max_connection_duration_rejected == true and .guardrails.connection_duration_ceiling_startup.tcp_max_connection_duration_rejected == true' benchmark_results/local_bench_connection_duration_runtime_20260622.json
```

## 2026-06-22 Filter Activation Nonblocking Snapshot

Artifacts:

- `benchmark_results/local_bench_filter_activation_nonblocking_20260622.json`
- `benchmark_results/local_bench_filter_activation_reload_20260623.json`
- `benchmark_results/local_bench_core_filter_activation_nonblocking_20260622.json`

This snapshot removes the long rule-list write lock from adaptive filter
activation. Request evaluation now clones the current `Arc<Vec<RuntimeRule>>`
under a short read lock, scans the snapshot after releasing the lock, and reads
adaptive activation state from per-rule atomic deadlines. Activation updates the
matching rule deadlines and the deadline-preservation map without taking the
rule-list write lock; reload builds a new validated snapshot and swaps it in
while preserving unexpired activation deadlines.

The 2026-06-23 follow-up extends the proof to the review-requested concurrent
reload case: while adaptive activation is being triggered against 512 dormant
adaptive rules, the benchmark writes and reloads a separate 512-rule runtime
filter file and keeps a control-request loop active. The guardrail requires the
runtime-only rule to block after reload, the activated adaptive rule to block
after activation, and all concurrent control requests to remain `204`.

Reference checks used for the change:

- [Rust `RwLock`](https://doc.rust-lang.org/std/sync/struct.RwLock.html) allows multiple readers or one writer, and OS-dependent writer priority can make long reader/writer sections an availability risk.
- [Rust `Arc`](https://doc.rust-lang.org/std/sync/struct.Arc.html) clone shares the same allocation through a reference count, which fits short snapshot acquisition.
- [arc-swap](https://docs.rs/arc-swap/latest/arc_swap/) is a read-mostly atomic `Arc` option, but was not added because the std-only snapshot keeps the hot path simple and dependency-free.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 7846.75 RPS | `204: 15745` | 0 | 14.910 ms |
| admin health | 8470.56 RPS | `200: 16976` | 0 | 13.739 ms |
| raw TCP persistent echo | 17594.72 msg/s | `35234` echoed messages | 0 | 3.403 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 7002.79 RPS | `204: 14054` | 0 | 16.160 ms |
| admin health on `core` | 6714.25 RPS | `200: 13477` | 0 | 16.967 ms |
| raw TCP persistent echo on `core` | 28384.82 msg/s | `56820` echoed messages | 0 | 1.080 ms |

Filter-activation nonblocking probe:

| Probe | Local | `core` |
| --- | --- | --- |
| configured adaptive rule count | `512` | `512` |
| activation trigger statuses | `204,403,403,403,403,403,403` | `204,403,403,403,403,403,403` |
| final matching request status | `403` | `403` |
| concurrent control request count | `6` | `6` |
| control request errors | `0` | `0` |
| max control request latency | `1.481 ms` | `0.790 ms` |
| active filters after activation | `1` | `1` |
| activation nonblocking guardrail | `true` | `true` |

Current-tree local follow-up on 2026-06-23:

| Probe | Result |
| --- | --- |
| configured dormant adaptive rules | `512` |
| configured runtime reload rules | `512` |
| runtime reload file size | `117750` bytes |
| activation trigger statuses | `204,429,429,429,429,429,429` |
| runtime-only reload match status | `403` |
| final adaptive match status | `403` |
| active filters after reload and activation | `513` |
| concurrent control request count | `6171` |
| control request errors | `0` |
| max control request latency | `5.142 ms` |
| activation plus runtime reload nonblocking guardrail | `true` |

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo fmt --check
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 32 > benchmark_results/local_bench_filter_activation_nonblocking_20260622.json
jq -e '.guardrails.filter_activation_nonblocking.activation_nonblocking == true and .guardrails.filter_activation_nonblocking.final_matching_status == 403 and .guardrails.filter_activation_nonblocking.control_errors == 0 and .guardrails.runtime_filter_hot_path.many_rules_loaded == true and .guardrails.rate_limit_before_filter.rate_limit_precedes_filter == true and .guardrails.tracked_ip_cap.new_client_denied_when_active_shard_full == true' benchmark_results/local_bench_filter_activation_nonblocking_20260622.json
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 32 --tcp-workers 16 > benchmark_results/local_bench_filter_activation_reload_20260623.json
jq -e '.guardrails.filter_activation_nonblocking.activation_reload_nonblocking == true and .guardrails.filter_activation_nonblocking.runtime_reload_loaded == true and .guardrails.filter_activation_nonblocking.runtime_reload_status == 403 and .guardrails.filter_activation_nonblocking.control_errors == 0 and .guardrails.filter_activation_nonblocking.configured_rule_count == 512 and .guardrails.filter_activation_nonblocking.configured_runtime_rule_count == 512' benchmark_results/local_bench_filter_activation_reload_20260623.json

ssh core 'rm -rf /root/altura-prot-filter-activation-nonblocking-20260622 && mkdir -p /root/altura-prot-filter-activation-nonblocking-20260622 /root/altura-prot-tmp'
rsync -az --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-filter-activation-nonblocking-20260622/
ssh core 'cd /root/altura-prot-filter-activation-nonblocking-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py && PYTHONPATH=tools python3 tools/test_ai_tools.py && python3 tools/validate_edge_templates.py --config configs/example.json && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-filter-activation-nonblocking-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release && mkdir -p benchmark_results && TMPDIR=/root/altura-prot-tmp python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_filter_activation_nonblocking_20260622.json'
rsync -az core:/root/altura-prot-filter-activation-nonblocking-20260622/benchmark_results/local_bench_core_filter_activation_nonblocking_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.filter_activation_nonblocking.activation_nonblocking == true and .guardrails.filter_activation_nonblocking.final_matching_status == 403 and .guardrails.filter_activation_nonblocking.control_errors == 0 and .guardrails.runtime_filter_hot_path.many_rules_loaded == true and .guardrails.rate_limit_before_filter.rate_limit_precedes_filter == true and .guardrails.tracked_ip_cap.new_client_denied_when_active_shard_full == true' benchmark_results/local_bench_core_filter_activation_nonblocking_20260622.json
```

`core` was used for the remote loopback benchmark. Clippy and `cargo
fmt --check` were enforced locally.

## 2026-06-22 Tracked-Key Fail-Closed Snapshot

Artifacts:

- `benchmark_results/local_bench_tracked_key_fail_closed_20260622.json`
- `benchmark_results/local_bench_core_tracked_key_fail_closed_20260622.json`

This snapshot fixes active rate-bucket eviction under high-cardinality churn.
Per-client, signature, and path-shape rate limiters still evict stale entries
inside their configured state caps, but when a shard is full of active buckets a
new key is denied instead of evicting an active bucket and receiving a fresh
burst. Connection and in-flight limiters already used the same fail-closed
pattern for shards full of active entries. Follow-up hardening caps each
eviction attempt to `32` queue probes, so a new distinct key cannot force a full
large-shard scan while holding the limiter mutex; additional requests continue
incremental stale/idle cleanup.

Reference checks used for the change:

- [NGINX `limit_req`](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) keeps bounded keyed state and terminates requests when new state cannot be created after LRU cleanup.
- [HAProxy stick tables](https://www.haproxy.com/blog/four-examples-of-haproxy-rate-limiting) use expiring keyed records for rate limiting and remove inactive records to free space.
- [Envoy local rate limit dynamic descriptors](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/local_ratelimit/v3/local_rate_limit.proto) bound dynamic descriptor state with an explicit maximum.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8651.90 RPS | `204: 17345` | 0 | 13.363 ms |
| admin health | 9043.49 RPS | `200: 18128` | 0 | 12.445 ms |
| raw TCP persistent echo | 18357.40 msg/s | `36752` echoed messages | 0 | 3.203 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6537.29 RPS | `204: 13115` | 0 | 17.384 ms |
| admin health on `core` | 6527.67 RPS | `200: 13099` | 0 | 17.385 ms |
| raw TCP persistent echo on `core` | 28125.85 msg/s | `56310` echoed messages | 0 | 1.089 ms |

Tracked-key cap probe:

| Probe | Local | `core` |
| --- | --- | --- |
| first request from same-shard forwarded client A | `204` | `204` |
| second request from client A | `429` | `429` |
| first request from same-shard forwarded client B while shard is full | `429` | `429` |
| third request from client A after B is denied | `429` | `429` |
| new active client denied when shard full | `true` | `true` |
| first client bucket not evicted | `true` | `true` |

Same-run framing guardrails also preserved the no-allocation
Transfer-Encoding comma-spray rejection path: `Transfer-Encoding: gzip, ...`
and an empty comma spray both returned `400`, and explicit
`allow_chunked_request_bodies: true` still allowed a valid chunked request.

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test limiter -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 32 > benchmark_results/local_bench_tracked_key_fail_closed_20260622.json

ssh core 'rm -rf /root/altura-prot-tracked-key-fail-closed-20260622 && mkdir -p /root/altura-prot-tracked-key-fail-closed-20260622 /root/altura-prot-tmp'
rsync -az --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-tracked-key-fail-closed-20260622/
ssh core 'cd /root/altura-prot-tracked-key-fail-closed-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-tracked-key-fail-closed-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-tracked-key-fail-closed-20260622 && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-tracked-key-fail-closed-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release'
ssh core 'cd /root/altura-prot-tracked-key-fail-closed-20260622 && mkdir -p benchmark_results && TMPDIR=/root/altura-prot-tmp python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_tracked_key_fail_closed_20260622.json'
rsync -az core:/root/altura-prot-tracked-key-fail-closed-20260622/benchmark_results/local_bench_core_tracked_key_fail_closed_20260622.json /Users/core/AlturaProt/benchmark_results/
```

`core` was used for the remote loopback benchmark. Clippy was enforced locally
with `-D warnings`.

## 2026-06-22 Rate Limits Before Filter Evaluation Snapshot

Artifacts:

- `benchmark_results/local_bench_rate_limit_before_filter_20260622.json`
- `benchmark_results/local_bench_core_rate_limit_before_filter_20260622.json`

This snapshot moves normal HTTP request-rate checks ahead of static/runtime
filter evaluation. After method, Host, forwarded-header, request-target,
framing, content-coding, `Expect`, `Range`, and declared body-size guards pass,
AlturaProt now checks signature, path-shape, per-client/global, and
trusted-proxy aggregate request buckets before taking the filter read lock or
scanning loaded rules. Over-budget traffic therefore sheds with `429` even when
it would also match a block rule; in-budget traffic still reaches the filter
engine and receives the configured filter response.

Reference checks used for the change:

- [Envoy local rate limit](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter) returns `429` when a checked local token bucket is exhausted.
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) frames rate limiting as a resource-exhaustion control.
- [Cloudflare WAF concepts](https://developers.cloudflare.com/waf/concepts/) document that terminating actions stop later rule evaluation, so rule/limit ordering is an explicit availability decision.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8500.25 RPS | `204: 17035` | 0 | 13.378 ms |
| admin health | 8729.96 RPS | `200: 17498` | 0 | 13.077 ms |
| raw TCP persistent echo | 18397.72 msg/s | `36842` echoed messages | 0 | 3.206 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6992.92 RPS | `204: 14031` | 0 | 16.230 ms |
| admin health on `core` | 6751.81 RPS | `200: 13555` | 0 | 16.842 ms |
| raw TCP persistent echo on `core` | 28276.89 msg/s | `56608` echoed messages | 0 | 1.086 ms |

Rate-limit-before-filter probe:

| Probe | Local | `core` |
| --- | --- | --- |
| first request from client A to spend the IP bucket | `204` | `204` |
| second request from client A that also matches a block rule | `429` | `429` |
| first matching request from fresh client B | `403` | `403` |
| fresh client filter header | `rate-limit-before-filter` | `rate-limit-before-filter` |
| `altura_http_blocked` delta | `1` | `1` |
| `altura_http_rate_limited` delta | `1` | `1` |
| rate limit precedes filter guardrail | `true` | `true` |

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test rate_limit_denial_precedes_filter_evaluation -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo fmt --check
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 32 > benchmark_results/local_bench_rate_limit_before_filter_20260622.json
jq -e '.guardrails.rate_limit_before_filter.rate_limit_precedes_filter == true and .guardrails.rate_limit_before_filter.prime_status == 204 and .guardrails.rate_limit_before_filter.over_limit_matching_status == 429 and .guardrails.rate_limit_before_filter.fresh_matching_status == 403 and .guardrails.rate_limit_before_filter.http_blocked_delta == 1 and .guardrails.rate_limit_before_filter.http_rate_limited_delta >= 1' benchmark_results/local_bench_rate_limit_before_filter_20260622.json

ssh core 'rm -rf /root/altura-prot-rate-limit-before-filter-20260622 && mkdir -p /root/altura-prot-rate-limit-before-filter-20260622 /root/altura-prot-tmp'
rsync -az --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-rate-limit-before-filter-20260622/
ssh core 'cd /root/altura-prot-rate-limit-before-filter-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py && PYTHONPATH=tools python3 tools/test_ai_tools.py && python3 tools/validate_edge_templates.py --config configs/example.json && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-rate-limit-before-filter-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release && mkdir -p benchmark_results && TMPDIR=/root/altura-prot-tmp python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_rate_limit_before_filter_20260622.json'
rsync -az core:/root/altura-prot-rate-limit-before-filter-20260622/benchmark_results/local_bench_core_rate_limit_before_filter_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.rate_limit_before_filter.rate_limit_precedes_filter == true and .guardrails.rate_limit_before_filter.prime_status == 204 and .guardrails.rate_limit_before_filter.over_limit_matching_status == 429 and .guardrails.rate_limit_before_filter.fresh_matching_status == 403 and .guardrails.rate_limit_before_filter.http_blocked_delta == 1 and .guardrails.rate_limit_before_filter.http_rate_limited_delta >= 1' benchmark_results/local_bench_core_rate_limit_before_filter_20260622.json
```

`core` was used for the remote loopback benchmark. Clippy and `cargo
fmt --check` were enforced locally.

## 2026-06-22 Event Serialization Off Request Thread Snapshot

Artifacts:

- `benchmark_results/local_bench_event_serialization_off_thread_20260622.json`
- `benchmark_results/local_bench_core_event_serialization_off_thread_20260622.json`

This snapshot closes the remaining event-log hot-path cost after the async queue
work: request workers now enqueue bounded owned attack events, while JSON
serialization, file writes, flushes, and rotation run on the dedicated event-log
writer thread. Queue saturation still uses nonblocking `try_send`; events are
dropped and `altura_event_log_dropped` increments instead of making request
workers wait behind a blocked sink.

Reference checks used for the change:

- [Rust `sync_channel`](https://doc.rust-lang.org/std/sync/mpsc/fn.sync_channel.html) provides a bounded ordered channel; AlturaProt keeps `try_send` for nonblocking request-path enqueue.
- [Serde JSON](https://docs.rs/serde_json/latest/serde_json/) provides `to_vec`/writer-side serialization APIs, which are now used after dequeue rather than before enqueue.
- [tracing-appender non-blocking writer](https://docs.rs/tracing-appender/latest/tracing_appender/non_blocking/index.html) was checked as the reference pattern for moving log I/O to a dedicated worker; no new production dependency was added.
- [Clippy `large_enum_variant`](https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant) and [Rust `Box`](https://doc.rust-lang.org/std/boxed/struct.Box.html) were checked after clippy flagged the large owned-event command variant; the queued event payload is boxed to keep the command enum small.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8907.36 RPS | `204: 17832` | 0 | 6.272 ms |
| admin health | 8571.48 RPS | `200: 17161` | 0 | 6.532 ms |
| raw TCP persistent echo | 18830.28 msg/s | `37674` echoed messages | 0 | 0.704 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6673.20 RPS | `204: 13394` | 0 | 17.155 ms |
| admin health on `core` | 6558.96 RPS | `200: 13161` | 0 | 17.233 ms |
| raw TCP persistent echo on `core` | 28321.87 msg/s | `56697` echoed messages | 0 | 1.079 ms |

Blocked event-log sink guardrail:

| Probe | Local | `core` |
| --- | ---: | ---: |
| configured queue capacity | `1` | `1` |
| unique adaptive-event requests | 2000, all `204` | 2000, all `204` |
| request burst throughput | 6035.99 RPS | 4700.27 RPS |
| dropped event-log metric delta | `1982` | `1913` |
| queue-drop behavior observed | `true` | `true` |

Field-bounds and rotation guardrails remained intact in the same run:
`all_event_fields_bounded: true`, event line size `4749` bytes, and event-log
rotation retained valid JSONL with bounded active/backup files.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test event_logger -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 32 --tcp-workers 8 > benchmark_results/local_bench_event_serialization_off_thread_20260622.json

ssh core 'mkdir -p /root/altura-prot-event-serialization-off-thread-20260622 /root/altura-prot-tmp'
rsync -az --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/root/altura-prot-event-serialization-off-thread-20260622/
ssh core 'cd /root/altura-prot-event-serialization-off-thread-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-event-serialization-off-thread-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-event-serialization-off-thread-20260622 && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-event-serialization-off-thread-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release'
ssh core 'cd /root/altura-prot-event-serialization-off-thread-20260622 && python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_event_serialization_off_thread_20260622.json'
```

`core` did not have the `cargo clippy` subcommand installed in this run; clippy
was enforced locally with `-D warnings`.

## 2026-06-22 Upstream Failure Circuit Scoping Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_failure_circuit_scoped_20260622.json`
- `benchmark_results/local_bench_core_upstream_failure_circuit_scoped_20260622.json`
- `benchmark_results/local_bench_upstream_circuit_preserve_20260622.json`

This snapshot scopes the passive upstream failure circuit by normalized path
shape. Repeated upstream connect/header failures or upstream response timeouts
for one route family still open a short local fail-fast circuit for that shape,
but unrelated route families continue to attempt the upstream instead of being
shed by a service-wide breaker. Circuit state is sharded and bounded by the
existing `http.limits.max_tracked_path_shapes` cap. Follow-up hardening preserves
currently open circuit entries when a shard is full, reclaims closed or expired
entries first, and skips tracking a new failing shape if every probed entry is
still open.

Reference checks used for the change:

- [Envoy outlier detection](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/outlier) distinguishes locally originated failures such as timeouts and connect failures from transaction errors, and notes that one shared cluster ejection can affect other filter chains.
- [Envoy circuit breaking](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/circuit_breaking) tracks limits per upstream cluster and priority, supporting scoped limits rather than one undifferentiated global backstop.
- [NGINX passive health checks](https://nginx.org/en/docs/http/load_balancing.html) mark an upstream failed after `max_fails` within `fail_timeout`, and live requests probe again after the timeout.
- [NGINX upstream module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html) documents that a single-server upstream is never considered unavailable by its `max_fails`/`fail_timeout` mechanism, highlighting the blast-radius tradeoff of single-target passive ejection.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8935.42 RPS | `204: 17926` | 0 | 6.283 ms |
| admin health | 8907.08 RPS | `200: 17832` | 0 | 6.187 ms |
| raw TCP persistent echo | 19004.41 msg/s | `38022` echoed messages | 0 | 0.704 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6435.93 RPS | `204: 12919` | 0 | 17.660 ms |
| admin health on `core` | 6582.23 RPS | `200: 13213` | 0 | 17.240 ms |
| raw TCP persistent echo on `core` | 27954.64 msg/s | `55966` echoed messages | 0 | 1.094 ms |

Guardrail probe:

| Probe | Local | `core` |
| --- | ---: | ---: |
| first failing-shape upstream attempt | `502` after `0.078` s | `502` after `0.077` s |
| second failing-shape upstream attempt | `502` after `0.079` s | `502` after `0.077` s |
| third failing-shape request while circuit open | `503` after `0.000` s | `503` after `0.000` s |
| unrelated shape while failing shape is open | `502` after `0.078` s | `502` after `0.077` s |
| failing shape after open window | `502` after `0.078` s | `502` after `0.077` s |
| `circuit_scoped_to_path_shape` | `true` | `true` |
| `altura_http_upstream_circuit_open` delta | `1` | `1` |
| `altura_http_upstream_errors` delta | `4` | `4` |

Follow-up local guardrail artifact
`local_bench_upstream_circuit_preserve_20260622.json` preserved the same runtime
contract: the failing shape opened after two upstream failures, the third
matching request was locally shed with `503`/`Retry-After: 1`, an unrelated
shape still attempted upstream, the original shape was reallowed after the
configured open window, and adaptive detector window counts stayed bounded.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test upstream_failure_circuit -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 32 --tcp-workers 8 > benchmark_results/local_bench_upstream_failure_circuit_scoped_20260622.json

ssh core 'rm -rf /root/altura-prot-upstream-failure-circuit-scoped-20260622 && mkdir -p /root/altura-prot-upstream-failure-circuit-scoped-20260622 /root/altura-prot-tmp'
rsync -az --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/root/altura-prot-upstream-failure-circuit-scoped-20260622/
ssh core 'cd /root/altura-prot-upstream-failure-circuit-scoped-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py && PYTHONPATH=tools python3 tools/test_ai_tools.py && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-upstream-failure-circuit-scoped-20260622 && TMPDIR=/root/altura-prot-tmp cargo test upstream_failure_circuit -- --nocapture'
ssh core 'cd /root/altura-prot-upstream-failure-circuit-scoped-20260622 && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture && TMPDIR=/root/altura-prot-tmp cargo build --release'
ssh core 'cd /root/altura-prot-upstream-failure-circuit-scoped-20260622 && python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_upstream_failure_circuit_scoped_20260622.json'
```

`core` did not have the `cargo clippy` subcommand installed in this run; clippy
was enforced locally with `-D warnings`.

## 2026-06-22 Path-Shape Strong-Evidence Activation Snapshot

Artifacts:

- `benchmark_results/local_bench_path_shape_strong_evidence_20260622.json`
- `benchmark_results/local_bench_core_path_shape_strong_evidence_20260622.json`

This snapshot keeps observed route-family telemetry but prevents observed-only
successful traffic from activating broad adaptive path-shape filters.
Catalog/login/product-looking routes still have no hidden source-code
exemption: they use the same bounded path-shape windows as every other route
family. The activation threshold now applies to strong evidence from
deterministic denial paths, such as trusted-proxy aggregate limiting, rather
than plain request volume that could be legitimate flash traffic.

Reference checks used for the change:

- [OWASP DoS guidance](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) recommends cheap resource controls first and warns that thresholds should be based on genuine traffic baselines.
- [Cloudflare rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) separate match criteria, counting characteristics, thresholds, and mitigation duration, supporting explicit evidence before action.
- [Cloudflare HTTP DDoS rule categories](https://developers.cloudflare.com/ddos-protection/managed-rulesets/http/rule-categories/) note that generic flood rules can also trigger on unusual legitimate volume and therefore use higher activation thresholds or softer actions by default.
- [Envoy local rate limit](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter) returns `429` when a checked token bucket is exhausted, making rate-limit denials a concrete strong signal for downstream learning.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8815.49 RPS | `204: 17669` | 0 | 12.816 ms |
| admin health | 8838.75 RPS | `200: 17716` | 0 | 12.813 ms |
| raw TCP persistent echo | 18516.52 msg/s | `37077` echoed messages | 0 | 3.179 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6779.12 RPS | `204: 13603` | 0 | 16.747 ms |
| admin health on `core` | 6515.76 RPS | `200: 13079` | 0 | 17.560 ms |
| raw TCP persistent echo on `core` | 28318.65 msg/s | `56700` echoed messages | 0 | 1.085 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| observed-only catalog request statuses | `204,204,204,204` | `204,204,204,204` |
| observed-only filter-block delta | `0` | `0` |
| observed-only catalog traffic did not activate path-shape filter | `true` | `true` |
| trusted-proxy strong-evidence statuses | `204,429,429` | `204,429,429` |
| trusted-proxy rate-limit delta | `2` | `2` |
| fresh catalog request after strong evidence | `403` | `403` |
| blocked response carried `x-altura-filter: catalog-shape` | `true` | `true` |
| catalog shape requires strong evidence guardrail | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test adaptive -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 32 > benchmark_results/local_bench_path_shape_strong_evidence_20260622.json
jq -e '.guardrails.adaptive_catalog_shape.catalog_shape_requires_strong_evidence == true and .guardrails.adaptive_catalog_shape.observed_only_not_activated == true and .guardrails.adaptive_catalog_shape.strong_evidence_activated == true and .guardrails.filter_activation_nonblocking.activation_nonblocking == true and .guardrails.rate_limit_before_filter.rate_limit_precedes_filter == true and .guardrails.tracked_ip_cap.new_client_denied_when_active_shard_full == true' benchmark_results/local_bench_path_shape_strong_evidence_20260622.json

ssh core 'rm -rf /root/altura-prot-path-shape-strong-evidence-20260622 && mkdir -p /root/altura-prot-path-shape-strong-evidence-20260622 /root/altura-prot-tmp'
rsync -az --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-path-shape-strong-evidence-20260622/
ssh core 'cd /root/altura-prot-path-shape-strong-evidence-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py && PYTHONPATH=tools python3 tools/test_ai_tools.py && python3 tools/validate_edge_templates.py --config configs/example.json && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-path-shape-strong-evidence-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release && mkdir -p benchmark_results && TMPDIR=/root/altura-prot-tmp python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_path_shape_strong_evidence_20260622.json'
rsync -az core:/root/altura-prot-path-shape-strong-evidence-20260622/benchmark_results/local_bench_core_path_shape_strong_evidence_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.adaptive_catalog_shape.catalog_shape_requires_strong_evidence == true and .guardrails.adaptive_catalog_shape.observed_only_not_activated == true and .guardrails.adaptive_catalog_shape.strong_evidence_activated == true and .guardrails.filter_activation_nonblocking.activation_nonblocking == true and .guardrails.rate_limit_before_filter.rate_limit_precedes_filter == true and .guardrails.tracked_ip_cap.new_client_denied_when_active_shard_full == true' benchmark_results/local_bench_core_path_shape_strong_evidence_20260622.json
```

`core` was used for the remote loopback benchmark. Clippy and `cargo
fmt --check` were enforced locally.

## 2026-06-22 Path Shape, Adaptive Window, and Min-Rate Hardening Snapshot

Artifacts:

- `benchmark_results/local_bench_path_shape_window_minrate_20260622.json`
- `benchmark_results/local_bench_core_path_shape_window_minrate_20260622.json`

This snapshot closes four review-confirmed DDoS protection gaps:

- Path-shape keys collapse high-confidence short tokens immediately, while
  short lowercase rotations such as `/api/ab`, `/api/cd`, and `/api/ef` are
  handled by a bounded sibling-churn bucket that preserves stable short routes
  and version segments such as `/api/v1`.
- Adaptive signature and path-shape activation use rolling token-bucket
  counters instead of a one-second tumbling reset.
- Detector and limiter high-cardinality state uses bounded admission/cleanup work
  instead of repeated full-map retain/min scans on insertion. Adaptive detector
  shards preserve recent windows and only reclaim idle windows; limiter shards
  deny new active keys rather than resetting hot buckets.
- HTTP request/upstream body and raw TCP min-rate guards measure from the grace
  deadline as soon as post-grace bytes arrive, so a fast initial payload cannot
  bank lifetime average credit or a free first post-grace drip.

The same slice also rejects root-wide `path_prefix: "/"` filter rules, recovers
limiter mutex poison the same way as adaptive/filter state, compares metrics
tokens with a constant-work helper, and moves TCP global admission after per-IP
checks so denied per-IP TCP connections do not transiently count against the
global active-connection cap.

Reference checks used for the change:

- [Kestrel server limits](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/options?view=aspnetcore-10.0) document periodic minimum data-rate enforcement after a grace period.
- [Apache `mod_reqtimeout`](https://httpd.apache.org/docs/current/mod/mod_reqtimeout.html) documents finite low-rate request-body/header enforcement.
- [NGINX `limit_req`](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html), [Envoy local rate limit](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter), and [Cloudflare WAF rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) support keyed route/descriptor-style rate limiting rather than relying only on exact dynamic paths.
- [Rust `Mutex`](https://doc.rust-lang.org/std/sync/struct.Mutex.html) documents poison recovery through `into_inner()`, and [RustCrypto `subtle`](https://github.com/dalek-cryptography/subtle) was checked before choosing a no-new-dependency constant-work token compare.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8691.25 RPS | `204: 17401` | 0 | 6.539 ms |
| admin health | 8427.89 RPS | `200: 16875` | 0 | 7.027 ms |
| raw TCP persistent echo | 18708.05 msg/s | `37430` echoed messages | 0 | 0.715 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6397.65 RPS | `204: 12846` | 0 | 17.875 ms |
| admin health on `core` | 6570.59 RPS | `200: 13185` | 0 | 17.269 ms |
| raw TCP persistent echo on `core` | 27889.86 msg/s | `55843` echoed messages | 0 | 1.103 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| long-token path-shape burst returned `204,204,429,429` | `true` | `true` |
| short-token sibling-churn burst returned `204,204,429,429` | `true` | `true` |
| version route shape `/api/v1/users` remained allowed | `true` | `true` |
| path-shape and aggregate rate-limit counters increased by 4 | `true` | `true` |
| HTTP request body recent min-rate rejected slow drip | `true` | `true` |
| HTTP upstream body recent min-rate rejected slow drip | `true` | `true` |
| TCP downstream recent min-rate rejected slow drip | `true` | `true` |
| static filter `ttl_seconds` ceiling rejected | `true` | `true` |
| adaptive activation TTL ceiling rejected | `true` | `true` |

Validation commands:

```bash
cargo fmt
python3 -m py_compile tools/codex_analyzer.py tools/test_ai_tools.py tools/run_local_bench.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 32 --tcp-workers 8 > benchmark_results/local_bench_path_shape_window_minrate_20260622.json

ssh core 'mkdir -p /root/altura-prot-path-shape-window-minrate-20260622 /root/altura-prot-tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-path-shape-window-minrate-20260622/
ssh core 'cd /root/altura-prot-path-shape-window-minrate-20260622 && python3 -m py_compile tools/codex_analyzer.py tools/test_ai_tools.py tools/run_local_bench.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-path-shape-window-minrate-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-path-shape-window-minrate-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-path-shape-window-minrate-20260622 && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-path-shape-window-minrate-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release'
ssh core 'cd /root/altura-prot-path-shape-window-minrate-20260622 && mkdir -p benchmark_results && TMPDIR=/root/altura-prot-tmp python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_path_shape_window_minrate_20260622.json'
rsync -a core:/root/altura-prot-path-shape-window-minrate-20260622/benchmark_results/local_bench_core_path_shape_window_minrate_20260622.json /Users/core/AlturaProt/benchmark_results/
```

## 2026-06-22 HTTP Metadata Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_http_metadata_ceiling_20260622.json`
- `benchmark_results/local_bench_core_http_metadata_ceiling_20260622.json`

This snapshot adds startup ceilings for request metadata, trailer metadata, and
trusted-forwarded-header parsing caps:

- `http.max_host_bytes` must be no higher than `1024`.
- `http.max_uri_bytes` and `http.max_query_bytes` must be no higher than `65536`.
- `http.max_query_pairs` must be no higher than `8192`.
- `http.max_path_segments` must be no higher than `4096`.
- `http.max_trailer_bytes` and `http.upstream_max_trailer_bytes` must be no higher than `262144`.
- `http.max_trailers` and `http.upstream_max_trailers` must be no higher than `1024`.
- `http.client_ip.max_forwarded_for_bytes` must be no higher than `16384`.
- `http.client_ip.max_forwarded_for_hops` must be no higher than `256`.

These ceilings keep request-target parsing, Host validation, trailer processing,
and trusted proxy identity parsing finite even after a bad config deploy. The
defaults remain much smaller, so normal deployments should not need to approach
the ceilings.

Reference checks used for the change:

- [Apache `LimitRequestLine`, `LimitRequestFieldSize`, and `LimitRequestFields`](https://httpd.apache.org/docs/current/mod/core.html) document request-line/header-field/header-count limits, common defaults near 8 KiB and 100 fields, and DoS-control rationale.
- [NGINX `client_header_buffer_size` and `large_client_header_buffers`](https://nginx.org/en/docs/http/ngx_http_core_module.html#large_client_header_buffers) default to small header buffers and reject oversized request lines/header fields.
- [HAProxy `tune.bufsize` and `tune.http.maxhdr`](https://docs.haproxy.org/2.8/configuration.html) document memory impact from larger buffers and a bounded header-count range.
- [MDN `Host`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Host) documents Host as the request host plus optional port, supporting a small finite Host cap.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9371.11 RPS | `204: 18760` | 0 | 6.031 ms |
| admin health | 9302.92 RPS | `200: 18625` | 0 | 5.990 ms |
| raw TCP persistent echo | 19286.32 msg/s | `38586` echoed messages | 0 | 0.686 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6505.40 RPS | `204: 13059` | 0 | 17.541 ms |
| admin health on `core` | 6528.82 RPS | `200: 13106` | 0 | 17.411 ms |
| raw TCP persistent echo on `core` | 28285.99 msg/s | `56625` echoed messages | 0 | 1.088 ms |

Startup ceiling guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.max_host_bytes: 1025` rejected | `true` | `true` |
| `http.max_uri_bytes: 65537` rejected | `true` | `true` |
| `http.max_query_bytes: 65537` rejected | `true` | `true` |
| `http.max_query_pairs: 8193` rejected | `true` | `true` |
| `http.max_path_segments: 4097` rejected | `true` | `true` |
| `http.max_trailer_bytes: 262145` rejected | `true` | `true` |
| `http.max_trailers: 1025` rejected | `true` | `true` |
| `http.upstream_max_trailer_bytes: 262145` rejected | `true` | `true` |
| `http.upstream_max_trailers: 1025` rejected | `true` | `true` |
| `http.client_ip.max_forwarded_for_bytes: 16385` rejected | `true` | `true` |
| `http.client_ip.max_forwarded_for_hops: 257` rejected | `true` | `true` |
| all HTTP metadata ceilings rejected | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
cargo test metadata_caps -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 32 --tcp-workers 8 > benchmark_results/local_bench_http_metadata_ceiling_20260622.json
jq -e '.guardrails.http_metadata_ceiling_startup.all_http_metadata_ceilings_rejected == true and ([.guardrails.http_metadata_ceiling_startup.max_host_bytes, .guardrails.http_metadata_ceiling_startup.max_uri_bytes, .guardrails.http_metadata_ceiling_startup.max_query_bytes, .guardrails.http_metadata_ceiling_startup.max_query_pairs, .guardrails.http_metadata_ceiling_startup.max_path_segments, .guardrails.http_metadata_ceiling_startup.max_trailer_bytes, .guardrails.http_metadata_ceiling_startup.max_trailers, .guardrails.http_metadata_ceiling_startup.upstream_max_trailer_bytes, .guardrails.http_metadata_ceiling_startup.upstream_max_trailers, .guardrails.http_metadata_ceiling_startup.max_forwarded_for_bytes, .guardrails.http_metadata_ceiling_startup.max_forwarded_for_hops] | all(.startup_rejected == true)) and (.guardrails.http_metadata_ceiling_startup.max_host_bytes.stderr_tail | join("\n") | contains("http.max_host_bytes")) and (.guardrails.http_metadata_ceiling_startup.max_uri_bytes.stderr_tail | join("\n") | contains("http.max_uri_bytes")) and (.guardrails.http_metadata_ceiling_startup.max_forwarded_for_hops.stderr_tail | join("\n") | contains("http.client_ip.max_forwarded_for_hops"))' benchmark_results/local_bench_http_metadata_ceiling_20260622.json benchmark_results/local_bench_core_http_metadata_ceiling_20260622.json

ssh core 'mkdir -p /root/altura-prot-http-metadata-ceiling-20260622 /root/altura-prot-tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-http-metadata-ceiling-20260622/
ssh core 'cd /root/altura-prot-http-metadata-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-http-metadata-ceiling-20260622 && TMPDIR=/root/altura-prot-tmp cargo test metadata_caps -- --nocapture'
ssh core 'cd /root/altura-prot-http-metadata-ceiling-20260622 && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-http-metadata-ceiling-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release'
ssh core 'cd /root/altura-prot-http-metadata-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/altura-prot-tmp python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_http_metadata_ceiling_20260622.json'
rsync -a core:/root/altura-prot-http-metadata-ceiling-20260622/benchmark_results/local_bench_core_http_metadata_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
```

Core still lacks `cargo fmt` and `cargo clippy` subcommands, so those checks ran
locally.

## 2026-06-22 Min Rate Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_min_rate_ceiling_20260622.json`
- `benchmark_results/local_bench_core_min_rate_ceiling_20260622.json`

This snapshot adds startup ceilings for minimum data-rate byte floors:
`http.request_body_min_rate_bytes_per_second`,
`http.upstream_body_min_rate_bytes_per_second`,
`tcp[].downstream_min_rate_bytes_per_second`, and
`tcp[].upstream_min_rate_bytes_per_second` must be no higher than `1048576`
B/s. `0` remains the explicit disable value for these byte floors, preserving
quiet TCP protocols and operator-controlled HTTP body-rate behavior, while
rejecting typo-sized floors that could shed valid slow clients or origins during
congestion.

Reference checks used for the change:

- [Apache `mod_reqtimeout`](https://httpd.apache.org/docs/current/mod/mod_reqtimeout.html) documents request timeout and `MinRate` controls, with default body/header rates in the hundreds of bytes per second.
- [Kestrel `MinRequestBodyDataRate`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.core.kestrelserverlimits.minrequestbodydatarate) documents request-body minimum data rate in bytes/second, nullable disable semantics, and a conservative default.
- [NGINX `limit_rate`](https://nginx.org/en/docs/http/ngx_http_core_module.html#limit_rate) documents byte-per-second rate knobs and `0` as disable semantics, reinforcing that these controls should be finite and intentional.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9356.28 RPS | `204: 18732` | 0 | 6.053 ms |
| admin health | 9321.64 RPS | `200: 18662` | 0 | 5.959 ms |
| raw TCP persistent echo | 19594.24 msg/s | `39202` echoed messages | 0 | 0.677 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6685.11 RPS | `204: 13419` | 0 | 16.901 ms |
| admin health on `core` | 6599.22 RPS | `200: 13248` | 0 | 17.212 ms |
| raw TCP persistent echo on `core` | 28254.00 msg/s | `56567` echoed messages | 0 | 1.083 ms |

Startup ceiling guardrails with oversized value `1048577`:

| Probe | Local | `core` |
| --- | --- | --- |
| HTTP request body min-rate floor rejected | `true` | `true` |
| HTTP upstream body min-rate floor rejected | `true` | `true` |
| TCP downstream min-rate floor rejected | `true` | `true` |
| TCP upstream min-rate floor rejected | `true` | `true` |
| all min-rate ceilings rejected | `true` | `true` |

Validation commands:

```bash
cargo fmt
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
cargo test min_rate -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 32 --tcp-workers 8 > benchmark_results/local_bench_min_rate_ceiling_20260622.json
jq -e '.guardrails.min_rate_ceiling_startup.all_min_rate_ceilings_rejected == true and .guardrails.min_rate_ceiling_startup.http_request_body_min_rate_rejected == true and .guardrails.min_rate_ceiling_startup.http_upstream_body_min_rate_rejected == true and .guardrails.min_rate_ceiling_startup.tcp_downstream_min_rate_rejected == true and .guardrails.min_rate_ceiling_startup.tcp_upstream_min_rate_rejected == true and (.guardrails.min_rate_ceiling_startup.http_request_body_min_rate.stderr_tail | join("\n") | contains("http.request_body_min_rate_bytes_per_second")) and (.guardrails.min_rate_ceiling_startup.http_request_body_min_rate.stderr_tail | join("\n") | contains("must be no higher than 1048576")) and (.guardrails.min_rate_ceiling_startup.http_upstream_body_min_rate.stderr_tail | join("\n") | contains("http.upstream_body_min_rate_bytes_per_second")) and (.guardrails.min_rate_ceiling_startup.tcp_downstream_min_rate.stderr_tail | join("\n") | contains("tcp[0].downstream_min_rate_bytes_per_second")) and (.guardrails.min_rate_ceiling_startup.tcp_upstream_min_rate.stderr_tail | join("\n") | contains("tcp[0].upstream_min_rate_bytes_per_second"))' benchmark_results/local_bench_min_rate_ceiling_20260622.json benchmark_results/local_bench_core_min_rate_ceiling_20260622.json

ssh core 'mkdir -p /root/altura-prot-min-rate-ceiling-20260622 /root/altura-prot-tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-min-rate-ceiling-20260622/
ssh core 'cd /root/altura-prot-min-rate-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-min-rate-ceiling-20260622 && TMPDIR=/root/altura-prot-tmp cargo test min_rate -- --nocapture'
ssh core 'cd /root/altura-prot-min-rate-ceiling-20260622 && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-min-rate-ceiling-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release'
ssh core 'cd /root/altura-prot-min-rate-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/altura-prot-tmp python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_min_rate_ceiling_20260622.json'
rsync -a core:/root/altura-prot-min-rate-ceiling-20260622/benchmark_results/local_bench_core_min_rate_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
```

Core still lacks `cargo fmt` and `cargo clippy` subcommands, so those checks ran
locally.

## 2026-06-22 Header Line Cap Snapshot

Artifacts:

- `benchmark_results/local_bench_header_line_cap_20260622.json`
- `benchmark_results/local_bench_core_header_line_cap_20260622.json`

This snapshot adds explicit per-field header caps:
`http.max_header_line_bytes` for downstream requests and
`http.upstream_max_header_line_bytes` for upstream responses. Both default to
`8192`, must be positive, are startup-capped at `262144`, and must not exceed
their corresponding total header byte caps. The raw connection-opening precheck
rejects a first-request oversized field before Hyper parsing; parsed request
validation catches oversized fields on opt-in keep-alive follow-up requests; and
upstream response validation rejects an oversized origin header field before
forwarding it downstream. Client request rejections return generated `431`
responses with `Cache-Control: no-store` and `Connection: close`; upstream
response rejections return generated `502` responses, increment
`altura_http_upstream_header_rejected` and `altura_http_upstream_errors`, and
record an upstream circuit failure.

Reference checks used for the change:

- [Apache `LimitRequestFieldSize`](https://httpd.apache.org/docs/current/mod/core.html#limitrequestfieldsize) documents a per-request-header-field byte limit, default `8190`, as useful control over abnormal client behavior and some denial-of-service exposure.
- [NGINX `large_client_header_buffers`](https://nginx.org/en/docs/http/ngx_http_core_module.html#large_client_header_buffers) defaults to `4 8k`; one request line or one request header field must fit in one buffer, otherwise NGINX returns `414` or `400`.
- [HAProxy `tune.bufsize`](https://docs.haproxy.org/2.8/configuration.html#3.3-tune.bufsize) documents the memory tradeoff of larger buffers and rejects oversized requests/responses with `400`/`502`.
- [Hyper HTTP/1 builder](https://docs.rs/hyper/latest/hyper/server/conn/http1/struct.Builder.html) exposes `max_headers`, `header_read_timeout`, and total `max_buf_size` with an `8192` minimum, but not a separate per-field cap, so AlturaProt enforces the per-field boundary itself.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9285.36 RPS | `204: 18590` | 0 | 6.005 ms |
| admin health | 9341.86 RPS | `200: 18703` | 0 | 5.918 ms |
| raw TCP persistent echo | 19406.08 msg/s | `38826` echoed messages | 0 | 0.684 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6665.81 RPS | `204: 13375` | 0 | 16.829 ms |
| admin health on `core` | 6446.15 RPS | `200: 12941` | 0 | 17.488 ms |
| raw TCP persistent echo on `core` | 28937.63 msg/s | `57925` echoed messages | 0 | 1.058 ms |

Header-line guardrails with `max_header_line_bytes: 128` and
`upstream_max_header_line_bytes: 128`:

| Probe | Local | `core` |
| --- | --- | --- |
| raw first request oversized field returns `431`, no-store, close | `true` | `true` |
| keep-alive second request oversized field returns `431`, no-store, close | `true` | `true` |
| upstream oversized response field returns `502`, no-store, close | `true` | `true` |
| `altura_http_initial_header_too_large` delta | `1` | `1` |
| `altura_http_header_line_rejected` delta | `1` | `1` |
| `altura_http_upstream_header_rejected` delta | `1` | `1` |
| `altura_http_upstream_errors` delta | `1` | `1` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
cargo test header_line -- --nocapture
cargo test -- --nocapture
cargo clippy -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 32 --tcp-workers 8 > benchmark_results/local_bench_header_line_cap_20260622.json
jq -e '.guardrails.header_line_cap.header_line_cap_observed == true and .guardrails.header_line_cap.raw_initial_431 == true and .guardrails.header_line_cap.keepalive_second_431 == true and .guardrails.header_line_cap.upstream_502 == true and .guardrails.header_line_cap.http_initial_header_too_large_delta >= 1 and .guardrails.header_line_cap.http_header_line_rejected_delta >= 1 and .guardrails.header_line_cap.http_upstream_header_rejected_delta >= 1 and .guardrails.header_line_cap.http_upstream_errors_delta >= 1' benchmark_results/local_bench_header_line_cap_20260622.json

ssh core 'mkdir -p /root/altura-prot-header-line-cap-20260622 /root/altura-prot-tmp'
rsync -a --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-header-line-cap-20260622/
ssh core 'cd /root/altura-prot-header-line-cap-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-header-line-cap-20260622 && TMPDIR=/root/altura-prot-tmp cargo test header_line -- --nocapture'
ssh core 'cd /root/altura-prot-header-line-cap-20260622 && TMPDIR=/root/altura-prot-tmp cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-header-line-cap-20260622 && TMPDIR=/root/altura-prot-tmp cargo build --release'
ssh core 'cd /root/altura-prot-header-line-cap-20260622 && mkdir -p benchmark_results && TMPDIR=/root/altura-prot-tmp python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 2 --workers 64 --tcp-workers 16 > benchmark_results/local_bench_core_header_line_cap_20260622.json'
rsync -a core:/root/altura-prot-header-line-cap-20260622/benchmark_results/local_bench_core_header_line_cap_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.header_line_cap.header_line_cap_observed == true and .guardrails.header_line_cap.raw_initial_431 == true and .guardrails.header_line_cap.keepalive_second_431 == true and .guardrails.header_line_cap.upstream_502 == true and .guardrails.header_line_cap.http_initial_header_too_large_delta >= 1 and .guardrails.header_line_cap.http_header_line_rejected_delta >= 1 and .guardrails.header_line_cap.http_upstream_header_rejected_delta >= 1 and .guardrails.header_line_cap.http_upstream_errors_delta >= 1' benchmark_results/local_bench_header_line_cap_20260622.json benchmark_results/local_bench_core_header_line_cap_20260622.json
```

## 2026-06-22 Initial Header Scan Snapshot

Artifacts:

- `benchmark_results/local_bench_initial_header_scan_20260622.json`
- `benchmark_results/local_bench_core_initial_header_scan_20260622.json`

This snapshot makes the raw connection-opening HTTP/1 precheck search for the
header terminator with a rolling scan: only the newly appended bytes plus the
required three-byte overlap are searched for `\r\n\r\n`. It also treats
`http.max_header_bytes` as a hard cap when the terminator arrives after the cap
in the same socket read. Oversized initial headers still return generated `431`
with `Cache-Control: no-store` and `Connection: close`, and increment
`altura_http_initial_header_too_large`.

Reference checks used for the change:

- [Hyper HTTP/1 builder](https://docs.rs/hyper/latest/hyper/server/conn/http1/struct.Builder.html) exposes `max_headers`, `header_read_timeout`, and `max_buf_size`; its `max_buf_size` minimum is `8192` bytes.
- [NGINX core HTTP docs](https://nginx.org/en/docs/http/ngx_http_core_module.html) bound client header reads with `client_header_buffer_size`, `large_client_header_buffers`, and `client_header_timeout`, returning `414`, `400`, or `408` on pressure paths.
- [HAProxy configuration docs](https://docs.haproxy.org/2.8/configuration.html) warn that increasing request buffer size increases per-session memory and may require reducing global connection capacity.
- [`memchr` docs](https://docs.rs/memchr/latest/memchr/) were checked as a dependency option, but the chosen implementation kept the existing dependency set and used a small suffix-overlap scan.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9079.91 RPS | `204: 27310` | 0 | 24.819 ms |
| admin health | 9024.42 RPS | `200: 27151` | 0 | 25.631 ms |
| raw TCP persistent echo | 19505.58 msg/s | `58561` echoed messages | 0 | 3.016 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6659.11 RPS | `204: 20065` | 0 | 33.806 ms |
| admin health on `core` | 6548.21 RPS | `200: 19733` | 0 | 34.544 ms |
| raw TCP persistent echo on `core` | 25984.21 msg/s | `78073` echoed messages | 0 | 2.480 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| raw obsolete-fold precheck returns `400`, no-store, close | `true` | `true` |
| raw oversized initial header without terminator returns `431`, no-store, close | `true` | `true` |
| raw oversized initial header with late terminator returns `431`, no-store, close | `true` | `true` |
| `altura_http_initial_header_too_large` increments for both oversized probes | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
cargo test initial_precheck -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_initial_header_scan_20260622.json
jq -e '.guardrails.initial_framing_precheck_response.initial_framing_precheck_response_observed == true and .guardrails.initial_framing_precheck_response.initial_header_too_large_response_observed == true and .guardrails.initial_framing_precheck_response.initial_header_late_terminator_over_cap_observed == true and .guardrails.initial_framing_precheck_response.raw_initial_late_terminator_431_not_stored == true and .guardrails.initial_framing_precheck_response.raw_initial_late_terminator_431_closes_connection == true and .guardrails.initial_framing_precheck_response.http_initial_header_too_large_delta >= 2' benchmark_results/local_bench_initial_header_scan_20260622.json

ssh core 'rm -rf /root/altura-prot-initial-header-scan-20260622 && mkdir -p /root/altura-prot-initial-header-scan-20260622 /root/tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-initial-header-scan-20260622/
ssh core 'cd /root/altura-prot-initial-header-scan-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-initial-header-scan-20260622 && TMPDIR=/root/tmp cargo test initial_precheck -- --nocapture'
ssh core 'cd /root/altura-prot-initial-header-scan-20260622 && TMPDIR=/root/tmp cargo build --release'
ssh core 'cd /root/altura-prot-initial-header-scan-20260622 && mkdir -p benchmark_results && TMPDIR=/root/tmp python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_initial_header_scan_20260622.json'
rsync -a core:/root/altura-prot-initial-header-scan-20260622/benchmark_results/local_bench_core_initial_header_scan_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.initial_framing_precheck_response.initial_framing_precheck_response_observed == true and .guardrails.initial_framing_precheck_response.initial_header_too_large_response_observed == true and .guardrails.initial_framing_precheck_response.initial_header_late_terminator_over_cap_observed == true and .guardrails.initial_framing_precheck_response.raw_initial_late_terminator_431_not_stored == true and .guardrails.initial_framing_precheck_response.raw_initial_late_terminator_431_closes_connection == true and .guardrails.initial_framing_precheck_response.http_initial_header_too_large_delta >= 2' benchmark_results/local_bench_initial_header_scan_20260622.json benchmark_results/local_bench_core_initial_header_scan_20260622.json
```

## 2026-06-22 Dynamic State Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_dynamic_state_ceiling_20260622.json`
- `benchmark_results/local_bench_core_dynamic_state_ceiling_20260622.json`

This snapshot adds startup ceilings for dynamic state and control-plane inputs
that were previously only positive-validated. Runtime filter reload reads are
capped at `16777216` bytes, runtime/static rule counts at `8192`, adaptive
event-log rotation size at `1073741824` bytes, adaptive signature/path-shape
window maps at `262144` each, HTTP and TCP tracked IP maps at `1048576`, and
HTTP tracked signature/path-shape maps at `262144` each. The goal is to keep a
bad deploy from converting flood-facing learned state, limiter maps, event-log
rotation, or filter evaluation into excessive memory, filesystem, or hot-path
scan work.

Reference checks used for the ceilings:

- [HAProxy stick tables](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/custom-rules/stick-tables/) use explicit table `size` and expiry; the documented `size 1m` example holds `1048576` records.
- [NGINX `limit_req`](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) keeps per-key state in a fixed shared-memory zone and terminates requests that exceed the configured burst.
- [Envoy circuit breakers](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/circuit_breaker.proto) default key upstream concurrency limits to `1024` and explicitly warn that connection-pool counts can otherwise be unlimited.
- [Apache request limits](https://httpd.apache.org/docs/current/mod/core.html) document request body/header count/field-size limits as controls for abnormal behavior and DoS exposure, while `0` means unlimited for several limit directives.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8959.44 RPS | `204: 26953` | 0 | 25.288 ms |
| admin health | 9036.32 RPS | `200: 27186` | 0 | 25.371 ms |
| raw TCP persistent echo | 19365.11 msg/s | `58139` echoed messages | 0 | 3.036 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6524.72 RPS | `204: 19663` | 0 | 34.764 ms |
| admin health on `core` | 6509.14 RPS | `200: 19620` | 0 | 34.614 ms |
| raw TCP persistent echo on `core` | 26825.66 msg/s | `80598` echoed messages | 0 | 2.395 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `filters.max_runtime_file_bytes: 16777217` rejected at startup | `true` | `true` |
| `filters.max_runtime_filters: 8193` rejected at startup | `true` | `true` |
| `filters.max_static_filters: 8193` rejected at startup | `true` | `true` |
| `adaptive.event_log_max_bytes: 1073741825` rejected at startup | `true` | `true` |
| `adaptive.max_signature_windows: 262145` rejected at startup | `true` | `true` |
| `adaptive.max_path_shape_windows: 262145` rejected at startup | `true` | `true` |
| `http.limits.max_tracked_ips: 1048577` rejected at startup | `true` | `true` |
| `http.limits.max_tracked_signatures: 262145` rejected at startup | `true` | `true` |
| `http.limits.max_tracked_path_shapes: 262145` rejected at startup | `true` | `true` |
| `tcp[0].limits.max_tracked_ips: 1048577` rejected at startup | `true` | `true` |
| every rejection includes its config path and ceiling | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
cargo test state_caps -- --nocapture
cargo test app_config_rejects_zero -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_dynamic_state_ceiling_20260622.json
jq -e '.guardrails.dynamic_state_ceiling_startup.all_dynamic_state_ceilings_rejected == true and .guardrails.dynamic_state_ceiling_startup.filter_runtime_file_bytes.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.filter_runtime_filters.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.filter_static_filters.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.adaptive_event_log_max_bytes.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.adaptive_signature_windows.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.adaptive_path_shape_windows.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.http_max_tracked_ips.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.http_max_tracked_signatures.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.http_max_tracked_path_shapes.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.tcp_max_tracked_ips.startup_rejected == true' benchmark_results/local_bench_dynamic_state_ceiling_20260622.json

ssh core 'rm -rf /root/altura-prot-dynamic-state-ceiling-20260622 && mkdir -p /root/altura-prot-dynamic-state-ceiling-20260622 /root/tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-dynamic-state-ceiling-20260622/
ssh core 'cd /root/altura-prot-dynamic-state-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-dynamic-state-ceiling-20260622 && TMPDIR=/root/tmp cargo test state_caps -- --nocapture'
ssh core 'cd /root/altura-prot-dynamic-state-ceiling-20260622 && TMPDIR=/root/tmp cargo build --release'
ssh core 'cd /root/altura-prot-dynamic-state-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/tmp python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_dynamic_state_ceiling_20260622.json'
rsync -a core:/root/altura-prot-dynamic-state-ceiling-20260622/benchmark_results/local_bench_core_dynamic_state_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.dynamic_state_ceiling_startup.all_dynamic_state_ceilings_rejected == true and .guardrails.dynamic_state_ceiling_startup.filter_runtime_file_bytes.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.filter_runtime_filters.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.filter_static_filters.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.adaptive_event_log_max_bytes.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.adaptive_signature_windows.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.adaptive_path_shape_windows.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.http_max_tracked_ips.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.http_max_tracked_signatures.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.http_max_tracked_path_shapes.startup_rejected == true and .guardrails.dynamic_state_ceiling_startup.tcp_max_tracked_ips.startup_rejected == true' benchmark_results/local_bench_dynamic_state_ceiling_20260622.json benchmark_results/local_bench_core_dynamic_state_ceiling_20260622.json
```

## 2026-06-22 Upstream Failure Circuit Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_failure_circuit_ceiling_20260622.json`
- `benchmark_results/local_bench_core_upstream_failure_circuit_ceiling_20260622.json`

This snapshot adds startup ceilings for the passive upstream failure circuit.
`http.upstream_failure_threshold` remains configurable but must stay between
`1` and `1024` consecutive upstream failures. `http.upstream_failure_open_ms`
remains configurable but must stay between `1` and `300000` ms. Defaults remain
`8` failures and `1000` ms. The ceiling prevents a bad deploy from making the
circuit effectively unreachable during origin failure floods or from shedding
valid origin-bound traffic for hours after a transient failure.

Reference checks used for the ceiling:

- Envoy outlier detection documents consecutive-failure ejection defaults of
  `5`, a base ejection time of `30000` ms, and a default max ejection time of
  `300000` ms.
- NGINX passive upstream health checks use `max_fails` and `fail_timeout`; the
  timeout also controls how long an upstream is marked failed before live
  traffic probes it again.
- HAProxy passive health checks use `error-limit` and `on-error` to react after
  a bounded number of observed live-traffic failures.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8939.51 RPS | `204: 26891` | 0 | 25.272 ms |
| admin health | 9026.86 RPS | `200: 27134` | 0 | 26.037 ms |
| raw TCP persistent echo | 19444.37 msg/s | `58375` echoed messages | 0 | 3.015 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6395.82 RPS | `204: 19272` | 0 | 35.556 ms |
| admin health on `core` | 6497.73 RPS | `200: 19587` | 0 | 34.487 ms |
| raw TCP persistent echo on `core` | 25146.57 msg/s | `75526` echoed messages | 0 | 2.568 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.upstream_failure_threshold: 1025` rejected at startup | `true` | `true` |
| `http.upstream_failure_open_ms: 300001` rejected at startup | `true` | `true` |
| every rejection includes its config path | `true` | `true` |
| every rejection includes the configured ceiling | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test upstream_failure_circuit -- --nocapture
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_upstream_failure_circuit_ceiling_20260622.json
jq -e '.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_threshold_rejected == true and .guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_open_ms_rejected == true and (.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_threshold.stderr_tail | join("\n") | contains("http.upstream_failure_threshold")) and (.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_open_ms.stderr_tail | join("\n") | contains("http.upstream_failure_open_ms")) and (.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_threshold.stderr_tail | join("\n") | contains("must be no higher than 1024")) and (.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_open_ms.stderr_tail | join("\n") | contains("must be no higher than 300000"))' benchmark_results/local_bench_upstream_failure_circuit_ceiling_20260622.json

ssh core 'rm -rf /root/altura-prot-upstream-failure-circuit-ceiling-20260622 && mkdir -p /root/altura-prot-upstream-failure-circuit-ceiling-20260622 /root/tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-upstream-failure-circuit-ceiling-20260622/
ssh core 'cd /root/altura-prot-upstream-failure-circuit-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-upstream-failure-circuit-ceiling-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-upstream-failure-circuit-ceiling-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-upstream-failure-circuit-ceiling-20260622 && TMPDIR=/root/tmp cargo test upstream_failure_circuit -- --nocapture'
ssh core 'cd /root/altura-prot-upstream-failure-circuit-ceiling-20260622 && TMPDIR=/root/tmp cargo build --release'
ssh core 'cd /root/altura-prot-upstream-failure-circuit-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/tmp python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_upstream_failure_circuit_ceiling_20260622.json'
rsync -a core:/root/altura-prot-upstream-failure-circuit-ceiling-20260622/benchmark_results/local_bench_core_upstream_failure_circuit_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_threshold_rejected == true and .guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_open_ms_rejected == true and (.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_threshold.stderr_tail | join("\n") | contains("http.upstream_failure_threshold")) and (.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_open_ms.stderr_tail | join("\n") | contains("http.upstream_failure_open_ms")) and (.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_threshold.stderr_tail | join("\n") | contains("must be no higher than 1024")) and (.guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_open_ms.stderr_tail | join("\n") | contains("must be no higher than 300000"))' benchmark_results/local_bench_upstream_failure_circuit_ceiling_20260622.json benchmark_results/local_bench_core_upstream_failure_circuit_ceiling_20260622.json
```

## 2026-06-22 Upstream Idle Pool Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_idle_pool_ceiling_20260622.json`
- `benchmark_results/local_bench_core_upstream_idle_pool_ceiling_20260622.json`

This snapshot adds startup ceilings for the upstream HTTP idle connection pool.
`http.upstream_pool_idle_timeout_ms` remains configurable but must stay between
`1` and `60000` ms. `http.upstream_pool_max_idle_per_host` remains configurable
between `0` and `4096`, where `0` intentionally disables idle origin pooling.
The defaults remain `30000` ms and `256` idle origin connections per host. The
ceiling prevents a bad deploy from turning Hyper's idle origin pool into
effectively unbounded retained sockets or multi-minute/hour idle retention while
preserving measured high-reuse deployments.

Reference checks used for the ceiling:

- Hyper/hyper-util documents `pool_idle_timeout` as an optional idle socket
  timeout, with `None` disabling it and a default of 90 seconds.
- Hyper/hyper-util documents `pool_max_idle_per_host` as the maximum idle
  connections per host and defaults it to `usize::MAX`, meaning no limit unless
  AlturaProt sets one.
- NGINX upstream keepalive documents a finite idle connection cache, a default
  upstream keepalive timeout of `60s`, and warns to keep cached connection
  counts small enough for upstream servers to accept new connections.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8922.82 RPS | `204: 26842` | 0 | 25.243 ms |
| admin health | 9053.78 RPS | `200: 27234` | 0 | 25.223 ms |
| raw TCP persistent echo | 19337.08 msg/s | `58056` echoed messages | 0 | 3.037 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6380.17 RPS | `204: 19233` | 0 | 35.619 ms |
| admin health on `core` | 6568.82 RPS | `200: 19797` | 0 | 34.399 ms |
| raw TCP persistent echo on `core` | 26260.81 msg/s | `78877` echoed messages | 0 | 2.457 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.upstream_pool_idle_timeout_ms: 60001` rejected at startup | `true` | `true` |
| `http.upstream_pool_max_idle_per_host: 4097` rejected at startup | `true` | `true` |
| every rejection includes its config path | `true` | `true` |
| every rejection includes the configured ceiling | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test upstream_idle_pool -- --nocapture
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_upstream_idle_pool_ceiling_20260622.json
jq -e '.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_idle_timeout_rejected == true and .guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_max_idle_per_host_rejected == true and (.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_idle_timeout.stderr_tail | join("\n") | contains("http.upstream_pool_idle_timeout_ms")) and (.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_max_idle_per_host.stderr_tail | join("\n") | contains("http.upstream_pool_max_idle_per_host")) and (.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_idle_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_max_idle_per_host.stderr_tail | join("\n") | contains("must be no higher than 4096"))' benchmark_results/local_bench_upstream_idle_pool_ceiling_20260622.json

ssh core 'rm -rf /root/altura-prot-upstream-idle-pool-ceiling-20260622 && mkdir -p /root/altura-prot-upstream-idle-pool-ceiling-20260622 /root/tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-upstream-idle-pool-ceiling-20260622/
ssh core 'cd /root/altura-prot-upstream-idle-pool-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-upstream-idle-pool-ceiling-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-upstream-idle-pool-ceiling-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-upstream-idle-pool-ceiling-20260622 && TMPDIR=/root/tmp cargo test upstream_idle_pool -- --nocapture'
ssh core 'cd /root/altura-prot-upstream-idle-pool-ceiling-20260622 && TMPDIR=/root/tmp cargo build --release'
ssh core 'cd /root/altura-prot-upstream-idle-pool-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/tmp python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_upstream_idle_pool_ceiling_20260622.json'
rsync -a core:/root/altura-prot-upstream-idle-pool-ceiling-20260622/benchmark_results/local_bench_core_upstream_idle_pool_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_idle_timeout_rejected == true and .guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_max_idle_per_host_rejected == true and (.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_idle_timeout.stderr_tail | join("\n") | contains("http.upstream_pool_idle_timeout_ms")) and (.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_max_idle_per_host.stderr_tail | join("\n") | contains("http.upstream_pool_max_idle_per_host")) and (.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_idle_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_max_idle_per_host.stderr_tail | join("\n") | contains("must be no higher than 4096"))' benchmark_results/local_bench_upstream_idle_pool_ceiling_20260622.json benchmark_results/local_bench_core_upstream_idle_pool_ceiling_20260622.json
```

## 2026-06-22 Connection Request Count Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_connection_request_count_ceiling_20260622.json`
- `benchmark_results/local_bench_core_connection_request_count_ceiling_20260622.json`

This snapshot adds a startup ceiling for the HTTP per-connection request budget.
`http.max_requests_per_connection` remains configurable but must stay between
`1` and `10000`; the default remains `1000`. The ceiling prevents a bad deploy
from stretching persistent-connection work into an effectively unlimited
per-socket budget while keeping high measured keep-alive reuse possible.
Downstream keep-alive remains opt-in and disabled by default.

Reference checks used for the ceiling:

- NGINX documents `keepalive_requests 1000` as the default, closes a keep-alive
  connection after the configured request count, and warns that values that are
  too high can retain excessive per-connection memory.
- Apache HTTP Server documents `MaxKeepAliveRequests 100` as the default,
  `0` as unlimited, and recommends a high finite value for performance.
- Envoy documents `max_requests_per_connection` as optional; if it is not
  specified, there is no limit, while `1` effectively disables keep-alive.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9028.90 RPS | `204: 27155` | 0 | 24.807 ms |
| admin health | 9039.04 RPS | `200: 27193` | 0 | 25.119 ms |
| raw TCP persistent echo | 19439.20 msg/s | `58360` echoed messages | 0 | 3.029 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6619.32 RPS | `204: 19946` | 0 | 34.470 ms |
| admin health on `core` | 6407.24 RPS | `200: 19319` | 0 | 34.746 ms |
| raw TCP persistent echo on `core` | 24386.91 msg/s | `73270` echoed messages | 0 | 2.648 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.max_requests_per_connection: 10001` rejected at startup | `true` | `true` |
| every rejection names `http.max_requests_per_connection` | `true` | `true` |
| every rejection includes ceiling `10000` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
cargo test connection_request_count -- --nocapture
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_connection_request_count_ceiling_20260622.json
jq -e '.guardrails.connection_request_count_ceiling_startup.max_requests_per_connection_rejected == true and (.guardrails.connection_request_count_ceiling_startup.stderr_tail | join("\n") | contains("http.max_requests_per_connection")) and (.guardrails.connection_request_count_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 10000"))' benchmark_results/local_bench_connection_request_count_ceiling_20260622.json

ssh core 'rm -rf /root/altura-prot-connection-request-count-ceiling-20260622 && mkdir -p /root/altura-prot-connection-request-count-ceiling-20260622 /root/tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-connection-request-count-ceiling-20260622/
ssh core 'cd /root/altura-prot-connection-request-count-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-connection-request-count-ceiling-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-connection-request-count-ceiling-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-connection-request-count-ceiling-20260622 && TMPDIR=/root/tmp cargo test connection_request_count -- --nocapture'
ssh core 'cd /root/altura-prot-connection-request-count-ceiling-20260622 && TMPDIR=/root/tmp cargo build --release'
ssh core 'cd /root/altura-prot-connection-request-count-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/tmp python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_connection_request_count_ceiling_20260622.json'
rsync -a core:/root/altura-prot-connection-request-count-ceiling-20260622/benchmark_results/local_bench_core_connection_request_count_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.connection_request_count_ceiling_startup.max_requests_per_connection_rejected == true and (.guardrails.connection_request_count_ceiling_startup.stderr_tail | join("\n") | contains("http.max_requests_per_connection")) and (.guardrails.connection_request_count_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 10000"))' benchmark_results/local_bench_connection_request_count_ceiling_20260622.json benchmark_results/local_bench_core_connection_request_count_ceiling_20260622.json
```

## 2026-06-22 Body Size Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_body_size_ceiling_20260622.json`
- `benchmark_results/local_bench_core_body_size_ceiling_20260622.json`

This snapshot adds startup ceilings for HTTP request and upstream response body
byte caps. `http.max_body_bytes` and `http.max_upstream_body_bytes` remain
configurable but must stay between `1` and `1073741824` bytes. The defaults
remain `10485760` and `104857600` bytes. The ceiling prevents a bad deploy from
turning request or response body guards into effectively unbounded byte streams
while still allowing explicitly measured large upload/download routes.

Reference checks used for the ceiling:

- Apache HTTP Server documents `LimitRequestBody 1073741824` as the default
  request-body ceiling and describes the directive as useful for avoiding
  denial-of-service behavior.
- NGINX documents `client_max_body_size 1m` as a finite request-body default
  that rejects oversized requests with `413`.
- Envoy's HTTP buffer filter requires a finite `max_request_bytes` before
  returning `413` for oversized buffered requests.
- NGINX proxy buffering documents `proxy_max_temp_file_size 1024m` as the
  default response temporary-file cap when proxied responses exceed memory
  buffers.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9059.50 RPS | `204: 27250` | 0 | 24.763 ms |
| admin health | 9070.75 RPS | `200: 27287` | 0 | 25.202 ms |
| raw TCP persistent echo | 19380.95 msg/s | `58184` echoed messages | 0 | 3.020 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6621.82 RPS | `204: 19951` | 0 | 34.236 ms |
| admin health on `core` | 6367.30 RPS | `200: 19193` | 0 | 34.770 ms |
| raw TCP persistent echo on `core` | 25015.16 msg/s | `75144` echoed messages | 0 | 2.580 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.max_body_bytes: 1073741825` rejected at startup | `true` | `true` |
| `http.max_upstream_body_bytes: 1073741825` rejected at startup | `true` | `true` |
| every rejection includes ceiling `1073741824` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test body_size_caps -- --nocapture
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_body_size_ceiling_20260622.json
jq -e '.guardrails.body_size_ceiling_startup.max_body_bytes_rejected == true and .guardrails.body_size_ceiling_startup.max_upstream_body_bytes_rejected == true and (.guardrails.body_size_ceiling_startup.max_body_bytes.stderr_tail | join("\n") | contains("http.max_body_bytes")) and (.guardrails.body_size_ceiling_startup.max_upstream_body_bytes.stderr_tail | join("\n") | contains("http.max_upstream_body_bytes")) and (.guardrails.body_size_ceiling_startup.max_body_bytes.stderr_tail | join("\n") | contains("must be no higher than 1073741824")) and (.guardrails.body_size_ceiling_startup.max_upstream_body_bytes.stderr_tail | join("\n") | contains("must be no higher than 1073741824"))' benchmark_results/local_bench_body_size_ceiling_20260622.json

ssh core 'rm -rf /root/altura-prot-body-size-ceiling-20260622 && mkdir -p /root/altura-prot-body-size-ceiling-20260622 /root/tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-body-size-ceiling-20260622/
ssh core 'cd /root/altura-prot-body-size-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-body-size-ceiling-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-body-size-ceiling-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-body-size-ceiling-20260622 && TMPDIR=/root/tmp cargo test body_size_caps -- --nocapture'
ssh core 'cd /root/altura-prot-body-size-ceiling-20260622 && TMPDIR=/root/tmp cargo build --release'
ssh core 'cd /root/altura-prot-body-size-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/tmp python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_body_size_ceiling_20260622.json'
rsync -a core:/root/altura-prot-body-size-ceiling-20260622/benchmark_results/local_bench_core_body_size_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.body_size_ceiling_startup.max_body_bytes_rejected == true and .guardrails.body_size_ceiling_startup.max_upstream_body_bytes_rejected == true and (.guardrails.body_size_ceiling_startup.max_body_bytes.stderr_tail | join("\n") | contains("http.max_body_bytes")) and (.guardrails.body_size_ceiling_startup.max_upstream_body_bytes.stderr_tail | join("\n") | contains("http.max_upstream_body_bytes")) and (.guardrails.body_size_ceiling_startup.max_body_bytes.stderr_tail | join("\n") | contains("must be no higher than 1073741824")) and (.guardrails.body_size_ceiling_startup.max_upstream_body_bytes.stderr_tail | join("\n") | contains("must be no higher than 1073741824"))' benchmark_results/local_bench_body_size_ceiling_20260622.json benchmark_results/local_bench_core_body_size_ceiling_20260622.json
```

## 2026-06-22 HTTP Stream Timeout Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_http_stream_timeout_ceiling_20260622.json`
- `benchmark_results/local_bench_core_http_stream_timeout_ceiling_20260622.json`

This snapshot adds startup ceilings for HTTP stream timeout knobs:
`http.downstream_write_timeout_ms`, `http.request_body_idle_timeout_ms`,
`http.upstream_body_idle_timeout_ms`, `http.request_body_min_rate_grace_ms`,
and `http.upstream_body_min_rate_grace_ms` remain configurable but must stay
between `1` and `60000` ms. The ceiling prevents a bad deploy from stretching
slow-reader, slow-upload, or slow-origin-body protections into minute/hour waits
while still allowing measured slow-client or slow-origin behavior up to one
minute.

Reference checks used for the ceiling:

- Envoy documents `stream_idle_timeout` as an idle timeout for HTTP streams.
- NGINX documents `client_body_timeout` and proxy timeouts with `60s` defaults
  and applies them between successive read/write operations.
- HAProxy documents client/server timeouts as inactivity limits for stalled
  client or server data paths.
- Apache `mod_reqtimeout` documents request read timeout and minimum-rate
  controls for headers and bodies.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9037.27 RPS | `204: 27184` | 0 | 24.992 ms |
| admin health | 9098.69 RPS | `200: 27369` | 0 | 25.211 ms |
| raw TCP persistent echo | 19363.44 msg/s | `58132` echoed messages | 0 | 3.031 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6491.20 RPS | `204: 19561` | 0 | 34.959 ms |
| admin health on `core` | 6324.43 RPS | `200: 19064` | 0 | 35.944 ms |
| raw TCP persistent echo on `core` | 24462.08 msg/s | `73476` echoed messages | 0 | 2.656 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.downstream_write_timeout_ms: 60001` rejected at startup | `true` | `true` |
| `http.request_body_idle_timeout_ms: 60001` rejected at startup | `true` | `true` |
| `http.upstream_body_idle_timeout_ms: 60001` rejected at startup | `true` | `true` |
| `http.request_body_min_rate_grace_ms: 60001` rejected at startup | `true` | `true` |
| `http.upstream_body_min_rate_grace_ms: 60001` rejected at startup | `true` | `true` |
| every rejection includes ceiling `60000` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test http_stream_timeouts -- --nocapture
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_http_stream_timeout_ceiling_20260622.json
jq -e '.guardrails.http_stream_timeout_ceiling_startup.downstream_write_timeout_rejected == true and .guardrails.http_stream_timeout_ceiling_startup.request_body_idle_timeout_rejected == true and .guardrails.http_stream_timeout_ceiling_startup.upstream_body_idle_timeout_rejected == true and .guardrails.http_stream_timeout_ceiling_startup.request_body_min_rate_grace_rejected == true and .guardrails.http_stream_timeout_ceiling_startup.upstream_body_min_rate_grace_rejected == true and (.guardrails.http_stream_timeout_ceiling_startup.downstream_write_timeout.stderr_tail | join("\n") | contains("http.downstream_write_timeout_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.request_body_idle_timeout.stderr_tail | join("\n") | contains("http.request_body_idle_timeout_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.upstream_body_idle_timeout.stderr_tail | join("\n") | contains("http.upstream_body_idle_timeout_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.request_body_min_rate_grace.stderr_tail | join("\n") | contains("http.request_body_min_rate_grace_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.upstream_body_min_rate_grace.stderr_tail | join("\n") | contains("http.upstream_body_min_rate_grace_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.downstream_write_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.http_stream_timeout_ceiling_startup.request_body_idle_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.http_stream_timeout_ceiling_startup.upstream_body_idle_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.http_stream_timeout_ceiling_startup.request_body_min_rate_grace.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.http_stream_timeout_ceiling_startup.upstream_body_min_rate_grace.stderr_tail | join("\n") | contains("must be no higher than 60000"))' benchmark_results/local_bench_http_stream_timeout_ceiling_20260622.json

ssh core 'rm -rf /root/altura-prot-http-stream-timeout-ceiling-20260622 && mkdir -p /root/altura-prot-http-stream-timeout-ceiling-20260622 /root/tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-http-stream-timeout-ceiling-20260622/
ssh core 'cd /root/altura-prot-http-stream-timeout-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-http-stream-timeout-ceiling-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-http-stream-timeout-ceiling-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-http-stream-timeout-ceiling-20260622 && TMPDIR=/root/tmp cargo test http_stream_timeouts -- --nocapture'
ssh core 'cd /root/altura-prot-http-stream-timeout-ceiling-20260622 && TMPDIR=/root/tmp cargo build --release'
ssh core 'cd /root/altura-prot-http-stream-timeout-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/tmp python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_http_stream_timeout_ceiling_20260622.json'
rsync -a core:/root/altura-prot-http-stream-timeout-ceiling-20260622/benchmark_results/local_bench_core_http_stream_timeout_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.http_stream_timeout_ceiling_startup.downstream_write_timeout_rejected == true and .guardrails.http_stream_timeout_ceiling_startup.request_body_idle_timeout_rejected == true and .guardrails.http_stream_timeout_ceiling_startup.upstream_body_idle_timeout_rejected == true and .guardrails.http_stream_timeout_ceiling_startup.request_body_min_rate_grace_rejected == true and .guardrails.http_stream_timeout_ceiling_startup.upstream_body_min_rate_grace_rejected == true and (.guardrails.http_stream_timeout_ceiling_startup.downstream_write_timeout.stderr_tail | join("\n") | contains("http.downstream_write_timeout_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.request_body_idle_timeout.stderr_tail | join("\n") | contains("http.request_body_idle_timeout_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.upstream_body_idle_timeout.stderr_tail | join("\n") | contains("http.upstream_body_idle_timeout_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.request_body_min_rate_grace.stderr_tail | join("\n") | contains("http.request_body_min_rate_grace_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.upstream_body_min_rate_grace.stderr_tail | join("\n") | contains("http.upstream_body_min_rate_grace_ms")) and (.guardrails.http_stream_timeout_ceiling_startup.downstream_write_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.http_stream_timeout_ceiling_startup.request_body_idle_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.http_stream_timeout_ceiling_startup.upstream_body_idle_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.http_stream_timeout_ceiling_startup.request_body_min_rate_grace.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.http_stream_timeout_ceiling_startup.upstream_body_min_rate_grace.stderr_tail | join("\n") | contains("must be no higher than 60000"))' benchmark_results/local_bench_http_stream_timeout_ceiling_20260622.json benchmark_results/local_bench_core_http_stream_timeout_ceiling_20260622.json
```

## 2026-06-22 Connect Timeout Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_connect_timeout_ceiling_20260622.json`
- `benchmark_results/local_bench_core_connect_timeout_ceiling_20260622.json`

This snapshot adds startup ceilings for upstream connection establishment
timeouts. `http.upstream_connect_timeout_ms` and `tcp[].connect_timeout_ms`
remain configurable but must stay between `1` and `60000` ms. The shared
default remains `1000` ms. The ceiling prevents a bad deploy from stretching
origin or TCP upstream connect attempts into minute/hour waits while still
allowing measured private-network behavior up to one minute.

Reference checks used for the ceiling:

- Envoy documents the upstream cluster `connect_timeout` as the time it waits
  for an upstream TCP connection to be established, with a default of `5s`.
- NGINX HTTP proxy docs set `proxy_connect_timeout` to `60s` by default and
  note it cannot usually exceed `75s`.
- HAProxy docs describe `timeout connect` as the maximum time to wait for a
  server connection attempt to succeed, and recommend short backend connect
  timeouts around TCP retransmission multiples.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9081.60 RPS | `204: 27315` | 0 | 25.046 ms |
| admin health | 9092.75 RPS | `200: 27357` | 0 | 25.165 ms |
| raw TCP persistent echo | 19385.56 msg/s | `58200` echoed messages | 0 | 3.016 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6434.15 RPS | `204: 19394` | 0 | 35.392 ms |
| admin health on `core` | 6340.42 RPS | `200: 19114` | 0 | 35.250 ms |
| raw TCP persistent echo on `core` | 24325.33 msg/s | `73068` echoed messages | 0 | 2.667 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.upstream_connect_timeout_ms: 60001` rejected at startup | `true` | `true` |
| `tcp[0].connect_timeout_ms: 60001` rejected at startup | `true` | `true` |
| rejection includes ceiling `60000` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test connect_timeout -- --nocapture
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_connect_timeout_ceiling_20260622.json
jq -e '.guardrails.connect_timeout_ceiling_startup.http_upstream_connect_timeout_rejected == true and .guardrails.connect_timeout_ceiling_startup.tcp_connect_timeout_rejected == true and (.guardrails.connect_timeout_ceiling_startup.http_upstream_connect_timeout.stderr_tail | join("\n") | contains("http.upstream_connect_timeout_ms")) and (.guardrails.connect_timeout_ceiling_startup.tcp_connect_timeout.stderr_tail | join("\n") | contains("tcp[0].connect_timeout_ms")) and (.guardrails.connect_timeout_ceiling_startup.http_upstream_connect_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.connect_timeout_ceiling_startup.tcp_connect_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000"))' benchmark_results/local_bench_connect_timeout_ceiling_20260622.json

ssh core 'rm -rf /root/altura-prot-connect-timeout-ceiling-20260622 && mkdir -p /root/altura-prot-connect-timeout-ceiling-20260622 /root/tmp'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-connect-timeout-ceiling-20260622/
ssh core 'cd /root/altura-prot-connect-timeout-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-connect-timeout-ceiling-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-connect-timeout-ceiling-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-connect-timeout-ceiling-20260622 && TMPDIR=/root/tmp cargo test connect_timeout -- --nocapture'
ssh core 'cd /root/altura-prot-connect-timeout-ceiling-20260622 && TMPDIR=/root/tmp cargo build --release'
ssh core 'cd /root/altura-prot-connect-timeout-ceiling-20260622 && mkdir -p benchmark_results && TMPDIR=/root/tmp python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_connect_timeout_ceiling_20260622.json'
rsync -a core:/root/altura-prot-connect-timeout-ceiling-20260622/benchmark_results/local_bench_core_connect_timeout_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.connect_timeout_ceiling_startup.http_upstream_connect_timeout_rejected == true and .guardrails.connect_timeout_ceiling_startup.tcp_connect_timeout_rejected == true and (.guardrails.connect_timeout_ceiling_startup.http_upstream_connect_timeout.stderr_tail | join("\n") | contains("http.upstream_connect_timeout_ms")) and (.guardrails.connect_timeout_ceiling_startup.tcp_connect_timeout.stderr_tail | join("\n") | contains("tcp[0].connect_timeout_ms")) and (.guardrails.connect_timeout_ceiling_startup.http_upstream_connect_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000")) and (.guardrails.connect_timeout_ceiling_startup.tcp_connect_timeout.stderr_tail | join("\n") | contains("must be no higher than 60000"))' benchmark_results/local_bench_connect_timeout_ceiling_20260622.json benchmark_results/local_bench_core_connect_timeout_ceiling_20260622.json
```

## 2026-06-22 Connection Duration Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_connection_duration_ceiling_20260622.json`
- `benchmark_results/local_bench_core_connection_duration_ceiling_20260622.json`

This snapshot adds startup ceilings for HTTP and TCP connection lifetimes.
`http.max_connection_duration_seconds` and
`tcp[].max_connection_duration_seconds` remain configurable but must stay
between `1` and `3600` seconds. The defaults remain `120` seconds for HTTP
and `300` seconds for TCP. The ceiling prevents a bad deploy from stretching
connection permit lifetimes into days while still allowing measured long-lived
traffic up to a full hour.

Reference checks used for the ceiling:

- Envoy documents HTTP `max_connection_duration` as a connection age limit,
  and documents a default one-hour HTTP protocol idle timeout when idle timeout
  is otherwise unspecified.
- NGINX [`keepalive_time`](https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_time)
  defaults to `1h` and limits how long requests may be processed through one
  keep-alive connection.
- Apache [`KeepAliveTimeout`](https://httpd.apache.org/docs/current/mod/core.html#keepalivetimeout)
  warns that high keep-alive timeouts can keep server workers occupied under
  load.
- HAProxy timeout documentation warns that unspecified infinite timeouts are
  not recommended because they can accumulate sessions.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9017.71 RPS | `204: 27126` | 0 | 24.543 ms |
| admin health | 8972.68 RPS | `200: 26994` | 0 | 25.674 ms |
| raw TCP persistent echo | 19264.30 msg/s | `57838` echoed messages | 0 | 3.050 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6603.37 RPS | `204: 19896` | 0 | 34.580 ms |
| admin health on `core` | 6475.55 RPS | `200: 19516` | 0 | 34.326 ms |
| raw TCP persistent echo on `core` | 25032.79 msg/s | `75195` echoed messages | 0 | 2.579 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.max_connection_duration_seconds: 3601` rejected at startup | `true` | `true` |
| `tcp[0].max_connection_duration_seconds: 3601` rejected at startup | `true` | `true` |
| rejection includes ceiling `3600` | `true` | `true` |

Validation commands:

```bash
cargo fmt
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
cargo test connection_duration -- --nocapture
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_connection_duration_ceiling_20260622.json
jq -e '.guardrails.connection_duration_ceiling_startup.http_max_connection_duration_rejected == true and .guardrails.connection_duration_ceiling_startup.tcp_max_connection_duration_rejected == true and (.guardrails.connection_duration_ceiling_startup.http_max_connection_duration.stderr_tail | join("\n") | contains("http.max_connection_duration_seconds")) and (.guardrails.connection_duration_ceiling_startup.tcp_max_connection_duration.stderr_tail | join("\n") | contains("tcp[0].max_connection_duration_seconds")) and (.guardrails.connection_duration_ceiling_startup.http_max_connection_duration.stderr_tail | join("\n") | contains("must be no higher than 3600")) and (.guardrails.connection_duration_ceiling_startup.tcp_max_connection_duration.stderr_tail | join("\n") | contains("must be no higher than 3600"))' benchmark_results/local_bench_connection_duration_ceiling_20260622.json

ssh core 'mktemp -d /root/altura-prot-connection-duration-ceiling-20260622.XXXXXX'
rsync -a --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-connection-duration-ceiling-20260622.bjkWWi/
ssh core 'cd /root/altura-prot-connection-duration-ceiling-20260622.bjkWWi && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-connection-duration-ceiling-20260622.bjkWWi && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-connection-duration-ceiling-20260622.bjkWWi && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-connection-duration-ceiling-20260622.bjkWWi && cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-connection-duration-ceiling-20260622.bjkWWi && cargo build --release'
ssh core 'cd /root/altura-prot-connection-duration-ceiling-20260622.bjkWWi && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_connection_duration_ceiling_20260622.json'
rsync -a core:/root/altura-prot-connection-duration-ceiling-20260622.bjkWWi/benchmark_results/local_bench_core_connection_duration_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.connection_duration_ceiling_startup.http_max_connection_duration_rejected == true and .guardrails.connection_duration_ceiling_startup.tcp_max_connection_duration_rejected == true and (.guardrails.connection_duration_ceiling_startup.http_max_connection_duration.stderr_tail | join("\n") | contains("http.max_connection_duration_seconds")) and (.guardrails.connection_duration_ceiling_startup.tcp_max_connection_duration.stderr_tail | join("\n") | contains("tcp[0].max_connection_duration_seconds")) and (.guardrails.connection_duration_ceiling_startup.http_max_connection_duration.stderr_tail | join("\n") | contains("must be no higher than 3600")) and (.guardrails.connection_duration_ceiling_startup.tcp_max_connection_duration.stderr_tail | join("\n") | contains("must be no higher than 3600"))' benchmark_results/local_bench_connection_duration_ceiling_20260622.json benchmark_results/local_bench_core_connection_duration_ceiling_20260622.json
```

## 2026-06-22 HTTP Upstream Timeout Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_timeout_ceiling_20260622.json`
- `benchmark_results/local_bench_core_upstream_timeout_ceiling_20260622.json`

This snapshot adds a startup ceiling for `http.upstream_timeout_ms`. The value
remains configurable but must stay between `1` and `60000` ms. The default
remains `15000` ms. The ceiling prevents a bad deploy from stretching the
origin response-header wait into minutes or hours, where stuck origin paths can
pin proxy and origin in-flight capacity.

Reference checks used for the ceiling:

- NGINX [`proxy_read_timeout`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout)
  defaults to `60s` and closes the upstream connection if the proxied server
  transmits no response data within the timeout.
- Envoy route timeout guidance documents a default `15` second route timeout
  for upstream response completion, with separate idle timeout guidance for
  streaming responses.
- Apache [`mod_proxy`](https://httpd.apache.org/docs/current/mod/mod_proxy.html)
  documents `ProxyTimeout` as the socket timeout for waiting on backend data.
- HAProxy [`timeout server`](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/)
  is the server-side inactivity timeout and is especially relevant while
  waiting for upstream response headers.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8993.14 RPS | `204: 27050` | 0 | 25.175 ms |
| admin health | 9090.47 RPS | `200: 27346` | 0 | 24.974 ms |
| raw TCP persistent echo | 19353.47 msg/s | `58103` echoed messages | 0 | 3.050 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6418.49 RPS | `204: 19346` | 0 | 35.181 ms |
| admin health on `core` | 6469.49 RPS | `200: 19493` | 0 | 34.858 ms |
| raw TCP persistent echo on `core` | 26471.67 msg/s | `79507` echoed messages | 0 | 2.433 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.upstream_timeout_ms: 60001` rejected at startup | `true` | `true` |
| rejection names `http.upstream_timeout_ms` | `true` | `true` |
| rejection includes ceiling `60000` | `true` | `true` |

Validation commands:

```bash
cargo fmt
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
cargo test upstream_timeout -- --nocapture
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_upstream_timeout_ceiling_20260622.json
jq -e '.guardrails.upstream_timeout_ceiling_startup.upstream_timeout_rejected == true and (.guardrails.upstream_timeout_ceiling_startup.stderr_tail | join("\n") | contains("http.upstream_timeout_ms")) and (.guardrails.upstream_timeout_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 60000"))' benchmark_results/local_bench_upstream_timeout_ceiling_20260622.json

ssh core 'mktemp -d /root/altura-prot-upstream-timeout-ceiling-20260622.XXXXXX'
rsync -a --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-upstream-timeout-ceiling-20260622.Y2xDOs/
ssh core 'cd /root/altura-prot-upstream-timeout-ceiling-20260622.Y2xDOs && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-upstream-timeout-ceiling-20260622.Y2xDOs && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-upstream-timeout-ceiling-20260622.Y2xDOs && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-upstream-timeout-ceiling-20260622.Y2xDOs && cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-upstream-timeout-ceiling-20260622.Y2xDOs && cargo build --release'
ssh core 'cd /root/altura-prot-upstream-timeout-ceiling-20260622.Y2xDOs && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_upstream_timeout_ceiling_20260622.json'
rsync -a core:/root/altura-prot-upstream-timeout-ceiling-20260622.Y2xDOs/benchmark_results/local_bench_core_upstream_timeout_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.upstream_timeout_ceiling_startup.upstream_timeout_rejected == true and (.guardrails.upstream_timeout_ceiling_startup.stderr_tail | join("\n") | contains("http.upstream_timeout_ms")) and (.guardrails.upstream_timeout_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 60000"))' benchmark_results/local_bench_upstream_timeout_ceiling_20260622.json benchmark_results/local_bench_core_upstream_timeout_ceiling_20260622.json
```

## 2026-06-22 HTTP Header Read Timeout Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_header_read_timeout_ceiling_20260622.json`
- `benchmark_results/local_bench_core_header_read_timeout_ceiling_20260622.json`

This snapshot adds a startup ceiling for `http.header_read_timeout_ms`.
The value remains configurable but must stay between `1` and `60000` ms.
The default remains `5000` ms for internet-facing slowloris posture. The
ceiling prevents a bad deploy from stretching the header-read window into
minutes or hours while keeping a compatibility margin above Hyper's HTTP/1
default.

Reference checks used for the ceiling:

- Hyper HTTP/1 [`header_read_timeout`](https://docs.rs/hyper/latest/hyper/server/conn/http1/struct.Builder.html)
  closes the connection when a client does not transmit the entire header in
  time; the documented default is `30` seconds.
- NGINX [`client_header_timeout`](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_header_timeout)
  defaults to `60s` and returns `408` when the full header is not transmitted
  in time.
- Apache [`mod_reqtimeout`](https://httpd.apache.org/docs/current/mod/mod_reqtimeout.html)
  documents header-stage request-read timeouts such as `header=10` and
  `header=10-30,MinRate=500`, with a default header timeout range capped at
  `40` seconds.
- Envoy timeout guidance documents downstream `request_headers_timeout` as the
  header-only timer that prevents mostly idle clients from consuming memory
  while waiting for headers.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9081.14 RPS | `204: 27314` | 0 | 24.826 ms |
| admin health | 9062.71 RPS | `200: 27263` | 0 | 25.794 ms |
| raw TCP persistent echo | 19396.98 msg/s | `58233` echoed messages | 0 | 3.034 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6450.71 RPS | `204: 19437` | 0 | 34.472 ms |
| admin health on `core` | 6563.56 RPS | `200: 19781` | 0 | 34.599 ms |
| raw TCP persistent echo on `core` | 26705.83 msg/s | `80227` echoed messages | 0 | 2.409 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.header_read_timeout_ms: 60001` rejected at startup | `true` | `true` |
| rejection names `http.header_read_timeout_ms` | `true` | `true` |
| rejection includes ceiling `60000` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test header_read_timeout -- --nocapture
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_header_read_timeout_ceiling_20260622.json
jq -e '.guardrails.header_read_timeout_ceiling_startup.header_read_timeout_rejected == true and (.guardrails.header_read_timeout_ceiling_startup.stderr_tail | join("\n") | contains("http.header_read_timeout_ms")) and (.guardrails.header_read_timeout_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 60000"))' benchmark_results/local_bench_header_read_timeout_ceiling_20260622.json

ssh core 'mktemp -d /root/altura-prot-header-read-timeout-ceiling-20260622.XXXXXX'
rsync -a --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-header-read-timeout-ceiling-20260622.6Gz7G6/
ssh core 'cd /root/altura-prot-header-read-timeout-ceiling-20260622.6Gz7G6 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-header-read-timeout-ceiling-20260622.6Gz7G6 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-header-read-timeout-ceiling-20260622.6Gz7G6 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-header-read-timeout-ceiling-20260622.6Gz7G6 && cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-header-read-timeout-ceiling-20260622.6Gz7G6 && cargo build --release'
ssh core 'cd /root/altura-prot-header-read-timeout-ceiling-20260622.6Gz7G6 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_header_read_timeout_ceiling_20260622.json'
rsync -a core:/root/altura-prot-header-read-timeout-ceiling-20260622.6Gz7G6/benchmark_results/local_bench_core_header_read_timeout_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.header_read_timeout_ceiling_startup.header_read_timeout_rejected == true and (.guardrails.header_read_timeout_ceiling_startup.stderr_tail | join("\n") | contains("http.header_read_timeout_ms")) and (.guardrails.header_read_timeout_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 60000"))' benchmark_results/local_bench_header_read_timeout_ceiling_20260622.json benchmark_results/local_bench_core_header_read_timeout_ceiling_20260622.json
```

## 2026-06-22 Event Log Queue Capacity Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_event_log_queue_capacity_ceiling_20260622.json`
- `benchmark_results/local_bench_core_event_log_queue_capacity_ceiling_20260622.json`

This snapshot adds a startup ceiling for the adaptive event-log queue.
`adaptive.event_log_queue_capacity` remains configurable but must stay at or
below `8192` events. The default remains `4096`. The event logger already uses
nonblocking enqueue and drops telemetry when the queue fills, so the ceiling
keeps a bad deploy from converting the logging control plane into an oversized
memory reservoir while still allowing measured deployments to double the
default backlog.

Reference checks used for the ceiling:

- Rust [`std::sync::mpsc::sync_channel`](https://doc.rust-lang.org/std/sync/mpsc/fn.sync_channel.html)
  creates a synchronous bounded channel where the configured bound is the
  internal buffer size.
- Python [`queue.Queue(maxsize)`](https://docs.python.org/3/library/queue.html#queue.Queue)
  treats `maxsize` as the upper bound and documents nonpositive values as
  infinite queue sizes.
- Tokio [`mpsc`](https://docs.rs/tokio/latest/tokio/sync/mpsc/) distinguishes
  bounded channels, which apply backpressure, from unbounded channels.
- Logback [`AsyncAppender`](https://logback.qos.ch/manual/appenders.html)
  defaults its async logging queue to `256` events and blocks application
  threads when the event buffer is full.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9009.47 RPS | `204: 27100` | 0 | 25.143 ms |
| admin health | 9080.66 RPS | `200: 27320` | 0 | 25.232 ms |
| raw TCP persistent echo | 19377.45 msg/s | `58176` echoed messages | 0 | 3.029 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6641.18 RPS | `204: 20008` | 0 | 34.192 ms |
| admin health on `core` | 6567.90 RPS | `200: 19794` | 0 | 34.435 ms |
| raw TCP persistent echo on `core` | 24375.20 msg/s | `73241` echoed messages | 0 | 2.638 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `adaptive.event_log_queue_capacity: 8193` rejected at startup | `true` | `true` |
| rejection names `adaptive.event_log_queue_capacity` | `true` | `true` |
| rejection includes ceiling `8192` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_event_log_queue_capacity_ceiling_20260622.json
jq -e '.guardrails.event_log_queue_capacity_ceiling_startup.event_log_queue_capacity_rejected == true and (.guardrails.event_log_queue_capacity_ceiling_startup.stderr_tail | join("\n") | contains("adaptive.event_log_queue_capacity")) and (.guardrails.event_log_queue_capacity_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 8192"))' benchmark_results/local_bench_event_log_queue_capacity_ceiling_20260622.json

ssh core 'mktemp -d /root/altura-prot-event-log-queue-capacity-ceiling-20260622.XXXXXX'
rsync -a --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-event-log-queue-capacity-ceiling-20260622.CvidtG/
ssh core 'cd /root/altura-prot-event-log-queue-capacity-ceiling-20260622.CvidtG && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-event-log-queue-capacity-ceiling-20260622.CvidtG && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-event-log-queue-capacity-ceiling-20260622.CvidtG && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-event-log-queue-capacity-ceiling-20260622.CvidtG && cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-event-log-queue-capacity-ceiling-20260622.CvidtG && cargo build --release'
ssh core 'cd /root/altura-prot-event-log-queue-capacity-ceiling-20260622.CvidtG && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_event_log_queue_capacity_ceiling_20260622.json'
rsync -a core:/root/altura-prot-event-log-queue-capacity-ceiling-20260622.CvidtG/benchmark_results/local_bench_core_event_log_queue_capacity_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.event_log_queue_capacity_ceiling_startup.event_log_queue_capacity_rejected == true and (.guardrails.event_log_queue_capacity_ceiling_startup.stderr_tail | join("\n") | contains("adaptive.event_log_queue_capacity")) and (.guardrails.event_log_queue_capacity_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 8192"))' benchmark_results/local_bench_event_log_queue_capacity_ceiling_20260622.json benchmark_results/local_bench_core_event_log_queue_capacity_ceiling_20260622.json
```

## 2026-06-22 Event Log Backup Count Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_event_log_backup_count_ceiling_20260622.json`
- `benchmark_results/local_bench_core_event_log_backup_count_ceiling_20260622.json`

This snapshot adds a startup ceiling for adaptive event-log backup retention.
`adaptive.event_log_backup_count` must now stay between `1` and `128`. The
current numbered rotation path deletes the highest retained backup, scans
existing backups, and renames each numbered file up by one slot, so very large
backup counts make each attack-event rotation perform excessive filesystem
work. Longer incident retention should be handled by external log archival
instead of the writer thread's hot rotation path.

Reference checks used for the ceiling:

- [`logrotate rotate count`](https://man7.org/linux/man-pages/man8/logrotate.8.html)
  uses an explicit retained-rotation count and warns that unbounded old logs can
  waste performance and disk space.
- [`systemd-journald SystemMaxFiles` and `RuntimeMaxFiles`](https://man7.org/linux/man-pages/man5/journald.conf.5.html)
  keep an explicit maximum number of journal files, defaulting to `100`.
- Python's [`RotatingFileHandler`](https://docs.python.org/3/library/logging.handlers.html#logging.handlers.RotatingFileHandler)
  uses `backupCount` to keep numbered backups and renames existing `.1`, `.2`,
  and later files during rollover.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9001.79 RPS | `204: 27079` | 0 | 25.217 ms |
| admin health | 9132.71 RPS | `200: 27477` | 0 | 25.070 ms |
| raw TCP persistent echo | 19229.55 msg/s | `57731` echoed messages | 0 | 3.036 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6553.36 RPS | `204: 19746` | 0 | 34.794 ms |
| admin health on `core` | 6572.09 RPS | `200: 19806` | 0 | 34.034 ms |
| raw TCP persistent echo on `core` | 26780.46 msg/s | `80434` echoed messages | 0 | 2.401 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `adaptive.event_log_backup_count: 129` rejected at startup | `true` | `true` |
| rejection names `adaptive.event_log_backup_count` | `true` | `true` |
| rejection includes ceiling `128` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_event_log_backup_count_ceiling_20260622.json
jq -e '.guardrails.event_log_backup_count_ceiling_startup.event_log_backup_count_rejected == true and (.guardrails.event_log_backup_count_ceiling_startup.stderr_tail | join("\n") | contains("adaptive.event_log_backup_count")) and (.guardrails.event_log_backup_count_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 128"))' benchmark_results/local_bench_event_log_backup_count_ceiling_20260622.json

ssh core 'mktemp -d /root/altura-prot-event-log-backup-count-ceiling-20260622.XXXXXX'
rsync -a --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ /Users/core/AlturaProt/ core:/root/altura-prot-event-log-backup-count-ceiling-20260622.3yzX84/
ssh core 'cd /root/altura-prot-event-log-backup-count-ceiling-20260622.3yzX84 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /root/altura-prot-event-log-backup-count-ceiling-20260622.3yzX84 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /root/altura-prot-event-log-backup-count-ceiling-20260622.3yzX84 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/altura-prot-event-log-backup-count-ceiling-20260622.3yzX84 && cargo test -- --nocapture'
ssh core 'cd /root/altura-prot-event-log-backup-count-ceiling-20260622.3yzX84 && cargo build --release'
ssh core 'cd /root/altura-prot-event-log-backup-count-ceiling-20260622.3yzX84 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_event_log_backup_count_ceiling_20260622.json'
rsync -a core:/root/altura-prot-event-log-backup-count-ceiling-20260622.3yzX84/benchmark_results/local_bench_core_event_log_backup_count_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.event_log_backup_count_ceiling_startup.event_log_backup_count_rejected == true and (.guardrails.event_log_backup_count_ceiling_startup.stderr_tail | join("\n") | contains("adaptive.event_log_backup_count")) and (.guardrails.event_log_backup_count_ceiling_startup.stderr_tail | join("\n") | contains("must be no higher than 128"))' benchmark_results/local_bench_event_log_backup_count_ceiling_20260622.json benchmark_results/local_bench_core_event_log_backup_count_ceiling_20260622.json
```

## 2026-06-22 HTTP Header Count Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_header_count_ceiling_20260622.json`
- `benchmark_results/local_bench_core_header_count_ceiling_20260622.json`

This snapshot adds a startup ceiling for configured HTTP/1 header counts.
`http.max_headers` and `http.upstream_max_headers` remain configurable but must
stay at or below `1024`. The default remains `100`, matching common proxy
defaults. The ceiling prevents a bad deploy from making Hyper reserve
unreasonably large parser header arrays for downstream requests or upstream
responses.

Reference checks used for the ceiling:

- Hyper's HTTP/1 server builder documents that the request parser reserves a
  header buffer from `max_headers` and returns `431` if the request exceeds it.
- Envoy protocol options default maximum header count to `100`, return `431` for
  downstream HTTP/1 overflow, and treat upstream response overflow as an upstream
  error.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 7970.69 RPS | `204: 23980` | 0 | 29.399 ms |
| admin health | 8053.60 RPS | `200: 24242` | 0 | 29.365 ms |
| raw TCP persistent echo | 17880.60 msg/s | `53686` echoed messages | 0 | 3.336 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6526.82 RPS | `204: 19672` | 0 | 34.613 ms |
| admin health on `core` | 6397.02 RPS | `200: 19282` | 0 | 35.364 ms |
| raw TCP persistent echo on `core` | 26502.52 msg/s | `79628` echoed messages | 0 | 2.435 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.max_headers: 1025` rejected at startup | `true` | `true` |
| rejection names `http.max_headers` | `true` | `true` |
| rejection includes ceiling `1024` | `true` | `true` |
| `http.upstream_max_headers: 1025` rejected at startup | `true` | `true` |
| rejection names `http.upstream_max_headers` | `true` | `true` |
| rejection includes ceiling `1024` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_header_count_ceiling_20260622.json
jq -e '.guardrails.header_count_ceiling_startup.downstream_max_headers_rejected == true and .guardrails.header_count_ceiling_startup.upstream_max_headers_rejected == true and (.guardrails.header_count_ceiling_startup.downstream_max_headers.stderr_tail | join("\n") | contains("http.max_headers")) and (.guardrails.header_count_ceiling_startup.upstream_max_headers.stderr_tail | join("\n") | contains("http.upstream_max_headers")) and (.guardrails.header_count_ceiling_startup.downstream_max_headers.stderr_tail | join("\n") | contains("must be no higher than 1024")) and (.guardrails.header_count_ceiling_startup.upstream_max_headers.stderr_tail | join("\n") | contains("must be no higher than 1024"))' benchmark_results/local_bench_header_count_ceiling_20260622.json

ssh core 'rm -rf /tmp/altura-prot-header-count-ceiling-20260622 && mkdir -p /tmp/altura-prot-header-count-ceiling-20260622'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/tmp/altura-prot-header-count-ceiling-20260622/
ssh core 'cd /tmp/altura-prot-header-count-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-header-count-ceiling-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-header-count-ceiling-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-header-count-ceiling-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-header-count-ceiling-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-header-count-ceiling-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_header_count_ceiling_20260622.json'
rsync -a core:/tmp/altura-prot-header-count-ceiling-20260622/benchmark_results/local_bench_core_header_count_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.header_count_ceiling_startup.downstream_max_headers_rejected == true and .guardrails.header_count_ceiling_startup.upstream_max_headers_rejected == true and (.guardrails.header_count_ceiling_startup.downstream_max_headers.stderr_tail | join("\n") | contains("http.max_headers")) and (.guardrails.header_count_ceiling_startup.upstream_max_headers.stderr_tail | join("\n") | contains("http.upstream_max_headers")) and (.guardrails.header_count_ceiling_startup.downstream_max_headers.stderr_tail | join("\n") | contains("must be no higher than 1024")) and (.guardrails.header_count_ceiling_startup.upstream_max_headers.stderr_tail | join("\n") | contains("must be no higher than 1024"))' benchmark_results/local_bench_header_count_ceiling_20260622.json benchmark_results/local_bench_core_header_count_ceiling_20260622.json
```

## 2026-06-22 HTTP Header Buffer Ceiling Snapshot

Artifacts:

- `benchmark_results/local_bench_header_buffer_ceiling_20260622.json`
- `benchmark_results/local_bench_core_header_buffer_ceiling_20260622.json`

This snapshot adds a startup ceiling for the configured HTTP/1 header-byte
buffers. `http.max_header_bytes` and `http.upstream_max_header_bytes` must now
stay between Hyper's required `8192` byte floor and AlturaProt's `262144` byte
startup ceiling. The cap keeps a bad deploy from allowing excessive
per-connection parser buffers while still leaving headroom above common proxy
defaults for services with measured large-cookie or large-metadata needs.

Reference checks used for the ceiling:

- NGINX defaults large client header buffers to `4 8k` and notes oversized
  request lines/fields are rejected when they do not fit configured buffers.
- Envoy defaults incoming request headers to `60 KiB` and reports oversized
  request headers as `431`.
- Node.js defaults server and client request header limits to `16 KiB`.
- Envoy protocol options default header counts to `100`, matching AlturaProt's
  default header-count cap.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 7754.00 RPS | `204: 23339` | 0 | 30.569 ms |
| admin health | 7860.61 RPS | `200: 23661` | 0 | 29.818 ms |
| raw TCP persistent echo | 18401.12 msg/s | `55249` echoed messages | 0 | 3.254 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6509.84 RPS | `204: 19618` | 0 | 35.117 ms |
| admin health on `core` | 6536.70 RPS | `200: 19700` | 0 | 34.033 ms |
| raw TCP persistent echo on `core` | 25934.13 msg/s | `77912` echoed messages | 0 | 2.506 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.max_header_bytes: 262145` rejected at startup | `true` | `true` |
| rejection names `http.max_header_bytes` | `true` | `true` |
| rejection includes ceiling `262144` | `true` | `true` |
| `http.upstream_max_header_bytes: 262145` rejected at startup | `true` | `true` |
| rejection names `http.upstream_max_header_bytes` | `true` | `true` |
| rejection includes ceiling `262144` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_header_buffer_ceiling_20260622.json
jq -e '.guardrails.header_buffer_ceiling_startup.downstream_max_header_bytes_rejected == true and .guardrails.header_buffer_ceiling_startup.upstream_max_header_bytes_rejected == true and (.guardrails.header_buffer_ceiling_startup.downstream_max_header_bytes.stderr_tail | join("\n") | contains("http.max_header_bytes")) and (.guardrails.header_buffer_ceiling_startup.upstream_max_header_bytes.stderr_tail | join("\n") | contains("http.upstream_max_header_bytes")) and (.guardrails.header_buffer_ceiling_startup.downstream_max_header_bytes.stderr_tail | join("\n") | contains("must be no higher than 262144")) and (.guardrails.header_buffer_ceiling_startup.upstream_max_header_bytes.stderr_tail | join("\n") | contains("must be no higher than 262144"))' benchmark_results/local_bench_header_buffer_ceiling_20260622.json

ssh core 'rm -rf /tmp/altura-prot-header-buffer-ceiling-20260622 && mkdir -p /tmp/altura-prot-header-buffer-ceiling-20260622'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/tmp/altura-prot-header-buffer-ceiling-20260622/
ssh core 'cd /tmp/altura-prot-header-buffer-ceiling-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-header-buffer-ceiling-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-header-buffer-ceiling-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-header-buffer-ceiling-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-header-buffer-ceiling-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-header-buffer-ceiling-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_header_buffer_ceiling_20260622.json'
rsync -a core:/tmp/altura-prot-header-buffer-ceiling-20260622/benchmark_results/local_bench_core_header_buffer_ceiling_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.header_buffer_ceiling_startup.downstream_max_header_bytes_rejected == true and .guardrails.header_buffer_ceiling_startup.upstream_max_header_bytes_rejected == true and (.guardrails.header_buffer_ceiling_startup.downstream_max_header_bytes.stderr_tail | join("\n") | contains("http.max_header_bytes")) and (.guardrails.header_buffer_ceiling_startup.upstream_max_header_bytes.stderr_tail | join("\n") | contains("http.upstream_max_header_bytes")) and (.guardrails.header_buffer_ceiling_startup.downstream_max_header_bytes.stderr_tail | join("\n") | contains("must be no higher than 262144")) and (.guardrails.header_buffer_ceiling_startup.upstream_max_header_bytes.stderr_tail | join("\n") | contains("must be no higher than 262144"))' benchmark_results/local_bench_header_buffer_ceiling_20260622.json benchmark_results/local_bench_core_header_buffer_ceiling_20260622.json
```

## 2026-06-22 Admin Response Close Snapshot

Artifacts:

- `benchmark_results/local_bench_admin_response_close_20260622.json`
- `benchmark_results/local_bench_core_admin_response_close_20260622.json`

This snapshot makes generated admin control-plane responses explicitly close the
downstream HTTP/1.1 connection. `GET /__altura/health`, forbidden
`GET /__altura/metrics`, and token-authorized `GET /__altura/metrics` now return
both `Cache-Control: no-store` and `Connection: close`. The benchmark also sends
body-bearing admin requests over a keep-alive socket and verifies that no
follow-up request can be processed on that same connection.

Reference checks used for the invariant:

- RFC 9112 documents HTTP/1.1 persistent connections by default and the
  `Connection: close` signal for closing after the response.
- RFC 9110 says a server that sends a final response before reading all request
  content should indicate whether it intends to close or continue reading.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8187.59 RPS | `204: 24792` | 0 | 28.359 ms |
| admin health | 8448.57 RPS | `200: 25554` | 0 | 27.313 ms |
| raw TCP persistent echo | 19037.87 msg/s | `57156` echoed messages | 0 | 3.105 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6436.91 RPS | `204: 19398` | 0 | 35.567 ms |
| admin health on `core` | 6562.80 RPS | `200: 19778` | 0 | 34.477 ms |
| raw TCP persistent echo on `core` | 26273.90 msg/s | `78939` echoed messages | 0 | 2.444 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| health response no-store and close | `true` | `true` |
| metrics-without-token response no-store and close | `true` | `true` |
| metrics-with-token response no-store and close | `true` | `true` |
| body-bearing health request cannot be followed on same socket | `true` | `true` |
| body-bearing metrics-without-token request cannot be followed on same socket | `true` | `true` |
| body-bearing metrics-with-token request cannot be followed on same socket | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_admin_response_close_20260622.json
jq -e '.guardrails.admin_control_plane.admin_responses_not_stored == true and .guardrails.admin_control_plane.admin_responses_close_connection == true and .guardrails.admin_control_plane.body_bearing_admin_responses_not_stored == true and .guardrails.admin_control_plane.body_bearing_health_closes_connection == true and .guardrails.admin_control_plane.body_bearing_metrics_without_token_closes_connection == true and .guardrails.admin_control_plane.body_bearing_metrics_with_token_closes_connection == true' benchmark_results/local_bench_admin_response_close_20260622.json

ssh core 'rm -rf /tmp/altura-prot-admin-response-close-20260622 && mkdir -p /tmp/altura-prot-admin-response-close-20260622'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/tmp/altura-prot-admin-response-close-20260622/
ssh core 'cd /tmp/altura-prot-admin-response-close-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-admin-response-close-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-admin-response-close-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-admin-response-close-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-admin-response-close-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-admin-response-close-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_admin_response_close_20260622.json'
rsync -a core:/tmp/altura-prot-admin-response-close-20260622/benchmark_results/local_bench_core_admin_response_close_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.admin_control_plane.admin_responses_not_stored == true and .guardrails.admin_control_plane.admin_responses_close_connection == true and .guardrails.admin_control_plane.body_bearing_admin_responses_not_stored == true and .guardrails.admin_control_plane.body_bearing_health_closes_connection == true and .guardrails.admin_control_plane.body_bearing_metrics_without_token_closes_connection == true and .guardrails.admin_control_plane.body_bearing_metrics_with_token_closes_connection == true' benchmark_results/local_bench_admin_response_close_20260622.json benchmark_results/local_bench_core_admin_response_close_20260622.json
```

## 2026-06-22 HTTP/1 Header Buffer Floor Snapshot

Artifacts:

- `benchmark_results/local_bench_header_buffer_floor_20260622.json`
- `benchmark_results/local_bench_core_header_buffer_floor_20260622.json`

This snapshot makes Hyper's HTTP/1 parser buffer floor explicit in config
validation. `http.max_header_bytes` and `http.upstream_max_header_bytes` must be
at least `8192`, matching Hyper's documented minimum for downstream server and
upstream client HTTP/1 buffer caps. The runtime now passes the validated values
directly to Hyper instead of silently raising below-floor config values.

Reference checks used for the invariant:

- Hyper server HTTP/1 `Builder::max_buf_size` documents an `8192` minimum and
  panics below that value.
- Hyper-util legacy client `Builder::http1_max_buf_size` documents the same
  `8192` minimum and panic behavior.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8413.03 RPS | `204: 25300` | 0 | 27.732 ms |
| admin health | 8106.43 RPS | `200: 24398` | 0 | 28.983 ms |
| raw TCP persistent echo | 18721.44 msg/s | `56208` echoed messages | 0 | 3.172 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6631.97 RPS | `204: 19984` | 0 | 34.337 ms |
| admin health on `core` | 6492.35 RPS | `200: 19567` | 0 | 35.082 ms |
| raw TCP persistent echo on `core` | 23404.50 msg/s | `70316` echoed messages | 0 | 2.752 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `http.max_header_bytes: 8191` rejected at startup | `true` | `true` |
| rejection names `http.max_header_bytes` | `true` | `true` |
| `http.upstream_max_header_bytes: 8191` rejected at startup | `true` | `true` |
| rejection names `http.upstream_max_header_bytes` | `true` | `true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_header_buffer_floor_20260622.json
jq -e '.guardrails.header_buffer_floor_startup.downstream_max_header_bytes_rejected == true and .guardrails.header_buffer_floor_startup.upstream_max_header_bytes_rejected == true and (.guardrails.header_buffer_floor_startup.downstream_max_header_bytes.stderr_tail | join("\n") | contains("http.max_header_bytes")) and (.guardrails.header_buffer_floor_startup.upstream_max_header_bytes.stderr_tail | join("\n") | contains("http.upstream_max_header_bytes"))' benchmark_results/local_bench_header_buffer_floor_20260622.json

ssh core 'rm -rf /tmp/altura-prot-header-buffer-floor-20260622 && mkdir -p /tmp/altura-prot-header-buffer-floor-20260622'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/tmp/altura-prot-header-buffer-floor-20260622/
ssh core 'cd /tmp/altura-prot-header-buffer-floor-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-header-buffer-floor-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-header-buffer-floor-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-header-buffer-floor-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-header-buffer-floor-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-header-buffer-floor-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_header_buffer_floor_20260622.json'
rsync -a core:/tmp/altura-prot-header-buffer-floor-20260622/benchmark_results/local_bench_core_header_buffer_floor_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.header_buffer_floor_startup.downstream_max_header_bytes_rejected == true and .guardrails.header_buffer_floor_startup.upstream_max_header_bytes_rejected == true and (.guardrails.header_buffer_floor_startup.downstream_max_header_bytes.stderr_tail | join("\n") | contains("http.max_header_bytes")) and (.guardrails.header_buffer_floor_startup.upstream_max_header_bytes.stderr_tail | join("\n") | contains("http.upstream_max_header_bytes"))' benchmark_results/local_bench_header_buffer_floor_20260622.json benchmark_results/local_bench_core_header_buffer_floor_20260622.json
```

## 2026-06-22 Upstream Connect Timeout Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_connect_timeout_validation_20260622.json`
- `benchmark_results/local_bench_core_upstream_connect_timeout_validation_20260622.json`

This snapshot makes `http.upstream_connect_timeout_ms` a positive startup
capacity invariant. The HTTP client always installs the configured Hyper-util
connector timeout, and config validation now rejects `0` so a typo cannot
silently remove the origin TCP connection-establishment guard and leave only the
broader upstream header wait budget.

Reference checks used for the invariant:

- Hyper-util documents `HttpConnector::set_connect_timeout` as optional, with
  `None` as the default.
- Tokio's broader `timeout` wrapper is a request/future budget, not an explicit
  connector setting.
- NGINX documents upstream connection establishment timeout separately from
  upstream read/send timeouts.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8399.83 RPS | `204: 25275` | 0 | 27.106 ms |
| admin health | 8434.74 RPS | `200: 25380` | 0 | 27.810 ms |
| raw TCP persistent echo | 18815.17 msg/s | `56492` echoed messages | 0 | 3.120 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6659.84 RPS | `204: 20065` | 0 | 34.029 ms |
| admin health on `core` | 6583.31 RPS | `200: 19839` | 0 | 33.828 ms |
| raw TCP persistent echo on `core` | 25890.04 msg/s | `77756` echoed messages | 0 | 2.516 ms |

Guardrails:

| Probe | Local | `core` |
| --- | --- | --- |
| `upstream_connect_timeout_ms: 0` rejected at startup | `true` | `true` |
| rejection names `http.upstream_connect_timeout_ms` | `true` | `true` |
| saturated-loopback upstream connect timeout observed | `true` | `true` |
| first saturated origin connect | `502` after `0.078` s | `502` after `0.076` s |
| second saturated origin connect | `502` after `0.077` s | `502` after `0.077` s |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_upstream_connect_timeout_validation_20260622.json
jq -e '.guardrails.zero_capacity_startup.http_upstream_connect_timeout_rejected == true and .guardrails.zero_capacity_startup.http_upstream_connect_timeout.startup_rejected == true and (.guardrails.zero_capacity_startup.http_upstream_connect_timeout.stderr_tail | join("\n") | contains("http.upstream_connect_timeout_ms")) and .guardrails.upstream_connect_timeout.upstream_connect_timeout_observed == true' benchmark_results/local_bench_upstream_connect_timeout_validation_20260622.json

ssh core 'mkdir -p /tmp/altura-prot-upstream-connect-timeout-validation-20260622'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/tmp/altura-prot-upstream-connect-timeout-validation-20260622/
ssh core 'cd /tmp/altura-prot-upstream-connect-timeout-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-upstream-connect-timeout-validation-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-upstream-connect-timeout-validation-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-upstream-connect-timeout-validation-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-upstream-connect-timeout-validation-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-upstream-connect-timeout-validation-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_upstream_connect_timeout_validation_20260622.json'
rsync -a core:/tmp/altura-prot-upstream-connect-timeout-validation-20260622/benchmark_results/local_bench_core_upstream_connect_timeout_validation_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.zero_capacity_startup.http_upstream_connect_timeout_rejected == true and .guardrails.zero_capacity_startup.http_upstream_connect_timeout.startup_rejected == true and (.guardrails.zero_capacity_startup.http_upstream_connect_timeout.stderr_tail | join("\n") | contains("http.upstream_connect_timeout_ms")) and .guardrails.upstream_connect_timeout.upstream_connect_timeout_observed == true' benchmark_results/local_bench_upstream_connect_timeout_validation_20260622.json benchmark_results/local_bench_core_upstream_connect_timeout_validation_20260622.json
```

## 2026-06-22 Generic TCP L4Proto Snapshot

Artifacts:

- `benchmark_results/local_bench_generic_tcp_l4proto_20260622.json`
- `benchmark_results/local_bench_core_generic_tcp_l4proto_20260622.json`

This snapshot moves generic dual-stack protected-port TCP backstops onto an
explicit `meta l4proto tcp` predicate before transport-header matches. The
covered rules are the pre-conntrack null-flag drop, Xmas-flag drop, global SYN
flood drop, post-conntrack new non-SYN drop, and global new-connection flood
drop. This keeps the compact `inet` table shape while making these generic
TCP rules use the real transport protocol for IPv4/IPv6 traffic. The validator
and benchmark guardrail reject a template where those generic rules fall back
to bare `tcp dport`/`tcp flags` matches.

Reference checks used for the rule shape:

- nftables packet-header docs recommend `meta l4proto tcp` in `inet` family
  tables and note that it skips IPv6 extension headers.
- The nft manpage documents `meta l4proto` as the layer-4 protocol expression
  that skips IPv6 extension headers.
- nftables family docs describe `inet` as the shared IPv4/IPv6 table family and
  recommend `meta l4proto` for layer-4 protocol matching across both families.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8840.04 RPS | `204: 26588` | 0 | 25.563 ms |
| admin health | 8938.76 RPS | `200: 26893` | 0 | 25.967 ms |
| raw TCP persistent echo | 19304.59 msg/s | `57958` echoed messages | 0 | 3.041 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6571.34 RPS | `204: 19802` | 0 | 34.832 ms |
| admin health on `core` | 6428.95 RPS | `200: 19380` | 0 | 34.754 ms |
| raw TCP persistent echo on `core` | 26617.13 msg/s | `79961` echoed messages | 0 | 2.423 ms |

Generic TCP guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| shipped generic protected-port TCP backstops use `meta l4proto tcp` | `true` | `true` |
| template missing generic `meta l4proto tcp` is rejected | `true` | `true` |
| IPv6-specific extension-safe protocol checks remain valid | `true` | `true` |

Validation commands:

```bash
python3 -m py_compile tools/validate_edge_templates.py tools/run_local_bench.py tools/test_ai_tools.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_generic_tcp_l4proto_20260622.json
jq -e '.guardrails.edge_template_port_coverage.generic_tcp_backstops_allowed == true and .guardrails.edge_template_port_coverage.missing_generic_tcp_l4proto_rejected == true and .guardrails.edge_template_port_coverage.ipv6_extension_safe_protocols_allowed == true' benchmark_results/local_bench_generic_tcp_l4proto_20260622.json

ssh core 'rm -rf /tmp/altura-prot-generic-tcp-l4proto-20260622 && mkdir -p /tmp/altura-prot-generic-tcp-l4proto-20260622'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/tmp/altura-prot-generic-tcp-l4proto-20260622/
ssh core 'cd /tmp/altura-prot-generic-tcp-l4proto-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py && PYTHONPATH=tools python3 tools/test_ai_tools.py && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-generic-tcp-l4proto-20260622 && cargo test -- --nocapture && cargo build --release'
ssh core 'cd /tmp/altura-prot-generic-tcp-l4proto-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_generic_tcp_l4proto_20260622.json'
rsync -a core:/tmp/altura-prot-generic-tcp-l4proto-20260622/benchmark_results/local_bench_core_generic_tcp_l4proto_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.generic_tcp_backstops_allowed == true and .guardrails.edge_template_port_coverage.missing_generic_tcp_l4proto_rejected == true and .guardrails.edge_template_port_coverage.ipv6_extension_safe_protocols_allowed == true' benchmark_results/local_bench_generic_tcp_l4proto_20260622.json benchmark_results/local_bench_core_generic_tcp_l4proto_20260622.json
```

## 2026-06-22 ICMPv4 Control Exemption Snapshot

Artifacts:

- `benchmark_results/local_bench_icmpv4_control_exemption_20260622.json`
- `benchmark_results/local_bench_core_icmpv4_control_exemption_20260622.json`

This snapshot exempts essential IPv4 ICMP control messages before the generic
ICMPv4 flood backstop in `ops/nftables/altura-prot-edge.nft`. The exempted
types are destination unreachable, time exceeded, and parameter problem, which
preserves IPv4 Path MTU Discovery and related control feedback while leaving
non-essential ICMP covered by the flood-rate backstop. The validator and
benchmark guardrail reject a missing exemption and reject an exemption that
appears after the generic ICMPv4 flood drop.

Reference checks used for the rule shape:

- RFC 1191 Path MTU Discovery requires ICMP destination unreachable with the
  fragmentation-needed code for PMTUD feedback.
- IANA's ICMP registry lists destination unreachable, time exceeded, and
  parameter problem as IPv4 ICMP types.
- nftables documents `icmp type { ... }` symbolic matching for these types.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8987.15 RPS | `204: 27035` | 0 | 25.153 ms |
| admin health | 9056.91 RPS | `200: 27250` | 0 | 25.505 ms |
| raw TCP persistent echo | 19431.03 msg/s | `58339` echoed messages | 0 | 3.029 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6602.89 RPS | `204: 19897` | 0 | 34.297 ms |
| admin health on `core` | 6561.62 RPS | `200: 19778` | 0 | 33.986 ms |
| raw TCP persistent echo on `core` | 23296.83 msg/s | `69990` echoed messages | 0 | 2.765 ms |

ICMP control guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| shipped ICMPv4 control exemption appears before flood drop | `true` | `true` |
| template missing ICMPv4 control exemption is rejected | `true` | `true` |
| template with late ICMPv4 control exemption is rejected | `true` | `true` |
| shipped ICMPv6 control exemption remains valid | `true` | `true` |
| template missing ICMPv6 control exemption is rejected | `true` | `true` |
| template with late ICMPv6 control exemption is rejected | `true` | `true` |

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_icmpv4_control_exemption_20260622.json
jq -e '.guardrails.edge_template_port_coverage.icmpv4_control_exemption_allowed == true and .guardrails.edge_template_port_coverage.missing_icmpv4_control_exemption_rejected == true and .guardrails.edge_template_port_coverage.late_icmpv4_control_exemption_rejected == true and .guardrails.edge_template_port_coverage.icmpv6_control_exemption_allowed == true and .guardrails.edge_template_port_coverage.missing_icmpv6_control_exemption_rejected == true and .guardrails.edge_template_port_coverage.late_icmpv6_control_exemption_rejected == true' benchmark_results/local_bench_icmpv4_control_exemption_20260622.json

ssh core 'rm -rf /tmp/altura-prot-icmpv4-control-exemption-20260622 && mkdir -p /tmp/altura-prot-icmpv4-control-exemption-20260622'
rsync -a --delete --exclude target --exclude .git --exclude .DS_Store /Users/core/AlturaProt/ core:/tmp/altura-prot-icmpv4-control-exemption-20260622/
ssh core 'cd /tmp/altura-prot-icmpv4-control-exemption-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py && PYTHONPATH=tools python3 tools/test_ai_tools.py && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-icmpv4-control-exemption-20260622 && cargo test -- --nocapture && cargo build --release'
ssh core 'cd /tmp/altura-prot-icmpv4-control-exemption-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_icmpv4_control_exemption_20260622.json'
rsync -a core:/tmp/altura-prot-icmpv4-control-exemption-20260622/benchmark_results/local_bench_core_icmpv4_control_exemption_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.icmpv4_control_exemption_allowed == true and .guardrails.edge_template_port_coverage.missing_icmpv4_control_exemption_rejected == true and .guardrails.edge_template_port_coverage.late_icmpv4_control_exemption_rejected == true and .guardrails.edge_template_port_coverage.icmpv6_control_exemption_allowed == true and .guardrails.edge_template_port_coverage.missing_icmpv6_control_exemption_rejected == true and .guardrails.edge_template_port_coverage.late_icmpv6_control_exemption_rejected == true' benchmark_results/local_bench_icmpv4_control_exemption_20260622.json benchmark_results/local_bench_core_icmpv4_control_exemption_20260622.json
```

## 2026-06-22 ICMPv6 Control Exemption Snapshot

Artifacts:

- `benchmark_results/local_bench_icmpv6_control_exemption_20260622.json`
- `benchmark_results/local_bench_core_icmpv6_control_exemption_20260622.json`

This snapshot exempts essential ICMPv6 control messages before the generic
ICMPv6 flood backstop in `ops/nftables/altura-prot-edge.nft`. The exempted
types are destination unreachable, packet too big, time exceeded, parameter
problem, router solicitation/advertisement, and neighbor solicitation/
advertisement. The validator and benchmark guardrail reject a missing exemption
and reject an exemption that appears after the generic ICMPv6 flood drop.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8803.06 RPS | `204: 26478` | 0 | 25.520 ms |
| admin health | 9070.30 RPS | `200: 27287` | 0 | 25.352 ms |
| raw TCP persistent echo | 19078.33 msg/s | `57276` echoed messages | 0 | 3.045 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6403.20 RPS | `204: 19292` | 0 | 35.551 ms |
| admin health on `core` | 6387.17 RPS | `200: 19255` | 0 | 34.743 ms |
| raw TCP persistent echo on `core` | 24179.01 msg/s | `72637` echoed messages | 0 | 2.685 ms |

ICMPv6 control guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| shipped ICMPv6 control exemption appears before flood drop | `true` | `true` |
| template missing ICMPv6 control exemption is rejected | `true` | `true` |
| template with late ICMPv6 control exemption is rejected | `true` | `true` |
| missing-exemption validator status | `1` | `1` |
| late-exemption validator status | `1` | `1` |

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_icmpv6_control_exemption_20260622.json
jq -e '.guardrails.edge_template_port_coverage.icmpv6_control_exemption_allowed == true and .guardrails.edge_template_port_coverage.missing_icmpv6_control_exemption_rejected == true and .guardrails.edge_template_port_coverage.late_icmpv6_control_exemption_rejected == true' benchmark_results/local_bench_icmpv6_control_exemption_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-icmpv6-control-exemption-20260622/
ssh core 'cd /tmp/altura-prot-icmpv6-control-exemption-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py && PYTHONPATH=tools python3 tools/test_ai_tools.py && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-icmpv6-control-exemption-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-icmpv6-control-exemption-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-icmpv6-control-exemption-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_icmpv6_control_exemption_20260622.json'
rsync -a core:/tmp/altura-prot-icmpv6-control-exemption-20260622/benchmark_results/local_bench_core_icmpv6_control_exemption_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.icmpv6_control_exemption_allowed == true and .guardrails.edge_template_port_coverage.missing_icmpv6_control_exemption_rejected == true and .guardrails.edge_template_port_coverage.late_icmpv6_control_exemption_rejected == true' benchmark_results/local_bench_core_icmpv6_control_exemption_20260622.json
```

## 2026-06-22 SYN Rate Set Bounds Snapshot

Artifacts:

- `benchmark_results/local_bench_syn_rate_set_bounds_20260622.json`
- `benchmark_results/local_bench_core_syn_rate_set_bounds_20260622.json`

This snapshot changes the pre-conntrack nftables SYN backstop from inline
meters to named dynamic sets with explicit capacity and retention bounds:
`tcp4_syn_rate` and `tcp6_syn_rate` now use `size 65535`, `flags
dynamic,timeout`, and `timeout 10s`. The validator and benchmark guardrail now
reject missing SYN-rate set sizes and missing timeout support, so high-cardinality
SYN source pressure cannot leave this kernel-side state capacity implicit.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8760.66 RPS | `204: 26349` | 0 | 26.393 ms |
| admin health | 9068.58 RPS | `200: 27278` | 0 | 25.342 ms |
| raw TCP persistent echo | 19455.50 msg/s | `58411` echoed messages | 0 | 3.026 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6637.83 RPS | `204: 20003` | 0 | 34.345 ms |
| admin health on `core` | 6577.15 RPS | `200: 19818` | 0 | 34.607 ms |
| raw TCP persistent echo on `core` | 25724.64 msg/s | `77257` echoed messages | 0 | 2.518 ms |

SYN-rate set guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| shipped SYN-rate sets have explicit size and timeout bounds | `true` | `true` |
| template missing SYN-rate set size is rejected | `true` | `true` |
| template missing SYN-rate set timeout support is rejected | `true` | `true` |
| missing-size validator status | `1` | `1` |
| missing-timeout validator status | `1` | `1` |

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_syn_rate_set_bounds_20260622.json
jq -e '.guardrails.edge_template_port_coverage.syn_rate_set_bounds_allowed == true and .guardrails.edge_template_port_coverage.missing_syn_rate_set_size_rejected == true and .guardrails.edge_template_port_coverage.missing_syn_rate_set_timeout_rejected == true' benchmark_results/local_bench_syn_rate_set_bounds_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-syn-rate-set-bounds-20260622/
ssh core 'cd /tmp/altura-prot-syn-rate-set-bounds-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py && PYTHONPATH=tools python3 tools/test_ai_tools.py && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-syn-rate-set-bounds-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-syn-rate-set-bounds-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-syn-rate-set-bounds-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_syn_rate_set_bounds_20260622.json'
rsync -a core:/tmp/altura-prot-syn-rate-set-bounds-20260622/benchmark_results/local_bench_core_syn_rate_set_bounds_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.syn_rate_set_bounds_allowed == true and .guardrails.edge_template_port_coverage.missing_syn_rate_set_size_rejected == true and .guardrails.edge_template_port_coverage.missing_syn_rate_set_timeout_rejected == true' benchmark_results/local_bench_core_syn_rate_set_bounds_20260622.json
```

## 2026-06-22 Connlimit Set Size Snapshot

Artifacts:

- `benchmark_results/local_bench_connlimit_set_size_20260622.json`
- `benchmark_results/local_bench_core_connlimit_set_size_20260622.json`

This snapshot adds explicit `size 65535` bounds to the host-edge nftables
`tcp4_connlimit` and `tcp6_connlimit` dynamic sets, then extends
`tools/validate_edge_templates.py` and the benchmark guardrail probe so missing
connlimit-set sizes fail validation. The template intentionally avoids timeouts
on the `ct count` connlimit sets because nftables documents that `ct count`
uses connection-tracking timers and does not support timeout sets for this
policy.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9004.32 RPS | `204: 27085` | 0 | 25.092 ms |
| admin health | 9021.64 RPS | `200: 27141` | 0 | 25.575 ms |
| raw TCP persistent echo | 19247.44 msg/s | `57789` echoed messages | 0 | 3.042 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6643.23 RPS | `204: 20014` | 0 | 34.123 ms |
| admin health on `core` | 6553.63 RPS | `200: 19752` | 0 | 34.803 ms |
| raw TCP persistent echo on `core` | 28395.00 msg/s | `85320` echoed messages | 0 | 2.244 ms |

Connlimit-set guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| shipped connlimit sets have explicit positive size bounds | `true` | `true` |
| template missing connlimit set size is rejected | `true` | `true` |
| missing-size validator status | `1` | `1` |

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_connlimit_set_size_20260622.json
jq -e '.guardrails.edge_template_port_coverage.connlimit_set_sizes_allowed == true and .guardrails.edge_template_port_coverage.missing_connlimit_set_size_rejected == true' benchmark_results/local_bench_connlimit_set_size_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-connlimit-set-size-20260622/
ssh core 'cd /tmp/altura-prot-connlimit-set-size-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-connlimit-set-size-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-connlimit-set-size-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-connlimit-set-size-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-connlimit-set-size-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-connlimit-set-size-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_connlimit_set_size_20260622.json'
rsync -a core:/tmp/altura-prot-connlimit-set-size-20260622/benchmark_results/local_bench_core_connlimit_set_size_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.connlimit_set_sizes_allowed == true and .guardrails.edge_template_port_coverage.missing_connlimit_set_size_rejected == true' benchmark_results/local_bench_core_connlimit_set_size_20260622.json
```

## 2026-06-22 Accept Shards Snapshot

Artifacts:

- `benchmark_results/local_bench_accept_shards_20260622.json`
- `benchmark_results/local_bench_core_accept_shards_20260622.json`

This snapshot adds bounded `SO_REUSEPORT` listener sharding for HTTP and raw TCP.
`http.accept_shards` and `tcp[].accept_shards` default to `1`, reject `0`, reject
values above `64`, and are counted in the `runtime.min_nofile` socket-budget
preflight. When a deployment opts into multiple shards, AlturaProt binds one
listener socket per shard while preserving one shared userspace connection and
request limiter state.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8966.43 RPS | `204: 26969` | 0 | 25.333 ms |
| admin health | 8995.11 RPS | `200: 27062` | 0 | 25.627 ms |
| raw TCP persistent echo | 19488.30 msg/s | `58506` echoed messages | 0 | 3.022 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6641.26 RPS | `204: 20011` | 0 | 34.410 ms |
| admin health on `core` | 6479.98 RPS | `200: 19529` | 0 | 34.605 ms |
| raw TCP persistent echo on `core` | 26234.31 msg/s | `78789` echoed messages | 0 | 2.470 ms |

Accept-shard guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| HTTP listener with `listen_backlog: 128` and `accept_shards: 2` | `204` | `204` |
| TCP listener with `listen_backlog: 128` and `accept_shards: 2` | echo ok | echo ok |
| listener guard recorded `accept_shards_started` | `true` | `true` |

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/test_ai_tools.py tools/validate_edge_templates.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo test -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_accept_shards_20260622.json
jq -e '.guardrails.listen_backlog.configured_accept_shards == 2 and .guardrails.listen_backlog.accept_shards_started == true and .guardrails.listen_backlog.http_status == 204 and .guardrails.listen_backlog.tcp_echo_ok == true' benchmark_results/local_bench_accept_shards_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-accept-shards-20260622/
ssh core 'cd /tmp/altura-prot-accept-shards-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-accept-shards-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-accept-shards-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-accept-shards-20260622 && cargo test -- --nocapture'
ssh core 'cd /tmp/altura-prot-accept-shards-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-accept-shards-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_accept_shards_20260622.json'
rsync -a core:/tmp/altura-prot-accept-shards-20260622/benchmark_results/local_bench_core_accept_shards_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.listen_backlog.configured_accept_shards == 2 and .guardrails.listen_backlog.accept_shards_started == true and .guardrails.listen_backlog.http_status == 204 and .guardrails.listen_backlog.tcp_echo_ok == true' benchmark_results/local_bench_core_accept_shards_20260622.json
```

## 2026-06-22 Systemd Service Guardrail Snapshot

Artifacts:

- `benchmark_results/local_bench_systemd_service_guardrails_20260622.json`
- `benchmark_results/local_bench_core_systemd_service_guardrails_20260622.json`

This snapshot adds a shipped systemd unit template and extends the edge-template
validator so deployment cannot silently drop service-manager backstops. The
validator rejects units with `LimitNOFILE` below `runtime.min_nofile`, stop
timeouts that are shorter than `runtime.shutdown_grace_ms`, weak sandboxing such
as `ProtectSystem=false`, broad capabilities beyond `CAP_NET_BIND_SERVICE`,
missing non-root `User`/`Group`, missing restart-storm limits, unbounded memory
limits, or raw packet/netlink address families.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8925.25 RPS | `204: 26845` | 0 | 25.403 ms |
| admin health | 9091.09 RPS | `200: 27350` | 0 | 25.450 ms |
| raw TCP persistent echo | 19326.31 msg/s | `58024` echoed messages | 0 | 3.053 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6581.73 RPS | `204: 19827` | 0 | 34.307 ms |
| admin health on `core` | 6568.94 RPS | `200: 19793` | 0 | 34.200 ms |
| raw TCP persistent echo on `core` | 24587.16 msg/s | `73848` echoed messages | 0 | 2.610 ms |

Systemd/service-manager guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| shipped systemd unit with full service-manager guardrails | allowed | allowed |
| `LimitNOFILE=1024` below `runtime.min_nofile` | rejected | rejected |
| weak sandbox with `ProtectSystem=false` | rejected | rejected |
| excessive ambient capability `CAP_NET_RAW` | rejected | rejected |
| fragment sysctls, public-port coverage, UDP drop, IPv6 `/64`, and `meta l4proto` edge checks | still enforced | still enforced |

Core edge validation used the Linux/nftables/sysctl path:
`python3 tools/validate_edge_templates.py --config configs/example.json` passed
without macOS skip messages. Native systemd syntax verification also passed on a
temporary copy of the unit pointing at the just-built release binary; the only
output was unrelated host warnings from existing `xfs_scrub` units.

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
PYTHONPATH=tools python3 - <<'PY'
import tempfile
from pathlib import Path
import run_local_bench
with tempfile.TemporaryDirectory() as tmp:
    result = run_local_bench.run_edge_template_port_coverage_probe(Path(tmp))
expected = [
    'systemd_unit_allowed',
    'insufficient_systemd_nofile_rejected',
    'weak_systemd_sandbox_rejected',
    'excessive_systemd_capabilities_rejected',
    'fragment_sysctls_allowed',
    'missing_public_port_rejected',
]
missing = [key for key in expected if result.get(key) is not True]
if missing:
    raise SystemExit({key: result.get(key) for key in missing})
print('systemd guardrail probe ok')
PY
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_systemd_service_guardrails_20260622.json
jq -e '.guardrails.edge_template_port_coverage.systemd_unit_allowed == true and .guardrails.edge_template_port_coverage.insufficient_systemd_nofile_rejected == true and .guardrails.edge_template_port_coverage.weak_systemd_sandbox_rejected == true and .guardrails.edge_template_port_coverage.excessive_systemd_capabilities_rejected == true and .guardrails.edge_template_port_coverage.fragment_sysctls_allowed == true and .guardrails.edge_template_port_coverage.missing_public_port_rejected == true' benchmark_results/local_bench_systemd_service_guardrails_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-systemd-service-guardrails-20260622/
ssh core 'cd /tmp/altura-prot-systemd-service-guardrails-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-systemd-service-guardrails-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-systemd-service-guardrails-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-systemd-service-guardrails-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-systemd-service-guardrails-20260622 && tmp_unit=/tmp/altura-prot-systemd-service-guardrails-verify.service && sed "s#/usr/local/bin/altura-prot --config /etc/altura-prot/config.json#/tmp/altura-prot-systemd-service-guardrails-20260622/target/release/altura-prot --config /tmp/altura-prot-systemd-service-guardrails-20260622/configs/example.json#" ops/systemd/altura-prot.service > "$tmp_unit" && systemd-analyze verify "$tmp_unit"'
ssh core 'cd /tmp/altura-prot-systemd-service-guardrails-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_systemd_service_guardrails_20260622.json'
rsync -a core:/tmp/altura-prot-systemd-service-guardrails-20260622/benchmark_results/local_bench_core_systemd_service_guardrails_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.systemd_unit_allowed == true and .guardrails.edge_template_port_coverage.insufficient_systemd_nofile_rejected == true and .guardrails.edge_template_port_coverage.weak_systemd_sandbox_rejected == true and .guardrails.edge_template_port_coverage.excessive_systemd_capabilities_rejected == true and .guardrails.edge_template_port_coverage.fragment_sysctls_allowed == true and .guardrails.edge_template_port_coverage.missing_public_port_rejected == true' benchmark_results/local_bench_core_systemd_service_guardrails_20260622.json
```

## 2026-06-22 Fragment Reassembly Sysctl Snapshot

Artifacts:

- `benchmark_results/local_bench_fragment_reassembly_sysctl_20260622.json`
- `benchmark_results/local_bench_core_fragment_reassembly_sysctl_20260622.json`

This snapshot adds explicit IPv4/IPv6 fragment reassembly memory and retention bounds to the host-edge sysctl profile. Fragment floods can pin kernel reassembly queues before AlturaProt can classify traffic, and AlturaProt's TCP proxy should rely on MSS/PMTUD instead of IP fragmentation. The validator now rejects missing fragment sysctl bounds, fragment retention above 30 seconds, and inverted IPv6 low/high thresholds.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8942.53 RPS | `204: 26902` | 0 | 25.238 ms |
| admin health | 9077.11 RPS | `200: 27311` | 0 | 25.329 ms |
| raw TCP persistent echo | 19298.83 msg/s | `57941` echoed messages | 0 | 3.030 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6412.74 RPS | `204: 19329` | 0 | 35.747 ms |
| admin health on `core` | 6389.67 RPS | `200: 19259` | 0 | 34.796 ms |
| raw TCP persistent echo on `core` | 26610.05 msg/s | `79947` echoed messages | 0 | 2.444 ms |

Edge/sysctl guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| covered public ports with full nftables and fragment sysctl template | allowed | allowed |
| fragment reassembly sysctls missing | rejected | rejected |
| IPv4 fragment queue retention set to `60` seconds | rejected | rejected |
| IPv6 fragment low threshold above high threshold | rejected | rejected |
| public TCP `[::]:7000`, nft set missing `7000` | rejected | rejected |
| raw UDP drop for protected TCP service ports missing | rejected | rejected |
| IPv6 `/64` and extension-safe protocol backstops | allowed | allowed |

Core edge validation used the Linux/nftables/sysctl path: `python3 tools/validate_edge_templates.py --config configs/example.json` passed without macOS skip messages.

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
PYTHONPATH=tools python3 - <<'PY'
import tempfile
from pathlib import Path
import run_local_bench
with tempfile.TemporaryDirectory() as tmp:
    result = run_local_bench.run_edge_template_port_coverage_probe(Path(tmp))
expected = [
    'missing_public_port_rejected',
    'covered_public_ports_allowed',
    'missing_udp_drop_rejected',
    'missing_ipv6_prefix_syn_backstop_rejected',
    'missing_ipv6_prefix_connlimit_rejected',
    'ipv6_prefix_backstops_allowed',
    'missing_ipv6_syn_l4proto_rejected',
    'missing_ipv6_connlimit_l4proto_rejected',
    'missing_ipv6_icmp_l4proto_rejected',
    'ipv6_extension_safe_protocols_allowed',
    'fragment_sysctls_allowed',
    'missing_fragment_sysctls_rejected',
    'excessive_fragment_time_rejected',
    'invalid_fragment_thresholds_rejected',
    'loopback_missing_port_allowed',
]
missing = [key for key in expected if result.get(key) is not True]
if missing:
    raise SystemExit({key: result.get(key) for key in missing})
for key in ('missing_fragment_sysctls_stderr','excessive_fragment_time_stderr','invalid_fragment_thresholds_stderr'):
    if 'extension-safe' in result[key]:
        raise SystemExit(f'unrelated nft error leaked into {key}: {result[key]}')
print('edge guardrail probe ok')
PY
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_fragment_reassembly_sysctl_20260622.json
jq -e '.guardrails.edge_template_port_coverage.fragment_sysctls_allowed == true and .guardrails.edge_template_port_coverage.missing_fragment_sysctls_rejected == true and .guardrails.edge_template_port_coverage.excessive_fragment_time_rejected == true and .guardrails.edge_template_port_coverage.invalid_fragment_thresholds_rejected == true and (.guardrails.edge_template_port_coverage.missing_fragment_sysctls_stderr | contains("extension-safe") | not) and (.guardrails.edge_template_port_coverage.excessive_fragment_time_stderr | contains("extension-safe") | not) and (.guardrails.edge_template_port_coverage.invalid_fragment_thresholds_stderr | contains("extension-safe") | not)' benchmark_results/local_bench_fragment_reassembly_sysctl_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-fragment-reassembly-sysctl-20260622/
ssh core 'cd /tmp/altura-prot-fragment-reassembly-sysctl-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-fragment-reassembly-sysctl-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-fragment-reassembly-sysctl-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-fragment-reassembly-sysctl-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-fragment-reassembly-sysctl-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_fragment_reassembly_sysctl_20260622.json'
rsync -a core:/tmp/altura-prot-fragment-reassembly-sysctl-20260622/benchmark_results/local_bench_core_fragment_reassembly_sysctl_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.fragment_sysctls_allowed == true and .guardrails.edge_template_port_coverage.missing_fragment_sysctls_rejected == true and .guardrails.edge_template_port_coverage.excessive_fragment_time_rejected == true and .guardrails.edge_template_port_coverage.invalid_fragment_thresholds_rejected == true and (.guardrails.edge_template_port_coverage.missing_fragment_sysctls_stderr | contains("extension-safe") | not) and (.guardrails.edge_template_port_coverage.excessive_fragment_time_stderr | contains("extension-safe") | not) and (.guardrails.edge_template_port_coverage.invalid_fragment_thresholds_stderr | contains("extension-safe") | not)' benchmark_results/local_bench_core_fragment_reassembly_sysctl_20260622.json
```

## 2026-06-22 Host Edge IPv6 Extension Header Backstop Snapshot

Artifacts:

- `benchmark_results/local_bench_edge_ipv6_extension_header_backstop_20260622.json`
- `benchmark_results/local_bench_core_edge_ipv6_extension_header_backstop_20260622.json`

This snapshot hardens the host-edge nftables template so IPv6 protected-port TCP and ICMPv6 flood controls match the real transport protocol with `meta l4proto`, not `ip6 nexthdr`. `ip6 nexthdr` only matches the immediate IPv6 next-header field, so extension headers could skip legacy TCP SYN, connection-count, or ICMPv6 flood backstops. The validator now rejects those legacy predicates while preserving the `/64` IPv6 source-prefix backstops.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8663.88 RPS | `204: 26062` | 0 | 26.987 ms |
| admin health | 9017.98 RPS | `200: 27132` | 0 | 25.937 ms |
| raw TCP persistent echo | 19257.65 msg/s | `57819` echoed messages | 0 | 3.057 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6693.19 RPS | `204: 20168` | 0 | 33.654 ms |
| admin health on `core` | 6644.69 RPS | `200: 20026` | 0 | 33.460 ms |
| raw TCP persistent echo on `core` | 25889.74 msg/s | `77781` echoed messages | 0 | 2.487 ms |

Edge-template guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| covered public HTTP/TCP ports with IPv6 `/64` keys and `meta l4proto` predicates | allowed | allowed |
| public TCP `[::]:7000`, nft set missing `7000` | rejected | rejected |
| raw UDP drop for protected TCP service ports missing | rejected | rejected |
| IPv6 SYN meter keyed by exact `ip6 saddr . tcp dport` | rejected | rejected |
| IPv6 connection-count cap keyed by exact `ip6 saddr . tcp dport` | rejected | rejected |
| IPv6 SYN meter gated by legacy `ip6 nexthdr tcp` | rejected | rejected |
| IPv6 connection-count cap gated by legacy `ip6 nexthdr tcp` | rejected | rejected |
| ICMPv6 flood limiter gated by legacy `ip6 nexthdr ipv6-icmp` | rejected | rejected |
| loopback-only HTTP/TCP listeners with nft set missing `7000` | allowed | allowed |

Core edge validation used the Linux/nftables path: `python3 tools/validate_edge_templates.py --config configs/example.json` passed without macOS skip messages.

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
PYTHONPATH=tools python3 - <<'PY'
import tempfile
from pathlib import Path
import run_local_bench
with tempfile.TemporaryDirectory() as tmp:
    result = run_local_bench.run_edge_template_port_coverage_probe(Path(tmp))
expected = [
    'missing_public_port_rejected',
    'covered_public_ports_allowed',
    'missing_udp_drop_rejected',
    'missing_ipv6_prefix_syn_backstop_rejected',
    'missing_ipv6_prefix_connlimit_rejected',
    'ipv6_prefix_backstops_allowed',
    'missing_ipv6_syn_l4proto_rejected',
    'missing_ipv6_connlimit_l4proto_rejected',
    'missing_ipv6_icmp_l4proto_rejected',
    'ipv6_extension_safe_protocols_allowed',
    'loopback_missing_port_allowed',
]
missing = [key for key in expected if result.get(key) is not True]
if missing:
    raise SystemExit({key: result.get(key) for key in missing})
print('edge guardrail probe ok')
PY
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_edge_ipv6_extension_header_backstop_20260622.json
jq -e '.guardrails.edge_template_port_coverage.ipv6_extension_safe_protocols_allowed == true and .guardrails.edge_template_port_coverage.missing_ipv6_syn_l4proto_rejected == true and .guardrails.edge_template_port_coverage.missing_ipv6_connlimit_l4proto_rejected == true and .guardrails.edge_template_port_coverage.missing_ipv6_icmp_l4proto_rejected == true and .guardrails.edge_template_port_coverage.ipv6_prefix_backstops_allowed == true and .guardrails.edge_template_port_coverage.missing_ipv6_prefix_syn_backstop_rejected == true and .guardrails.edge_template_port_coverage.missing_ipv6_prefix_connlimit_rejected == true and .guardrails.edge_template_port_coverage.missing_public_port_rejected == true and .guardrails.edge_template_port_coverage.missing_udp_drop_rejected == true' benchmark_results/local_bench_edge_ipv6_extension_header_backstop_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-edge-ipv6-extension-header-backstop-20260622/
ssh core 'cd /tmp/altura-prot-edge-ipv6-extension-header-backstop-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-edge-ipv6-extension-header-backstop-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-edge-ipv6-extension-header-backstop-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-edge-ipv6-extension-header-backstop-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-edge-ipv6-extension-header-backstop-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_edge_ipv6_extension_header_backstop_20260622.json'
rsync -a core:/tmp/altura-prot-edge-ipv6-extension-header-backstop-20260622/benchmark_results/local_bench_core_edge_ipv6_extension_header_backstop_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.ipv6_extension_safe_protocols_allowed == true and .guardrails.edge_template_port_coverage.missing_ipv6_syn_l4proto_rejected == true and .guardrails.edge_template_port_coverage.missing_ipv6_connlimit_l4proto_rejected == true and .guardrails.edge_template_port_coverage.missing_ipv6_icmp_l4proto_rejected == true and .guardrails.edge_template_port_coverage.ipv6_prefix_backstops_allowed == true and .guardrails.edge_template_port_coverage.missing_ipv6_prefix_syn_backstop_rejected == true and .guardrails.edge_template_port_coverage.missing_ipv6_prefix_connlimit_rejected == true and .guardrails.edge_template_port_coverage.missing_public_port_rejected == true and .guardrails.edge_template_port_coverage.missing_udp_drop_rejected == true' benchmark_results/local_bench_core_edge_ipv6_extension_header_backstop_20260622.json
```

## 2026-06-22 Host Edge IPv6 Prefix Backstop Snapshot

Artifacts:

- `benchmark_results/local_bench_edge_ipv6_prefix_backstop_20260622.json`
- `benchmark_results/local_bench_core_edge_ipv6_prefix_backstop_20260622.json`

This snapshot hardens the host-edge nftables template so protected-port IPv6 SYN meters and connection-count caps key source addresses by `/64`, matching AlturaProt's default HTTP/TCP IPv6 client-prefix buckets. The validator now rejects exact-address IPv6 nftables backstops, so privacy-address or same-subnet IPv6 rotation cannot split across exact host-edge buckets before userspace sees the traffic.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9026.02 RPS | `204: 27152` | 0 | 25.015 ms |
| admin health | 9023.70 RPS | `200: 27152` | 0 | 25.838 ms |
| raw TCP persistent echo | 19252.65 msg/s | `57804` echoed messages | 0 | 3.047 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6414.37 RPS | `204: 19329` | 0 | 35.330 ms |
| admin health on `core` | 6349.69 RPS | `200: 19136` | 0 | 35.202 ms |
| raw TCP persistent echo on `core` | 27931.42 msg/s | `83897` echoed messages | 0 | 2.283 ms |

Edge-template guardrail:

| Probe | Local | `core` |
| --- | --- | --- |
| covered public HTTP/TCP ports with IPv6 `/64` SYN and connection-count keys | allowed | allowed |
| public TCP `[::]:7000`, nft set missing `7000` | rejected | rejected |
| raw UDP drop for protected TCP service ports missing | rejected | rejected |
| IPv6 SYN meter keyed by exact `ip6 saddr . tcp dport` | rejected | rejected |
| IPv6 connection-count cap keyed by exact `ip6 saddr . tcp dport` | rejected | rejected |
| loopback-only HTTP/TCP listeners with nft set missing `7000` | allowed | allowed |

Core edge validation used the Linux/nftables path: `python3 tools/validate_edge_templates.py --config configs/example.json` passed without macOS skip messages.

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_edge_ipv6_prefix_backstop_20260622.json
jq -e '.guardrails.edge_template_port_coverage.ipv6_prefix_backstops_allowed == true and .guardrails.edge_template_port_coverage.missing_ipv6_prefix_syn_backstop_rejected == true and .guardrails.edge_template_port_coverage.missing_ipv6_prefix_connlimit_rejected == true and .guardrails.edge_template_port_coverage.missing_public_port_rejected == true and .guardrails.edge_template_port_coverage.missing_udp_drop_rejected == true' benchmark_results/local_bench_edge_ipv6_prefix_backstop_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-edge-ipv6-prefix-backstop-20260622/
ssh core 'cd /tmp/altura-prot-edge-ipv6-prefix-backstop-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-edge-ipv6-prefix-backstop-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-edge-ipv6-prefix-backstop-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-edge-ipv6-prefix-backstop-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-edge-ipv6-prefix-backstop-20260622 && mkdir -p benchmark_results && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_edge_ipv6_prefix_backstop_20260622.json'
rsync -a core:/tmp/altura-prot-edge-ipv6-prefix-backstop-20260622/benchmark_results/local_bench_core_edge_ipv6_prefix_backstop_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.edge_template_port_coverage.ipv6_prefix_backstops_allowed == true and .guardrails.edge_template_port_coverage.missing_ipv6_prefix_syn_backstop_rejected == true and .guardrails.edge_template_port_coverage.missing_ipv6_prefix_connlimit_rejected == true and .guardrails.edge_template_port_coverage.missing_public_port_rejected == true and .guardrails.edge_template_port_coverage.missing_udp_drop_rejected == true' benchmark_results/local_bench_core_edge_ipv6_prefix_backstop_20260622.json
```

## 2026-06-22 IP Prefix Aggregation Snapshot

Artifacts:

- `benchmark_results/local_bench_ip_prefix_aggregation_20260622.json`
- `benchmark_results/local_bench_core_ip_prefix_aggregation_20260622.json`

This snapshot adds configurable source-prefix aggregation for HTTP/TCP per-client limit keys. The new knobs are `http.limits.ipv4_prefix_len`, `http.limits.ipv6_prefix_len`, `tcp[].limits.ipv4_prefix_len`, and `tcp[].limits.ipv6_prefix_len`. Defaults are IPv4 `/32` and IPv6 `/64`, so IPv4 remains exact by default while IPv6 privacy-address or same-subnet rotation shares one request-rate, connection-open, and in-flight bucket. Trusted-proxy aggregate limits remain keyed by the exact immediate peer IP.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8961.99 RPS | `204: 26968` | 0 | 25.122 ms |
| admin health | 8976.39 RPS | `200: 27000` | 0 | 25.905 ms |
| raw TCP persistent echo | 19312.76 msg/s | `57981` echoed messages | 0 | 3.045 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6938.10 RPS | `204: 20903` | 0 | 32.966 ms |
| admin health on `core` | 6614.64 RPS | `200: 19938` | 0 | 34.289 ms |
| raw TCP persistent echo on `core` | 24426.80 msg/s | `73368` echoed messages | 0 | 2.636 ms |

Guardrail probe:

| Probe | Local | `core` |
| --- | --- | --- |
| configured prefix lengths | IPv4 `/32`, IPv6 `/64` | IPv4 `/32`, IPv6 `/64` |
| first IPv6 `/64` request | `204` | `204` |
| second IPv6 address in same `/64` | `429` | `429` |
| IPv6 address in different `/64` | `204` | `204` |
| neighboring IPv4 addresses with default `/32` | `204`, `204` | `204`, `204` |
| `altura_http_rate_limited` delta | `1` | `1` |
| generated 429 headers | `Retry-After: 1`, `Cache-Control: no-store` | `Retry-After: 1`, `Cache-Control: no-store` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test prefix -- --nocapture
cargo test trusted_proxy -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_ip_prefix_aggregation_20260622.json
jq -e '.guardrails.ip_prefix_aggregation.same_ipv6_prefix_limited == true and .guardrails.ip_prefix_aggregation.different_ipv6_prefix_allowed == true and .guardrails.ip_prefix_aggregation.ipv4_exact_default_allows_neighbor == true and .guardrails.ip_prefix_aggregation.rate_limited_metric_matches == true' benchmark_results/local_bench_ip_prefix_aggregation_20260622.json

rsync -a --delete --exclude target --exclude .git --exclude benchmark_results/ /Users/core/AlturaProt/ core:/tmp/altura-prot-ip-prefix-aggregation-20260622/
ssh core 'cd /tmp/altura-prot-ip-prefix-aggregation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-ip-prefix-aggregation-20260622 && cargo test prefix -- --nocapture'
ssh core 'cd /tmp/altura-prot-ip-prefix-aggregation-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-ip-prefix-aggregation-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-ip-prefix-aggregation-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-ip-prefix-aggregation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_ip_prefix_aggregation_20260622.json'
rsync -a core:/tmp/altura-prot-ip-prefix-aggregation-20260622/benchmark_results/local_bench_core_ip_prefix_aggregation_20260622.json /Users/core/AlturaProt/benchmark_results/
jq -e '.guardrails.ip_prefix_aggregation.same_ipv6_prefix_limited == true and .guardrails.ip_prefix_aggregation.different_ipv6_prefix_allowed == true and .guardrails.ip_prefix_aggregation.ipv4_exact_default_allows_neighbor == true and .guardrails.ip_prefix_aggregation.rate_limited_metric_matches == true' benchmark_results/local_bench_core_ip_prefix_aggregation_20260622.json
```

## 2026-06-22 Startup Config File Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_config_file_validation_20260622.json`
- `benchmark_results/local_bench_core_config_file_validation_20260622.json`

This snapshot adds fail-fast validation for the `--config` input itself. The config path must be a regular file and the file is capped at `1048576` bytes before JSON deserialization. This keeps a bad deploy artifact from turning startup into an unbounded file-read or JSON-parse memory path. Large learned rule sets should stay in the separately bounded runtime filter file rather than being embedded in startup config.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9057.90 RPS | `204: 27245` | 0 | 25.053 ms |
| admin health | 9076.17 RPS | `200: 27300` | 0 | 25.666 ms |
| raw TCP persistent echo | 19405.30 msg/s | `58260` echoed messages | 0 | 3.018 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6925.42 RPS | `204: 20870` | 0 | 32.656 ms |
| admin health on `core` | 6616.89 RPS | `200: 19945` | 0 | 34.655 ms |
| raw TCP persistent echo on `core` | 25622.45 msg/s | `76981` echoed messages | 0 | 2.514 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| oversized `--config` file | startup exited `1` before binding |
| oversized rejection message | `above configured cap of 1048576 bytes` |
| non-regular `--config` path | startup exited `1` before binding |
| non-regular rejection message | `must be a regular file` |
| local guardrail booleans | `oversized_config_rejected: true`, `non_regular_config_rejected: true` |
| `core` guardrail booleans | `oversized_config_rejected: true`, `non_regular_config_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test app_config_from_path_rejects -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_config_file_validation_20260622.json
jq -e '.guardrails.config_file_startup.oversized_config_rejected == true and .guardrails.config_file_startup.non_regular_config_rejected == true' benchmark_results/local_bench_config_file_validation_20260622.json
ssh core 'cd /tmp/altura-prot-config-file-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-config-file-validation-20260622 && cargo test app_config_from_path_rejects -- --nocapture'
ssh core 'cd /tmp/altura-prot-config-file-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_config_file_validation_20260622.json'
jq -e '.guardrails.config_file_startup.oversized_config_rejected == true and .guardrails.config_file_startup.non_regular_config_rejected == true' benchmark_results/local_bench_core_config_file_validation_20260622.json
```

## 2026-06-22 Filter Rule Shape Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_filter_rule_validation_20260622.json`
- `benchmark_results/local_bench_core_filter_rule_validation_20260622.json`

This snapshot adds fail-fast validation for static config filters and shared rule-shape validation for runtime filter reloads. Static rules are capped by `filters.max_static_filters` (`1024` by default). Static and runtime rules must have a non-empty bounded ID, at least one bounded matcher, bounded method/header matcher counts, valid header names, `action.kind: "block"`, a 4xx/5xx block status, and a block body no larger than `1024` bytes. Runtime reloads reject invalid analyzer output while preserving the last-good in-memory rules.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9046.44 RPS | `204: 27213` | 0 | 25.131 ms |
| admin health | 9125.78 RPS | `200: 27450` | 0 | 25.134 ms |
| raw TCP persistent echo | 19442.65 msg/s | `58372` echoed messages | 0 | 3.029 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6934.99 RPS | `204: 20892` | 0 | 32.776 ms |
| admin health on `core` | 6678.51 RPS | `200: 20121` | 0 | 33.406 ms |
| raw TCP persistent echo on `core` | 25996.52 msg/s | `78082` echoed messages | 0 | 2.484 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| static filters above `filters.max_static_filters` | startup exited `1` before binding |
| static count rejection message | `filters.static_rules contains 2 filters, above configured cap 1` |
| static filter with no matcher | startup exited `1` before binding |
| empty-condition rejection message | `filters.static_rules[0].condition must include at least one matcher` |
| static filter with `action.status: 200` | startup exited `1` before binding |
| invalid status rejection message | `filters.static_rules[0].action.status must be an HTTP 4xx or 5xx status` |
| static filter with oversized block body | startup exited `1` before binding |
| oversized body rejection message | `filters.static_rules[0].action.body is 2048 bytes, above configured cap 1024` |
| local guardrail booleans | `too_many_static_filters_rejected: true`, `empty_condition_rejected: true`, `invalid_status_rejected: true`, `oversized_body_rejected: true` |
| `core` guardrail booleans | `too_many_static_filters_rejected: true`, `empty_condition_rejected: true`, `invalid_status_rejected: true`, `oversized_body_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test app_config_rejects_static_filter_rule_capacity_and_shape_errors -- --nocapture
cargo test runtime_filter_reload_rejects_invalid_rules_and_preserves_last_good_rules -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_filter_rule_validation_20260622.json
jq -e '.guardrails.filter_rule_startup.too_many_static_filters_rejected == true and .guardrails.filter_rule_startup.empty_condition_rejected == true and .guardrails.filter_rule_startup.invalid_status_rejected == true and .guardrails.filter_rule_startup.oversized_body_rejected == true' benchmark_results/local_bench_filter_rule_validation_20260622.json
rsync -az --delete --exclude target --exclude .git --exclude .DS_Store --exclude benchmark_results/ ./ core:/tmp/altura-prot-filter-rule-validation-20260622/
ssh core 'cd /tmp/altura-prot-filter-rule-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-filter-rule-validation-20260622 && cargo test app_config_rejects_static_filter_rule_capacity_and_shape_errors -- --nocapture'
ssh core 'cd /tmp/altura-prot-filter-rule-validation-20260622 && cargo test runtime_filter_reload_rejects_invalid_rules_and_preserves_last_good_rules -- --nocapture'
ssh core 'cd /tmp/altura-prot-filter-rule-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_filter_rule_validation_20260622.json'
jq -e '.guardrails.filter_rule_startup.too_many_static_filters_rejected == true and .guardrails.filter_rule_startup.empty_condition_rejected == true and .guardrails.filter_rule_startup.invalid_status_rejected == true and .guardrails.filter_rule_startup.oversized_body_rejected == true' benchmark_results/local_bench_core_filter_rule_validation_20260622.json
```

## 2026-06-22 Allowed Methods Config Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_allowed_methods_validation_20260622.json`
- `benchmark_results/local_bench_core_allowed_methods_validation_20260622.json`

This snapshot adds fail-fast validation for `http.allowed_methods`. The list must be non-empty, contain no more than `16` methods, use valid HTTP method tokens, avoid duplicate entries, and keep each method token at or below `32` bytes. This prevents a bad deploy from turning every request into a `405` with an empty or malformed `Allow` header, or from generating oversized proxy-owned `405` responses during method-probe floods.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8932.59 RPS | `204: 26869` | 0 | 25.443 ms |
| admin health | 9058.21 RPS | `200: 27280` | 0 | 25.381 ms |
| raw TCP persistent echo | 19429.94 msg/s | `58334` echoed messages | 0 | 3.032 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6418.79 RPS | `204: 19344` | 0 | 35.476 ms |
| admin health on `core` | 6487.24 RPS | `200: 19550` | 0 | 34.202 ms |
| raw TCP persistent echo on `core` | 25923.84 msg/s | `77881` echoed messages | 0 | 2.485 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| empty `http.allowed_methods` | startup exited `1` before binding |
| empty-list rejection message | `http.allowed_methods must contain at least one method` |
| invalid method token with whitespace | startup exited `1` before binding |
| invalid-token rejection message | `http.allowed_methods[0] is not a valid HTTP method token` |
| 33-byte method token | startup exited `1` before binding |
| oversized-token rejection message | `http.allowed_methods[0] is 33 bytes, above configured cap of 32 bytes` |
| duplicate method entry | startup exited `1` before binding |
| duplicate rejection message | `http.allowed_methods[1] duplicates 'GET'` |
| 17 configured method tokens | startup exited `1` before binding |
| too-many rejection message | `http.allowed_methods contains 17 methods, above configured cap of 16` |
| local guardrail booleans | `empty_rejected: true`, `invalid_token_rejected: true`, `oversized_token_rejected: true`, `duplicate_rejected: true`, `too_many_rejected: true` |
| `core` guardrail booleans | `empty_rejected: true`, `invalid_token_rejected: true`, `oversized_token_rejected: true`, `duplicate_rejected: true`, `too_many_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test allowed_methods -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_allowed_methods_validation_20260622.json
jq -e '.guardrails.allowed_methods_startup.empty_rejected == true and .guardrails.allowed_methods_startup.invalid_token_rejected == true and .guardrails.allowed_methods_startup.oversized_token_rejected == true and .guardrails.allowed_methods_startup.duplicate_rejected == true and .guardrails.allowed_methods_startup.too_many_rejected == true' benchmark_results/local_bench_allowed_methods_validation_20260622.json
ssh core 'cd /tmp/altura-prot-allowed-methods-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-allowed-methods-validation-20260622 && cargo test allowed_methods -- --nocapture'
ssh core 'cd /tmp/altura-prot-allowed-methods-validation-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-allowed-methods-validation-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-allowed-methods-validation-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-allowed-methods-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_allowed_methods_validation_20260622.json'
jq -e '.guardrails.allowed_methods_startup.empty_rejected == true and .guardrails.allowed_methods_startup.invalid_token_rejected == true and .guardrails.allowed_methods_startup.oversized_token_rejected == true and .guardrails.allowed_methods_startup.duplicate_rejected == true and .guardrails.allowed_methods_startup.too_many_rejected == true' benchmark_results/local_bench_core_allowed_methods_validation_20260622.json
```

`core` did not have `cargo-clippy` installed and no `rustup` was available there; local `cargo clippy --all-targets -- -D warnings` passed.

## 2026-06-22 Allowed Hosts Config Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_allowed_hosts_validation_20260622.json`
- `benchmark_results/local_bench_core_allowed_hosts_validation_20260622.json`

This snapshot adds fail-fast validation for configured `http.allowed_hosts` entries. An empty list remains the explicit "Host allowlist disabled" value, but once entries are configured the list must contain no more than `128` exact authorities. Each entry must be non-empty, trimmed, free of whitespace/control characters, a valid HTTP authority, not URI userinfo, not wildcard-looking, duplicate-free ignoring ASCII case, no longer than `255` bytes, and no longer than `http.max_host_bytes`. This keeps the request-path Host allowlist scan bounded and prevents operator typos from creating surprising exact-match behavior.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8982.99 RPS | `204: 27018` | 0 | 25.220 ms |
| admin health | 9026.53 RPS | `200: 27152` | 0 | 25.364 ms |
| raw TCP persistent echo | 19325.08 msg/s | `58020` echoed messages | 0 | 3.033 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6728.46 RPS | `204: 20273` | 0 | 33.765 ms |
| admin health on `core` | 6641.78 RPS | `200: 20018` | 0 | 34.220 ms |
| raw TCP persistent echo on `core` | 25556.99 msg/s | `76784` echoed messages | 0 | 2.522 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| blank `http.allowed_hosts` entry | startup exited `1` before binding |
| blank-entry rejection message | `http.allowed_hosts[0] must not be empty` |
| leading whitespace in Host allowlist entry | startup exited `1` before binding |
| whitespace rejection message | `http.allowed_hosts[0] must not start or end with whitespace` |
| URL-shaped Host allowlist entry | startup exited `1` before binding |
| invalid-authority rejection message | `http.allowed_hosts[0] is not a valid HTTP authority` |
| URI userinfo in Host allowlist entry | startup exited `1` before binding |
| userinfo rejection message | `http.allowed_hosts[0] must not contain URI userinfo` |
| wildcard-looking Host allowlist entry | startup exited `1` before binding |
| wildcard rejection message | `http.allowed_hosts[0] must be an exact host or host:port, not a wildcard` |
| Host allowlist entry above `http.max_host_bytes` | startup exited `1` before binding |
| oversize rejection message | `http.allowed_hosts[0] is 14 bytes, above configured cap of 8 bytes` |
| duplicate Host allowlist entry | startup exited `1` before binding |
| duplicate rejection message | `http.allowed_hosts[1] duplicates 'GOOD.local'` |
| 129 configured Host allowlist entries | startup exited `1` before binding |
| too-many rejection message | `http.allowed_hosts contains 129 hosts, above configured cap of 128` |
| local guardrail booleans | `blank_rejected: true`, `whitespace_rejected: true`, `invalid_authority_rejected: true`, `userinfo_rejected: true`, `wildcard_rejected: true`, `oversized_rejected: true`, `duplicate_rejected: true`, `too_many_rejected: true` |
| `core` guardrail booleans | `blank_rejected: true`, `whitespace_rejected: true`, `invalid_authority_rejected: true`, `userinfo_rejected: true`, `wildcard_rejected: true`, `oversized_rejected: true`, `duplicate_rejected: true`, `too_many_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test allowed_host -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_allowed_hosts_validation_20260622.json
jq -e '.guardrails.allowed_hosts_startup.blank_rejected == true and .guardrails.allowed_hosts_startup.whitespace_rejected == true and .guardrails.allowed_hosts_startup.invalid_authority_rejected == true and .guardrails.allowed_hosts_startup.userinfo_rejected == true and .guardrails.allowed_hosts_startup.wildcard_rejected == true and .guardrails.allowed_hosts_startup.oversized_rejected == true and .guardrails.allowed_hosts_startup.duplicate_rejected == true and .guardrails.allowed_hosts_startup.too_many_rejected == true' benchmark_results/local_bench_allowed_hosts_validation_20260622.json
ssh core 'cd /tmp/altura-prot-allowed-hosts-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-allowed-hosts-validation-20260622 && cargo test allowed_host -- --nocapture'
ssh core 'cd /tmp/altura-prot-allowed-hosts-validation-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-allowed-hosts-validation-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-allowed-hosts-validation-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-allowed-hosts-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_allowed_hosts_validation_20260622.json'
jq -e '.guardrails.allowed_hosts_startup.blank_rejected == true and .guardrails.allowed_hosts_startup.whitespace_rejected == true and .guardrails.allowed_hosts_startup.invalid_authority_rejected == true and .guardrails.allowed_hosts_startup.userinfo_rejected == true and .guardrails.allowed_hosts_startup.wildcard_rejected == true and .guardrails.allowed_hosts_startup.oversized_rejected == true and .guardrails.allowed_hosts_startup.duplicate_rejected == true and .guardrails.allowed_hosts_startup.too_many_rejected == true' benchmark_results/local_bench_core_allowed_hosts_validation_20260622.json
```

`core` did not have `cargo-clippy` installed and no `rustup` was available there; local `cargo clippy --all-targets -- -D warnings` passed.

## 2026-06-22 Client IP Trust Config Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_client_ip_config_validation_20260622.json`
- `benchmark_results/local_bench_core_client_ip_config_validation_20260622.json`

This snapshot adds fail-fast validation for `http.client_ip.header` and `http.client_ip.trusted_proxies`. The configured client-IP header must be non-empty, trimmed, a valid HTTP field name, and no more than `64` bytes. Trusted-proxy entries must be non-empty, trimmed, free of whitespace/control characters, no more than `64` bytes each, no more than `128` total, duplicate-free ignoring ASCII case, and valid IP/CIDR ranges. The runtime resolver now relies on validated config instead of silently falling back to `x-forwarded-for` or ignoring invalid trusted-proxy entries.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9058.91 RPS | `204: 27251` | 0 | 24.999 ms |
| admin health | 9060.66 RPS | `200: 27256` | 0 | 25.302 ms |
| raw TCP persistent echo | 19376.47 msg/s | `58175` echoed messages | 0 | 3.043 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6885.86 RPS | `204: 20741` | 0 | 32.935 ms |
| admin health on `core` | 6647.40 RPS | `200: 20034` | 0 | 33.783 ms |
| raw TCP persistent echo on `core` | 24705.37 msg/s | `74208` echoed messages | 0 | 2.607 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| invalid `http.client_ip.header` with whitespace | startup exited `1` before binding |
| invalid-header rejection message | `http.client_ip.header is not a valid HTTP field name` |
| 65-byte `http.client_ip.header` | startup exited `1` before binding |
| oversized-header rejection message | `http.client_ip.header is 65 bytes, above configured cap of 64 bytes` |
| blank trusted-proxy entry | startup exited `1` before binding |
| blank-entry rejection message | `http.client_ip.trusted_proxies[0] must not be empty` |
| invalid trusted-proxy range | startup exited `1` before binding |
| invalid-range rejection message | `invalid http.client_ip.trusted_proxies entry 'not-a-cidr'` |
| 65-byte trusted-proxy entry | startup exited `1` before binding |
| oversized-entry rejection message | `http.client_ip.trusted_proxies[0] is 65 bytes, above configured cap of 64 bytes` |
| duplicate trusted-proxy entry | startup exited `1` before binding |
| duplicate rejection message | `http.client_ip.trusted_proxies[1] duplicates '127.0.0.1/32'` |
| 129 configured trusted-proxy entries | startup exited `1` before binding |
| too-many rejection message | `http.client_ip.trusted_proxies contains 129 entries, above configured cap of 128` |
| local guardrail booleans | `invalid_header_rejected: true`, `oversized_header_rejected: true`, `blank_trusted_proxy_rejected: true`, `invalid_trusted_proxy_rejected: true`, `oversized_trusted_proxy_rejected: true`, `duplicate_trusted_proxy_rejected: true`, `too_many_trusted_proxies_rejected: true` |
| `core` guardrail booleans | `invalid_header_rejected: true`, `oversized_header_rejected: true`, `blank_trusted_proxy_rejected: true`, `invalid_trusted_proxy_rejected: true`, `oversized_trusted_proxy_rejected: true`, `duplicate_trusted_proxy_rejected: true`, `too_many_trusted_proxies_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test client_ip -- --nocapture
cargo test trusted_proxy -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_client_ip_config_validation_20260622.json
jq -e '.guardrails.client_ip_config_startup.invalid_header_rejected == true and .guardrails.client_ip_config_startup.oversized_header_rejected == true and .guardrails.client_ip_config_startup.blank_trusted_proxy_rejected == true and .guardrails.client_ip_config_startup.invalid_trusted_proxy_rejected == true and .guardrails.client_ip_config_startup.oversized_trusted_proxy_rejected == true and .guardrails.client_ip_config_startup.duplicate_trusted_proxy_rejected == true and .guardrails.client_ip_config_startup.too_many_trusted_proxies_rejected == true' benchmark_results/local_bench_client_ip_config_validation_20260622.json
ssh core 'cd /tmp/altura-prot-client-ip-config-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-client-ip-config-validation-20260622 && cargo test client_ip -- --nocapture'
ssh core 'cd /tmp/altura-prot-client-ip-config-validation-20260622 && cargo test trusted_proxy -- --nocapture'
ssh core 'cd /tmp/altura-prot-client-ip-config-validation-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-client-ip-config-validation-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-client-ip-config-validation-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-client-ip-config-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_client_ip_config_validation_20260622.json'
jq -e '.guardrails.client_ip_config_startup.invalid_header_rejected == true and .guardrails.client_ip_config_startup.oversized_header_rejected == true and .guardrails.client_ip_config_startup.blank_trusted_proxy_rejected == true and .guardrails.client_ip_config_startup.invalid_trusted_proxy_rejected == true and .guardrails.client_ip_config_startup.oversized_trusted_proxy_rejected == true and .guardrails.client_ip_config_startup.duplicate_trusted_proxy_rejected == true and .guardrails.client_ip_config_startup.too_many_trusted_proxies_rejected == true' benchmark_results/local_bench_core_client_ip_config_validation_20260622.json
```

`core` did not have `cargo-clippy` installed and no `rustup` was available there; local `cargo clippy --all-targets -- -D warnings` passed.

## 2026-06-22 Upstream Failure Circuit Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_failure_circuit_20260622.json`
- `benchmark_results/local_bench_core_upstream_failure_circuit_20260622.json`

This historical snapshot added a passive upstream failure circuit breaker. Current behavior scopes this circuit by normalized path shape; see the 2026-06-22 Upstream Failure Circuit Scoping Snapshot above. `http.upstream_failure_threshold` controls how many consecutive upstream connect/header failures or upstream response timeouts trip a shape circuit; `http.upstream_failure_open_ms` controls how long matching origin-bound requests are shed locally before the proxy probes that shape again. Open-circuit requests return `503`, `Retry-After: 1`, `Cache-Control: no-store`, and `Connection: close`, incrementing `altura_http_upstream_circuit_open` without making another upstream connection attempt.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9010.05 RPS | `204: 27104` | 0 | 25.119 ms |
| admin health | 8976.36 RPS | `200: 27059` | 0 | 25.489 ms |
| raw TCP persistent echo | 19452.21 msg/s | `58399` echoed messages | 0 | 3.020 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6918.92 RPS | `204: 20845` | 0 | 32.958 ms |
| admin health on `core` | 6623.25 RPS | `200: 19960` | 0 | 34.388 ms |
| raw TCP persistent echo on `core` | 26203.64 msg/s | `78727` echoed messages | 0 | 2.466 ms |

Guardrail probe:

| Probe | Local result |
| --- | --- |
| configured `upstream_connect_timeout_ms` | `75` ms |
| configured `upstream_failure_threshold` | `2` |
| configured `upstream_failure_open_ms` | `200` ms |
| first saturated-loopback upstream attempt | `502` after `0.079` s |
| second saturated-loopback upstream attempt | `502` after `0.078` s |
| third request while circuit open | `503` after `0.001` s |
| third response headers | `Retry-After: 1`, `Cache-Control: no-store`, `Connection: close` |
| fourth request after open window | `502` after `0.079` s |
| metric deltas | `altura_http_upstream_errors: 3`, `altura_http_upstream_timeouts: 0`, `altura_http_upstream_circuit_open: 1` |

| Probe | `core` result |
| --- | --- |
| configured `upstream_connect_timeout_ms` | `75` ms |
| configured `upstream_failure_threshold` | `2` |
| configured `upstream_failure_open_ms` | `200` ms |
| first saturated-loopback upstream attempt | `502` after `0.076` s |
| second saturated-loopback upstream attempt | `502` after `0.076` s |
| third request while circuit open | `503` after `0.000` s |
| third response headers | `Retry-After: 1`, `Cache-Control: no-store`, `Connection: close` |
| fourth request after open window | `502` after `0.076` s |
| metric deltas | `altura_http_upstream_errors: 3`, `altura_http_upstream_timeouts: 0`, `altura_http_upstream_circuit_open: 1` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test upstream_failure -- --nocapture
cargo test upstream_circuit -- --nocapture
cargo test zero_http_capacity -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_upstream_failure_circuit_20260622.json
jq -e '.guardrails.upstream_failure_circuit.circuit_opened_after_consecutive_failures == true and .guardrails.upstream_failure_circuit.circuit_reallowed_after_open_window == true and .guardrails.upstream_failure_circuit.http_upstream_circuit_open_delta == 1' benchmark_results/local_bench_upstream_failure_circuit_20260622.json
ssh core 'cd /tmp/altura-prot-upstream-failure-circuit-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-upstream-failure-circuit-20260622 && cargo test upstream_failure -- --nocapture'
ssh core 'cd /tmp/altura-prot-upstream-failure-circuit-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-upstream-failure-circuit-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-upstream-failure-circuit-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-upstream-failure-circuit-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_upstream_failure_circuit_20260622.json'
jq -e '.guardrails.upstream_failure_circuit.circuit_opened_after_consecutive_failures == true and .guardrails.upstream_failure_circuit.circuit_reallowed_after_open_window == true and .guardrails.upstream_failure_circuit.http_upstream_circuit_open_delta == 1' benchmark_results/local_bench_core_upstream_failure_circuit_20260622.json
```

`core` did not have `cargo-clippy` installed and no `rustup` was available there; local `cargo clippy --all-targets -- -D warnings` passed.

## 2026-06-22 Filter and Adaptive Capacity Config Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_control_capacity_validation_20260622.json`
- `benchmark_results/local_bench_core_control_capacity_validation_20260622.json`

This snapshot adds fail-fast validation for filter and adaptive control-plane capacity knobs. Runtime filter reload cadence, runtime filter file-size cap, runtime filter count cap, adaptive thresholds/TTLs/cooldowns, adaptive detector window caps, event-log queue capacity, event-log flush interval, event-log rotation size, and event-log backup count must be greater than zero. This prevents a typo from silently clamping security-critical values to `1`, disabling event-log rotation, forcing flush-every-event disk pressure, or discarding all rotated analyzer evidence.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9096.60 RPS | `204: 27360` | 0 | 24.925 ms |
| admin health | 9021.99 RPS | `200: 27142` | 0 | 25.562 ms |
| raw TCP persistent echo | 19276.45 msg/s | `57876` echoed messages | 0 | 3.052 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6654.86 RPS | `204: 20048` | 0 | 34.262 ms |
| admin health on `core` | 6598.04 RPS | `200: 19881` | 0 | 34.418 ms |
| raw TCP persistent echo on `core` | 25435.92 msg/s | `76399` echoed messages | 0 | 2.544 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| `filters.max_runtime_file_bytes: 0` | startup exited `1` before binding |
| filter file-cap rejection message | `filters.max_runtime_file_bytes must be greater than zero` |
| `filters.max_runtime_filters: 0` | startup exited `1` before binding |
| filter rule-cap rejection message | `filters.max_runtime_filters must be greater than zero` |
| `adaptive.event_log_max_bytes: 0` | startup exited `1` before binding |
| event-log size-cap rejection message | `adaptive.event_log_max_bytes must be greater than zero` |
| `adaptive.event_log_queue_capacity: 0` | startup exited `1` before binding |
| event-log queue-cap rejection message | `adaptive.event_log_queue_capacity must be greater than zero` |
| `adaptive.event_log_flush_interval_ms: 0` | startup exited `1` before binding |
| event-log flush interval rejection message | `adaptive.event_log_flush_interval_ms must be greater than zero` |
| `adaptive.max_signature_windows: 0` | startup exited `1` before binding |
| adaptive window-cap rejection message | `adaptive.max_signature_windows must be greater than zero` |
| local guardrail booleans | `filter_file_cap_rejected: true`, `filter_rule_cap_rejected: true`, `adaptive_log_cap_rejected: true`, `adaptive_queue_cap_rejected: true`, `adaptive_flush_interval_rejected: true`, `adaptive_window_cap_rejected: true` |
| `core` guardrail booleans | `filter_file_cap_rejected: true`, `filter_rule_cap_rejected: true`, `adaptive_log_cap_rejected: true`, `adaptive_queue_cap_rejected: true`, `adaptive_flush_interval_rejected: true`, `adaptive_window_cap_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test app_config_rejects_zero_filter_capacity_limits -- --nocapture
cargo test app_config_rejects_zero_adaptive_capacity_limits -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_control_capacity_validation_20260622.json
jq -e '.guardrails.control_capacity_startup.filter_file_cap_rejected == true and .guardrails.control_capacity_startup.filter_rule_cap_rejected == true and .guardrails.control_capacity_startup.adaptive_log_cap_rejected == true and .guardrails.control_capacity_startup.adaptive_queue_cap_rejected == true and .guardrails.control_capacity_startup.adaptive_flush_interval_rejected == true and .guardrails.control_capacity_startup.adaptive_window_cap_rejected == true' benchmark_results/local_bench_control_capacity_validation_20260622.json
ssh core 'cd /tmp/altura-prot-control-capacity-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-control-capacity-validation-20260622 && cargo test app_config_rejects_zero_filter_capacity_limits -- --nocapture'
ssh core 'cd /tmp/altura-prot-control-capacity-validation-20260622 && cargo test app_config_rejects_zero_adaptive_capacity_limits -- --nocapture'
ssh core 'cd /tmp/altura-prot-control-capacity-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_control_capacity_validation_20260622.json'
jq -e '.guardrails.control_capacity_startup.filter_file_cap_rejected == true and .guardrails.control_capacity_startup.filter_rule_cap_rejected == true and .guardrails.control_capacity_startup.adaptive_log_cap_rejected == true and .guardrails.control_capacity_startup.adaptive_queue_cap_rejected == true and .guardrails.control_capacity_startup.adaptive_flush_interval_rejected == true and .guardrails.control_capacity_startup.adaptive_window_cap_rejected == true' benchmark_results/local_bench_core_control_capacity_validation_20260622.json
```

## 2026-06-22 Zero Capacity Config Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_zero_capacity_validation_20260622.json`
- `benchmark_results/local_bench_core_zero_capacity_validation_20260622.json`

This snapshot adds fail-fast validation for DDoS-critical resource-capacity knobs. HTTP/TCP connection caps, in-flight caps, limiter-state caps, parser metadata caps, `http.max_ranges`, body-size caps, trailer caps, forwarded-header caps, listener backlogs, and active timeout/grace windows must be greater than zero. `0` remains reserved for explicit rate-bucket or optional minimum-rate byte-floor disables, not for removing finite resource ceilings.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9016.03 RPS | `204: 27121` | 0 | 25.054 ms |
| admin health | 8940.06 RPS | `200: 26897` | 0 | 25.709 ms |
| raw TCP persistent echo | 19596.45 msg/s | `58836` echoed messages | 0 | 3.012 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6675.94 RPS | `204: 20117` | 0 | 34.175 ms |
| admin health on `core` | 6543.74 RPS | `200: 19721` | 0 | 34.250 ms |
| raw TCP persistent echo on `core` | 24968.36 msg/s | `75019` echoed messages | 0 | 2.571 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| `http.limits.max_connections: 0` | startup exited `1` before binding |
| HTTP connection-cap rejection message | `http.limits.max_connections must be greater than zero` |
| `http.max_header_bytes: 0` | startup exited `1` before binding |
| HTTP metadata-cap rejection message | `http.max_header_bytes must be greater than zero` |
| `http.client_ip.max_forwarded_for_hops: 0` | startup exited `1` before binding |
| HTTP forwarded-cap rejection message | `http.client_ip.max_forwarded_for_hops must be greater than zero` |
| `tcp[0].limits.max_connections: 0` | startup exited `1` before binding |
| TCP connection-cap rejection message | `tcp[0].limits.max_connections must be greater than zero` |
| local guardrail booleans | `http_connection_cap_rejected: true`, `http_metadata_cap_rejected: true`, `http_forwarded_cap_rejected: true`, `tcp_connection_cap_rejected: true` |
| `core` guardrail booleans | `http_connection_cap_rejected: true`, `http_metadata_cap_rejected: true`, `http_forwarded_cap_rejected: true`, `tcp_connection_cap_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test app_config_rejects_zero_http_capacity_limits -- --nocapture
cargo test app_config_rejects_zero_http_limiter_capacity_limits -- --nocapture
cargo test app_config_rejects_zero_tcp_capacity_limits -- --nocapture
cargo test app_config_rejects_zero_tcp_limiter_capacity_limits -- --nocapture
cargo test request_range_guard_fails_closed_when_capacity_is_zero -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_zero_capacity_validation_20260622.json
jq -e '.guardrails.zero_capacity_startup.http_connection_cap_rejected == true and .guardrails.zero_capacity_startup.http_metadata_cap_rejected == true and .guardrails.zero_capacity_startup.http_forwarded_cap_rejected == true and .guardrails.zero_capacity_startup.tcp_connection_cap_rejected == true' benchmark_results/local_bench_zero_capacity_validation_20260622.json
ssh core 'cd /tmp/altura-prot-zero-capacity-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-zero-capacity-validation-20260622 && cargo test app_config_rejects_zero_http_capacity_limits -- --nocapture'
ssh core 'cd /tmp/altura-prot-zero-capacity-validation-20260622 && cargo test app_config_rejects_zero_http_limiter_capacity_limits -- --nocapture'
ssh core 'cd /tmp/altura-prot-zero-capacity-validation-20260622 && cargo test app_config_rejects_zero_tcp_capacity_limits -- --nocapture'
ssh core 'cd /tmp/altura-prot-zero-capacity-validation-20260622 && cargo test app_config_rejects_zero_tcp_limiter_capacity_limits -- --nocapture'
ssh core 'cd /tmp/altura-prot-zero-capacity-validation-20260622 && cargo test request_range_guard_fails_closed_when_capacity_is_zero -- --nocapture'
ssh core 'cd /tmp/altura-prot-zero-capacity-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_zero_capacity_validation_20260622.json'
jq -e '.guardrails.zero_capacity_startup.http_connection_cap_rejected == true and .guardrails.zero_capacity_startup.http_metadata_cap_rejected == true and .guardrails.zero_capacity_startup.http_forwarded_cap_rejected == true and .guardrails.zero_capacity_startup.tcp_connection_cap_rejected == true' benchmark_results/local_bench_core_zero_capacity_validation_20260622.json
```

## 2026-06-22 Admin Token Config Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_admin_token_validation_20260622.json`
- `benchmark_results/local_bench_core_admin_token_validation_20260622.json`

This snapshot adds fail-fast validation for configured `http.admin_token` values. An absent token still makes metrics return `403`, but a configured token must be non-empty, non-blank, trimmed, and free of control characters. This prevents a config typo from turning metrics auth into an empty or whitespace shared secret.

Current-tree follow-up on 2026-06-23 caps configured admin tokens at 256 bytes
and uses a bounded fixed-budget byte comparison for presented metrics tokens.
That keeps the metrics auth path from doing attacker-controlled comparison work
for oversized `x-altura-admin-token` values. A second follow-up on the same
current-tree artifact requires exactly one presented admin-token header, so
duplicate metrics-token headers fail closed rather than relying on first-value
header map behavior. The regenerated
`benchmark_results/local_bench_ci_guardrails_20260623.json` asserts
`long_token_rejected: true` and `duplicate_metrics_token_rejected: true`; the CI
local-benchmark assertion now requires both guardrails.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8995.00 RPS | `204: 27055` | 0 | 25.257 ms |
| admin health | 9031.38 RPS | `200: 27168` | 0 | 25.428 ms |
| raw TCP persistent echo | 19425.35 msg/s | `58320` echoed messages | 0 | 3.022 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6937.68 RPS | `204: 20896` | 0 | 32.869 ms |
| admin health on `core` | 6616.07 RPS | `200: 19939` | 0 | 33.727 ms |
| raw TCP persistent echo on `core` | 26222.74 msg/s | `78790` echoed messages | 0 | 2.464 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| `http.admin_token: ""` | startup exited `1` before binding |
| empty-token rejection message | `http.admin_token must not be empty when configured` |
| `http.admin_token: "   "` | startup exited `1` before binding |
| blank-token rejection message | `http.admin_token must not be blank when configured` |
| `http.admin_token: " secret"` | startup exited `1` before binding |
| padded-token rejection message | `http.admin_token must not start or end with whitespace` |
| `http.admin_token` containing newline | startup exited `1` before binding |
| control-token rejection message | `http.admin_token must not contain control characters` |
| `http.admin_token` with 257 bytes | startup exited `1` before binding |
| long-token rejection message | `http.admin_token is 257 bytes, above configured cap of 256` |
| duplicate `x-altura-admin-token` metrics request | `403`, `Cache-Control: no-store`, `Connection: close` |
| local guardrail booleans | `empty_token_rejected: true`, `blank_token_rejected: true`, `padded_token_rejected: true`, `control_token_rejected: true` |
| `core` guardrail booleans | `empty_token_rejected: true`, `blank_token_rejected: true`, `padded_token_rejected: true`, `control_token_rejected: true` |
| current-tree CI guardrail booleans | `long_token_rejected: true`, `duplicate_metrics_token_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test app_config_rejects_invalid_admin_token -- --nocapture
cargo test metrics_admin_token_must_match -- --nocapture
cargo test metrics_admin_token_rejects_duplicate_headers -- --nocapture
cargo test bounded_constant_time_compare_rejects_lengths_outside_budget -- --nocapture
cargo test app_config_allows_valid_admin_token -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_admin_token_validation_20260622.json
jq -e '.guardrails.admin_token_startup.empty_token_rejected == true and .guardrails.admin_token_startup.blank_token_rejected == true and .guardrails.admin_token_startup.padded_token_rejected == true and .guardrails.admin_token_startup.control_token_rejected == true' benchmark_results/local_bench_admin_token_validation_20260622.json
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 8 --tcp-workers 4 > benchmark_results/local_bench_ci_guardrails_20260623.json
python3 tools/assert_local_bench.py benchmark_results/local_bench_ci_guardrails_20260623.json
ssh core 'cd /tmp/altura-prot-admin-token-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-admin-token-validation-20260622 && cargo test app_config_rejects_invalid_admin_token -- --nocapture'
ssh core 'cd /tmp/altura-prot-admin-token-validation-20260622 && cargo test app_config_allows_valid_admin_token -- --nocapture'
ssh core 'cd /tmp/altura-prot-admin-token-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_admin_token_validation_20260622.json'
jq -e '.guardrails.admin_token_startup.empty_token_rejected == true and .guardrails.admin_token_startup.blank_token_rejected == true and .guardrails.admin_token_startup.padded_token_rejected == true and .guardrails.admin_token_startup.control_token_rejected == true' benchmark_results/local_bench_core_admin_token_validation_20260622.json
```

## 2026-06-22 Admin Prefix Config Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_admin_prefix_validation_20260622.json`
- `benchmark_results/local_bench_core_admin_prefix_validation_20260622.json`

This snapshot adds fail-fast validation for `http.admin_path_prefix`. The prefix must be an absolute, non-root path prefix with no query marker, fragment marker, whitespace, or control characters. Trailing slashes remain accepted. This prevents typos from silently moving the control plane to `/health` and `/metrics`, making it unreachable, or mixing path matching with query/fragment text.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8718.17 RPS | `204: 26225` | 0 | 26.638 ms |
| admin health | 9097.63 RPS | `200: 27367` | 0 | 25.285 ms |
| raw TCP persistent echo | 19482.69 msg/s | `58488` echoed messages | 0 | 3.037 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6896.00 RPS | `204: 20778` | 0 | 33.002 ms |
| admin health on `core` | 6438.30 RPS | `200: 19405` | 0 | 34.832 ms |
| raw TCP persistent echo on `core` | 26741.92 msg/s | `80336` echoed messages | 0 | 2.417 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| `http.admin_path_prefix: "/"` | startup exited `1` before binding |
| root-prefix rejection message | `http.admin_path_prefix must use a non-root absolute path prefix such as /__altura` |
| `http.admin_path_prefix: "admin"` | startup exited `1` before binding |
| relative-prefix rejection message | `http.admin_path_prefix must start with '/' and use a non-root absolute path prefix such as /__altura` |
| `http.admin_path_prefix: "/__altura?debug=true"` | startup exited `1` before binding |
| query-prefix rejection message | `http.admin_path_prefix must not contain query or fragment markers` |
| local guardrail booleans | `root_prefix_rejected: true`, `relative_prefix_rejected: true`, `query_prefix_rejected: true` |
| `core` guardrail booleans | `root_prefix_rejected: true`, `relative_prefix_rejected: true`, `query_prefix_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test app_config_rejects_invalid_admin_path_prefix -- --nocapture
cargo test app_config_allows_trailing_slash_admin_path_prefix -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_admin_prefix_validation_20260622.json
jq -e '.guardrails.admin_prefix_startup.root_prefix_rejected == true and .guardrails.admin_prefix_startup.relative_prefix_rejected == true and .guardrails.admin_prefix_startup.query_prefix_rejected == true' benchmark_results/local_bench_admin_prefix_validation_20260622.json
ssh core 'cd /tmp/altura-prot-admin-prefix-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-admin-prefix-validation-20260622 && cargo test app_config_rejects_invalid_admin_path_prefix -- --nocapture'
ssh core 'cd /tmp/altura-prot-admin-prefix-validation-20260622 && cargo test app_config_allows_trailing_slash_admin_path_prefix -- --nocapture'
ssh core 'cd /tmp/altura-prot-admin-prefix-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_admin_prefix_validation_20260622.json'
jq -e '.guardrails.admin_prefix_startup.root_prefix_rejected == true and .guardrails.admin_prefix_startup.relative_prefix_rejected == true and .guardrails.admin_prefix_startup.query_prefix_rejected == true' benchmark_results/local_bench_core_admin_prefix_validation_20260622.json
```

## 2026-06-22 Negative Rate Config Validation Snapshot

Artifacts:

- `benchmark_results/local_bench_negative_rate_validation_20260622.json`
- `benchmark_results/local_bench_core_negative_rate_validation_20260622.json`

This snapshot adds fail-fast validation for DDoS-critical floating-point rate knobs. Negative or non-finite HTTP/TCP rate values now fail startup with the exact config path, so typos such as `-1` cannot silently disable a token bucket. Existing `0` semantics remain unchanged as the explicit per-bucket disable value.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9060.73 RPS | `204: 27254` | 0 | 24.992 ms |
| admin health | 9032.16 RPS | `200: 27172` | 0 | 25.153 ms |
| raw TCP persistent echo | 19281.42 msg/s | `57890` echoed messages | 0 | 3.032 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6743.53 RPS | `204: 20323` | 0 | 34.030 ms |
| admin health on `core` | 6368.23 RPS | `200: 19195` | 0 | 35.108 ms |
| raw TCP persistent echo on `core` | 26521.52 msg/s | `79654` echoed messages | 0 | 2.419 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| HTTP `http.limits.per_ip_rps: -1.0` | startup exited `1` before binding |
| HTTP rejection message | `http.limits.per_ip_rps must be finite and non-negative, got -1` |
| TCP `tcp[0].limits.global_connects_per_second: -1.0` | startup exited `1` before binding |
| TCP rejection message | `tcp[0].limits.global_connects_per_second must be finite and non-negative, got -1` |
| local guardrail booleans | `negative_http_rate_rejected: true`, `negative_tcp_rate_rejected: true` |
| `core` guardrail booleans | `negative_http_rate_rejected: true`, `negative_tcp_rate_rejected: true` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test app_config_rejects_negative -- --nocapture
cargo test app_config_rejects_non_finite_rate_limits -- --nocapture
cargo test app_config_allows_zero_rate_limits_as_explicit_disable -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_negative_rate_validation_20260622.json
jq -e '.guardrails.negative_rate_startup.negative_http_rate_rejected == true and .guardrails.negative_rate_startup.negative_tcp_rate_rejected == true' benchmark_results/local_bench_negative_rate_validation_20260622.json
ssh core 'cd /tmp/altura-prot-negative-rate-validation-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-negative-rate-validation-20260622 && cargo test app_config_rejects_negative -- --nocapture'
ssh core 'cd /tmp/altura-prot-negative-rate-validation-20260622 && cargo test app_config_rejects_non_finite_rate_limits -- --nocapture'
ssh core 'cd /tmp/altura-prot-negative-rate-validation-20260622 && cargo test app_config_allows_zero_rate_limits_as_explicit_disable -- --nocapture'
ssh core 'cd /tmp/altura-prot-negative-rate-validation-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_negative_rate_validation_20260622.json'
jq -e '.guardrails.negative_rate_startup.negative_http_rate_rejected == true and .guardrails.negative_rate_startup.negative_tcp_rate_rejected == true' benchmark_results/local_bench_core_negative_rate_validation_20260622.json
```

## 2026-06-22 Trusted Proxy In-Flight Cap Snapshot

Artifacts:

- `benchmark_results/local_bench_trusted_proxy_in_flight_20260622.json`
- `benchmark_results/local_bench_core_trusted_proxy_in_flight_20260622.json`

This snapshot adds `http.limits.trusted_proxy_max_in_flight_requests`, a per-trusted-proxy-peer cap on concurrent upstream requests when the resolved forwarded client IP differs from the immediate peer IP. The existing trusted-proxy request-rate bucket covers fast XFF-rotation floods; this cap covers slow or origin-consuming rotated-XFF traffic so one trusted edge hop cannot occupy the whole origin in-flight budget with many apparent clients.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9044.86 RPS | `204: 27209` | 0 | 25.203 ms |
| admin health | 9030.30 RPS | `200: 27168` | 0 | 25.625 ms |
| raw TCP persistent echo | 19372.87 msg/s | `58160` echoed messages | 0 | 3.039 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6617.82 RPS | `204: 19939` | 0 | 34.369 ms |
| admin health on `core` | 6476.69 RPS | `200: 19522` | 0 | 34.606 ms |
| raw TCP persistent echo on `core` | 26418.56 msg/s | `79366` echoed messages | 0 | 2.442 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| configured `trusted_proxy_max_in_flight_requests` | `1` |
| first trusted-proxy `/slow` request with `X-Forwarded-For: 198.51.100.10` | `204` |
| second concurrent trusted-proxy `/slow` request with `X-Forwarded-For: 198.51.100.11` | `503` |
| generated overload headers | `Retry-After: 1`, `Cache-Control: no-store` |
| local metric deltas | `altura_http_trusted_proxy_in_flight_rejected: 1`, `altura_http_upstream_in_flight_rejected: 1` |
| `core` metric deltas | `altura_http_trusted_proxy_in_flight_rejected: 1`, `altura_http_upstream_in_flight_rejected: 1` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test trusted_proxy -- --nocapture
cargo test request_concurrency -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_trusted_proxy_in_flight_20260622.json
jq -e '.guardrails.trusted_proxy_in_flight.rotating_xff_peer_concurrency_limited == true and .guardrails.trusted_proxy_in_flight.first_slow_request_completed == true and .guardrails.trusted_proxy_in_flight.trusted_proxy_metric_matches == true and .guardrails.trusted_proxy_in_flight.upstream_metric_includes_proxy_limit == true' benchmark_results/local_bench_trusted_proxy_in_flight_20260622.json
ssh core 'cd /tmp/altura-prot-trusted-proxy-in-flight-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-trusted-proxy-in-flight-20260622 && cargo test trusted_proxy -- --nocapture'
ssh core 'cd /tmp/altura-prot-trusted-proxy-in-flight-20260622 && cargo test request_concurrency -- --nocapture'
ssh core 'cd /tmp/altura-prot-trusted-proxy-in-flight-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_trusted_proxy_in_flight_20260622.json'
ssh core 'cd /tmp/altura-prot-trusted-proxy-in-flight-20260622 && jq -e '"'"'.guardrails.trusted_proxy_in_flight.rotating_xff_peer_concurrency_limited == true and .guardrails.trusted_proxy_in_flight.first_slow_request_completed == true and .guardrails.trusted_proxy_in_flight.trusted_proxy_metric_matches == true and .guardrails.trusted_proxy_in_flight.upstream_metric_includes_proxy_limit == true'"'"' benchmark_results/local_bench_core_trusted_proxy_in_flight_20260622.json'
```

## 2026-06-22 Trusted Proxy Global Trust Startup Reject Snapshot

Artifacts:

- `benchmark_results/local_bench_trusted_proxy_global_reject_20260622.json`
- `benchmark_results/local_bench_core_trusted_proxy_global_reject_20260622.json`

This snapshot adds startup validation for trusted forwarded-client identity. A non-loopback HTTP listener now rejects `http.client_ip.trusted_proxies` entries that trust all peers, such as `0.0.0.0/0` or `::/0`. Without this fail-fast guard, any direct client could supply rotated `X-Forwarded-For` values and split traffic across spoofed per-client rate-limit buckets.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9057.07 RPS | `204: 27244` | 0 | 25.105 ms |
| admin health | 9040.91 RPS | `200: 27196` | 0 | 25.308 ms |
| raw TCP persistent echo | 19481.76 msg/s | `58490` echoed messages | 0 | 3.016 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6850.76 RPS | `204: 20639` | 0 | 33.273 ms |
| admin health on `core` | 6606.05 RPS | `200: 19906` | 0 | 34.023 ms |
| raw TCP persistent echo on `core` | 24169.32 msg/s | `72611` echoed messages | 0 | 2.669 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| `0.0.0.0:<port>` listener with `trusted_proxies: ["0.0.0.0/0"]` | startup exited `1` before binding |
| local rejection message | `must not trust all IPv4 peers on non-loopback listener` |
| `core` rejection message | `must not trust all IPv4 peers on non-loopback listener` |
| loopback listener with global trusted ranges | allowed by unit coverage for local-only stacks |
| invalid trusted proxy range | rejected by unit coverage |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py
cargo test trusted_proxy -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_trusted_proxy_global_reject_20260622.json
jq -e '.guardrails.trusted_proxy_global_trust_startup.global_trusted_proxy_rejected == true' benchmark_results/local_bench_trusted_proxy_global_reject_20260622.json
ssh core 'cd /tmp/altura-prot-trusted-proxy-global-reject-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-trusted-proxy-global-reject-20260622 && cargo test trusted_proxy -- --nocapture'
ssh core 'cd /tmp/altura-prot-trusted-proxy-global-reject-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_trusted_proxy_global_reject_20260622.json'
ssh core 'cd /tmp/altura-prot-trusted-proxy-global-reject-20260622 && jq -e '"'"'.guardrails.trusted_proxy_global_trust_startup.global_trusted_proxy_rejected == true'"'"' benchmark_results/local_bench_core_trusted_proxy_global_reject_20260622.json'
```

## 2026-06-22 Host-Edge UDP Dead-Port Drop Snapshot

Artifacts:

- `benchmark_results/local_bench_edge_udp_drop_20260622.json`
- `benchmark_results/local_bench_core_edge_udp_drop_20260622.json`

This snapshot extends the host-edge nftables template with a raw-hook UDP drop for packets directed at AlturaProt's protected TCP listener ports. AlturaProt does not serve UDP or QUIC, so the template now drops dead UDP on those ports before conntrack. The shipped rule now uses `meta l4proto udp` before `udp dport` so IPv6 extension headers stay on the same protected-port drop path. Operators that intentionally co-host UDP/QUIC on the same port should narrow or remove this rule before installing the template.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8813.53 RPS | `204: 26520` | 0 | 26.182 ms |
| admin health | 8961.43 RPS | `200: 26958` | 0 | 25.551 ms |
| raw TCP persistent echo | 19463.78 msg/s | `58432` echoed messages | 0 | 3.023 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6768.32 RPS | `204: 20390` | 0 | 33.248 ms |
| admin health on `core` | 6600.86 RPS | `200: 19896` | 0 | 33.884 ms |
| raw TCP persistent echo on `core` | 27140.23 msg/s | `81542` echoed messages | 0 | 2.372 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| public AlturaProt listener missing from `protected_tcp_ports` | validator rejected `7000` |
| public AlturaProt listeners covered by `protected_tcp_ports` | validator accepted |
| loopback-only AlturaProt listeners missing from edge set | validator accepted |
| raw UDP protected-port drop missing from `chain preraw` | validator rejected missing `meta l4proto udp udp dport @protected_tcp_ports drop` |
| Linux nftables syntax dry-run on `core` | `nft -c -f ops/nftables/altura-prot-edge.nft` passed |

Validation commands:

```bash
python3 -m py_compile tools/validate_edge_templates.py tools/test_ai_tools.py tools/run_local_bench.py
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_edge_udp_drop_20260622.json
jq -e '.guardrails.edge_template_port_coverage.missing_public_port_rejected == true and .guardrails.edge_template_port_coverage.covered_public_ports_allowed == true and .guardrails.edge_template_port_coverage.loopback_missing_port_allowed == true and .guardrails.edge_template_port_coverage.missing_udp_drop_rejected == true' benchmark_results/local_bench_edge_udp_drop_20260622.json
ssh core 'cd /tmp/altura-prot-edge-udp-drop-20260622 && python3 -m py_compile tools/validate_edge_templates.py tools/test_ai_tools.py tools/run_local_bench.py tools/run_defense_bench.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-edge-udp-drop-20260622 && PYTHONPATH=tools python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-edge-udp-drop-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /tmp/altura-prot-edge-udp-drop-20260622 && nft -c -f ops/nftables/altura-prot-edge.nft'
ssh core 'cd /tmp/altura-prot-edge-udp-drop-20260622 && cargo build --release && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_edge_udp_drop_20260622.json'
ssh core 'cd /tmp/altura-prot-edge-udp-drop-20260622 && jq -e '"'"'.guardrails.edge_template_port_coverage.missing_public_port_rejected == true and .guardrails.edge_template_port_coverage.covered_public_ports_allowed == true and .guardrails.edge_template_port_coverage.loopback_missing_port_allowed == true and .guardrails.edge_template_port_coverage.missing_udp_drop_rejected == true'"'"' benchmark_results/local_bench_core_edge_udp_drop_20260622.json'
```

## 2026-06-22 Initial URI 414 Snapshot

Artifacts:

- `benchmark_results/local_bench_initial_uri_414_20260622.json`
- `benchmark_results/local_bench_core_initial_uri_414_20260622.json`

This snapshot moves connection-opening HTTP/1 request-target pressure enforcement into the raw pre-parser path. Requests exceeding configured URI, query-byte, query-pair, or path-segment caps now return generated `414 URI Too Long` with `Cache-Control: no-store` and `Connection: close`, and increment `altura_http_initial_request_target_rejected` before Hyper parses the request.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9067.04 RPS | `204: 27273` | 0 | 24.992 ms |
| admin health | 8985.98 RPS | `200: 27030` | 0 | 26.100 ms |
| raw TCP persistent echo | 19392.68 msg/s | `58219` echoed messages | 0 | 3.026 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6415.61 RPS | `204: 19334` | 0 | 35.527 ms |
| admin health on `core` | 6391.84 RPS | `200: 19263` | 0 | 34.855 ms |
| raw TCP persistent echo on `core` | 24785.99 msg/s | `74449` echoed messages | 0 | 2.626 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| request target above `max_uri_bytes: 64` | `414`, `Cache-Control: no-store`, `Connection: close` |
| query above `max_query_bytes: 16` | `414`, `Cache-Control: no-store`, `Connection: close` |
| query above `max_query_pairs: 2` | `414`, `Cache-Control: no-store`, `Connection: close` |
| path above `max_path_segments: 3` | `414`, `Cache-Control: no-store`, `Connection: close` |
| aggregate URI rejection counter | `altura_http_uri_rejected +4` |
| raw initial request-target counter | `altura_http_initial_request_target_rejected +4` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test request_target -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_initial_uri_414_20260622.json
jq -e '.guardrails.uri_guard.raw_initial_request_target_guard_observed == true and .guardrails.uri_guard.generated_414_not_stored == true and .guardrails.uri_guard.generated_414_closes_connection == true and .guardrails.uri_guard.metrics_delta.altura_http_uri_rejected >= 4 and .guardrails.uri_guard.metrics_delta.altura_http_initial_request_target_rejected >= 4' benchmark_results/local_bench_initial_uri_414_20260622.json
ssh core 'cd /tmp/altura-prot-initial-uri-414-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-initial-uri-414-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-initial-uri-414-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-initial-uri-414-20260622 && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_initial_uri_414_20260622.json'
ssh core 'cd /tmp/altura-prot-initial-uri-414-20260622 && jq -e '"'"'.guardrails.uri_guard.raw_initial_request_target_guard_observed == true and .guardrails.uri_guard.generated_414_not_stored == true and .guardrails.uri_guard.generated_414_closes_connection == true and .guardrails.uri_guard.metrics_delta.altura_http_uri_rejected >= 4 and .guardrails.uri_guard.metrics_delta.altura_http_initial_request_target_rejected >= 4'"'"' benchmark_results/local_bench_core_initial_uri_414_20260622.json'
```

## 2026-06-22 Initial Header Count 431 Snapshot

Artifacts:

- `benchmark_results/local_bench_initial_header_count_431_20260622.json`
- `benchmark_results/local_bench_core_initial_header_count_431_20260622.json`

This snapshot moves connection-opening HTTP/1 header-count enforcement into the raw pre-parser path. Requests exceeding `http.max_headers` now return generated `431 Request Header Fields Too Large` with `Cache-Control: no-store` and `Connection: close`, and increment `altura_http_initial_headers_too_many`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8994.51 RPS | `204: 27056` | 0 | 25.196 ms |
| admin health | 9001.91 RPS | `200: 27080` | 0 | 25.461 ms |
| raw TCP persistent echo | 19363.71 msg/s | `58136` echoed messages | 0 | 3.035 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6616.47 RPS | `204: 19939` | 0 | 34.440 ms |
| admin health on `core` | 6573.63 RPS | `200: 19811` | 0 | 34.341 ms |
| raw TCP persistent echo on `core` | 25901.39 msg/s | `77823` echoed messages | 0 | 2.504 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| `27` headers against `max_headers: 8` | `431`, `Cache-Control: no-store`, `Connection: close` |
| raw initial header-count counter | `altura_http_initial_headers_too_many +1` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test header_ -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_initial_header_count_431_20260622.json
jq -e '.guardrails.header_count.header_count_guard_observed == true and .guardrails.header_count.raw_initial_431_not_stored == true and .guardrails.header_count.raw_initial_431_closes_connection == true and .guardrails.header_count.http_initial_headers_too_many_delta >= 1' benchmark_results/local_bench_initial_header_count_431_20260622.json
ssh core 'cd /tmp/altura-prot-initial-header-count-431-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-initial-header-count-431-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-initial-header-count-431-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-initial-header-count-431-20260622 && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_initial_header_count_431_20260622.json'
ssh core 'cd /tmp/altura-prot-initial-header-count-431-20260622 && jq -e '"'"'.guardrails.header_count.header_count_guard_observed == true and .guardrails.header_count.raw_initial_431_not_stored == true and .guardrails.header_count.raw_initial_431_closes_connection == true and .guardrails.header_count.http_initial_headers_too_many_delta >= 1'"'"' benchmark_results/local_bench_core_initial_header_count_431_20260622.json'
```

## 2026-06-22 Initial Header Timeout 408 Snapshot

Artifacts:

- `benchmark_results/local_bench_initial_timeout_408_20260622.json`
- `benchmark_results/local_bench_core_initial_timeout_408_20260622.json`

This snapshot verifies the raw connection-opening HTTP/1 header timeout path before Hyper parsing. Slow initial header drips now return generated `408 Request Timeout` with `Cache-Control: no-store` and `Connection: close`, and increment `altura_http_initial_header_timeouts`. Idle keep-alive timeout behavior remains covered by the same probe.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9035.25 RPS | `204: 27178` | 0 | 24.988 ms |
| admin health | 9087.93 RPS | `200: 27340` | 0 | 25.173 ms |
| raw TCP persistent echo | 19263.28 msg/s | `57836` echoed messages | 0 | 3.059 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6647.08 RPS | `204: 20028` | 0 | 34.474 ms |
| admin health on `core` | 6539.72 RPS | `200: 19705` | 0 | 34.234 ms |
| raw TCP persistent echo on `core` | 25907.23 msg/s | `77839` echoed messages | 0 | 2.503 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| slow connection-opening header drip | `408`, `Cache-Control: no-store`, `Connection: close` |
| raw initial header-timeout counter | `altura_http_initial_header_timeouts +1` |
| idle keep-alive socket | closed before reuse after the configured header timeout |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test initial_ -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_initial_timeout_408_20260622.json
jq -e '.guardrails.header_timeout.slow_initial_header_timeout_observed == true and .guardrails.header_timeout.raw_initial_408_not_stored == true and .guardrails.header_timeout.raw_initial_408_closes_connection == true and .guardrails.header_timeout.http_initial_header_timeouts_delta >= 1' benchmark_results/local_bench_initial_timeout_408_20260622.json
ssh core 'cd /tmp/altura-prot-initial-timeout-408-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-initial-timeout-408-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-initial-timeout-408-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-initial-timeout-408-20260622 && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_initial_timeout_408_20260622.json'
ssh core 'cd /tmp/altura-prot-initial-timeout-408-20260622 && jq -e '"'"'.guardrails.header_timeout.slow_initial_header_timeout_observed == true and .guardrails.header_timeout.raw_initial_408_not_stored == true and .guardrails.header_timeout.raw_initial_408_closes_connection == true and .guardrails.header_timeout.http_initial_header_timeouts_delta >= 1'"'"' benchmark_results/local_bench_core_initial_timeout_408_20260622.json'
```

## 2026-06-22 Initial Header 431 Snapshot

Artifacts:

- `benchmark_results/local_bench_initial_header_431_20260622.json`
- `benchmark_results/local_bench_core_initial_header_431_20260622.json`

This snapshot verifies the raw connection-opening HTTP/1 pre-parser path before Hyper parsing. Malformed initial framing still returns generated `400` with `Cache-Control: no-store` and `Connection: close`; oversized initial header sections now return generated `431 Request Header Fields Too Large` with the same no-store/close semantics and increment `altura_http_initial_header_too_large`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9054.71 RPS | `204: 27236` | 0 | 24.992 ms |
| admin health | 9092.33 RPS | `200: 27351` | 0 | 25.932 ms |
| raw TCP persistent echo | 19348.74 msg/s | `58089` echoed messages | 0 | 3.017 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6541.27 RPS | `204: 19712` | 0 | 35.079 ms |
| admin health on `core` | 6443.53 RPS | `200: 19421` | 0 | 34.639 ms |
| raw TCP persistent echo on `core` | 25015.24 msg/s | `75158` echoed messages | 0 | 2.573 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| obsolete folded initial header | `400`, `Cache-Control: no-store`, `Connection: close` |
| oversized initial header section | `431`, `Cache-Control: no-store`, `Connection: close` |
| raw malformed-header counter | `altura_http_framing_rejected +1` |
| raw oversized-header counter | `altura_http_initial_header_too_large +1` |

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test initial_ -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_initial_header_431_20260622.json
jq -e '.guardrails.initial_framing_precheck_response.initial_framing_precheck_response_observed == true and .guardrails.initial_framing_precheck_response.initial_header_too_large_response_observed == true and .guardrails.initial_framing_precheck_response.raw_initial_400_not_stored == true and .guardrails.initial_framing_precheck_response.raw_initial_400_closes_connection == true and .guardrails.initial_framing_precheck_response.raw_initial_431_not_stored == true and .guardrails.initial_framing_precheck_response.raw_initial_431_closes_connection == true and .guardrails.initial_framing_precheck_response.http_framing_rejected_delta >= 1 and .guardrails.initial_framing_precheck_response.http_initial_header_too_large_delta >= 1' benchmark_results/local_bench_initial_header_431_20260622.json
ssh core 'cd /tmp/altura-prot-initial-header-431-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-initial-header-431-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-initial-header-431-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-initial-header-431-20260622 && python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32 > benchmark_results/local_bench_core_initial_header_431_20260622.json'
ssh core 'cd /tmp/altura-prot-initial-header-431-20260622 && jq -e '"'"'.guardrails.initial_framing_precheck_response.initial_framing_precheck_response_observed == true and .guardrails.initial_framing_precheck_response.initial_header_too_large_response_observed == true and .guardrails.initial_framing_precheck_response.raw_initial_400_not_stored == true and .guardrails.initial_framing_precheck_response.raw_initial_400_closes_connection == true and .guardrails.initial_framing_precheck_response.raw_initial_431_not_stored == true and .guardrails.initial_framing_precheck_response.raw_initial_431_closes_connection == true and .guardrails.initial_framing_precheck_response.http_framing_rejected_delta >= 1 and .guardrails.initial_framing_precheck_response.http_initial_header_too_large_delta >= 1'"'"' benchmark_results/local_bench_core_initial_header_431_20260622.json'
```

## 2026-06-22 Control-Plane and Early-Deny No-Store Snapshot

Artifacts:

- `benchmark_results/local_bench_control_plane_no_store_20260622.json`
- `benchmark_results/local_bench_core_control_plane_no_store_20260622.json`

This snapshot verifies that generated admin/control-plane responses and shared early-deny responses are explicitly non-storeable. Covered paths include admin health, token-protected metrics, unauthorized metrics, filter/method/request-target body-bearing keep-alive rejections, `Expect` guard rejections, `Range` guard rejections, Host guard rejections, and trusted-forwarded-header bounds rejections.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8957.26 RPS | `204: 26944` | 0 | 25.351 ms |
| admin health | 8909.92 RPS | `200: 26801` | 0 | 25.360 ms |
| raw TCP persistent echo | 19440.04 msg/s | `58365` echoed messages | 0 | 3.026 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6383.48 RPS | `204: 19240` | 0 | 35.744 ms |
| admin health on `core` | 6465.99 RPS | `200: 19487` | 0 | 34.413 ms |
| raw TCP persistent echo on `core` | 24100.39 msg/s | `72382` echoed messages | 0 | 2.686 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| admin health | `200`, `Cache-Control: no-store` |
| metrics without token | `403`, `Cache-Control: no-store` |
| metrics with token | `200`, `Cache-Control: no-store` |
| filter/method/request-target body-bearing rejections | close/no-store response before connection reuse |
| `Expect`, `Range`, Host, and forwarded-header bounds rejects | no-store generated response |

## 2026-06-22 Generated Denial No-Store Snapshot

Artifacts:

- `benchmark_results/local_bench_generated_denial_no_store_20260622.json`
- `benchmark_results/local_bench_core_generated_denial_no_store_20260622.json`

This snapshot verifies that proxy-generated request-denial responses are explicitly non-storeable and connection-closing. Covered paths include `408` request-body idle/min-rate timeouts, `413` oversized request bodies, `400` request-framing rejects from both the raw pre-parser guard and the Hyper service path, and `415` unsupported request content codings.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9035.17 RPS | `204: 27173` | 0 | 25.157 ms |
| admin health | 9207.03 RPS | `200: 27695` | 0 | 24.559 ms |
| raw TCP persistent echo | 19509.94 msg/s | `58574` echoed messages | 0 | 3.016 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6524.45 RPS | `204: 19657` | 0 | 33.987 ms |
| admin health on `core` | 6540.56 RPS | `200: 19711` | 0 | 34.638 ms |
| raw TCP persistent echo on `core` | 26628.99 msg/s | `79997` echoed messages | 0 | 2.414 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| oversized `Content-Length` | `413`, `Cache-Control: no-store`, `Connection: close` |
| idle request body timeout | `408`, `Cache-Control: no-store`, `Connection: close` |
| request body minimum-rate timeout | `408`, `Cache-Control: no-store`, `Connection: close` |
| unsupported request `Content-Encoding` | `415`, `Accept-Encoding: identity`, `Cache-Control: no-store`, `Connection: close` |
| request framing rejects after Hyper parsing | `400`, `Cache-Control: no-store`, `Connection: close` |
| raw initial framing precheck reject | `400`, `Cache-Control: no-store`, `Connection: close` |

## 2026-06-22 Upstream Failure Close/No-Store Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_failure_close_20260622.json`
- `benchmark_results/local_bench_core_upstream_failure_close_20260622.json`

This snapshot verifies that generated upstream failure responses are explicit transient proxy responses: upstream connect/header failures return `502` with `Cache-Control: no-store` and `Connection: close`, and upstream response timeouts return `504` with the same headers.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9019.49 RPS | `204: 27122` | 0 | 25.080 ms |
| admin health | 9242.36 RPS | `200: 27802` | 0 | 24.769 ms |
| raw TCP persistent echo | 19569.02 msg/s | `58751` echoed messages | 0 | 3.010 ms |

`core` release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6405.50 RPS | `204: 19303` | 0 | 35.669 ms |
| admin health on `core` | 6540.58 RPS | `200: 19710` | 0 | 34.756 ms |
| raw TCP persistent echo on `core` | 25668.80 msg/s | `77099` echoed messages | 0 | 2.534 ms |

Guardrail probes:

| Probe | Result |
| --- | --- |
| loopback backlog connect timeout | `502`, `Cache-Control: no-store`, `Connection: close` |
| upstream oversized/many-header rejection | `502`, `Cache-Control: no-store`, `Connection: close` |
| upstream response timeout | `504`, `Cache-Control: no-store`, `Connection: close` |
| metrics deltas | connect/header failures incremented `altura_http_upstream_errors`; response timeout incremented `altura_http_upstream_timeouts` without `altura_http_upstream_errors` |

## 2026-06-21 Guardrail Snapshot

Artifacts:

- `benchmark_results/local_bench_guardrails_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_guardrails.json`

Local release build, loopback only, Python client/upstream:

| Scenario | RPS | Statuses | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed upstream with HTTP guardrails | 16401.30 | `204: 49295` | 0 | 18.258 ms |
| admin health with HTTP guardrails | 17774.95 | `200: 53420` | 0 | 15.702 ms |

Deterministic all-scenario defense benchmark:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.5 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced scenarios met the benchmark targets: attacker replay block at or above 90% and benign probe allow at or above 95%. Most scenarios blocked 100%; the lowest passing attacker-block rates were `smart-api-mix` at 95.36% and `dictionary-slug-xff` at 95.85%.

## 2026-06-21 Streamed Body Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_stream_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_stream_guard.json`

Local release build, loopback only. The `core` server was not reachable from this session, so this snapshot ran locally.

| Scenario | RPS | Statuses | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed upstream with streamed-body guard | 16860.72 | `204: 50675` | 0 | 17.323 ms |
| admin health with streamed-body guard | 17667.01 | `200: 53099` | 0 | 15.770 ms |

HTTP guardrail probes:

| Probe | Result |
| --- | --- |
| oversized `Content-Length` | `413` |
| slow request body | `408` after 0.21 s |
| metrics delta | `altura_http_body_rejected: 1`, `altura_http_body_timeouts: 1`, `altura_http_upstream_errors: 0` |

Deterministic all-scenario defense benchmark:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.76% and `smart-api-mix` at 96.53%.

## 2026-06-21 TCP Global Cap Snapshot

Artifact:

- `benchmark_results/local_bench_tcp_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_tcp_guard.json`

Local release build, loopback only. TCP throughput uses persistent echo connections so the benchmark measures proxy copy overhead without exhausting local ephemeral ports; connection-flood behavior is covered by the explicit global-cap probe.

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 17017.61 RPS | `204: 51148` | 0 | 17.029 ms |
| admin health | 17200.25 RPS | `200: 51693` | 0 | 16.303 ms |
| raw TCP persistent echo | 19039.16 msg/s | `57161` echoed messages | 0 | 3.094 ms |

TCP guardrail probe:

| Probe | Result |
| --- | --- |
| held connections against `max_connections: 2` | 2 |
| third connection | closed/reset |
| metrics delta | `altura_tcp_rejected: 1` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.73% and `smart-api-mix` at 97.98%.

## 2026-06-21 Admin Guard Snapshot

Artifact:

- `benchmark_results/local_bench_admin_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_admin_guard.json`

Local release build, loopback only. This snapshot adds admin-surface checks to the HTTP/TCP guard benchmark.

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16963.08 RPS | `204: 50977` | 0 | 17.193 ms |
| admin health | 17586.91 RPS | `200: 52852` | 0 | 15.932 ms |
| raw TCP persistent echo | 19008.86 msg/s | `57072` echoed messages | 0 | 3.095 ms |

Admin guardrail probes:

| Probe | Result |
| --- | --- |
| metrics without `x-altura-admin-token` | `403` |
| low-limit health checks | `[200, 429]` |
| oversized `Content-Length` | `413` |
| slow request body | `408` after 0.201 s |
| TCP third connection with `max_connections: 2` | closed/reset |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.78% and `smart-api-mix` at 97.86%.

## 2026-06-21 Upstream In-Flight Guard Snapshot

Artifact:

- `benchmark_results/local_bench_inflight_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_inflight_guard.json`

Local release build, loopback only. This snapshot adds an origin-shielding probe with `max_in_flight_requests: 1`.

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16901.08 RPS | `204: 50798` | 0 | 17.288 ms |
| admin health | 17551.30 RPS | `200: 52743` | 0 | 16.038 ms |
| raw TCP persistent echo | 19025.88 msg/s | `57120` echoed messages | 0 | 3.096 ms |

Upstream in-flight guardrail probe:

| Probe | Result |
| --- | --- |
| first slow upstream request | `204` |
| second concurrent slow upstream request with one slot held | `503` |
| metrics delta | `altura_http_upstream_in_flight_rejected: 1` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.93% and `smart-api-mix` at 94.80%.

## 2026-06-21 Rate-Limiter Fairness Snapshot

Artifact:

- `benchmark_results/local_bench_rate_fairness_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_rate_fairness.json`
- `benchmark_results/local_bench_core_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621.json`

Local release build, loopback only. This snapshot verifies that per-IP-denied requests do not consume global request tokens.

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16893.03 RPS | `204: 50777` | 0 | 17.145 ms |
| admin health | 17955.86 RPS | `200: 53964` | 0 | 15.494 ms |
| raw TCP persistent echo | 19007.62 msg/s | `57067` echoed messages | 0 | 3.111 ms |

Rate-limiter fairness probe:

| Probe | Result |
| --- | --- |
| first request from forwarded client A | `204` |
| second request from forwarded client A | `429` |
| first request from forwarded client B | `204` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.82%, `slow-xff-polymorphic` at 95.16%, and `smart-api-mix` at 98.04%.

Core server validation after the local snapshot:

```bash
python3 tools/run_local_bench.py --duration 10 --workers 512
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.5 --workers 96 --analyzer-wait 10 --json-only
```

`tools/run_local_bench.py` uses a larger synthetic-upstream listen backlog for this run so the benchmark measures AlturaProt instead of Python `socketserver` accept-queue saturation.

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11667.74 RPS | `204: 117194` | 0 | 70.689 ms |
| admin health on `core` | 11208.45 RPS | `200: 112575` | 0 | 65.819 ms |
| raw TCP persistent echo on `core` | 25489.43 msg/s | `255070` echoed messages | 0 | 2.553 ms |

Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 93.87%, `smart-api-mix` at 96.70%, and `legit-interleave-xff` at 98.82%.

## 2026-06-21 Tracked-IP Cap Snapshot (Historical)

Artifacts:

- `benchmark_results/local_bench_tracked_ip_cap_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_tracked_ip_cap.json`
- `benchmark_results/local_bench_core_tracked_ip_cap_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_tracked_ip_cap.json`

This historical snapshot enforced `max_tracked_ips` as a bounded limiter-state
cap but still allowed active rate-bucket eviction. It is superseded by the
2026-06-22 tracked-key fail-closed snapshot above, where active rate buckets are
not evicted to admit new high-cardinality keys.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 15968.23 RPS | `204: 47991` | 0 | 18.668 ms |
| admin health | 17843.63 RPS | `200: 53620` | 0 | 15.720 ms |
| raw TCP persistent echo | 18993.08 msg/s | `57023` echoed messages | 0 | 3.096 ms |

Tracked-IP cap probe:

| Probe | Result |
| --- | --- |
| first request from same-shard forwarded client A | `204` |
| second request from client A | `429` |
| first request from same-shard forwarded client B | `204` |
| third request from client A after B evicts A's bucket | `204` (historical bypass; fixed on 2026-06-22) |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 93.02% and `smart-api-mix` at 95.16%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 10 --workers 512
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.5 --workers 96 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11761.57 RPS | `204: 118150` | 0 | 80.844 ms |
| admin health on `core` | 11535.77 RPS | `200: 115876` | 0 | 65.681 ms |
| raw TCP persistent echo on `core` | 27154.01 msg/s | `271726` echoed messages | 0 | 2.375 ms |

Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 93.89%, `smart-api-mix` at 96.94%, and `legit-interleave-xff` at 98.40%.

## 2026-06-21 TCP Idle Timeout Snapshot

Artifacts:

- `benchmark_results/local_bench_tcp_idle_timeout_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_tcp_idle_timeout.json`
- `benchmark_results/local_bench_core_tcp_idle_timeout_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_tcp_idle_timeout.json`

This snapshot adds `tcp[].idle_timeout_seconds`, an activity-aware timeout for raw TCP proxy connections. The timer resets only after bytes are successfully relayed between downstream and upstream; idle established connections are closed and counted in `altura_tcp_idle_timeouts`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 15782.29 RPS | `204: 47438` | 0 | 18.970 ms |
| admin health | 17806.60 RPS | `200: 53512` | 0 | 15.710 ms |
| raw TCP persistent echo | 19066.65 msg/s | `57249` echoed messages | 0 | 3.095 ms |

TCP idle-timeout probe:

| Probe | Result |
| --- | --- |
| idle raw TCP connection with `idle_timeout_seconds: 1` | closed/reset after 1.208 s |
| metrics delta | `altura_tcp_idle_timeouts: 1`, `altura_tcp_rejected: 1` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.83% and `smart-api-mix` at 98.04%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 10 --workers 512
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.5 --workers 96 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11425.61 RPS | `204: 114788` | 0 | 105.972 ms |
| admin health on `core` | 11642.33 RPS | `200: 116955` | 0 | 65.651 ms |
| raw TCP persistent echo on `core` | 26208.72 msg/s | `262247` echoed messages | 0 | 2.477 ms |

Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 93.91%, `smart-api-mix` at 96.84%, and `legit-interleave-xff` at 98.42%.

## 2026-06-21 Upstream Response Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_response_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_upstream_response_guard.json`
- `benchmark_results/local_bench_core_upstream_response_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_upstream_response_guard.json`

This snapshot adds upstream response body guardrails: `http.upstream_body_idle_timeout_ms` and `http.max_upstream_body_bytes`. Response body failures close the downstream response stream and increment `altura_http_upstream_body_timeouts` or `altura_http_upstream_body_rejected`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 15893.57 RPS | `204: 47779` | 0 | 18.589 ms |
| admin health | 17840.61 RPS | `200: 53612` | 0 | 15.570 ms |
| raw TCP persistent echo | 18886.55 msg/s | `56706` echoed messages | 0 | 3.130 ms |

Upstream response guard probes:

| Probe | Result |
| --- | --- |
| stalled upstream response body with 100 ms idle timeout | closed after 0.105 s |
| oversized upstream response body with 8 byte cap | closed before forwarding body |
| metrics delta | `altura_http_upstream_body_timeouts: 1`, `altura_http_upstream_body_rejected: 1` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.73% and `smart-api-mix` at 98.00%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 10 --workers 512
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.5 --workers 96 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11563.44 RPS | `204: 116172` | 0 | 80.930 ms |
| admin health on `core` | 11663.22 RPS | `200: 117151` | 0 | 65.681 ms |
| raw TCP persistent echo on `core` | 25505.11 msg/s | `255227` echoed messages | 0 | 2.550 ms |

Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.02%, `smart-api-mix` at 96.10%, `legit-interleave-xff` at 98.42%, and `catalog-mimic-xff` at 98.47%.

## 2026-06-21 Header Count Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_header_count_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_header_count.json`
- `benchmark_results/local_bench_core_header_count_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_header_count.json`

This snapshot makes Hyper's HTTP/1 header-count cap explicit as `http.max_headers`, alongside the existing `http.max_header_bytes` cap. Oversized header counts are rejected by Hyper before the request reaches the proxy service, returning `431 Request Header Fields Too Large`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16135.11 RPS | `204: 48493` | 0 | 18.448 ms |
| admin health | 17756.36 RPS | `200: 53359` | 0 | 15.844 ms |
| raw TCP persistent echo | 19061.26 msg/s | `57229` echoed messages | 0 | 3.097 ms |

Header-count guard probe:

| Probe | Result |
| --- | --- |
| request with 27 headers against `max_headers: 8` | `431` in 0.001 s |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.94%, `smart-api-mix` at 96.39%, and `legit-interleave-xff` at 99.66%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11531.82 RPS | `204: 34725` | 0 | 29.801 ms |
| admin health on `core` | 11891.12 RPS | `200: 35806` | 0 | 29.495 ms |
| raw TCP persistent echo on `core` | 26894.26 msg/s | `80795` echoed messages | 0 | 2.384 ms |

Core header-count guard probe returned `431` for 27 headers against `max_headers: 8`. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.63%, `slow-xff-polymorphic` at 95.90%, `smart-api-mix` at 96.14%, and `legit-interleave-xff` at 98.09%.

## 2026-06-21 Upstream Pool Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_pool_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_upstream_pool.json`
- `benchmark_results/local_bench_core_upstream_pool_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_upstream_pool.json`

This snapshot bounds idle origin keep-alive pressure with `http.upstream_pool_idle_timeout_ms` and `http.upstream_pool_max_idle_per_host`. The defaults are 30 seconds and 256 idle connections per upstream host; setting `upstream_pool_max_idle_per_host` to `0` disables idle pooling for that host.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16017.83 RPS | `204: 48138` | 0 | 18.641 ms |
| admin health | 17810.97 RPS | `200: 53524` | 0 | 15.738 ms |
| raw TCP persistent echo | 18958.90 msg/s | `56924` echoed messages | 0 | 3.119 ms |

Upstream pool guard probe:

| Probe | Result |
| --- | --- |
| two sequential requests with `upstream_pool_max_idle_per_host: 0` | statuses `[204, 204]`, upstream accepted 2 connections |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 93.03% and `smart-api-mix` at 97.89%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11626.19 RPS | `204: 35005` | 0 | 32.322 ms |
| admin health on `core` | 11844.80 RPS | `200: 35663` | 0 | 29.274 ms |
| raw TCP persistent echo on `core` | 24211.96 msg/s | `72724` echoed messages | 0 | 2.663 ms |

Core upstream-pool guard probe returned statuses `[204, 204]` and 2 accepted upstream connections with idle pooling disabled. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.59%, `slow-xff-polymorphic` at 95.90%, `smart-api-mix` at 96.01%, and `legit-interleave-xff` at 98.20%.

## 2026-06-21 Listen Backlog Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_listen_backlog_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_listen_backlog.json`
- `benchmark_results/local_bench_core_listen_backlog_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_listen_backlog.json`
- `benchmark_results/listen_backlog_ss_core_20260621.json`

This snapshot adds explicit listener backlog controls: `http.listen_backlog` and `tcp[].listen_backlog`, both defaulting to `4096`. The listeners are now created with Tokio `TcpSocket::listen(backlog)` instead of the implicit `TcpListener::bind` backlog.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16115.12 RPS | `204: 48442` | 0 | 18.686 ms |
| admin health | 17631.29 RPS | `200: 52992` | 0 | 15.917 ms |
| raw TCP persistent echo | 19048.57 msg/s | `57189` echoed messages | 0 | 3.087 ms |

Listen-backlog guard probe:

| Probe | Result |
| --- | --- |
| HTTP and TCP listeners with `listen_backlog: 128` | HTTP `204`, TCP echo ok |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.87%, `slow-xff-polymorphic` at 95.12%, and `smart-api-mix` at 96.36%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11539.95 RPS | `204: 34749` | 0 | 30.484 ms |
| admin health on `core` | 12064.66 RPS | `200: 36328` | 0 | 29.207 ms |
| raw TCP persistent echo on `core` | 24411.05 msg/s | `73341` echoed messages | 0 | 2.643 ms |

Core listen-backlog guard probe returned HTTP `204` and TCP echo ok with `listen_backlog: 128`. A Linux `ss -ltn` probe confirmed configured backlog values reached the kernel: HTTP `333` and TCP `777` appeared in the LISTEN Send-Q column. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.42%, `slow-xff-polymorphic` at 95.90%, `smart-api-mix` at 96.42%, and `legit-interleave-xff` at 98.05%.

## 2026-06-21 Header Timeout Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_header_timeout_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_header_timeout.json`
- `benchmark_results/local_bench_core_header_timeout_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_header_timeout.json`

This snapshot adds explicit benchmark coverage for `http.header_read_timeout_ms`. Hyper's HTTP/1 header timeout is configured with a Tokio timer; the probes verify both incomplete slow headers and idle keep-alive sockets are closed before they can keep holding connection permits.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 15676.10 RPS | `204: 47121` | 0 | 18.731 ms |
| admin health | 18005.26 RPS | `200: 54105` | 0 | 15.502 ms |
| raw TCP persistent echo | 19059.96 msg/s | `57226` echoed messages | 0 | 3.095 ms |

Header-timeout guard probes with `header_read_timeout_ms: 100`:

| Probe | Result |
| --- | --- |
| incomplete header stalled beyond timeout | closed after 0.258 s |
| idle HTTP keep-alive before second request | first response `204`, second request got closed connection after 0.263 s |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.95% and `smart-api-mix` at 98.05%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11514.44 RPS | `204: 34671` | 0 | 29.601 ms |
| admin health on `core` | 11776.97 RPS | `200: 35457` | 0 | 29.705 ms |
| raw TCP persistent echo on `core` | 24258.61 msg/s | `72860` echoed messages | 0 | 2.660 ms |

Core header-timeout probes with `header_read_timeout_ms: 100` closed incomplete headers after 0.250 s and closed idle keep-alive before reuse after 0.251 s. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.52%, `slow-xff-polymorphic` at 95.90%, `smart-api-mix` at 96.03%, and `legit-interleave-xff` at 97.60%.

## 2026-06-21 URI Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_uri_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_uri_guard.json`
- `benchmark_results/local_bench_core_uri_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_uri_guard.json`

This snapshot adds request-target pressure limits before path/query cloning, request signature calculation, adaptive observation, filter evaluation, or rate limiting. The new knobs are `http.max_uri_bytes`, `http.max_query_bytes`, `http.max_query_pairs`, and `http.max_path_segments`; rejected request targets return HTTP `414` and increment `altura_http_uri_rejected`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16180.74 RPS | `204: 48629` | 0 | 18.458 ms |
| admin health | 17791.15 RPS | `200: 53471` | 0 | 15.759 ms |
| raw TCP persistent echo | 18912.59 msg/s | `56783` echoed messages | 0 | 3.123 ms |

URI guard probes with `max_uri_bytes: 64`, `max_query_bytes: 16`, `max_query_pairs: 2`, and `max_path_segments: 3`:

| Probe | Target bytes | Result |
| --- | ---: | --- |
| request target over `max_uri_bytes` | 86 | `414` |
| query string over `max_query_bytes` | 38 | `414` |
| three query pairs over `max_query_pairs` | 15 | `414` |
| four path segments over `max_path_segments` | 8 | `414` |

The local probe increased `altura_http_uri_rejected` by 4.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 93.08% and `smart-api-mix` at 98.20%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11456.87 RPS | `204: 34494` | 0 | 32.617 ms |
| admin health on `core` | 11807.96 RPS | `200: 35556` | 0 | 29.286 ms |
| raw TCP persistent echo on `core` | 24968.48 msg/s | `74998` echoed messages | 0 | 2.591 ms |

Core URI guard probes returned `414` for the long target, long query, excess query-pair, and excess path-segment cases, with `altura_http_uri_rejected` increasing by 4. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.47%, `smart-api-mix` at 95.59%, `slow-xff-polymorphic` at 95.90%, and `legit-interleave-xff` at 98.09%.

## 2026-06-21 Method Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_method_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_method_guard.json`
- `benchmark_results/local_bench_core_method_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_method_guard.json`

This snapshot adds a configurable `http.allowed_methods` allowlist before request-target validation, request signature calculation, adaptive observation, filter evaluation, rate limiting, or upstream proxying. Disallowed methods return HTTP `405` with an `Allow` header and increment `altura_http_method_rejected`. Defaults allow common origin/API methods: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16134.58 RPS | `204: 48490` | 0 | 18.507 ms |
| admin health | 17641.46 RPS | `200: 53010` | 0 | 15.858 ms |
| raw TCP persistent echo | 19005.32 msg/s | `57059` echoed messages | 0 | 3.106 ms |

Method guard probes with `allowed_methods: ["GET", "POST"]`:

| Probe | Result |
| --- | --- |
| `GET /` | `204` |
| `POST /drain` | `200` |
| `TRACE /` | `405`, `Allow: GET, POST` |
| `CONNECT 127.0.0.1:443` | `405`, `Allow: GET, POST` |
| `TRACK /` | `405`, `Allow: GET, POST` |
| `JEFF /` arbitrary extension method | `405`, `Allow: GET, POST` |

The local method probe increased `altura_http_method_rejected` by 4.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 94.72% and `smart-api-mix` at 98.16%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11505.09 RPS | `204: 34644` | 0 | 30.428 ms |
| admin health on `core` | 11793.14 RPS | `200: 35505` | 0 | 29.604 ms |
| raw TCP persistent echo on `core` | 23633.39 msg/s | `71006` echoed messages | 0 | 2.731 ms |

Core method guard probes matched local behavior: allowed `GET`/`POST` reached upstream, `TRACE`, `CONNECT`, `TRACK`, and `JEFF` returned `405` with `Allow: GET, POST`, and `altura_http_method_rejected` increased by 4. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.56%, `smart-api-mix` at 95.86%, `slow-xff-polymorphic` at 95.90%, and `legit-interleave-xff` at 98.56%.

## 2026-06-21 Host Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_host_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_host_guard.json`
- `benchmark_results/local_bench_core_host_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_host_guard.json`

This snapshot adds Host header validation before request-target validation, request signature calculation, adaptive observation, filter evaluation, rate limiting, or upstream proxying. The new knobs are `http.require_host_header`, `http.max_host_bytes`, and `http.allowed_hosts`; rejected Host inputs return HTTP `400` and increment `altura_http_host_rejected`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 15913.80 RPS | `204: 47831` | 0 | 18.790 ms |
| admin health | 17548.09 RPS | `200: 52739` | 0 | 15.998 ms |
| raw TCP persistent echo | 19007.04 msg/s | `57064` echoed messages | 0 | 3.099 ms |

Host guard probes with `max_host_bytes: 32` and `allowed_hosts: ["good.local", "api.good.local:8080"]`:

| Probe | Result |
| --- | --- |
| `Host: good.local` | `204` |
| `Host: api.good.local:8080` | `204` |
| missing `Host` | `400` |
| duplicate `Host` lines | `400` |
| invalid authority `Host: http://evil.local` | `400` |
| Host over `max_host_bytes` | `400` |
| disallowed `Host: evil.local` | `400` |

The local Host probe increased `altura_http_host_rejected` by 5.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.91% and `smart-api-mix` at 98.00%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11432.65 RPS | `204: 34428` | 0 | 32.429 ms |
| admin health on `core` | 11809.21 RPS | `200: 35559` | 0 | 29.442 ms |
| raw TCP persistent echo on `core` | 26005.19 msg/s | `78133` echoed messages | 0 | 2.501 ms |

Core Host guard probes matched local behavior: allowed Hosts reached upstream, missing/duplicate/invalid/long/disallowed Hosts returned `400`, and `altura_http_host_rejected` increased by 5. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.58%, `slow-xff-polymorphic` at 95.90%, `smart-api-mix` at 95.98%, and `legit-interleave-xff` at 98.06%.

## 2026-06-21 Request Framing Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_framing_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_framing_guard.json`
- `benchmark_results/local_bench_core_framing_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_framing_guard.json`

This snapshot adds application-level request framing validation for `Content-Length` and `Transfer-Encoding` headers that Hyper exposes to the service. Rejected framing inputs return HTTP `400` and increment `altura_http_framing_rejected`. Raw probes also record HTTP/1 parser-boundary behavior: Hyper can reject or normalize some wire-level ambiguity before the application guard sees the request, so those cases do not always increment `altura_http_framing_rejected`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 15530.96 RPS | `204: 46697` | 0 | 19.258 ms |
| admin health | 17097.74 RPS | `200: 51378` | 0 | 16.321 ms |
| raw TCP persistent echo | 18446.73 msg/s | `55383` echoed messages | 0 | 3.268 ms |

Local framing probes:

| Probe | Result |
| --- | --- |
| single `Content-Length: 0` | `200` |
| valid `Transfer-Encoding: chunked` | `200` |
| duplicate identical `Content-Length: 0` lines | `204`, normalized/accepted before app guard |
| conflicting `Content-Length: 0` and `Content-Length: 1` | `400` |
| comma-list `Content-Length: 0, 0` | `400` |
| invalid `Content-Length: nope` | `400` |
| `Transfer-Encoding: chunked` plus `Content-Length: 0` | `200`, processed before app guard |
| duplicate `Transfer-Encoding: chunked` lines | `400` |
| unsupported `Transfer-Encoding: gzip` | `400` |

The local dedicated framing probe increased `altura_http_framing_rejected` by 1. The lower count is expected for this Hyper-backed path: parser-rejected or parser-normalized requests can return a non-2xx result or a normalized upstream request before the application-level guard sees raw duplicate lines.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.92% and `smart-api-mix` at 98.02%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11575.27 RPS | `204: 34856` | 0 | 30.359 ms |
| admin health on `core` | 11966.41 RPS | `200: 36032` | 0 | 29.353 ms |
| raw TCP persistent echo on `core` | 25184.31 msg/s | `75643` echoed messages | 0 | 2.568 ms |

Core framing probes matched local behavior: valid single `Content-Length` and valid chunked requests reached upstream, conflicting/invalid/comma-list `Content-Length` and duplicate/unsupported `Transfer-Encoding` returned `400`, duplicate identical `Content-Length` was normalized/accepted with `204`, and `Transfer-Encoding: chunked` plus `Content-Length: 0` was processed with `200`. The Core dedicated framing probe increased `altura_http_framing_rejected` by 1. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.31%, `smart-api-mix` at 95.68%, `slow-xff-polymorphic` at 95.90%, and `legit-interleave-xff` at 98.01%.

## 2026-06-21 Absolute-Form Host Authority Snapshot

Artifacts:

- `benchmark_results/local_bench_absolute_form_host_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_absolute_form_host_guard.json`
- `benchmark_results/local_bench_core_absolute_form_host_guard_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_absolute_form_host_guard.json`

This snapshot makes Host policy effective-authority aware for absolute-form HTTP/1 request targets. Regular origin-form requests still validate the `Host` header. Absolute-form requests still require a syntactically valid single `Host` header when `require_host_header` is enabled, but the URI authority becomes the effective Host for allowlist checks, preserved upstream Host forwarding, and `X-Forwarded-Host`. That prevents proxy-form targets such as `GET http://evil.local/ HTTP/1.1` with `Host: good.local` from bypassing `allowed_hosts`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16247.98 RPS | `204: 48829` | 0 | 18.339 ms |
| admin health | 18221.15 RPS | `200: 54752` | 0 | 15.352 ms |
| raw TCP persistent echo | 19057.46 msg/s | `57220` echoed messages | 0 | 3.102 ms |

Host guard probes with `max_host_bytes: 32` and `allowed_hosts: ["good.local", "api.good.local:8080"]`:

| Probe | Result |
| --- | --- |
| `Host: good.local` | `204` |
| `Host: api.good.local:8080` | `204` |
| missing `Host` | `400` |
| duplicate `Host` lines | `400` |
| invalid authority `Host: http://evil.local` | `400` |
| Host over `max_host_bytes` | `400` |
| disallowed `Host: evil.local` | `400` |
| absolute-form `http://good.local/` with `Host: evil.local` | `204` |
| absolute-form `http://evil.local/` with `Host: good.local` | `400` |

The local Host probe increased `altura_http_host_rejected` by 6.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 91.26% and `smart-api-mix` at 96.30%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11275.41 RPS | `204: 33948` | 0 | 31.405 ms |
| admin health on `core` | 11404.98 RPS | `200: 34347` | 0 | 30.748 ms |
| raw TCP persistent echo on `core` | 25393.43 msg/s | `76290` echoed messages | 0 | 2.562 ms |

Core Host guard probes matched local behavior, including absolute-form `http://good.local/` with mismatched `Host: evil.local` reaching upstream and absolute-form `http://evil.local/` with `Host: good.local` returning `400`; `altura_http_host_rejected` increased by 6. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.30%, `smart-api-mix` at 95.58%, `slow-xff-polymorphic` at 95.90%, and `legit-interleave-xff` at 98.06%.

## 2026-06-21 Forwarded Header Sanitization Snapshot

Artifacts:

- `benchmark_results/local_bench_forwarded_header_sanitization_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_forwarded_header_sanitization.json`
- `benchmark_results/local_bench_core_forwarded_header_sanitization_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_forwarded_header_sanitization.json`

This snapshot prevents direct clients from spoofing origin-visible forwarding metadata. For untrusted peers, AlturaProt overwrites `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, and `X-Forwarded-Proto`, and removes `Forwarded` plus related forwarded aliases before proxying upstream. For configured trusted proxy peers, AlturaProt preserves the existing XFF chain, appends the immediate peer proxy, sets `X-Real-IP` to the resolved client identity, and still canonicalizes host/proto metadata. Sanitized requests increment `altura_http_forwarded_sanitized`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16178.62 RPS | `204: 48629` | 0 | 18.449 ms |
| admin health | 18003.77 RPS | `200: 54105` | 0 | 15.551 ms |
| raw TCP persistent echo | 18978.68 msg/s | `56980` echoed messages | 0 | 3.091 ms |

Forwarded-header probes against an upstream `/headers` echo endpoint:

| Probe | Origin-visible result |
| --- | --- |
| direct untrusted client with spoofed forwarded headers | `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `X-Forwarded-Host: good.local`, `X-Forwarded-Proto: http`, no `Forwarded` |
| trusted proxy peer with `X-Forwarded-For: 203.0.113.200` | `X-Forwarded-For: 203.0.113.200, 127.0.0.1`, `X-Real-IP: 203.0.113.200`, `X-Forwarded-Host: good.local`, `X-Forwarded-Proto: http`, no `Forwarded` |

Both dedicated local probes increased `altura_http_forwarded_sanitized` by 1.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 93.04% and `smart-api-mix` at 97.75%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11400.18 RPS | `204: 34327` | 0 | 30.258 ms |
| admin health on `core` | 11386.16 RPS | `200: 34286` | 0 | 30.575 ms |
| raw TCP persistent echo on `core` | 25718.73 msg/s | `77243` echoed messages | 0 | 2.510 ms |

Core forwarded-header probes matched local behavior. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.52%, `slow-xff-polymorphic` at 95.90%, `smart-api-mix` at 96.21%, and `legit-interleave-xff` at 98.58%.

## 2026-06-21 Initial Framing Precheck Snapshot

Artifacts:

- `benchmark_results/local_bench_initial_framing_precheck_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_initial_framing_precheck.json`
- `benchmark_results/local_bench_core_initial_framing_precheck_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_initial_framing_precheck.json`

This snapshot adds a raw HTTP/1 header precheck before Hyper parses the first request on each accepted connection. It preserves the bytes it reads and passes approved streams into Hyper unchanged, but rejects connection-opening request smuggling ambiguity before parser normalization can hide it from the app-level guard. Rejections return HTTP `400`, close the connection, and increment `altura_http_framing_rejected`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 16063.16 RPS | `204: 48275` | 0 | 18.675 ms |
| admin health | 18177.07 RPS | `200: 54625` | 0 | 15.350 ms |
| raw TCP persistent echo | 18984.40 msg/s | `56999` echoed messages | 0 | 3.108 ms |

Initial framing probes:

| Probe | Result |
| --- | --- |
| single `Content-Length: 0` | `200` |
| valid `Transfer-Encoding: chunked` | `200` |
| duplicate identical `Content-Length: 0` lines | `400` |
| conflicting `Content-Length: 0` and `Content-Length: 1` | `400` |
| comma-list `Content-Length: 0, 0` | `400` |
| invalid `Content-Length: nope` | `400` |
| `Transfer-Encoding: chunked` plus `Content-Length: 0` | `400` |
| duplicate `Transfer-Encoding: chunked` lines | `400` |
| unsupported `Transfer-Encoding: gzip` | `400` |

The local dedicated framing probe increased `altura_http_framing_rejected` by 7. This closes the earlier measured gap where duplicate-identical `Content-Length` and `Transfer-Encoding` plus `Content-Length` were accepted or normalized before the application-level guard saw them on connection-opening requests.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 93.08% and `smart-api-mix` at 98.21%.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 11659.09 RPS | `204: 35099` | 0 | 30.967 ms |
| admin health on `core` | 11846.98 RPS | `200: 35677` | 0 | 29.309 ms |
| raw TCP persistent echo on `core` | 24806.81 msg/s | `74520` echoed messages | 0 | 2.607 ms |

Core framing probes matched local behavior: valid single `Content-Length` and valid chunked requests reached upstream, while all seven malformed raw framing probes returned `400` and `altura_http_framing_rejected` increased by 7. Core deterministic all-scenario defense regression also passed all 18 scenarios. Benign probes were allowed at 100% in every scenario; the lowest passing attacker-block rates were `dictionary-slug-xff` at 92.43%, `slow-xff-polymorphic` at 95.90%, `smart-api-mix` at 96.20%, and `legit-interleave-xff` at 98.07%.

## 2026-06-21 Downstream Keep-Alive Disabled Snapshot

Artifacts:

- `benchmark_results/local_bench_downstream_keepalive_disabled_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_downstream_keepalive_disabled.json`
- `benchmark_results/local_bench_core_downstream_keepalive_disabled_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_core_20260621_downstream_keepalive_disabled.json`

This snapshot makes downstream HTTP/1 keep-alive opt-in with `http.downstream_keep_alive`, defaulting to `false`. The raw initial framing precheck therefore applies to every default client request because the proxy closes the downstream connection after the first response. Operators can still opt into persistent downstream connections, but the safer internet-facing default removes the measured keep-alive follow-up request smuggling/desync surface.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8738.83 RPS | `204: 26252` | 0 | 13.287 ms |
| admin health | 9248.50 RPS | `200: 27785` | 0 | 12.189 ms |
| raw TCP persistent echo | 18600.08 msg/s | `55881` echoed messages | 0 | 6.426 ms |

Downstream keep-alive probe:

| Probe | Result |
| --- | --- |
| first request with `Connection: keep-alive` | `204`, response header `Connection: close` |
| second request on same socket | connection closed before second response |
| second request framing metric | `altura_http_framing_rejected` delta `0` because the second request was never parsed |

Initial framing probes still matched the previous snapshot: valid single `Content-Length` and valid chunked requests reached upstream, while all seven malformed raw framing probes returned `400` and `altura_http_framing_rejected` increased by 7.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 2 --workers 32 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets. Benign probes were allowed at 100% in every scenario, attacker-block rates were 100% in every scenario, and replay/bypass errors were 0.

Core server validation:

```bash
python3 tools/run_local_bench.py --duration 3 --workers 64 --tcp-workers 64
python3 tools/run_defense_bench.py --no-codex --preset all --duration 2 --workers 32 --json-only
```

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6481.62 RPS | `204: 19491` | 0 | 17.539 ms |
| admin health on `core` | 6499.00 RPS | `200: 19547` | 0 | 17.568 ms |
| raw TCP persistent echo on `core` | 22160.09 msg/s | `66644` echoed messages | 0 | 5.845 ms |

Core keep-alive and framing probes matched local behavior: the first response carried `Connection: close`, the second same-socket request received no response, all seven malformed raw framing probes returned `400`, and `altura_http_framing_rejected` increased by 7 for the dedicated framing probe.

The Core all-scenario defense evidence was run in smaller scenario chunks and aggregated in `defense_bench_all_deterministic_core_20260621_downstream_keepalive_disabled.json` because a single long Core loopback process became noisy under forced downstream-close churn. The aggregate covers all 18 scenarios; every scenario met target with 100% benign allow, 100% attacker block, and 0 replay/bypass errors.

## 2026-06-21 Host Edge Profile Validation Snapshot

This snapshot strengthens the host-edge template for small-to-medium host-visible L3/L4 floods while keeping provider/CDN/scrubbing as the required control for true link saturation.

Changes validated:

- `ops/nftables/altura-prot-edge.nft` now drops impossible protected-port TCP flag combinations before conntrack.
- Protected-port SYN floods get a raw-prerouting pre-conntrack backstop: per-source meters plus a global SYN rate limiter.
- Input filtering still drops invalid conntrack state, and now also drops non-SYN new protected-port packets after conntrack.
- Protected ports get a coarse per-source connection-count cap before traffic reaches AlturaProt's request-aware controls.
- `ops/sysctl.d/99-altura-prot-ddos.conf` now includes `net.core.netdev_max_backlog` and `net.netfilter.nf_conntrack_tcp_timeout_syn_recv` alongside SYN cookies, SYN backlog, accept backlog, FIN timeout, and conntrack capacity.
- `tools/validate_edge_templates.py` validates nft syntax, sysctl key availability on Linux, and `somaxconn` versus configured listener backlogs without installing policy.

Validation commands:

```bash
python3 -m py_compile tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
ssh core 'cd /tmp/altura-edge-validate && python3 validate_edge_templates.py --config example.json --nft altura-prot-edge.nft --sysctl 99-altura-prot-ddos.conf && nft -c -f altura-prot-edge.nft'
cargo test
```

Results:

| Check | Result |
| --- | --- |
| local validator | passed; nft/sysctl kernel checks skipped on non-Linux |
| Core validator | `edge templates validated` |
| Core nft dry-run | passed with nftables v1.1.6 |
| Rust tests | 76 passed |

## 2026-06-21 Hot-Path Log Suppression Snapshot

Artifact:

- `benchmark_results/local_bench_log_suppression_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_log_suppression.json`
- `benchmark_results/defense_bench_dictionary_slug_log_suppression_20260621.json`

This snapshot rate-limits attacker-controllable stderr logs in HTTP/TCP timeout, reject, upstream-error, and telemetry write-failure paths. Lifecycle logs still emit immediately, but bursty hot-path failures now emit at most one line per site per second and report the number of suppressed similar messages on the next emitted line.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8821.43 RPS | `204: 17684` | 0 | 12.807 ms |
| admin health | 8723.84 RPS | `200: 17479` | 0 | 12.914 ms |
| raw TCP persistent echo | 18817.12 msg/s | `37658` echoed messages | 0 | 1.513 ms |

Log suppression probe:

| Probe | Result |
| --- | --- |
| slow-header timeout sockets | 48 opened, then 1 flush timeout |
| timeout log lines | 2 |
| suppression marker | `suppressed 47 similar messages` |
| bounded stderr check | passed |

The defense benchmark harness now uses deadline-bound worker joins and reports `hung_workers` in every phase summary. This prevents a wedged local `http.client` worker from blocking the whole regression indefinitely; hung workers are counted as errors so a scenario cannot silently pass.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 32 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets when using observed-learning results for the advanced scenarios that require them. Benign probes were allowed at 100% in every scenario. The lowest passing attacker-block rates were `dictionary-slug-xff` at 90.55%, `slow-xff-polymorphic` at 92.93%, `smart-api-mix` at 93.70%, `legit-interleave-xff` at 97.52%, and `v2-polymorphic-xff` at 99.37%. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0.

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py
python3 -m py_compile tools/run_defense_bench.py
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 16
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 32 --analyzer-wait 10 --json-only
```

## 2026-06-21 Adaptive Event-Log Flush Snapshot

Artifacts:

- `benchmark_results/local_bench_event_log_flush_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_event_log_flush.json`
- `benchmark_results/local_bench_core_event_log_flush_20260621.json`
- `benchmark_results/defense_bench_core_event_log_flush_dictionary_2s.json`

This snapshot bounds adaptive attack-event flush pressure. `adaptive.event_log_flush_interval_ms` defaults to `100`; the first event still flushes immediately so CodexSDGate can see a new attack quickly, while high-rate bursts are buffered and flushed at most once per positive interval. Application config now rejects `0` for this field so a typo cannot force flush-every-event disk pressure during a flood.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9443.63 RPS | `204: 18922` | 0 | 11.958 ms |
| admin health | 9498.38 RPS | `200: 19036` | 0 | 11.904 ms |
| raw TCP persistent echo | 19078.51 msg/s | `38181` echoed messages | 0 | 1.474 ms |

Event-log flush probe with `event_log_flush_interval_ms: 1000`:

| Probe | Result |
| --- | --- |
| unique adaptive-event requests | 10 requests, all `204` |
| first event visible lines | `1` |
| immediate burst visible lines | `1` |
| post-interval visible lines | `10` |
| first-event immediate flush | passed |
| burst flush batching | passed |
| interval flush | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 32 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets with the default 100 ms event-log flush interval. Benign probes were allowed at 100% in every scenario. The lowest passing attacker-block rates were `dictionary-slug-xff` at 90.37%, `slow-xff-polymorphic` at 92.76%, `smart-api-mix` at 94.24%, `legit-interleave-xff` at 97.45%, and `catalog-mimic-xff` at 98.21%. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6673.06 RPS | `204: 13391` | 0 | 17.060 ms |
| admin health on `core` | 6643.34 RPS | `200: 13332` | 0 | 17.087 ms |
| raw TCP persistent echo on `core` | 25927.89 msg/s | `51952` echoed messages | 0 | 2.470 ms |

Core event-log flush probe matched local behavior: 10 adaptive-event requests all returned `204`, the first event was visible immediately, the immediate burst remained at 1 visible line, and the post-interval count reached 10 lines. The narrow `dictionary-slug-xff` Core regression was also rerun alone at 2 seconds and reached 100% attacker block, 100% benign allow, 0 replay/bypass errors, and 0 hung workers. The direct-upstream baseline in that Core run reported 7 client-side loopback errors, so it is not used as a proxy/analyzer clean-all-phases claim.

Validation commands:

```bash
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 16
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 32 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-event-log-flush && cargo test && cargo build --release'
ssh core 'cd /tmp/altura-prot-event-log-flush && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
ssh core 'cd /tmp/altura-prot-event-log-flush && python3 tools/run_defense_bench.py --no-codex --scenarios dictionary-slug-xff --duration 2 --workers 32 --analyzer-wait 10 --json-only'
```

## 2026-06-21 Adaptive Event-Log Rotation Snapshot

Artifacts:

- `benchmark_results/local_bench_event_log_rotation_20260621.json`
- `benchmark_results/defense_bench_all_deterministic_20260621_event_log_rotation_all.json`
- `benchmark_results/local_bench_core_event_log_rotation_20260621.json`

This snapshot bounds adaptive attack-event disk growth. `adaptive.event_log_max_bytes` defaults to `67108864` bytes and `adaptive.event_log_backup_count` defaults to `2`. Application config now rejects `0` for both fields so attack telemetry cannot disable rotation or discard all rotated evidence by typo. CodexSDGate reads numbered backups before the active JSONL file, so recent rotated evidence remains available to the analyzer while disk use stays bounded by the active file plus configured backups, allowing one current event to exceed the cap if a single JSONL event is larger than the configured cap.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9439.26 RPS | `204: 18896` | 0 | 5.930 ms |
| admin health | 9471.66 RPS | `200: 18961` | 0 | 5.887 ms |
| raw TCP persistent echo | 19332.49 msg/s | `38688` echoed messages | 0 | 1.465 ms |

Event-log rotation probe with `event_log_max_bytes: 1800`, `event_log_backup_count: 1`, and short flush interval:

| Probe | Result |
| --- | --- |
| unique adaptive-event requests | 24 requests, all `204` |
| active event log | present, 1548 bytes, 3 valid JSONL lines |
| first backup | present, 1548 bytes, 3 valid JSONL lines |
| invalid JSONL lines | 0 |
| total retained event-log bytes | 3096 |
| bounded total bytes check | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 2 --workers 32 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets on the observed-learning layer with event-log rotation enabled in the current binary. Strict-only learning passed 15 of 18 scenarios; the high-cardinality XFF cases still rely on observed/path-shape learning for full coverage. Across 145 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6628.12 RPS | `204: 13298` | 0 | 17.265 ms |
| admin health on `core` | 6732.65 RPS | `200: 13510` | 0 | 16.975 ms |
| raw TCP persistent echo on `core` | 26127.09 msg/s | `52336` echoed messages | 0 | 2.459 ms |

Core event-log rotation matched local behavior: 24 adaptive-event requests all returned `204`, the active log and first backup were both present, each retained 3 valid JSONL lines at 1548 bytes, and total retained bytes were bounded at 3096 bytes. No local or Core benchmark/proxy/analyzer processes remained after validation.

Validation commands:

```bash
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/test_ai_tools.py
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 32 --tcp-workers 16
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-event-log-rotation && cargo test && cargo build --release'
ssh core 'cd /tmp/altura-prot-event-log-rotation && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 HTTP Connection-Rate Snapshot

Artifacts:

- `benchmark_results/local_bench_http_connection_rate_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_http_connection_rate.json`
- `benchmark_results/local_bench_core_http_connection_rate_20260622.json`

This snapshot adds accept-time HTTP connection-open rate limiting. Active connection caps stop slow holders; request-rate caps stop parsed request floods; the new `http.limits.per_ip_connects_per_second`, `per_ip_connect_burst`, `global_connects_per_second`, and `global_connect_burst` caps stop short-lived churn before header parsing and per-connection task work. Defaults are high safety rails (`20000` per-peer and global opens per second, `40000` bursts) because deployments behind a reverse proxy/CDN may see many clients through one peer IP; lower them at the edge after measuring real traffic.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9277.48 RPS | `204: 18576` | 0 | 6.046 ms |
| admin health | 9126.22 RPS | `200: 18272` | 0 | 6.315 ms |
| raw TCP persistent echo | 19140.22 msg/s | `38303` echoed messages | 0 | 1.477 ms |

HTTP connection-rate probe with `per_ip_connects_per_second: 1.0` and `per_ip_connect_burst: 4`:

| Probe | Result |
| --- | --- |
| measured request statuses | `[204, 204, null, null, null, null, null, null]` |
| accepted requests | 2 |
| rejected connection attempts | 6 |
| `altura_http_connections_rejected` delta | 6 |
| connection-rate limiting observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets on the observed-learning layer with HTTP connection-open rate limiting in the current binary. Strict-only learning passed 15 of 18 scenarios; the high-cardinality XFF/path-shape cases still rely on observed/path-shape learning for full coverage. Across 145 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0. The lowest observed-learning attacker block rate was `hex-slug-xff` at 99.99%; all other observed-learning scenarios were 100%.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6673.91 RPS | `204: 13394` | 0 | 17.096 ms |
| admin health on `core` | 6459.32 RPS | `200: 12962` | 0 | 17.673 ms |
| raw TCP persistent echo on `core` | 23625.33 msg/s | `47345` echoed messages | 0 | 2.726 ms |

Core connection-rate probe matched local behavior: two measured requests returned `204`, six connection attempts were rejected, and `altura_http_connections_rejected` increased by 6. No local or Core benchmark/proxy/analyzer processes remained after validation.

Validation commands:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 32 --tcp-workers 16
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-http-connection-rate && cargo test && cargo build --release'
ssh core 'cd /tmp/altura-prot-http-connection-rate && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Body Minimum-Rate Snapshot

Artifacts:

- `benchmark_results/local_bench_body_min_rate_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_body_min_rate.json`
- `benchmark_results/local_bench_core_body_min_rate_20260622.json`
- `benchmark_results/local_bench_body_min_rate_bank_guard_20260623.json`

This snapshot adds request and upstream response body minimum data-rate guards. Idle body timeouts catch fully stalled streams; the new `request_body_min_rate_bytes_per_second`, `request_body_min_rate_grace_ms`, `upstream_body_min_rate_bytes_per_second`, and `upstream_body_min_rate_grace_ms` settings close slow-drip streams that keep sending just often enough to avoid an idle timeout. Defaults are conservative (`512` B/s after `10000` ms) and should be tuned for expected upload/download profiles.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9132.86 RPS | `204: 18289` | 0 | 6.106 ms |
| admin health | 8662.92 RPS | `200: 17345` | 0 | 6.704 ms |
| raw TCP persistent echo | 18894.62 msg/s | `37812` echoed messages | 0 | 1.496 ms |

Body minimum-rate probe with `1000` B/s and `10` ms grace:

| Probe | Result |
| --- | --- |
| slow-drip request body | `408` after 0.085 s |
| `altura_http_body_too_slow` delta | `1` |
| request minimum-rate rejection | passed |
| banked pre-grace request body | `408` after 0.088 s after 512 initial bytes |
| `altura_http_body_too_slow` banked delta | `1` |
| banked request minimum-rate rejection | passed |
| slow-drip upstream response | client saw `200` then connection closed after 1 body byte |
| `altura_http_upstream_body_too_slow` delta | `1` |
| upstream minimum-rate rejection | passed |
| existing idle slow-body probe | `408` after 0.204 s |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets using the observed-learning path where present and strict learning for the simple strict-covered scenarios. Strict-only learning passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape learning for full coverage. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6556.30 RPS | `204: 13162` | 0 | 17.379 ms |
| admin health on `core` | 6635.99 RPS | `200: 13316` | 0 | 17.187 ms |
| raw TCP persistent echo on `core` | 23768.33 msg/s | `47618` echoed messages | 0 | 2.725 ms |

Core body minimum-rate probe matched local behavior: the slow-drip request body returned `408`, the upstream slow-drip response was cut after 1 body byte, and both `altura_http_body_too_slow` and `altura_http_upstream_body_too_slow` increased by 1.

2026-06-23 local follow-up: the body minimum-rate probe now also sends 512 request-body bytes inside the 10 ms grace window, waits until after grace, then sends one post-grace byte. The current recent-window guard returned `408` with `Cache-Control: no-store`, `Connection: close`, `request_banked_min_rate_rejected: true`, and `http_body_banked_too_slow_delta: 1`, proving pre-grace bytes do not bank lifetime-average credit.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 32 --tcp-workers 16
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-body-min-rate && cargo test && cargo build --release'
ssh core 'cd /tmp/altura-prot-body-min-rate && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Downstream Write Timeout Snapshot

Artifacts:

- `benchmark_results/local_bench_downstream_write_timeout_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_downstream_write_timeout.json`
- `benchmark_results/local_bench_core_downstream_write_timeout_20260622.json`

This snapshot adds `http.downstream_write_timeout_ms`, a timeout around writes to the downstream client socket. Body guards protect the proxy from slow request bodies and slow upstream response bodies; this guard covers the opposite direction, where a client accepts response headers and then stops reading, applying backpressure while an upstream response stream and in-flight permit stay held.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9230.89 RPS | `204: 18482` | 0 | 6.209 ms |
| admin health | 9043.81 RPS | `200: 18108` | 0 | 6.524 ms |
| raw TCP persistent echo | 18855.58 msg/s | `37736` echoed messages | 0 | 1.502 ms |

Downstream slow-reader probe with `downstream_write_timeout_ms: 20`:

| Probe | Result |
| --- | --- |
| slow reader request | client saw `200` and only the first 4096 bytes before the server-side timeout path |
| first response body bytes read | `3995` |
| `altura_http_downstream_write_timeouts` delta | `1` |
| downstream write timeout observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets using the observed-learning path where present and strict learning for the simple strict-covered scenarios. Strict-only learning passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape learning for full coverage. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0. The lowest effective attacker-block rates were `mixed-user-agent` at 99.05%, `hex-slug-xff` at 99.99%, and 100% for the remaining listed scenarios.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6659.56 RPS | `204: 13367` | 0 | 17.001 ms |
| admin health on `core` | 6647.47 RPS | `200: 13345` | 0 | 17.102 ms |
| raw TCP persistent echo on `core` | 23644.39 msg/s | `47380` echoed messages | 0 | 2.699 ms |

Core downstream slow-reader behavior matched local behavior: the slow reader saw `200` and 4096 initial bytes, `altura_http_downstream_write_timeouts` increased by 1, and no local or Core benchmark/proxy/analyzer processes remained after validation.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 32 --tcp-workers 16
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-downstream-write-timeout && cargo test && cargo build --release'
ssh core 'cd /tmp/altura-prot-downstream-write-timeout && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Upstream Response Header Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_header_guard_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_upstream_header_guard.json`
- `benchmark_results/local_bench_core_upstream_header_guard_20260622.json`

This snapshot makes upstream response header limits explicit with `http.upstream_max_header_bytes` and `http.upstream_max_headers`. The proxy already bounded upstream response header wait time and body behavior; these caps prevent oversized or too-many origin response headers from relying on Hyper's default connection buffer. Oversized upstream header parse failures return `502` and increment both `altura_http_upstream_errors` and `altura_http_upstream_header_rejected`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8292.27 RPS | `204: 16602` | 0 | 7.321 ms |
| admin health | 8135.87 RPS | `200: 16288` | 0 | 7.402 ms |
| raw TCP persistent echo | 18654.22 msg/s | `37331` echoed messages | 0 | 1.517 ms |

Upstream response-header probe with `upstream_max_header_bytes: 8192` and `upstream_max_headers: 8`:

| Probe | Result |
| --- | --- |
| huge upstream response header | `502` |
| too many upstream response headers | `502` |
| `altura_http_upstream_header_rejected` delta | `2` |
| `altura_http_upstream_errors` delta | `2` |
| upstream header guard observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets using the observed-learning path where present and strict learning for the simple strict-covered scenarios. Strict-only learning passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape learning for full coverage. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0. The lowest effective attacker-block rate was `hex-slug-xff` at 99.99%; the remaining listed effective scenarios were 100%.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6623.69 RPS | `204: 13295` | 0 | 17.238 ms |
| admin health on `core` | 6708.44 RPS | `200: 13459` | 0 | 17.005 ms |
| raw TCP persistent echo on `core` | 25068.07 msg/s | `50226` echoed messages | 0 | 2.563 ms |

Core upstream response-header behavior matched local behavior: the huge-header and too-many-header upstream responses both returned `502`, `altura_http_upstream_header_rejected` increased by 2, and no local or Core benchmark/proxy/analyzer processes remained after validation.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 32 --tcp-workers 16
python3 tools/run_defense_bench.py --preset all --no-codex --duration 2 --workers 32 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-upstream-header-guard && cargo test && cargo build --release'
ssh core 'cd /tmp/altura-prot-upstream-header-guard && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 TCP Minimum-Rate Snapshot

Artifacts:

- `benchmark_results/local_bench_tcp_min_rate_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_tcp_min_rate.json`
- `benchmark_results/local_bench_core_tcp_min_rate_20260622.json`

This snapshot adds default-enabled raw TCP minimum data-rate guards: `tcp[].downstream_min_rate_bytes_per_second`, `tcp[].upstream_min_rate_bytes_per_second`, and `tcp[].min_rate_grace_ms`. TCP services default to `512` B/s in both directions after the grace window, while `0` remains the explicit opt-out for quiet protocols that have been measured and are covered by idle timeout plus max connection duration.

This 2026-06-22 artifact is historical. It proved eventual slow-drip rejection,
but its local probe still echoed the second post-grace byte. The
`2026-06-23 Local Guardrail CI Gate` snapshot supersedes this with byte-level
assertions that both explicit and default TCP min-rate probes close before the
second and third post-grace bytes can be echoed.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8801.07 RPS | `204: 8820` | 0 | 6.369 ms |
| admin health | 9181.38 RPS | `200: 9218` | 0 | 6.130 ms |
| raw TCP persistent echo | 17593.44 msg/s | `17613` echoed messages | 0 | 1.633 ms |

TCP slow-drip probe with `downstream_min_rate_bytes_per_second: 1000`, `upstream_min_rate_bytes_per_second: 0`, and `min_rate_grace_ms: 10`:

| Probe | Result |
| --- | --- |
| first byte echo | 1 byte |
| second byte echo | 1 byte |
| third slow-drip byte | connection closed/reset before echo |
| `altura_tcp_downstream_too_slow` delta | `1` |
| `altura_tcp_upstream_too_slow` delta | `0` |
| TCP min-rate guard observed | passed |

The current benchmark also runs a second TCP listener that omits both min-rate
byte floors while keeping a short benchmark grace window. That listener inherits
the default `512` B/s downstream and upstream floors and rejects the same
slow-drip pattern, proving the guard is secure by default instead of
example-only.

| Default-floor probe | Result |
| --- | --- |
| inherited downstream floor | `512` B/s |
| inherited upstream floor | `512` B/s |
| first byte echo | 1 byte |
| second byte echo | 1 byte |
| third slow-drip byte | connection closed/reset before echo |
| default `altura_tcp_downstream_too_slow` delta | `1` |
| default TCP min-rate guard observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets using the observed-learning path where present and strict learning for the simple strict-covered scenarios. Strict-only learning passed 14 of 18 scenarios; `catalog-mimic-xff`, `dictionary-slug-xff`, `legit-interleave-xff`, and `xff-rotating` rely on observed/path-shape learning for full coverage in this run. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0. The lowest effective attacker-block rates were `dictionary-slug-xff` at 90.32%, `smart-api-mix` at 93.99%, and `slow-xff-polymorphic` at 94.96%.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6396.34 RPS | `204: 12839` | 0 | 17.713 ms |
| admin health on `core` | 6442.31 RPS | `200: 12932` | 0 | 17.824 ms |
| raw TCP persistent echo on `core` | 24330.11 msg/s | `48739` echoed messages | 0 | 2.664 ms |

Core TCP min-rate behavior matched the historical local eventual-rejection behavior: the slow drip closed after the post-grace probe, `altura_tcp_downstream_too_slow` increased by 1, and no Core benchmark/proxy/analyzer processes remained after validation. The 2026-06-23 CI gate is the current proof for closing before the second post-grace byte is echoed.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
PYTHONPATH=tools python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 1 --workers 32 --tcp-workers 16 > benchmark_results/local_bench_tcp_min_rate_20260622.json
jq -e '.guardrails.tcp_min_rate.tcp_min_rate_rejected == true and .guardrails.tcp_min_rate.default_tcp_min_rate_rejected == true and .guardrails.tcp_min_rate.default_configured_downstream_min_rate_bytes_per_second == 512 and .guardrails.tcp_min_rate.default_configured_upstream_min_rate_bytes_per_second == 512' benchmark_results/local_bench_tcp_min_rate_20260622.json
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-tcp-min-rate-20260622 && cargo test && cargo build --release'
ssh core 'cd /tmp/altura-prot-tcp-min-rate-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 HTTP Trailer Policy Snapshot

Artifacts:

- `benchmark_results/local_bench_trailer_policy_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_trailer_policy.json`
- `benchmark_results/local_bench_core_trailer_policy_20260622.json`

This snapshot adds an explicit HTTP trailer policy. Request trailers and upstream response trailers are stripped by default. Services that require trailers can opt in to forwarding with bounded caps through `forward_request_trailers`, `max_trailer_bytes`, `max_trailers`, `forward_response_trailers`, `upstream_max_trailer_bytes`, and `upstream_max_trailers`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9077.79 RPS | `204: 18219` | 0 | 12.695 ms |
| admin health | 8775.21 RPS | `200: 17585` | 0 | 13.572 ms |
| raw TCP persistent echo | 19385.09 msg/s | `38793` echoed messages | 0 | 1.453 ms |

Upstream trailer stripping probe with `forward_response_trailers: false`, `upstream_max_trailer_bytes: 64`, and `upstream_max_trailers: 4`:

| Probe | Result |
| --- | --- |
| response status | `200` |
| body observed | passed |
| actual trailing `X-Origin-Trailer` forwarded | no |
| `altura_http_upstream_trailers_dropped` delta | `1` |
| `altura_http_upstream_trailers_rejected` delta | `0` |
| upstream trailer policy observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets using the observed-learning path where present and strict learning for the simple strict-covered scenarios. Strict-only learning passed 14 of 18 scenarios; `catalog-mimic-xff`, `dictionary-slug-xff`, `legit-interleave-xff`, and `xff-rotating` rely on observed/path-shape learning for full coverage in this run. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0. The lowest effective attacker-block rates were `dictionary-slug-xff` at 90.29%, `smart-api-mix` at 94.05%, and `slow-xff-polymorphic` at 94.89%.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6669.12 RPS | `204: 13386` | 0 | 17.022 ms |
| admin health on `core` | 6598.05 RPS | `200: 13236` | 0 | 17.223 ms |
| raw TCP persistent echo on `core` | 24051.66 msg/s | `48197` echoed messages | 0 | 2.676 ms |

Core trailer behavior matched local behavior: the response body was preserved, the actual upstream `X-Origin-Trailer` trailer was stripped, `altura_http_upstream_trailers_dropped` increased by 1, and `altura_http_upstream_trailers_rejected` stayed at 0.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-trailer-policy-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-trailer-policy-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-trailer-policy-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Request-Trailer 431 Close Snapshot

Artifacts:

- `benchmark_results/local_bench_request_trailer_431_close_20260622.json`
- `benchmark_results/local_bench_core_request_trailer_431_close_20260622.json`

This snapshot hardens the request-trailer rejection path. When request trailer forwarding is explicitly enabled but the trailer section exceeds `max_trailer_bytes` or `max_trailers`, AlturaProt now returns a generated `431` with `Cache-Control: no-store` and `Connection: close`. The close behavior matches the rest of the body/framing rejection surface so an opt-in keep-alive client cannot reuse a connection after an oversized trailer section has been rejected.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8936.15 RPS | `204: 26878` | 0 | 25.334 ms |
| admin health | 9229.00 RPS | `200: 27763` | 0 | 24.791 ms |
| raw TCP persistent echo | 19495.38 msg/s | `58530` echoed messages | 0 | 3.035 ms |

Request-trailer guardrail with `allow_chunked_request_bodies: true`, `forward_request_trailers: true`, `max_trailer_bytes: 8`, `max_trailers: 1`, and opt-in downstream keep-alive:

| Probe | Result |
| --- | --- |
| oversized request trailer status | `431` |
| response body | `request trailers too large` |
| `Cache-Control` | `no-store` |
| `Connection` | `close` |
| follow-up request on same socket | no response |
| `altura_http_request_trailers_rejected` delta | `1` |

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6599.73 RPS | `204: 19885` | 0 | 34.492 ms |
| admin health on `core` | 6658.55 RPS | `200: 20064` | 0 | 33.478 ms |
| raw TCP persistent echo on `core` | 24601.64 msg/s | `73899` echoed messages | 0 | 2.626 ms |

Core request-trailer behavior matched local behavior: the oversized trailer probe returned `431`, `Cache-Control: no-store`, `Connection: close`, no follow-up response on the same socket, and `altura_http_request_trailers_rejected` increased by 1.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test request_metadata_too_large_response_is_not_stored_and_closes -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
jq -e '.guardrails.request_trailer_policy.oversized_request_trailer_rejected == true and .guardrails.request_trailer_policy.generated_431_not_stored == true and .guardrails.request_trailer_policy.generated_431_closes_connection == true and .guardrails.request_trailer_policy.connection_closed_before_followup == true and .guardrails.request_trailer_policy.http_request_trailers_rejected_delta >= 1' benchmark_results/local_bench_request_trailer_431_close_20260622.json
ssh core 'cd /tmp/altura-prot-request-trailer-431-close-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-request-trailer-431-close-20260622 && cargo test request_metadata_too_large_response_is_not_stored_and_closes -- --nocapture'
ssh core 'cd /tmp/altura-prot-request-trailer-431-close-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-request-trailer-431-close-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-request-trailer-431-close-20260622 && python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 3 --workers 128 --tcp-workers 32'
ssh core 'cd /tmp/altura-prot-request-trailer-431-close-20260622 && jq -e '"'"'.guardrails.request_trailer_policy.oversized_request_trailer_rejected == true and .guardrails.request_trailer_policy.generated_431_not_stored == true and .guardrails.request_trailer_policy.generated_431_closes_connection == true and .guardrails.request_trailer_policy.connection_closed_before_followup == true and .guardrails.request_trailer_policy.http_request_trailers_rejected_delta >= 1'"'"' benchmark_results/local_bench_core_request_trailer_431_close_20260622.json'
```

Core note: local Clippy passed with `-D warnings`; Core validation used test/build/benchmark because `cargo clippy` is not installed on the `core` toolchain.

## 2026-06-22 Connection Request-Limit Headers Snapshot

Artifacts:

- `benchmark_results/local_bench_connection_request_limit_headers_20260622.json`
- `benchmark_results/local_bench_core_connection_request_limit_headers_20260622.json`

This snapshot makes the per-connection HTTP request cap use the same generated rate-limit response contract as the other deterministic rate limiters. When `max_requests_per_connection` is exceeded, AlturaProt now returns `429` with `Retry-After: 1`, `Cache-Control: no-store`, and `Connection: close`, while still incrementing `altura_http_request_limited`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8940.93 RPS | `204: 26893` | 0 | 25.307 ms |
| admin health | 9209.94 RPS | `200: 27702` | 0 | 24.900 ms |
| raw TCP persistent echo | 19442.71 msg/s | `58374` echoed messages | 0 | 3.027 ms |

Connection request-limit guardrail with `downstream_keep_alive: true` and `max_requests_per_connection: 2`:

| Probe | Result |
| --- | --- |
| first request on socket | `204` |
| second request on socket | `204` |
| third request on socket | `429` |
| `Retry-After` | `1` |
| `Cache-Control` | `no-store` |
| `Connection` | `close` |
| fourth request on same socket | no response |
| `altura_http_request_limited` delta | `1` |

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6626.36 RPS | `204: 19968` | 0 | 34.352 ms |
| admin health on `core` | 6629.55 RPS | `200: 19981` | 0 | 34.033 ms |
| raw TCP persistent echo on `core` | 25176.55 msg/s | `75618` echoed messages | 0 | 2.573 ms |

Core connection request-limit behavior matched local behavior: the third request on one keep-alive socket returned `429`, `Retry-After: 1`, `Cache-Control: no-store`, `Connection: close`, no fourth response was sent on the same socket, and `altura_http_request_limited` increased by 1.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test connection_request_limit_response_is_retryable_not_stored_and_closes -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
jq -e '.guardrails.connection_request_limit.connection_request_limit_observed == true and .guardrails.connection_request_limit.third_request_limited == true and .guardrails.connection_request_limit.retry_after_header_matches == true and .guardrails.connection_request_limit.cache_control_header_matches == true and .guardrails.connection_request_limit.connection_close_header_matches == true and .guardrails.connection_request_limit.http_request_limited_delta == 1' benchmark_results/local_bench_connection_request_limit_headers_20260622.json
ssh core 'cd /tmp/altura-prot-connection-request-limit-headers-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-connection-request-limit-headers-20260622 && cargo test connection_request_limit_response_is_retryable_not_stored_and_closes -- --nocapture'
ssh core 'cd /tmp/altura-prot-connection-request-limit-headers-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-connection-request-limit-headers-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-connection-request-limit-headers-20260622 && python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 3 --workers 128 --tcp-workers 32'
ssh core 'cd /tmp/altura-prot-connection-request-limit-headers-20260622 && jq -e '"'"'.guardrails.connection_request_limit.connection_request_limit_observed == true and .guardrails.connection_request_limit.third_request_limited == true and .guardrails.connection_request_limit.retry_after_header_matches == true and .guardrails.connection_request_limit.cache_control_header_matches == true and .guardrails.connection_request_limit.connection_close_header_matches == true and .guardrails.connection_request_limit.http_request_limited_delta == 1'"'"' benchmark_results/local_bench_core_connection_request_limit_headers_20260622.json'
```

Core note: local Clippy passed with `-D warnings`; Core validation used test/build/benchmark because `cargo clippy` is not installed on the `core` toolchain.

## 2026-06-22 TCP Global Connection-Rate Snapshot

Artifacts:

- `benchmark_results/local_bench_tcp_global_rate_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_tcp_global_rate.json`
- `benchmark_results/local_bench_core_tcp_global_rate_20260622.json`

This snapshot adds a service-wide raw TCP connection-open token bucket: `tcp[].limits.global_connects_per_second` and `tcp[].limits.global_connect_burst`. Per-IP TCP open-rate limits still protect fairness for a single peer, and global/per-IP concurrent caps still protect active socket capacity. The new global open-rate bucket covers distributed connection churn where each source stays under its per-IP rate but the listener as a whole is being forced to accept, spawn, and connect upstream too quickly. Defaults are high backstops (`20000` opens/s and `40000` burst) so operators can lower them per raw TCP service after measuring normal traffic.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9271.28 RPS | `204: 18578` | 0 | 12.270 ms |
| admin health | 8894.30 RPS | `200: 17825` | 0 | 13.187 ms |
| raw TCP persistent echo | 19459.83 msg/s | `38965` echoed messages | 0 | 3.028 ms |

TCP global connection-rate probe with `global_connects_per_second: 1.0`, `global_connect_burst: 2`, and per-IP rate left effectively unlimited:

| Probe | Result |
| --- | --- |
| connection attempts | 8 |
| accepted echoes | 2 |
| rejected/reset attempts | 6 |
| `altura_tcp_rejected` delta | `6` |
| `altura_tcp_global_connect_rate_limited` delta | `6` |
| global connection-rate limiting observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets using the observed-learning path where present and strict learning for the simple strict-covered scenarios. Strict-only learning passed 14 of 18 scenarios; `catalog-mimic-xff`, `dictionary-slug-xff`, `legit-interleave-xff`, and `xff-rotating` rely on observed/path-shape learning for full coverage in this run. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0. The lowest effective attacker-block rates were `dictionary-slug-xff` at 90.31%, `smart-api-mix` at 94.13%, and `slow-xff-polymorphic` at 94.84%.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6700.82 RPS | `204: 13449` | 0 | 17.131 ms |
| admin health on `core` | 6442.90 RPS | `200: 12934` | 0 | 17.435 ms |
| raw TCP persistent echo on `core` | 22299.57 msg/s | `44688` echoed messages | 0 | 2.861 ms |

Core TCP global connection-rate behavior matched local behavior: 2 of 8 attempts were echoed, the remaining 6 were reset, `altura_tcp_rejected` increased by 6 inside the probe, and `altura_tcp_global_connect_rate_limited` increased by 6.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-tcp-global-rate-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-tcp-global-rate-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-tcp-global-rate-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Runtime NOFILE Preflight Snapshot

Artifacts:

- `benchmark_results/local_bench_runtime_nofile_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_runtime_nofile.json`
- `benchmark_results/local_bench_core_runtime_nofile_20260622.json`

This snapshot adds a startup file-descriptor preflight: `runtime.min_nofile`. On Unix-like systems the proxy reads `RLIMIT_NOFILE`, raises the soft limit to the configured floor when the inherited hard limit allows it, and fails startup if the final soft limit is still below the configured floor. This makes descriptor capacity explicit instead of silently relying on the shell or service manager that launched AlturaProt.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9103.79 RPS | `204: 18243` | 0 | 12.543 ms |
| admin health | 8866.03 RPS | `200: 17769` | 0 | 13.294 ms |
| raw TCP persistent echo | 19261.08 msg/s | `38562` echoed messages | 0 | 3.045 ms |

Runtime NOFILE probe with `runtime.min_nofile: 2048`:

| Probe | Result |
| --- | --- |
| child proxy health | `200` |
| runtime status line | `runtime nofile limit soft=1048575 hard=18446744073709551615 target=1048575 changed=false` |
| runtime nofile preflight observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets using the observed-learning path where present and strict learning for the simple strict-covered scenarios. Strict-only learning passed 14 of 18 scenarios; `catalog-mimic-xff`, `dictionary-slug-xff`, `legit-interleave-xff`, and `xff-rotating` rely on observed/path-shape learning for full coverage in this run. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0. The lowest effective attacker-block rates were `dictionary-slug-xff` at 90.28%, `smart-api-mix` at 94.11%, and `slow-xff-polymorphic` at 94.92%.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6681.08 RPS | `204: 13410` | 0 | 17.009 ms |
| admin health on `core` | 6499.40 RPS | `200: 13049` | 0 | 17.320 ms |
| raw TCP persistent echo on `core` | 24911.01 msg/s | `49923` echoed messages | 0 | 2.605 ms |

Core runtime NOFILE behavior matched the configured preflight and proved the raise path: the child proxy returned health `200` and logged `runtime nofile limit soft=2048 hard=524288 target=2048 changed=true`.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --no-codex --preset all --duration 1.2 --workers 48 --analyzer-wait 10 --json-only
ssh core 'cd /tmp/altura-prot-runtime-nofile-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-runtime-nofile-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-runtime-nofile-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Runtime NOFILE Capacity Snapshot

Artifacts:

- `benchmark_results/local_bench_runtime_nofile_capacity_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_runtime_nofile_capacity.json`
- `benchmark_results/local_bench_core_runtime_nofile_capacity_20260622.json`

This snapshot extends `runtime.min_nofile` from a floor check into a startup capacity check. When the runtime NOFILE preflight is enabled, AlturaProt estimates descriptor demand from a fixed reserve, listeners, HTTP downstream connections, HTTP upstream in-flight requests, HTTP idle upstream pool, and TCP downstream/upstream socket pairs. Startup fails before listeners bind if the final soft `RLIMIT_NOFILE` cannot cover that configured budget. Unbounded `max_connections: 0` is rejected while `runtime.min_nofile` is enabled because the FD budget is not knowable.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9447.71 RPS | `204: 18934` | 0 | 11.885 ms |
| admin health | 8848.35 RPS | `200: 17736` | 0 | 13.495 ms |
| raw TCP persistent echo | 19018.47 msg/s | `38078` echoed messages | 0 | 3.069 ms |

Runtime NOFILE capacity probe with child `ulimit -n 1024`:

| Probe | Result |
| --- | --- |
| configured `runtime.min_nofile` | `1024` |
| expected required descriptors | `3269` |
| child exit code | `1` |
| capacity rejection observed | passed |
| rejection summary | required `3269`; soft `1024`; reserve `256`; listeners `1`; HTTP downstream `1500`; HTTP upstream in-flight `1000`; HTTP idle pool `512` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 116 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. The lowest effective attacker-control result was `mixed-user-agent` at 99.61%; all other effective best layers were 100.0%.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6473.87 RPS | `204: 12994` | 0 | 17.497 ms |
| admin health on `core` | 6668.05 RPS | `200: 13382` | 0 | 16.987 ms |
| raw TCP persistent echo on `core` | 24997.15 msg/s | `50077` echoed messages | 0 | 2.598 ms |

Core runtime NOFILE capacity behavior matched local behavior: the healthy child with `runtime.min_nofile: 2048` returned health `200` and logged `runtime nofile limit soft=2048 hard=524288 target=2048 changed=true`; the intentionally undersized capacity child exited `1` with the same required `3269` versus soft `1024` startup rejection.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-runtime-nofile-capacity-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-runtime-nofile-capacity-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-runtime-nofile-capacity-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 SIGTERM Shutdown Snapshot

Artifacts:

- `benchmark_results/local_bench_sigterm_shutdown_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_sigterm_shutdown.json`
- `benchmark_results/local_bench_core_sigterm_shutdown_20260622.json`

This snapshot makes Unix SIGTERM enter AlturaProt's existing shutdown path instead of relying on the default immediate process termination. The main process now waits for Ctrl-C/SIGINT and SIGTERM, publishes shutdown to HTTP/TCP listeners, waits briefly for listener tasks, and then applies the optional `runtime.shutdown_grace_ms` final drain window. The example config sets `shutdown_grace_ms` to `2000`; benchmark probe configs keep it at `0` so repeated child-process cleanup remains fast.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9366.43 RPS | `204: 18769` | 0 | 12.081 ms |
| admin health | 9537.59 RPS | `200: 19113` | 0 | 11.887 ms |
| raw TCP persistent echo | 18935.29 msg/s | `37911` echoed messages | 0 | 3.064 ms |

Runtime SIGTERM probe:

| Probe | Result |
| --- | --- |
| child proxy health before signal | `200` |
| child exit code after SIGTERM | `0` |
| shutdown log | `shutdown signal received: SIGTERM` |
| listener shutdown log | `http proxy listener shutting down` |
| SIGTERM graceful path observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 116 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting in this run.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6690.10 RPS | `204: 13421` | 0 | 17.035 ms |
| admin health on `core` | 6606.82 RPS | `200: 13257` | 0 | 17.337 ms |
| raw TCP persistent echo on `core` | 25536.97 msg/s | `51177` echoed messages | 0 | 2.504 ms |

Core runtime SIGTERM behavior matched local behavior: the child returned health `200`, exited with code `0` after SIGTERM, and logged both `shutdown signal received: SIGTERM` and `http proxy listener shutting down`.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/codex_analyzer.py tools/run_local_bench.py tools/run_defense_bench.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-sigterm-shutdown-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-sigterm-shutdown-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-sigterm-shutdown-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Event Log Async Queue Snapshot

Artifacts:

- `benchmark_results/local_bench_event_log_async_queue_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_event_log_async_queue.json`
- `benchmark_results/local_bench_core_event_log_async_queue_20260622.json`

This snapshot moves adaptive attack-event file writes off the request path. Current behavior goes further: request workers enqueue bounded owned events, while JSON serialization and file I/O happen in the writer thread. If the queue is full, the event is dropped and `altura_event_log_dropped` increments instead of blocking HTTP workers behind a slow event-log sink. `adaptive.event_log_queue_capacity` defaults to `4096`; the saturation probe uses capacity `1` and a FIFO that is not drained during the request burst to prove the hot path remains responsive.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9294.28 RPS | `204: 18623` | 0 | 12.193 ms |
| admin health | 9536.22 RPS | `200: 19111` | 0 | 11.831 ms |
| raw TCP persistent echo | 19036.91 msg/s | `38121` echoed messages | 0 | 3.084 ms |

Blocked event-log sink probe:

| Probe | Result |
| --- | --- |
| configured queue capacity | `1` |
| unique adaptive-event requests | 2000 requests, all `204` |
| request burst throughput | 7001.18 RPS |
| dropped event-log metric delta | `1982` |
| queue-drop behavior observed | passed |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 116 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting in this run.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6661.22 RPS | `204: 13369` | 0 | 17.104 ms |
| admin health on `core` | 6519.49 RPS | `200: 13085` | 0 | 17.654 ms |
| raw TCP persistent echo on `core` | 24865.45 msg/s | `49827` echoed messages | 0 | 2.577 ms |

Core blocked event-log sink behavior matched local behavior: 2000 adaptive-event requests all returned `204`, the queue capacity was `1`, request burst throughput was 4890.58 RPS, `altura_event_log_dropped` increased by `1870`, and queue-drop behavior was observed without request failures.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/codex_analyzer.py tools/test_ai_tools.py tools/validate_edge_templates.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-event-log-async-queue-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-event-log-async-queue-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-event-log-async-queue-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Request Content-Encoding Snapshot

Artifacts:

- `benchmark_results/local_bench_request_content_encoding_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_request_content_encoding.json`
- `benchmark_results/local_bench_core_request_content_encoding_20260622.json`

This snapshot adds a request `Content-Encoding` policy before request-target validation, adaptive observation, filtering, rate limiting, and upstream proxying. AlturaProt does not decompress request bodies, so a compressed request body can otherwise stay under the proxy's encoded byte cap while expanding into much larger origin work. By default, non-`identity` request content codings return HTTP `415` with `Accept-Encoding: identity` and increment `altura_http_content_encoding_rejected`. Deployments that intentionally accept compressed uploads can set `http.allow_compressed_request_bodies: true`, but the origin must then enforce decoded-size, decompression-ratio, CPU, and memory limits.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9273.87 RPS | `204: 18583` | 0 | 12.246 ms |
| admin health | 9454.11 RPS | `200: 18945` | 0 | 11.975 ms |
| raw TCP persistent echo | 19281.61 msg/s | `38608` echoed messages | 0 | 3.062 ms |

Request content-encoding probe:

| Probe | Result |
| --- | --- |
| `Content-Encoding: gzip` request | `415` |
| response `Accept-Encoding` | `identity` |
| `Content-Encoding: identity` request | `200` |
| `altura_http_content_encoding_rejected` delta | `1` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 116 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting in this run.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6651.60 RPS | `204: 13347` | 0 | 17.146 ms |
| admin health on `core` | 6675.67 RPS | `200: 13400` | 0 | 17.034 ms |
| raw TCP persistent echo on `core` | 24269.38 msg/s | `48633` echoed messages | 0 | 2.639 ms |

Core request content-encoding behavior matched local behavior: `Content-Encoding: gzip` returned `415` with `Accept-Encoding: identity`, `Content-Encoding: identity` reached the upstream with `200`, and `altura_http_content_encoding_rejected` increased by 1.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-request-content-encoding-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-request-content-encoding-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-request-content-encoding-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Request Content-Encoding Close Snapshot

Artifacts:

- `benchmark_results/local_bench_request_content_encoding_close_20260622.json`
- `benchmark_results/local_bench_core_request_content_encoding_close_20260622.json`

This snapshot adds explicit `Connection: close` to generated `415 Unsupported Media Type` responses for unsupported request `Content-Encoding` values. AlturaProt rejects these requests before decoding or consuming the upload body; closing the connection prevents clients from attempting to reuse a connection that might still be carrying unread encoded request bytes while preserving `Accept-Encoding: identity` as the advertised supported request coding.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9290.76 RPS | `204: 18622` | 0 | 12.128 ms |
| admin health | 9478.82 RPS | `200: 18995` | 0 | 11.901 ms |
| raw TCP persistent echo | 19026.87 msg/s | `38095` echoed messages | 0 | 3.068 ms |

415 close guardrails:

| Probe | Status | `Accept-Encoding` | `Connection` |
| --- | --- | --- | --- |
| `Content-Encoding: gzip` request | `415` | `identity` | `close` |
| `Content-Encoding: identity` request | `200` | none | allowed |

The local probe increased `altura_http_content_encoding_rejected` by 1 and recorded `compressed_request_closes_connection: true`.

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 6810.68 RPS | `204: 13662` | 0 | 16.541 ms |
| admin health | 6667.15 RPS | `200: 13382` | 0 | 17.064 ms |
| raw TCP persistent echo | 27828.19 msg/s | `55768` echoed messages | 0 | 2.290 ms |

Core 415 close guardrails matched local behavior: the gzip request returned `415` with `Accept-Encoding: identity`, `Connection: close`, `altura_http_content_encoding_rejected` increased by 1, and `compressed_request_closes_connection` was true.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test unsupported_content_encoding_response_advertises_identity_and_closes_connection -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-content-encoding-close-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-content-encoding-close-20260622 && cargo test unsupported_content_encoding_response_advertises_identity_and_closes_connection -- --nocapture'
ssh core 'cd /tmp/altura-prot-content-encoding-close-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-content-encoding-close-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 HTTP Range Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_range_guard_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_range_guard.json`
- `benchmark_results/local_bench_core_range_guard_20260622.json`

This snapshot adds a bounded request `Range` policy before request-target validation, adaptive observation, filtering, rate limiting, and upstream proxying. The default `http.max_ranges: 1` allows common single byte ranges such as media fetches and download resume, while rejecting malformed ranges, unsupported range units, multiple `Range` header fields, and multipart range pressure that can amplify origin CPU, memory, I/O, and response work. Rejections return HTTP `416` and increment `altura_http_range_rejected`. Keep `http.max_ranges` greater than zero; startup rejects `0` so the range-amplification guard cannot be accidentally removed.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9321.61 RPS | `204: 18683` | 0 | 11.998 ms |
| admin health | 9428.52 RPS | `200: 18896` | 0 | 11.985 ms |
| raw TCP persistent echo | 19163.91 msg/s | `38368` echoed messages | 0 | 3.057 ms |

Range guard probe:

| Probe | Result |
| --- | --- |
| `Range: bytes=0-0` | `204` |
| `Range: bytes=0-0, 0-0` | `416` |
| `Range: items=0-1` | `416` |
| `Range: bytes=10-1` | `416` |
| `altura_http_range_rejected` delta | `3` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 163 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting in this run.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6552.36 RPS | `204: 13152` | 0 | 17.457 ms |
| admin health on `core` | 6453.87 RPS | `200: 12954` | 0 | 17.594 ms |
| raw TCP persistent echo on `core` | 27566.40 msg/s | `55214` echoed messages | 0 | 2.301 ms |

Core request range behavior matched local behavior: `Range: bytes=0-0` reached the upstream with `204`, multipart, unsupported-unit, and reversed byte ranges returned `416`, and `altura_http_range_rejected` increased by 3.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-range-guard-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-range-guard-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-range-guard-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Origin Accept-Encoding Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_accept_encoding_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_accept_encoding.json`
- `benchmark_results/local_bench_core_accept_encoding_20260622.json`

This snapshot suppresses origin response-compression negotiation by default. Client `Accept-Encoding` is removed during upstream request rewrite unless `http.forward_accept_encoding: true` is configured. This keeps compression/decompression out of AlturaProt's hot path and avoids making every proxied response a possible origin CPU and memory compression task during a flood. Strips increment `altura_http_accept_encoding_stripped`. Enable passthrough only for origins that have measured compression capacity or serve precompressed assets without per-request compression work.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9292.78 RPS | `204: 18623` | 0 | 12.091 ms |
| admin health | 9554.62 RPS | `200: 19147` | 0 | 11.827 ms |
| raw TCP persistent echo | 19030.07 msg/s | `38100` echoed messages | 0 | 3.077 ms |

Accept-Encoding guard probe:

| Probe | Result |
| --- | --- |
| client request header | `Accept-Encoding: gzip, br` |
| upstream observed `Accept-Encoding` | absent |
| upstream echo status | `200` |
| dedicated `altura_http_accept_encoding_stripped` delta | `1` |
| aggregate guardrail-run delta | `3` |

The aggregate delta is higher than the dedicated probe because other Python `http.client` guard probes add `Accept-Encoding: identity`; those are also stripped before the origin.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 163 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting in this run.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6677.40 RPS | `204: 13402` | 0 | 17.019 ms |
| admin health on `core` | 6540.47 RPS | `200: 13128` | 0 | 17.373 ms |
| raw TCP persistent echo on `core` | 24547.43 msg/s | `49192` echoed messages | 0 | 2.626 ms |

Core origin `Accept-Encoding` behavior matched local behavior: a client request with `Accept-Encoding: gzip, br` reached the upstream echo without an `Accept-Encoding` header, and the dedicated `altura_http_accept_encoding_stripped` delta was 1.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-accept-encoding-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-accept-encoding-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-accept-encoding-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Expect Header Guard Snapshot

Artifacts:

- `benchmark_results/local_bench_expect_guard_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_expect_guard.json`
- `benchmark_results/local_bench_core_expect_guard_20260622.json`

This snapshot rejects request `Expect` headers by default before request-target validation, adaptive observation, filtering, rate limiting, and upstream proxying. `Expect: 100-continue` changes request-body coordination between client, proxy, and origin; unsupported expectations are already a protocol error surface. By default AlturaProt returns HTTP `417` with `Connection: close` and increments `altura_http_expect_rejected`. Set `http.allow_expect_continue: true` only for origins that require `100-continue` upload negotiation and have tuned body size, idle, and minimum-rate limits.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9284.78 RPS | `204: 18608` | 0 | 12.052 ms |
| admin health | 9398.06 RPS | `200: 18836` | 0 | 11.996 ms |
| raw TCP persistent echo | 19218.43 msg/s | `38478` echoed messages | 0 | 3.066 ms |

Expect guard probe:

| Probe | Result |
| --- | --- |
| `Expect: 100-continue` | `417`, `Connection: close` |
| `Expect: wait-for-magic` | `417`, `Connection: close` |
| normal POST without `Expect` | `200` |
| `altura_http_expect_rejected` delta | `2` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 163 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting in this clean rerun.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6603.66 RPS | `204: 13253` | 0 | 17.070 ms |
| admin health on `core` | 6678.09 RPS | `200: 13407` | 0 | 17.024 ms |
| raw TCP persistent echo on `core` | 27505.84 msg/s | `55101` echoed messages | 0 | 2.326 ms |

Core `Expect` behavior matched local behavior: `Expect: 100-continue` and an unsupported expectation returned `417` with `Connection: close`, normal POST reached the upstream with `200`, and `altura_http_expect_rejected` increased by 2.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-expect-guard-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-expect-guard-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-expect-guard-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Extended Client-IP Header Sanitization Snapshot

Artifacts:

- `benchmark_results/local_bench_extended_forwarded_header_sanitization_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_extended_forwarded_header_sanitization.json`
- `benchmark_results/local_bench_core_extended_forwarded_header_sanitization_20260622.json`

This snapshot broadens origin-visible forwarding sanitization from the core `Forwarded`/`X-Forwarded-*` fields to common CDN and proxy client-IP identity headers. AlturaProt now strips `CF-Connecting-IP`, `True-Client-IP`, `Fastly-Client-IP`, `Client-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `X-Forwarded`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Original-*`, `X-Rewrite-URL`, and related `X-Forwarded-*` routing aliases before proxying upstream. `X-Forwarded-For` remains topology-aware: direct untrusted peers are overwritten with the immediate peer IP, while configured trusted proxies preserve the existing XFF chain and append the peer proxy. Sanitized requests increment `altura_http_forwarded_sanitized`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9250.04 RPS | `204: 18539` | 0 | 12.234 ms |
| admin health | 9521.34 RPS | `200: 19080` | 0 | 11.779 ms |
| raw TCP persistent echo | 19052.56 msg/s | `38141` echoed messages | 0 | 3.078 ms |

Extended forwarded-header probe:

| Probe | Result |
| --- | --- |
| direct untrusted client with spoofed CDN/proxy client-IP headers | canonical forwarded headers valid, spoof-only headers stripped |
| trusted proxy peer with spoofed CDN/proxy client-IP headers | XFF chain preserved as `203.0.113.200, 127.0.0.1`, spoof-only headers stripped |
| direct `altura_http_forwarded_sanitized` delta | `1` |
| trusted-proxy `altura_http_forwarded_sanitized` delta | `1` |

The upstream echo observed no `Forwarded`, `CF-Connecting-IP`, `True-Client-IP`, `Fastly-Client-IP`, `Client-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `X-Forwarded`, `X-Forwarded-Server`, `X-Forwarded-Port`, `X-Forwarded-Scheme`, `X-Forwarded-Prefix`, `X-Forwarded-URI`, `X-Forwarded-Path`, `X-Original-Forwarded-For`, `X-Original-Host`, `X-Original-URL`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, or `X-Rewrite-URL` in either probe.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 163 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting in the clean rerun.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6636.58 RPS | `204: 13321` | 0 | 16.977 ms |
| admin health on `core` | 6511.13 RPS | `200: 13069` | 0 | 17.476 ms |
| raw TCP persistent echo on `core` | 24404.52 msg/s | `48888` echoed messages | 0 | 2.630 ms |

Core extended forwarded-header behavior matched local behavior: direct and trusted-proxy probes both reported `canonical_headers_valid: true` and `spoof_headers_stripped: true`, and each dedicated probe increased `altura_http_forwarded_sanitized` by 1.

Validation commands:

```bash
cargo fmt --check
cargo test forwarded_headers -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-extended-forwarded-headers-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-extended-forwarded-headers-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-extended-forwarded-headers-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Attack-Event Field Bounds Snapshot

Artifacts:

- `benchmark_results/local_bench_event_log_field_bounds_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_event_log_field_bounds.json`
- `benchmark_results/local_bench_core_event_log_field_bounds_20260622.json`

This snapshot bounds the size of user-controlled fields before adaptive attack events enter the nonblocking event-log queue. Path and query are capped at 1024 bytes each, path shape at 512 bytes, query keys at 128 bytes each, user-agent at 512 bytes, XFF at 512 bytes, header names at 128 bytes each, and signature basis at 1024 bytes. Truncated fields carry the `...[truncated]` marker. This keeps a threshold-crossing flood from turning each event into an oversized in-memory queue entry or disk line while preserving enough context for CodexSDGate and deterministic analysis.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9219.40 RPS | `204: 18474` | 0 | 12.245 ms |
| admin health | 9420.84 RPS | `200: 18880` | 0 | 11.914 ms |
| raw TCP persistent echo | 19280.00 msg/s | `38603` echoed messages | 0 | 3.036 ms |

Event-log field-bounds probe:

| Field | Bound observed |
| --- | ---: |
| path | 1024 bytes |
| query | 1024 bytes |
| user-agent | 512 bytes |
| XFF | 512 bytes |
| signature basis | 1024 bytes |
| max query key | 128 bytes |

The live-proxy probe returned `204`, wrote one visible JSON event line, and reported `all_event_fields_bounded: true`, `bounded_fields: true`, `bounded_query_keys: true`, and `bounded_header_name: true`. The event line was 4749 bytes despite oversized request path, query, user-agent, XFF, and header-name inputs.

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 163 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6618.40 RPS | `204: 13284` | 0 | 17.231 ms |
| admin health on `core` | 6666.46 RPS | `200: 13380` | 0 | 16.975 ms |
| raw TCP persistent echo on `core` | 27386.42 msg/s | `54854` echoed messages | 0 | 2.303 ms |

Core event-log field-bounds behavior matched local behavior: `all_event_fields_bounded: true`, the same field lengths were observed, and the oversized event line was 4749 bytes.

Validation commands:

```bash
cargo fmt --check
cargo test attack_events_bound_user_controlled_fields_before_queueing -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-event-log-field-bounds-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-event-log-field-bounds-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-event-log-field-bounds-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Adaptive Window Cap Snapshot

Artifacts:

- `benchmark_results/local_bench_adaptive_window_cap_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_adaptive_window_cap.json`
- `benchmark_results/local_bench_core_adaptive_window_cap_20260622.json`

This snapshot bounds adaptive detector memory under fresh high-cardinality traffic. `adaptive.max_signature_windows` and `adaptive.max_path_shape_windows` default to `8192` each and are divided across detector shards. When a shard is full, idle windows are removed first; if all entries are recent, the detector refuses to allocate a new signature or path-shape window and preserves the existing evidence. The metrics endpoint exposes current window counts and capacities for signature and path-shape tracking.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9373.94 RPS | `204: 18785` | 0 | 12.009 ms |
| admin health | 9528.29 RPS | `200: 19093` | 0 | 11.786 ms |
| raw TCP persistent echo | 18998.42 msg/s | `38039` echoed messages | 0 | 3.096 ms |

Adaptive window-cap live probe:

| Probe | Result |
| --- | --- |
| unique high-cardinality requests | 512 requests, all `204` |
| configured signature windows | `64` |
| signature windows after probe | `64` of `64` capacity |
| configured path-shape windows | `64` |
| path-shape windows after probe | `64` of `64` capacity |
| bounded checks | `signature_windows_bounded: true`, `path_shape_windows_bounded: true` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 163 counted phase summaries, total `errors` were 0 and total `hung_workers` were 0. All effective best layers reached 100.0% attacker blocking/limiting.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6673.93 RPS | `204: 13391` | 0 | 17.023 ms |
| admin health on `core` | 6470.39 RPS | `200: 12986` | 0 | 17.543 ms |
| raw TCP persistent echo on `core` | 25235.18 msg/s | `50562` echoed messages | 0 | 2.540 ms |

Core adaptive window-cap behavior matched local behavior: 512 unique high-cardinality requests all returned `204`, signature windows ended at `64` of `64` capacity, path-shape windows ended at `64` of `64` capacity, and both bounded checks were true.

Validation commands:

```bash
cargo fmt --check
cargo test adaptive -- --nocapture
cargo test adaptive_config_accepts_custom_event_log_bounds -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-adaptive-window-cap-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-adaptive-window-cap-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-adaptive-window-cap-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Runtime Filter Reload Bounds Snapshot

Artifacts:

- `benchmark_results/local_bench_runtime_filter_bounds_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_runtime_filter_bounds.json`
- `benchmark_results/local_bench_core_runtime_filter_bounds_20260622.json`

This snapshot bounds control-plane filter reload resource use. `filters.max_runtime_file_bytes` defaults to `1048576`, `filters.max_runtime_filters` defaults to `1024`, and runtime reloads reject non-regular files. If a reload fails because the file is oversized, non-regular, invalid, or contains too many runtime filters, the in-memory last-good rules remain active.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9279.16 RPS | `204: 18597` | 0 | 12.180 ms |
| admin health | 9472.24 RPS | `200: 18982` | 0 | 11.824 ms |
| raw TCP persistent echo | 19346.44 msg/s | `38734` echoed messages | 0 | 3.059 ms |

Runtime filter reload-bounds probe:

| Probe | Result |
| --- | --- |
| configured max runtime filter bytes | `4096` |
| configured max runtime filters | `4` |
| initial last-good runtime rule | `403` on `/runtime-filter-bounds-blocked` |
| oversized runtime filter file | `8388` bytes, rejected |
| too-many runtime filter file | `5` filters in `958` bytes, rejected |
| last-good rule after both reload failures | preserved, still `403` |
| new rejected rules after failed reloads | not loaded, returned `204` |
| normal traffic after reload failures | `204` |
| reload error logged | `true` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 163 counted phase summaries, proxy/analyzer phase `errors` were 0 and `hung_workers` were 0. The run recorded 2 client-side loopback errors in the direct-upstream baseline for `accept-spray-xff`; that baseline is not used as a proxy/analyzer clean-phase claim. All effective best layers reached 100.0% attacker blocking/limiting.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6690.65 RPS | `204: 13427` | 0 | 16.968 ms |
| admin health on `core` | 6602.19 RPS | `200: 13256` | 0 | 17.313 ms |
| raw TCP persistent echo on `core` | 26084.79 msg/s | `52279` echoed messages | 0 | 2.460 ms |

Core runtime filter reload-bounds behavior matched local behavior: oversized and too-many runtime filter files were rejected, `reload_error_logged` was true, the last-good rule stayed active, rejected new rules were not loaded, and normal traffic still returned `204`.

Validation commands:

```bash
cargo fmt --check
cargo test runtime_filter_reload -- --nocapture
cargo test filter_config_accepts_runtime_reload_bounds -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-runtime-filter-bounds-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-runtime-filter-bounds-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-runtime-filter-bounds-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Trusted Forwarded Header Bounds Snapshot

Artifacts:

- `benchmark_results/local_bench_forwarded_header_bounds_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_forwarded_header_bounds.json`
- `benchmark_results/local_bench_core_forwarded_header_bounds_20260622.json`

This snapshot bounds trusted `X-Forwarded-For` parsing before rate-limit identity, signature, filter, adaptive, or upstream work. `http.client_ip.max_forwarded_for_bytes` defaults to `1024` and `http.client_ip.max_forwarded_for_hops` defaults to `32`. The caps apply only when the immediate peer is in `http.client_ip.trusted_proxies`; untrusted direct peers still ignore and overwrite spoofable forwarded metadata. Malformed, oversized, or excessive trusted forwarded chains return HTTP `400` and increment `altura_http_forwarded_rejected`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8817.53 RPS | `204: 17668` | 0 | 12.987 ms |
| admin health | 9489.26 RPS | `200: 19013` | 0 | 11.931 ms |
| raw TCP persistent echo | 18416.47 msg/s | `36874` echoed messages | 0 | 3.234 ms |

Trusted forwarded-header bounds probe:

| Probe | Result |
| --- | --- |
| configured max XFF bytes | `64` |
| configured max XFF hops | `2` |
| valid trusted XFF chain | `204` |
| oversized trusted XFF chain | `400` |
| too-many-hop trusted XFF chain | `400` |
| malformed trusted XFF chain | `400` |
| `altura_http_forwarded_rejected` delta | `3` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios had an effective layer at or above 90% attacker blocking/limiting. Strict learned mode passed 15 of 18 scenarios; `catalog-mimic-xff`, `legit-interleave-xff`, and `xff-rotating` still rely on observed/path-shape or non-strict coverage. Across 163 counted phase summaries, proxy/analyzer phase `errors` were 0 and `hung_workers` were 0. The run recorded 1 client-side loopback error in the direct-upstream baseline for `rotating-path`; that baseline is not used as a proxy/analyzer clean-phase claim. All effective best layers reached 100.0% attacker blocking/limiting.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6659.86 RPS | `204: 13365` | 0 | 17.029 ms |
| admin health on `core` | 6683.91 RPS | `200: 13409` | 0 | 16.981 ms |
| raw TCP persistent echo on `core` | 24284.98 msg/s | `48650` echoed messages | 0 | 2.642 ms |

Core trusted forwarded-header bounds behavior matched local behavior: valid trusted XFF returned `204`, oversized, too-many-hop, and malformed trusted XFF returned `400`, and `altura_http_forwarded_rejected` increased by `3`.

Validation commands:

```bash
cargo fmt --check
cargo test client_ip_ -- --nocapture
cargo test forwarded_headers -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/test_ai_tools.py
python3 -m py_compile tools/run_local_bench.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-forwarded-header-bounds-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-forwarded-header-bounds-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-forwarded-header-bounds-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Trusted Proxy Aggregate Rate Snapshot

Artifacts:

- `benchmark_results/local_bench_trusted_proxy_aggregate_rate_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_trusted_proxy_aggregate_rate.json`
- `benchmark_results/local_bench_core_trusted_proxy_aggregate_rate_20260622.json`

This snapshot adds a separate trusted-proxy aggregate HTTP request-rate bucket. AlturaProt still resolves and rates the forwarded client IP when the immediate peer is in `http.client_ip.trusted_proxies`, but it also checks `http.limits.trusted_proxy_rps` and `http.limits.trusted_proxy_burst` against the immediate peer IP whenever a trusted forwarded client differs from the peer. This closes the single-edge XFF-rotation gap where many spoofed/rotated forwarded clients could avoid every per-client bucket while arriving from one trusted proxy. Trusted-proxy aggregate throttles return HTTP `429`, increment `altura_http_rate_limited`, and increment the dedicated `altura_http_trusted_proxy_rate_limited` metric.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8745.13 RPS | `204: 17525` | 0 | 13.207 ms |
| admin health | 8894.73 RPS | `200: 17826` | 0 | 13.398 ms |
| raw TCP persistent echo | 19282.26 msg/s | `38607` echoed messages | 0 | 3.026 ms |

Trusted proxy aggregate rate probe:

| Probe | Result |
| --- | --- |
| configured trusted proxy RPS | `0.000001` |
| configured trusted proxy burst | `2` |
| rotating trusted XFF statuses | `[204, 204, 429, 429]` |
| `altura_http_trusted_proxy_rate_limited` delta | `2` |
| `altura_http_rate_limited` delta inside probe | `2` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios met the benchmark targets in strict mode after the scorer correction that counts both `403` blocked traffic and `429` rate-limited traffic as attacker mitigation. The lowest strict attacker blocked-or-limited rates were `legit-interleave-xff` at 98.55%, `dictionary-slug-xff` at 98.62%, `catalog-mimic-xff` at 98.67%, and `xff-rotating` at 98.68%. The lowest strict benign allow rates were `dictionary-slug-xff` at 95.00% and `legit-interleave-xff` at 95.24%. Across 163 reported phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6671.28 RPS | `204: 13396` | 0 | 16.839 ms |
| admin health on `core` | 6545.35 RPS | `200: 13136` | 0 | 17.305 ms |
| raw TCP persistent echo on `core` | 23872.24 msg/s | `47841` echoed messages | 0 | 2.702 ms |

Core trusted proxy aggregate behavior matched local behavior: rotating trusted XFF statuses were `[204, 204, 429, 429]`, `altura_http_trusted_proxy_rate_limited` increased by `2`, and `altura_http_rate_limited` increased by `2` inside the probe.

Validation commands:

```bash
cargo test trusted_proxy -- --nocapture
cargo test rate_limit_response_increments_counter -- --nocapture
cargo test http_config_defaults_header_count_cap -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py
python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /tmp/altura-prot-trusted-proxy-aggregate-rate-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-trusted-proxy-aggregate-rate-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-trusted-proxy-aggregate-rate-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Runtime Filter Hot Path Snapshot

Artifacts:

- `benchmark_results/local_bench_filter_hot_path_20260622.json`
- `benchmark_results/defense_bench_all_deterministic_20260622_filter_hot_path.json`
- `benchmark_results/local_bench_core_filter_hot_path_20260622.json`

This snapshot compiles filter header names and case-insensitive user-agent/header match needles at filter load time. Request evaluation also computes a request path shape at most once while scanning rules. The goal is to keep learned/static filter evaluation bounded and allocation-light when the analyzer has retained many narrow rules.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9296.22 RPS | `204: 18627` | 0 | 12.070 ms |
| admin health | 9431.94 RPS | `200: 18901` | 0 | 11.997 ms |
| raw TCP persistent echo | 19119.63 msg/s | `38280` echoed messages | 0 | 3.068 ms |

Runtime filter hot-path probe:

| Probe | Result |
| --- | --- |
| configured runtime rules | `512` |
| runtime filter file size | `155646` bytes |
| active filters after start | `512` |
| nonmatching mixed user-agent/header request | `204` |
| matching mixed user-agent/header request | `403` |
| control request | `204` |

Current-binary deterministic all-scenario defense regression:

```bash
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
```

All 18 base plus advanced HTTP scenarios met the strict benchmark targets. The lowest strict attacker blocked-or-limited rates were `legit-interleave-xff` at 98.59%, `dictionary-slug-xff` at 98.63%, `catalog-mimic-xff` at 98.68%, and `xff-rotating` at 98.70%. The lowest strict benign allow rates were `dictionary-slug-xff` at 95.00% and `legit-interleave-xff` at 95.00%. Across 145 counted phase summaries, the maximum and total `errors` were 0, and the maximum and total `hung_workers` were 0.

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6703.73 RPS | `204: 13454` | 0 | 16.867 ms |
| admin health on `core` | 6708.05 RPS | `200: 13462` | 0 | 17.115 ms |
| raw TCP persistent echo on `core` | 25185.95 msg/s | `50471` echoed messages | 0 | 2.541 ms |

Core runtime filter hot-path behavior matched local behavior: `512` filters loaded, the nonmatching mixed user-agent/header request returned `204`, the matching mixed user-agent/header request returned `403`, and a control request returned `204`.

Validation commands:

```bash
cargo fmt --check
cargo test filter::tests --lib
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py
python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
python3 tools/run_defense_bench.py --preset all --no-codex --json-only
ssh core 'cd /root/tmp-altura-prot-filter-hot-path-202606220724 && cargo test'
ssh core 'cd /root/tmp-altura-prot-filter-hot-path-202606220724 && cargo build --release'
ssh core 'cd /root/tmp-altura-prot-filter-hot-path-202606220724 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Edge Port Coverage Snapshot

Artifacts:

- `benchmark_results/local_bench_edge_port_coverage_20260622.json`
- `benchmark_results/local_bench_core_edge_port_coverage_20260622.json`

This snapshot extends the host-edge validator so it parses the nftables `protected_tcp_ports` set and compares it with non-loopback AlturaProt `http.listen` and `tcp[].listen` ports. Loopback-only listeners are ignored because they are not internet-facing. Public listeners now fail preflight if their port is missing from the protected-port set, so SYN and connection-count backstops cannot silently protect the wrong service ports.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8941.41 RPS | `204: 17919` | 0 | 12.916 ms |
| admin health | 9421.99 RPS | `200: 18881` | 0 | 12.079 ms |
| raw TCP persistent echo | 19055.71 msg/s | `38153` echoed messages | 0 | 3.075 ms |

Edge port coverage guardrail:

| Probe | Result |
| --- | --- |
| public HTTP `0.0.0.0:8080` plus public TCP `[::]:7000`, nft set missing `7000` | rejected |
| missing-port validator stderr | `protected_tcp_ports is missing public AlturaProt listener ports: 7000` |
| same public listeners with nft set including `7000` | allowed |
| loopback HTTP/TCP listeners with nft set missing `7000` | allowed |

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6678.98 RPS | `204: 13402` | 0 | 17.083 ms |
| admin health on `core` | 6545.26 RPS | `200: 13137` | 0 | 17.545 ms |
| raw TCP persistent echo on `core` | 25420.80 msg/s | `50935` echoed messages | 0 | 2.543 ms |

Core edge validation used the Linux/nftables path: `python3 tools/validate_edge_templates.py --config configs/example.json` passed without macOS skip messages, and the benchmark guardrail matched local behavior for rejected missing public ports, allowed covered public ports, and allowed loopback-only ports.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py
python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /root/tmp-altura-prot-edge-port-coverage-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /root/tmp-altura-prot-edge-port-coverage-20260622 && python3 tools/test_ai_tools.py'
ssh core 'cd /root/tmp-altura-prot-edge-port-coverage-20260622 && python3 tools/validate_edge_templates.py --config configs/example.json'
ssh core 'cd /root/tmp-altura-prot-edge-port-coverage-20260622 && cargo test'
ssh core 'cd /root/tmp-altura-prot-edge-port-coverage-20260622 && cargo build --release'
ssh core 'cd /root/tmp-altura-prot-edge-port-coverage-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Upstream Connect Timeout Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_connect_timeout_20260622.json`
- `benchmark_results/local_bench_core_upstream_connect_timeout_20260622.json`

This snapshot adds `http.upstream_connect_timeout_ms`, wired directly into Hyper-util's `HttpConnector` connect timeout. The default is `1000` ms, matching the TCP proxy connect timeout. Later config-validation hardening rejects `0` for this field so the connector timeout cannot be silently disabled.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9123.40 RPS | `204: 18283` | 0 | 12.711 ms |
| admin health | 9487.72 RPS | `200: 19013` | 0 | 11.891 ms |
| raw TCP persistent echo | 19133.26 msg/s | `38311` echoed messages | 0 | 3.087 ms |

Upstream connect-timeout guardrail with a local listener whose accept backlog was intentionally saturated:

| Probe | Result |
| --- | --- |
| configured `upstream_connect_timeout_ms` | `75` ms |
| configured broader `upstream_timeout_ms` | `1000` ms |
| first stalled origin connect | `502` after `0.078` s |
| second stalled origin connect with one-slot in-flight cap | `502` after `0.079` s |
| `altura_http_upstream_errors` delta | `2` |
| `altura_http_upstream_timeouts` delta | `0` |
| `altura_http_upstream_in_flight_rejected` delta | `0` |

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6509.16 RPS | `204: 13062` | 0 | 17.459 ms |
| admin health on `core` | 6680.24 RPS | `200: 13410` | 0 | 17.099 ms |
| raw TCP persistent echo on `core` | 27090.19 msg/s | `54257` echoed messages | 0 | 2.372 ms |

Core connect-timeout guardrail matched local behavior: the saturated-loopback origin connect returned `502` after `0.076` s for both sequential requests, `altura_http_upstream_errors` increased by 2, `altura_http_upstream_timeouts` stayed at 0, and the one-slot in-flight permit was released between attempts.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /root/tmp-altura-prot-upstream-connect-timeout-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /root/tmp-altura-prot-upstream-connect-timeout-20260622 && cargo test'
ssh core 'cd /root/tmp-altura-prot-upstream-connect-timeout-20260622 && cargo build --release'
ssh core 'cd /root/tmp-altura-prot-upstream-connect-timeout-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

Core note: `cargo clippy` was not available on Core's installed Rust toolchain during this snapshot; local Clippy passed with `-D warnings`.

## 2026-06-22 Chunked Request Body Policy Snapshot

Artifacts:

- `benchmark_results/local_bench_chunked_request_policy_20260622.json`
- `benchmark_results/local_bench_core_chunked_request_policy_20260622.json`

This snapshot changes HTTP/1.1 request-body framing policy from accepting single `Transfer-Encoding: chunked` by default to rejecting chunked request bodies unless `http.allow_chunked_request_bodies` is explicitly enabled. `Content-Length` bodies remain the default accepted request-body framing because the proxy can reject oversized bodies before acquiring upstream capacity, while chunked bodies require streamed accounting.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9098.48 RPS | `204: 18232` | 0 | 12.743 ms |
| admin health | 9613.14 RPS | `200: 19263` | 0 | 11.686 ms |
| raw TCP persistent echo | 18930.61 msg/s | `37903` echoed messages | 0 | 3.067 ms |

Chunked request-body guardrails:

| Probe | Result |
| --- | --- |
| default `Transfer-Encoding: chunked` request body | `400` |
| valid `Content-Length: 0` request body | `200` |
| malformed/ambiguous framing rejection delta | `altura_http_framing_rejected +8` |
| explicit `http.allow_chunked_request_bodies: true` with chunked body | `200` |
| opt-in framing rejection delta | `0` |

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6495.18 RPS | `204: 13036` | 0 | 17.511 ms |
| admin health on `core` | 6594.05 RPS | `200: 13235` | 0 | 17.347 ms |
| raw TCP persistent echo on `core` | 25445.43 msg/s | `50996` echoed messages | 0 | 2.553 ms |

Core guardrails matched local behavior: default chunked request bodies returned `400`, valid `Content-Length: 0` returned `200`, malformed/ambiguous framing increased `altura_http_framing_rejected` by 8, and the explicit chunked-body opt-in returned `200` with no framing rejection delta.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-chunked-request-policy-20260622 && python3 -m py_compile tools/run_local_bench.py tools/validate_edge_templates.py tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-chunked-request-policy-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-chunked-request-policy-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-chunked-request-policy-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

Core note: `cargo clippy` was not available on Core's installed Rust toolchain during the prior snapshot; local Clippy passed with `-D warnings` for this policy slice.

## 2026-06-22 Signature Rate-Limit Snapshot

Artifacts:

- `benchmark_results/local_bench_signature_rate_20260622.json`
- `benchmark_results/local_bench_core_signature_rate_20260622.json`

This snapshot adds a bounded token bucket keyed by AlturaProt's normalized request signature: method, normalized path, query shape, user-agent family, and Accept class. The limiter sits after static/adaptive filter evaluation and before per-IP/global request buckets and upstream admission. It lets one hot request shape shed with `429` before it consumes the whole service-wide request budget during a distributed L7 flood. The default is `http.limits.signature_rps: 5000`, `signature_burst: 10000`, and `max_tracked_signatures: 8192`; set `signature_rps: 0` to disable.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9275.28 RPS | `204: 18590` | 0 | 12.190 ms |
| admin health | 9451.81 RPS | `200: 18940` | 0 | 11.900 ms |
| raw TCP persistent echo | 19072.81 msg/s | `38186` echoed messages | 0 | 3.077 ms |

Signature-rate guardrails:

| Probe | Result |
| --- | --- |
| configured `signature_rps` / burst | `0.000001` / `2` |
| four requests to one hot signature | `204, 204, 429, 429` |
| request to different signature after hot limit | `204` |
| `altura_http_signature_rate_limited` delta | `2` |
| `altura_http_rate_limited` delta | `2` |

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6448.72 RPS | `204: 12945` | 0 | 17.698 ms |
| admin health on `core` | 6692.20 RPS | `200: 13431` | 0 | 17.056 ms |
| raw TCP persistent echo on `core` | 26723.48 msg/s | `53534` echoed messages | 0 | 2.394 ms |

Core guardrails matched local behavior: one hot signature returned `204, 204, 429, 429`, a different signature returned `204`, `altura_http_signature_rate_limited` increased by 2, and the aggregate `altura_http_rate_limited` counter also increased by 2.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/codex_analyzer.py tools/test_ai_tools.py tools/validate_edge_templates.py
python3 tools/test_ai_tools.py
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-signature-rate-20260622 && python3 -m py_compile tools/run_local_bench.py tools/codex_analyzer.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-signature-rate-20260622 && python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-signature-rate-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-signature-rate-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-signature-rate-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

Core note: local Clippy passed with `-D warnings`; Core's installed Rust toolchain did not have Clippy available in prior snapshots, so this validation kept Core to test/build/benchmark.

## 2026-06-22 Admin Signature Rate-Limit Snapshot

Artifacts:

- `benchmark_results/local_bench_admin_signature_rate_20260622.json`
- `benchmark_results/local_bench_core_admin_signature_rate_20260622.json`

This snapshot closes the admin early-return gap: `GET /__altura/health` and `GET /__altura/metrics` now pass through the normalized request-signature limiter before returning admin responses. They still keep the existing per-client, global, and trusted-proxy request checks, and metrics still require `http.admin_token`. Admin signature limiting does not feed adaptive learning, so health-check noise cannot train filters.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9288.87 RPS | `204: 18614` | 0 | 12.171 ms |
| admin health | 9535.80 RPS | `200: 19113` | 0 | 11.802 ms |
| raw TCP persistent echo | 19038.97 msg/s | `38118` echoed messages | 0 | 3.084 ms |

Admin signature-rate guardrails:

| Probe | Result |
| --- | --- |
| configured `signature_rps` / burst | `0.000001` / `2` |
| four `GET /__altura/health` requests | `200, 200, 429, 429` |
| `altura_http_signature_rate_limited` delta | `2` |
| `altura_http_rate_limited` delta | `2` |

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6709.91 RPS | `204: 13466` | 0 | 17.049 ms |
| admin health on `core` | 6752.34 RPS | `200: 13557` | 0 | 16.933 ms |
| raw TCP persistent echo on `core` | 25315.04 msg/s | `50726` echoed messages | 0 | 2.556 ms |

Core guardrails matched local behavior: four `GET /__altura/health` requests returned `200, 200, 429, 429`, `altura_http_signature_rate_limited` increased by 2, and the aggregate `altura_http_rate_limited` counter also increased by 2.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/codex_analyzer.py tools/test_ai_tools.py tools/validate_edge_templates.py
python3 tools/test_ai_tools.py
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-admin-signature-rate-20260622 && python3 -m py_compile tools/run_local_bench.py tools/codex_analyzer.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-admin-signature-rate-20260622 && python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-admin-signature-rate-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-admin-signature-rate-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-admin-signature-rate-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

Core note: local Clippy passed with `-D warnings`; Core validation used test/build/benchmark.

## 2026-06-22 Hop-by-Hop Header Sanitization Snapshot

Artifacts:

- `benchmark_results/local_bench_hop_by_hop_sanitization_20260622.json`
- `benchmark_results/local_bench_core_hop_by_hop_sanitization_20260622.json`

This snapshot tightens hop-by-hop header sanitization in both proxy directions. AlturaProt already removed the standard hop-by-hop set before proxying requests; it now parses every repeated `Connection` field value with `HeaderMap::get_all` before removing connection-listed extension fields, and applies the same sanitization to upstream responses before sending them downstream. This closes the case where a sender uses one benign `Connection` line first and names an origin/client-visible header in a second `Connection` line.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 8667.45 RPS | `204: 26147` | 0 | 26.816 ms |
| admin health | 9013.35 RPS | `200: 27111` | 0 | 25.560 ms |
| raw TCP persistent echo | 19647.33 msg/s | `58988` echoed messages | 0 | 3.002 ms |

Forwarded and hop-by-hop header probes against the upstream `/headers` echo endpoint:

| Probe | Origin-visible result |
| --- | --- |
| direct untrusted client with spoofed forwarding headers and repeated `Connection` headers | canonical forwarding metadata valid, spoofed forwarding headers absent, `Connection`/`Proxy-Connection`/`Keep-Alive`/`TE`/`Trailer`/`Upgrade` absent, `X-Hop-By-Hop-Attack` absent |
| trusted proxy peer with spoofed forwarding headers and repeated `Connection` headers | canonical trusted-proxy XFF chain valid, spoofed forwarding headers absent, `Connection`/`Proxy-Connection`/`Keep-Alive`/`TE`/`Trailer`/`Upgrade` absent, `X-Hop-By-Hop-Attack` absent |

Both local forwarded-header probes increased `altura_http_forwarded_sanitized` by 1.

Upstream-response hop-by-hop probe:

| Probe | Downstream-visible result |
| --- | --- |
| origin response with repeated `Connection`, `X-Origin-Hop`, `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`, and `Upgrade` | `200`, body `ok`, no origin hop-by-hop headers forwarded; downstream `Connection: close` is the proxy/client connection control |

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6487.92 RPS | `204: 19554` | 0 | 35.279 ms |
| admin health on `core` | 6600.66 RPS | `200: 19892` | 0 | 34.429 ms |
| raw TCP persistent echo on `core` | 25522.35 msg/s | `76657` echoed messages | 0 | 2.549 ms |

Core guardrails matched local behavior: direct and trusted-proxy forwarded-header probes both reported `hop_by_hop_headers_stripped: true`, `spoof_headers_stripped: true`, and origin-visible `x_hop_by_hop_attack: null`; the upstream-response probe also reported `hop_by_hop_headers_stripped: true` with only `Connection: close`, `Content-Length`, and `Date` visible downstream.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test hop_by_hop -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 3 --workers 128 --tcp-workers 32
jq -e '.guardrails.forwarded_headers.untrusted_direct.hop_by_hop_headers_stripped == true and .guardrails.forwarded_headers.trusted_proxy.hop_by_hop_headers_stripped == true and .guardrails.forwarded_headers.untrusted_direct.spoof_headers_stripped == true and .guardrails.forwarded_headers.trusted_proxy.spoof_headers_stripped == true and .guardrails.upstream_response_guard.hop_by_hop_headers_stripped == true' benchmark_results/local_bench_hop_by_hop_sanitization_20260622.json
ssh core 'cd /tmp/altura-prot-hop-by-hop-sanitization-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-hop-by-hop-sanitization-20260622 && cargo test hop_by_hop -- --nocapture'
ssh core 'cd /tmp/altura-prot-hop-by-hop-sanitization-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-hop-by-hop-sanitization-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-hop-by-hop-sanitization-20260622 && python3 tools/run_local_bench.py --binary target/release/altura-prot --duration 3 --workers 128 --tcp-workers 32'
ssh core 'cd /tmp/altura-prot-hop-by-hop-sanitization-20260622 && jq -e '"'"'.guardrails.forwarded_headers.untrusted_direct.hop_by_hop_headers_stripped == true and .guardrails.forwarded_headers.trusted_proxy.hop_by_hop_headers_stripped == true and .guardrails.forwarded_headers.untrusted_direct.spoof_headers_stripped == true and .guardrails.forwarded_headers.trusted_proxy.spoof_headers_stripped == true and .guardrails.upstream_response_guard.hop_by_hop_headers_stripped == true'"'"' benchmark_results/local_bench_core_hop_by_hop_sanitization_20260622.json'
```

Core note: local Clippy passed with `-D warnings`; Core validation used test/build/benchmark because `cargo clippy` is not installed on the `core` toolchain.

## 2026-06-22 Request-Framing Close Snapshot

Artifacts:

- `benchmark_results/local_bench_framing_close_20260622.json`
- `benchmark_results/local_bench_core_framing_close_20260622.json`

This snapshot makes generated application-level request-framing rejections return `400` with `Connection: close`. The raw initial HTTP/1 precheck already closed connection-opening framing failures; this closes the opt-in downstream keep-alive follow-up path where Hyper has accepted a previous request and the application guard rejects a later `Content-Length`/`Transfer-Encoding` policy violation before upstream work.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9334.99 RPS | `204: 18708` | 0 | 11.984 ms |
| admin health | 9377.18 RPS | `200: 18790` | 0 | 11.984 ms |
| raw TCP persistent echo | 19116.26 msg/s | `38279` echoed messages | 0 | 3.085 ms |

Request-framing close guardrails:

| Probe | Result |
| --- | --- |
| valid `Content-Length: 0` | `200` |
| malformed or policy-rejected initial framing probes | `400` with `Connection: close` |
| opt-in keep-alive first request | `200` with `Connection: keep-alive` |
| opt-in keep-alive follow-up `Transfer-Encoding: chunked` with default chunked-body policy | `400` with `Connection: close` |
| generated app-level framing rejection close flag | `true` |
| dedicated framing rejection delta | `altura_http_framing_rejected +9` |
| explicit `http.allow_chunked_request_bodies: true` with chunked body | `200` |

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6688.85 RPS | `204: 13423` | 0 | 17.102 ms |
| admin health on `core` | 6704.09 RPS | `200: 13458` | 0 | 17.133 ms |
| raw TCP persistent echo on `core` | 26989.25 msg/s | `54092` echoed messages | 0 | 2.357 ms |

Core guardrails matched local behavior: the keep-alive follow-up framing rejection returned `400` with `Connection: close`, the first request stayed keep-alive, `generated_framing_rejection_closes_connection` was true, and the dedicated framing rejection delta was `+9`.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test request_framing_rejected_response_closes_connection -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-framing-close-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-framing-close-20260622 && cargo test request_framing_rejected_response_closes_connection -- --nocapture'
ssh core 'cd /tmp/altura-prot-framing-close-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-framing-close-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Early-Deny Body Close Snapshot

Artifacts:

- `benchmark_results/local_bench_early_rejection_close_20260622.json`
- `benchmark_results/local_bench_core_early_rejection_close_20260622.json`

This snapshot broadens the close-on-reject policy from request-framing failures to generated early-deny responses emitted before request content is consumed. Method guards, filter blocks, request-target pressure, rate-limit responses, and upstream in-flight overload responses now carry `Connection: close`; status-specific cache/retry headers are preserved. The benchmark exercises opt-in downstream keep-alive with body-bearing second requests so the probe covers the persistence/desync risk condition.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9019.87 RPS | `204: 18074` | 0 | 12.721 ms |
| admin health | 9283.37 RPS | `200: 18604` | 0 | 12.290 ms |
| raw TCP persistent echo | 19059.98 msg/s | `38162` echoed messages | 0 | 3.073 ms |

Early-deny close guardrails:

| Probe | Result |
| --- | --- |
| opt-in keep-alive warm-up request | `204` with `Connection: keep-alive` |
| `TRACE /` with a request body | `405` with `Connection: close` |
| static filter block on `POST /blocked-upload` with a request body | `403` with `Connection: close` |
| long `POST` request target with a request body | `414` with `Connection: close` |
| aggregate body-bearing early rejection close flag | `true` |

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6816.04 RPS | `204: 13678` | 0 | 16.819 ms |
| admin health on `core` | 6659.96 RPS | `200: 13365` | 0 | 16.974 ms |
| raw TCP persistent echo on `core` | 25929.58 msg/s | `51963` echoed messages | 0 | 2.463 ms |

Core guardrails matched local behavior: body-bearing method, filter, and request-target early rejections all returned the expected status with `Connection: close`, and `body_bearing_early_rejections_close_connection` was true.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
cargo test response -- --nocapture
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-early-rejection-close-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-early-rejection-close-20260622 && cargo test response -- --nocapture'
ssh core 'cd /tmp/altura-prot-early-rejection-close-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-early-rejection-close-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Trusted-Proxy Strong-Evidence Snapshot

Artifact:

- `benchmark_results/defense_bench_trusted_proxy_strong_20260622.json`

This snapshot treats `trusted_proxy_rate_limited` as a strong analyzer signal. The trusted-proxy aggregate bucket already rejects XFF-rotation bursts from one edge hop; this change lets CodexSDGate's deterministic fallback and provider prompt preserve that reason as high-confidence evidence instead of treating it like weak observed-only volume.

Targeted deterministic `xff-rotating` run, loopback only, with `signature_threshold_per_second: 1` to isolate the learning contract:

| Layer | Learned filters | Collect statuses | Replay statuses | Target score |
| --- | ---: | --- | --- | --- |
| strict deterministic learned filter | 1 | `204: 160`, `429: 8548` | `403: 8374` | attacker blocked-or-limited `100.0%`, benign allowed `100.0%` |

Event reasons included `trusted_proxy_rate_limited: 1`, `filter_block: 1`, and `observed: 4`. The learned filter was a non-IP adaptive signature filter for `GET|/api/login|none|curl|*/*`, confirming that trusted-proxy aggregate throttling can now feed the same constrained learned-filter path as other strong rate-limit reasons.

Validation commands:

```bash
cargo fmt --check
cargo test trusted_proxy_rate_limited_is_strong_evidence
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/codex_analyzer.py tools/test_ai_tools.py
python3 tools/test_ai_tools.py
python3 tools/run_defense_bench.py --no-codex --scenarios xff-rotating --duration 1 --workers 16 --analyzer-wait 8 --signature-threshold 1 --json-only
```

## 2026-06-22 Defense-Bench Path-Shape Layer Snapshot

Artifact:

- `benchmark_results/defense_bench_path_shape_layer_20260622.json`

This snapshot extends `tools/run_defense_bench.py` with a separate `path_shape_rate_limit` layer. The layer keeps per-IP, trusted-proxy aggregate, global, and signature buckets high, then sets only `http.limits.path_shape_rps` and `http.limits.path_shape_burst` low. That makes the adversarial benchmark prove whether polymorphic route-family floods are stopped by the path-shape bucket itself.

Targeted deterministic `xff-polymorphic` run, loopback only, with `path_shape_rps: 80`:

| Layer | Statuses | Limited | Dedicated metric deltas | Effective score |
| --- | --- | ---: | --- | --- |
| regular `rate_limit` | `204: 160`, `429: 7810` | `97.99%` | `trusted_proxy_rate_limited: 7810`, `path_shape_rate_limited: 0` | trusted-proxy aggregate path |
| `path_shape_rate_limit` | `204: 160`, `429: 7967` | `98.03%` | `path_shape_rate_limited: 7967`, `trusted_proxy_rate_limited: 0`, `signature_rate_limited: 0` | attacker blocked-or-limited `98.03%` |

The new layer also emits per-layer selected Prometheus metric deltas so benchmark artifacts can attribute mitigation to the intended limiter instead of inferring from HTTP `429` alone.

Validation commands:

```bash
python3 -m py_compile tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py
python3 tools/test_ai_tools.py
python3 tools/run_defense_bench.py --no-codex --scenarios xff-polymorphic --duration 1 --workers 16 --analyzer-wait 8 --path-shape-rps 80 --json-only
```

## 2026-06-22 Rate-Limit Retry-After Snapshot

Artifact:

- `benchmark_results/local_bench_retry_after_20260622.json`
- `benchmark_results/local_bench_core_retry_after_20260622.json`

This snapshot adds `Retry-After: 1` to AlturaProt-generated HTTP `429` rate-limit responses. It covers the generic per-client/global request limiter, trusted-proxy aggregate limiter, normalized signature limiter, normalized path-shape limiter, and admin health-check limiter paths.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9346.98 RPS | `204: 18732` | 0 | 12.035 ms |
| admin health | 9550.53 RPS | `200: 19141` | 0 | 11.789 ms |
| raw TCP persistent echo | 18825.67 msg/s | `37695` echoed messages | 0 | 3.065 ms |

Retry-After guardrails:

| Probe | Statuses | `Retry-After` headers |
| --- | --- | --- |
| admin per-client rate limit | `200, 429` | `1` |
| trusted-proxy aggregate rate limit | `204, 204, 429, 429` | `1, 1` |
| signature rate limit | `204, 204, 429, 429` | `1, 1` |
| path-shape rate limit | `204, 204, 429, 429` | `1, 1` |
| admin signature rate limit | `200, 200, 429, 429` | `1, 1` |

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 6496.51 RPS | `204: 13045` | 0 | 17.543 ms |
| admin health | 6692.36 RPS | `200: 13434` | 0 | 16.765 ms |
| raw TCP persistent echo | 24554.67 msg/s | `49208` echoed messages | 0 | 2.623 ms |

Core Retry-After guardrails matched local behavior: admin per-client limiting returned `200, 429` with header `1`; trusted-proxy aggregate, signature, and path-shape probes returned `204, 204, 429, 429` with headers `1, 1`; admin signature limiting returned `200, 200, 429, 429` with headers `1, 1`.

Validation commands:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Rate-Limit 429 No-Store Snapshot

Artifact:

- `benchmark_results/local_bench_429_no_store_20260622.json`
- `benchmark_results/local_bench_core_429_no_store_20260622.json`

This snapshot adds `Cache-Control: no-store` to AlturaProt-generated HTTP `429` rate-limit responses while preserving `Retry-After: 1`. RFC 6585 says 429 responses must not be stored by caches, so the generated limiter response now states that contract explicitly for intermediaries and monitors.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9291.40 RPS | `204: 18619` | 0 | 12.137 ms |
| admin health | 9386.77 RPS | `200: 18811` | 0 | 12.043 ms |
| raw TCP persistent echo | 19098.06 msg/s | `38242` echoed messages | 0 | 3.079 ms |

429 header guardrails:

| Probe | Statuses | `Retry-After` headers | `Cache-Control` headers |
| --- | --- | --- | --- |
| admin per-client rate limit | `200, 429` | `1` | `no-store` |
| trusted-proxy aggregate rate limit | `204, 204, 429, 429` | `1, 1` | `no-store, no-store` |
| signature rate limit | `204, 204, 429, 429` | `1, 1` | `no-store, no-store` |
| path-shape rate limit | `204, 204, 429, 429` | `1, 1` | `no-store, no-store` |
| admin signature rate limit | `200, 200, 429, 429` | `1, 1` | `no-store, no-store` |

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 6613.40 RPS | `204: 13272` | 0 | 17.248 ms |
| admin health | 6542.70 RPS | `200: 13135` | 0 | 17.429 ms |
| raw TCP persistent echo | 24872.33 msg/s | `49833` echoed messages | 0 | 2.590 ms |

Core 429 header guardrails matched local behavior: admin per-client limiting returned `200, 429` with `Retry-After: 1` and `Cache-Control: no-store`; trusted-proxy aggregate, signature, and path-shape probes returned `204, 204, 429, 429` with headers `1, 1` and `no-store, no-store`; admin signature limiting returned `200, 200, 429, 429` with headers `1, 1` and `no-store, no-store`.

Validation commands:

```bash
cargo fmt --check
cargo test rate_limit -- --nocapture
cargo build --release
python3 -m py_compile tools/run_local_bench.py
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Upstream Overload Header Snapshot

Artifacts:

- `benchmark_results/local_bench_upstream_overload_headers_20260622.json`
- `benchmark_results/local_bench_core_upstream_overload_headers_20260622.json`

This snapshot adds `Cache-Control: no-store` to AlturaProt-generated upstream in-flight overload responses while preserving `Retry-After: 1`. The response remains `503 Service Unavailable`; the headers tell well-behaved clients to back off briefly and tell intermediaries not to store a temporary origin-shield rejection.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9416.62 RPS | `204: 18869` | 0 | 12.033 ms |
| admin health | 9437.65 RPS | `200: 18911` | 0 | 11.889 ms |
| raw TCP persistent echo | 19222.69 msg/s | `38486` echoed messages | 0 | 3.042 ms |

Upstream in-flight overload guardrail:

| Probe | Statuses | `Retry-After` headers | `Cache-Control` headers | Metric delta |
| --- | --- | --- | --- | --- |
| one slot held, second `/slow` request | first `204`, second `503` | `1` | `no-store` | `altura_http_upstream_in_flight_rejected: 1` |

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 6634.96 RPS | `204: 13314` | 0 | 17.413 ms |
| admin health | 6670.10 RPS | `200: 13389` | 0 | 17.190 ms |
| raw TCP persistent echo | 24591.64 msg/s | `49256` echoed messages | 0 | 2.639 ms |

Core upstream overload guardrails matched local behavior: the first slow upstream request completed with `204`, the second concurrent request returned `503`, `Retry-After: 1`, and `Cache-Control: no-store`, and `altura_http_upstream_in_flight_rejected` increased by `1`.

Validation commands:

```bash
cargo fmt --check
cargo test response_is -- --nocapture
cargo build --release
python3 -m py_compile tools/run_local_bench.py
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo test response_is -- --nocapture'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Request Timeout Close Snapshot

Artifacts:

- `benchmark_results/local_bench_request_timeout_close_20260622.json`
- `benchmark_results/local_bench_core_request_timeout_close_20260622.json`

This snapshot adds explicit `Connection: close` to generated `408 Request Timeout` responses from request-body idle timeout and request-body minimum-rate rejection. That matches the 408 contract that the server is done waiting for the request stream and prevents clients from attempting to reuse the timed-out connection when downstream keep-alive is enabled.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9383.59 RPS | `204: 18807` | 0 | 11.994 ms |
| admin health | 9428.45 RPS | `200: 18891` | 0 | 12.036 ms |
| raw TCP persistent echo | 19243.96 msg/s | `38529` echoed messages | 0 | 3.058 ms |

408 close guardrails:

| Probe | Status | `Connection` header | Metric |
| --- | --- | --- | --- |
| idle request-body timeout | `408` | `close` | `altura_http_body_timeouts` covered by existing slow-body probe |
| request-body minimum-rate timeout | `408` | `close` | `altura_http_body_too_slow: +1` |

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 6658.98 RPS | `204: 13361` | 0 | 17.058 ms |
| admin health | 6760.43 RPS | `200: 13570` | 0 | 16.887 ms |
| raw TCP persistent echo | 24297.26 msg/s | `48690` echoed messages | 0 | 2.636 ms |

Core 408 close guardrails matched local behavior: the idle slow-body probe returned `408` with `Connection: close`; the request-body minimum-rate probe returned `408` with `Connection: close` and the body-too-slow metric increased.

Validation commands:

```bash
cargo fmt --check
cargo test request_timeout_response_closes_connection -- --nocapture
cargo build --release
python3 -m py_compile tools/run_local_bench.py
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo test request_timeout_response_closes_connection -- --nocapture'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Content Too Large Close Snapshot

Artifacts:

- `benchmark_results/local_bench_content_too_large_close_20260622.json`
- `benchmark_results/local_bench_core_content_too_large_close_20260622.json`

This snapshot adds explicit `Connection: close` to generated `413 Content Too Large` responses from configured request-body size rejection. That matches the 413 contract that the server is refusing to process the request content and prevents clients from reusing a connection carrying rejected or unread oversized body bytes.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9249.35 RPS | `204: 18538` | 0 | 12.173 ms |
| admin health | 9460.70 RPS | `200: 18961` | 0 | 11.938 ms |
| raw TCP persistent echo | 19107.38 msg/s | `38256` echoed messages | 0 | 3.073 ms |

413 close guardrails:

| Probe | Status | `Connection` header |
| --- | --- | --- |
| oversized `Content-Length` POST | `413` | `close` |

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 6793.96 RPS | `204: 13632` | 0 | 16.693 ms |
| admin health | 6693.53 RPS | `200: 13434` | 0 | 17.087 ms |
| raw TCP persistent echo | 23896.18 msg/s | `47882` echoed messages | 0 | 2.692 ms |

Core 413 close guardrail matched local behavior: the oversized `Content-Length` POST returned `413` with `Connection: close`.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test content_too_large_response_closes_connection -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo test content_too_large_response_closes_connection -- --nocapture'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-retry-after-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 URI 414 No-Store Snapshot

Artifacts:

- `benchmark_results/local_bench_uri_414_no_store_20260622.json`
- `benchmark_results/local_bench_core_uri_414_no_store_20260622.json`

This snapshot adds `Cache-Control: no-store` to AlturaProt-generated `414 URI Too Long` responses from request-target pressure rejection. RFC 9110 makes 414 heuristically cacheable unless explicit cache controls say otherwise, and the same section calls out under-attack/security-hole cases, so generated DDoS guard responses now state that intermediaries must not store them.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9211.15 RPS | `204: 18456` | 0 | 12.292 ms |
| admin health | 9500.92 RPS | `200: 19035` | 0 | 11.884 ms |
| raw TCP persistent echo | 18517.12 msg/s | `37075` echoed messages | 0 | 3.207 ms |

414 no-store guardrails:

| Probe | Status | `Cache-Control` |
| --- | --- | --- |
| request target over `max_uri_bytes` | `414` | `no-store` |
| query string over `max_query_bytes` | `414` | `no-store` |
| query pairs over `max_query_pairs` | `414` | `no-store` |
| path segments over `max_path_segments` | `414` | `no-store` |

The local probe increased `altura_http_uri_rejected` by 4 and recorded `generated_414_not_stored: true`.

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 6656.80 RPS | `204: 13360` | 0 | 17.054 ms |
| admin health | 6548.47 RPS | `200: 13145` | 0 | 17.467 ms |
| raw TCP persistent echo | 25386.27 msg/s | `50875` echoed messages | 0 | 2.548 ms |

Core 414 no-store guardrails matched local behavior: all four URI pressure probes returned `414` with `Cache-Control: no-store`, `altura_http_uri_rejected` increased by 4, and `generated_414_not_stored` was true.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test request_target_rejected_response_is_not_stored -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-uri-414-no-store-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-uri-414-no-store-20260622 && cargo test request_target_rejected_response_is_not_stored -- --nocapture'
ssh core 'cd /tmp/altura-prot-uri-414-no-store-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-uri-414-no-store-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Method 405 No-Store Snapshot

Artifacts:

- `benchmark_results/local_bench_method_405_no_store_20260622.json`
- `benchmark_results/local_bench_core_method_405_no_store_20260622.json`

This snapshot adds `Cache-Control: no-store` to AlturaProt-generated `405 Method Not Allowed` responses while preserving the required `Allow` header. RFC 9110 makes 405 heuristically cacheable unless explicit cache controls say otherwise, so generated method-guard responses now avoid stale intermediary storage when `http.allowed_methods` changes or when disallowed-method traffic is attack-shaped.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9325.11 RPS | `204: 18710` | 0 | 12.205 ms |
| admin health | 9466.51 RPS | `200: 19175` | 0 | 11.942 ms |
| raw TCP persistent echo | 19156.50 msg/s | `38354` echoed messages | 0 | 3.076 ms |

405 no-store guardrails:

| Probe | Status | `Allow` | `Cache-Control` |
| --- | --- | --- | --- |
| `TRACE /` | `405` | `GET, POST` | `no-store` |
| `CONNECT 127.0.0.1:443` | `405` | `GET, POST` | `no-store` |
| `TRACK /` | `405` | `GET, POST` | `no-store` |
| `JEFF /` arbitrary extension method | `405` | `GET, POST` | `no-store` |

The local probe increased `altura_http_method_rejected` by 4 and recorded `generated_405_not_stored: true`.

Core release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 6779.31 RPS | `204: 13602` | 0 | 16.848 ms |
| admin health | 6583.42 RPS | `200: 13214` | 0 | 17.301 ms |
| raw TCP persistent echo | 24498.73 msg/s | `49079` echoed messages | 0 | 2.635 ms |

Core 405 no-store guardrails matched local behavior: all four disallowed-method probes returned `405` with `Allow: GET, POST`, `Cache-Control: no-store`, `altura_http_method_rejected` increased by 4, and `generated_405_not_stored` was true.

Validation commands:

```bash
cargo fmt --check
python3 -m py_compile tools/run_local_bench.py
cargo test method_not_allowed_response_preserves_allow_and_is_not_stored -- --nocapture
cargo build --release
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-method-405-no-store-20260622 && python3 -m py_compile tools/run_local_bench.py tools/run_defense_bench.py tools/test_ai_tools.py tools/codex_analyzer.py'
ssh core 'cd /tmp/altura-prot-method-405-no-store-20260622 && cargo test method_not_allowed_response_preserves_allow_and_is_not_stored -- --nocapture'
ssh core 'cd /tmp/altura-prot-method-405-no-store-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-method-405-no-store-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

## 2026-06-22 Path-Shape Rate-Limit Snapshot

Artifacts:

- `benchmark_results/local_bench_path_shape_rate_20260622.json`
- `benchmark_results/local_bench_core_path_shape_rate_20260622.json`

This snapshot adds a bounded normalized path-shape request-rate cap next to the existing normalized signature cap. Signature caps catch one repeated method/path/query/user-agent/accept shape; path-shape caps catch polymorphic route-family floods where attackers rotate readable tokens inside the same route family, for example `/api/abcdefghij/123`, `/api/klmnopqrst/456`, `/api/ZYXWVUTSRQ/789`, and `/api/qwertyuiop/321` all mapping to `/api/:token/:num`.

Local release build, loopback only:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream | 9277.87 RPS | `204: 18595` | 0 | 12.069 ms |
| admin health | 9506.85 RPS | `200: 19053` | 0 | 11.820 ms |
| raw TCP persistent echo | 19062.97 msg/s | `38166` echoed messages | 0 | 3.102 ms |

Path-shape guardrails:

| Probe | Result |
| --- | --- |
| configured `path_shape_rps` / burst | `0.000001` / `2` |
| four same-shape, distinct-signature API requests | `204, 204, 429, 429` |
| unrelated shape `/api/catalog/123` | `204` |
| `altura_http_path_shape_rate_limited` delta | `2` |
| `altura_http_rate_limited` delta | `2` |

Core server validation:

| Scenario | Throughput | Statuses/messages | Errors | p95 latency |
| --- | ---: | --- | ---: | ---: |
| proxied fixed HTTP upstream on `core` | 6679.65 RPS | `204: 13407` | 0 | 17.029 ms |
| admin health on `core` | 6654.40 RPS | `200: 13356` | 0 | 17.149 ms |
| raw TCP persistent echo on `core` | 25750.12 msg/s | `51601` echoed messages | 0 | 2.510 ms |

Core guardrails matched local behavior: the same-shape API burst returned `204, 204, 429, 429`, a different path shape returned `204`, `altura_http_path_shape_rate_limited` increased by 2, and the aggregate `altura_http_rate_limited` counter also increased by 2.

Validation commands:

```bash
cargo fmt --check
cargo test path_shape_rate
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 -m py_compile tools/run_local_bench.py tools/codex_analyzer.py tools/test_ai_tools.py tools/validate_edge_templates.py
python3 tools/test_ai_tools.py
python3 tools/validate_edge_templates.py --config configs/example.json
python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32
ssh core 'cd /tmp/altura-prot-path-shape-rate-20260622 && python3 -m py_compile tools/run_local_bench.py tools/codex_analyzer.py tools/test_ai_tools.py tools/validate_edge_templates.py'
ssh core 'cd /tmp/altura-prot-path-shape-rate-20260622 && python3 tools/test_ai_tools.py'
ssh core 'cd /tmp/altura-prot-path-shape-rate-20260622 && cargo test path_shape_rate'
ssh core 'cd /tmp/altura-prot-path-shape-rate-20260622 && cargo test'
ssh core 'cd /tmp/altura-prot-path-shape-rate-20260622 && cargo build --release'
ssh core 'cd /tmp/altura-prot-path-shape-rate-20260622 && python3 tools/run_local_bench.py --duration 2 --workers 64 --tcp-workers 32'
```

Core note: local Clippy passed with `-D warnings`; Core validation used test/build/benchmark.
