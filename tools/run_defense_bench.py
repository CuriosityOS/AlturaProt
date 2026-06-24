#!/usr/bin/env python3
"""Run local-only AlturaProt defense layer benchmarks.

The runner starts a loopback upstream, launches AlturaProt with temporary
configs, drives controlled HTTP flood patterns, and measures direct baseline,
proxy overhead, deterministic limits, learned filters, and trusted-proxy/XFF
spoof simulations. It never sends traffic to non-loopback targets.
"""

from __future__ import annotations

import argparse
import collections
import http.client
import json
import os
import random
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from bench_provenance import generated_at_utc, source_tree_metadata


TEST_NETS = ["192.0.2", "198.51.100", "203.0.113"]
SMART_ENDPOINTS = [
    "login",
    "search",
    "item",
    "object",
    "cart",
    "profile",
]
POLYMORPHIC_QUERY_KEYS = [
    "a",
    "b",
    "cache",
    "client",
    "cursor",
    "debug",
    "feature",
    "filter",
    "id",
    "page",
    "q",
    "ref",
    "region",
    "session",
    "sort",
    "ts",
    "view",
    "x",
    "y",
    "z",
]
BYPASS_DICTIONARY_SLUGS = [
    "subscription",
    "dashboard",
    "catalog",
    "inventory",
    "marketplace",
    "onboarding",
    "configuration",
    "authentication",
    "notifications",
    "transactions",
    "organization",
    "fulfillment",
    "warehouses",
]
ACCEPT_VARIANTS = [
    "*/*",
    "text/html,application/xhtml+xml",
    "application/json",
    "text/plain;q=0.9,*/*;q=0.8",
    "application/vnd.api+json",
]
METHOD_VARIANTS = ["GET", "HEAD", "OPTIONS"]
ADVANCED_SCENARIOS = [
    "catalog-mimic-xff",
    "dictionary-slug-xff",
    "hex-slug-xff",
    "v2-polymorphic-xff",
    "method-spray-xff",
    "accept-spray-xff",
    "legit-interleave-xff",
    "slow-xff-polymorphic",
    "mozilla-polymorphic-xff",
]
BASE_SCENARIOS = [
    "basic",
    "cachebuster",
    "rotating-path",
    "uuid-path",
    "mixed-user-agent",
    "smart-api-mix",
    "xff-single",
    "xff-rotating",
    "xff-polymorphic",
]
KNOWN_SCENARIOS = set(BASE_SCENARIOS) | set(ADVANCED_SCENARIOS)
DEFENSE_METRIC_KEYS = [
    "altura_http_blocked",
    "altura_http_rate_limited",
    "altura_http_trusted_proxy_rate_limited",
    "altura_http_trusted_proxy_in_flight_rejected",
    "altura_http_signature_rate_limited",
    "altura_http_path_shape_rate_limited",
]

BYPASS_PROBE_REFILL_SECONDS = 1.2
BYPASS_PROBE_DURATION_SECONDS = 0.75
BYPASS_PROBE_WORKERS = 1
BYPASS_PROBE_SLEEP_SECONDS = 0.03
ERROR_SAMPLE_LIMIT = 8


@dataclass
class PhaseResult:
    requests: int = 0
    errors: int = 0
    hung_workers: int = 0
    workers: int = 0
    statuses: collections.Counter[int] = field(default_factory=collections.Counter)
    first_status_at: dict[int, float] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)
    error_samples: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def record_error(self, err: BaseException | str) -> None:
        self.errors += 1
        if len(self.error_samples) < ERROR_SAMPLE_LIMIT:
            if isinstance(err, str):
                sample = err
            else:
                sample = f"{type(err).__name__}: {err}"
            self.error_samples.append(sample[:240])


class UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        buf = b""
        while True:
            try:
                data = self.request.recv(4096)
            except (ConnectionResetError, BrokenPipeError):
                return
            if not data:
                return
            buf += data
            if b"\r\n\r\n" not in buf:
                continue
            buf = b""
            try:
                self.request.sendall(
                    b"HTTP/1.1 204 No Content\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                )
            except (ConnectionResetError, BrokenPipeError):
                return


class UpstreamServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/release/altura-prot")
    parser.add_argument("--provider", default="codex", choices=["codex", "openai", "anthropic", "openrouter"])
    parser.add_argument("--no-codex", action="store_true", help="Use deterministic analyzer fallback only")
    parser.add_argument("--duration", type=float, default=2.5)
    parser.add_argument("--workers", type=int, default=48)
    parser.add_argument("--analyzer-wait", type=float, default=30.0)
    parser.add_argument("--per-ip-rps", type=int, default=80)
    parser.add_argument("--path-shape-rps", type=int, default=80)
    parser.add_argument("--signature-threshold", type=int, default=60)
    parser.add_argument("--workdir", default=None)
    parser.add_argument(
        "--scenarios",
        default=",".join(BASE_SCENARIOS),
        help="Comma-separated scenario list",
    )
    parser.add_argument(
        "--preset",
        choices=["base", "advanced", "all"],
        default=None,
        help="Scenario preset; overrides --scenarios when set",
    )
    parser.add_argument("--json-only", action="store_true")
    return parser.parse_args()


def resolve_scenarios(args: argparse.Namespace) -> list[str]:
    if args.preset == "base":
        return list(BASE_SCENARIOS)
    if args.preset == "advanced":
        return list(ADVANCED_SCENARIOS)
    if args.preset == "all":
        return list(BASE_SCENARIOS) + list(ADVANCED_SCENARIOS)
    return [item.strip() for item in args.scenarios.split(",") if item.strip()]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def tail_text(path: Path, max_bytes: int = 2000) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes), os.SEEK_SET)
            return handle.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def wait_health(
    port: int,
    process: subprocess.Popen[str] | None = None,
    log_path: Path | None = None,
) -> None:
    deadline = time.time() + 15
    conn: http.client.HTTPConnection | None = None
    last_error = None
    last_status = None
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            log_tail = tail_text(log_path) if log_path is not None else ""
            raise RuntimeError(
                f"proxy exited before ready with status {process.returncode}: {log_tail}"
            )
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
            conn.request("GET", "/__altura/health")
            resp = conn.getresponse()
            resp.read()
            last_status = resp.status
            if resp.status == 200:
                return
        except Exception as exc:
            last_error = type(exc).__name__
            time.sleep(0.1)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
    log_tail = tail_text(log_path) if log_path is not None else ""
    detail = f": {log_tail}" if log_tail else ""
    raise RuntimeError(
        f"proxy did not become ready; last_status={last_status}; "
        f"last_error={last_error}{detail}"
    )


def fetch_metrics(port: int, token: str = "bench-token") -> dict[str, float]:
    deadline = time.time() + 20.0
    last_error = "no attempts"
    while True:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
        try:
            conn.request("GET", "/__altura/metrics", headers={"x-altura-admin-token": token})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status == 200:
                metrics: dict[str, float] = {}
                for line in body.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) != 2:
                        continue
                    try:
                        metrics[parts[0]] = float(parts[1])
                    except ValueError:
                        continue
                return metrics
            if resp.status != 429 or time.time() >= deadline:
                raise RuntimeError(f"metrics returned HTTP {resp.status}")
            last_error = f"HTTP {resp.status}"
        except (TimeoutError, OSError, http.client.HTTPException) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if time.time() >= deadline:
                raise RuntimeError(f"metrics request failed: {last_error}") from exc
        finally:
            conn.close()
        if time.time() >= deadline:
            raise RuntimeError(f"metrics request failed: {last_error}")
        time.sleep(0.05)


def try_fetch_metrics(port: int, token: str = "bench-token") -> tuple[dict[str, float], str | None]:
    try:
        return fetch_metrics(port, token), None
    except RuntimeError as exc:
        return {}, str(exc)


def selected_metrics_delta(before: dict[str, float], after: dict[str, float]) -> dict[str, int]:
    return {
        key: int(after.get(key, 0) - before.get(key, 0))
        for key in DEFENSE_METRIC_KEYS
    }


def catalog_mimic_path(rng: random.Random) -> str:
    return f"/api/catalog/{rng.randrange(10_000)}?page={rng.randrange(8)}&sort={rng.choice(['asc', 'desc'])}"


def dictionary_slug_path(rng: random.Random) -> str:
    slug = rng.choice(BYPASS_DICTIONARY_SLUGS)
    return f"/api/{slug}/{rng.randrange(10_000)}?ref={rng.randrange(10**6)}"


def hex_slug_path(rng: random.Random) -> str:
    slug = "".join(rng.choice("0123456789abcdef") for _ in range(20))
    return f"/api/{slug}/{rng.randrange(10**5)}?view=compact"


def v2_polymorphic_path(rng: random.Random) -> str:
    slug = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(10))
    keys = rng.sample(POLYMORPHIC_QUERY_KEYS, 1 + rng.randrange(3))
    query = "&".join(f"{key}={rng.randrange(10**9)}" for key in keys)
    return f"/api/v2/{slug}/{rng.randrange(10**5)}?{query}"


def legit_interleave_path(rng: random.Random) -> str:
    if rng.randrange(100) < 70:
        return catalog_mimic_path(rng)
    return polymorphic_path(rng)


def scenario_path_builder(scenario: str, bypass: bool = False) -> Callable[[random.Random], str]:
    if bypass:
        if scenario == "cachebuster":
            return lambda rng: f"/api/search?q={rng.randrange(10**6)}&page={rng.randrange(10)}"
        if scenario in {"rotating-path", "uuid-path"}:
            return lambda rng: f"/api/product/{rng.randrange(10**9)}?view=compact"
        if scenario in {"smart-api-mix", "xff-polymorphic", *ADVANCED_SCENARIOS}:
            return lambda rng: f"/api/catalog/{rng.randrange(1000)}?page={rng.randrange(5)}"
        return lambda rng: "/api/login?legit=1"
    if scenario == "catalog-mimic-xff":
        return catalog_mimic_path
    if scenario == "dictionary-slug-xff":
        return dictionary_slug_path
    if scenario == "hex-slug-xff":
        return hex_slug_path
    if scenario == "v2-polymorphic-xff":
        return v2_polymorphic_path
    if scenario == "legit-interleave-xff":
        return legit_interleave_path
    if scenario in {"method-spray-xff", "accept-spray-xff", "slow-xff-polymorphic", "mozilla-polymorphic-xff"}:
        return polymorphic_path
    if scenario == "smart-api-mix":
        return smart_api_mix_path
    if scenario == "xff-polymorphic":
        return polymorphic_path
    if scenario == "cachebuster":
        return lambda rng: f"/api/search?cachebust={rng.randrange(10**12)}&id={rng.randrange(1000)}"
    if scenario == "rotating-path":
        return lambda rng: f"/api/item/{rng.randrange(10**9)}?view=full"
    if scenario == "uuid-path":
        return lambda rng: (
            f"/api/object/{rng.randrange(16**8):08x}-{rng.randrange(16**4):04x}-"
            f"{rng.randrange(16**4):04x}-{rng.randrange(16**4):04x}-"
            f"{rng.randrange(16**12):012x}?view=full"
        )
    return lambda rng: "/api/login"


def smart_api_mix_path(rng: random.Random) -> str:
    endpoint = rng.choice(SMART_ENDPOINTS)
    if endpoint == "login":
        return "/api/login"
    if endpoint == "search":
        return f"/api/search?cachebust={rng.randrange(10**12)}&id={rng.randrange(1000)}"
    if endpoint == "item":
        return f"/api/item/{rng.randrange(10**9)}?view=full"
    if endpoint == "object":
        return (
            f"/api/object/{rng.randrange(16**8):08x}-{rng.randrange(16**4):04x}-"
            f"{rng.randrange(16**4):04x}-{rng.randrange(16**4):04x}-"
            f"{rng.randrange(16**12):012x}?view=full"
        )
    if endpoint == "cart":
        return f"/api/cart/{rng.randrange(10**7)}/checkout?step={rng.choice(['ship', 'pay', 'review'])}"
    return f"/api/profile/{rng.randrange(10**8)}?include={rng.choice(['orders', 'settings', 'teams'])}"


def polymorphic_path(rng: random.Random) -> str:
    slug = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(10))
    key_count = 1 + rng.randrange(4)
    keys = rng.sample(POLYMORPHIC_QUERY_KEYS, key_count)
    query = "&".join(f"{key}={rng.randrange(10**9)}" for key in keys)
    return f"/api/{slug}/{rng.randrange(10**5)}?{query}"


def scenario_user_agents(scenario: str, bypass: bool = False) -> list[str]:
    if bypass:
        return ["Mozilla/5.0 altura-legit-probe"]
    if scenario == "mozilla-polymorphic-xff":
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ]
    if scenario in {"mixed-user-agent", "smart-api-mix", "xff-polymorphic", *ADVANCED_SCENARIOS}:
        return ["curl/8.0", "python-requests/2.32", "Mozilla/5.0 altura-e2e", "node-fetch/3"]
    return ["curl/8.0"]


def scenario_xff(scenario: str, rng: random.Random, bypass: bool = False) -> str | None:
    if bypass and (scenario == "xff-single" or scenario in {"xff-rotating", "xff-polymorphic", *ADVANCED_SCENARIOS}):
        return "198.51.100.250"
    if scenario == "xff-single":
        return "198.51.100.10"
    if scenario in {"xff-rotating", "xff-polymorphic", *ADVANCED_SCENARIOS}:
        net = TEST_NETS[rng.randrange(len(TEST_NETS))]
        return f"{net}.{1 + rng.randrange(240)}"
    return None


def scenario_method(scenario: str, rng: random.Random) -> str:
    if scenario == "method-spray-xff":
        return rng.choice(METHOD_VARIANTS)
    return "GET"


def scenario_accept(scenario: str, rng: random.Random) -> str:
    if scenario == "accept-spray-xff":
        return rng.choice(ACCEPT_VARIANTS)
    return "*/*"


def scenario_per_request_sleep(scenario: str) -> float:
    if scenario == "slow-xff-polymorphic":
        return 0.04
    return 0.0


def scenario_worker_count(
    scenario: str,
    workers: int,
    bypass: bool = False,
    direct_baseline: bool = False,
) -> int:
    if not bypass and not direct_baseline and scenario == "slow-xff-polymorphic":
        return max(workers, 128)
    return workers


def scenario_description(scenario: str) -> str:
    descriptions = {
        "catalog-mimic-xff": "Rotating XFF with benign catalog-shaped paths to evade :token filters",
        "dictionary-slug-xff": "Rotating XFF with dictionary API slugs that avoid :token normalization",
        "hex-slug-xff": "Rotating XFF with long hex path segments mapped to :hex instead of :token",
        "v2-polymorphic-xff": "Rotating XFF on /api/v2/:token/:num paths outside learned /api/:token/:num shape",
        "method-spray-xff": "Rotating XFF plus GET/HEAD/OPTIONS method spray to diversify signatures",
        "accept-spray-xff": "Rotating XFF plus Accept-header spray to diversify signatures",
        "legit-interleave-xff": "Rotating XFF mixing 70% catalog traffic with 30% polymorphic attack paths",
        "slow-xff-polymorphic": "Low-and-slow rotating-XFF polymorphic flood under per-IP and shape thresholds",
        "mozilla-polymorphic-xff": "Rotating XFF polymorphic paths with browser-like Mozilla user agents only",
    }
    return descriptions.get(scenario, "")


def response_closes_connection(resp: http.client.HTTPResponse) -> bool:
    connection = resp.getheader("Connection") or ""
    tokens = [token.strip().lower() for token in connection.split(",")]
    return "close" in tokens or bool(getattr(resp, "will_close", False))


def run_phase(
    port: int,
    scenario: str,
    duration: float,
    workers: int,
    bypass: bool = False,
    per_request_sleep: float | None = None,
    direct_baseline: bool = False,
) -> PhaseResult:
    request_timeout_seconds = 1.0
    stop_at = time.perf_counter() + duration
    started = time.perf_counter()
    result = PhaseResult()
    lock = threading.Lock()
    abandoned = threading.Event()
    path_builder = scenario_path_builder(scenario, bypass)
    user_agents = scenario_user_agents(scenario, bypass)
    if per_request_sleep is None:
        per_request_sleep = scenario_per_request_sleep(scenario)
    phase_workers = scenario_worker_count(scenario, workers, bypass, direct_baseline)
    result.workers = phase_workers

    def worker(worker_id: int) -> None:
        conn: http.client.HTTPConnection | None = None
        rng = random.Random((worker_id + 1) * 7919)
        local = PhaseResult()
        while time.perf_counter() < stop_at:
            req_started = time.perf_counter()
            headers = {
                "User-Agent": rng.choice(user_agents),
                "Accept": scenario_accept(scenario, rng),
            }
            if xff := scenario_xff(scenario, rng, bypass):
                headers["X-Forwarded-For"] = xff
            method = scenario_method(scenario, rng)
            path = path_builder(rng)
            for attempt in range(2):
                try:
                    if conn is None:
                        conn = http.client.HTTPConnection(
                            "127.0.0.1", port, timeout=request_timeout_seconds
                    )
                    conn.request(method, path, headers=headers)
                    resp = conn.getresponse()
                    should_close = response_closes_connection(resp)
                    resp.read()
                    now = time.perf_counter()
                    elapsed_ms = (now - req_started) * 1000
                    local.requests += 1
                    local.statuses[resp.status] += 1
                    local.first_status_at.setdefault(resp.status, now - started)
                    if len(local.latencies_ms) < 5000:
                        local.latencies_ms.append(elapsed_ms)
                    if should_close and conn is not None:
                        conn.close()
                        conn = None
                    if per_request_sleep > 0:
                        time.sleep(per_request_sleep)
                    break
                except (
                    http.client.RemoteDisconnected,
                    BrokenPipeError,
                    ConnectionResetError,
                    TimeoutError,
                ) as err:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    conn = None
                    if attempt == 0:
                        continue
                    local.record_error(err)
                    break
                except Exception as err:
                    local.record_error(err)
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    conn = None
                    break
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        with lock:
            if abandoned.is_set():
                return
            result.requests += local.requests
            result.errors += local.errors
            result.statuses.update(local.statuses)
            result.latencies_ms.extend(local.latencies_ms)
            remaining_samples = ERROR_SAMPLE_LIMIT - len(result.error_samples)
            if remaining_samples > 0:
                result.error_samples.extend(local.error_samples[:remaining_samples])
            for status, first_at in local.first_status_at.items():
                if status not in result.first_status_at or first_at < result.first_status_at[status]:
                    result.first_status_at[status] = first_at

    threads = [
        threading.Thread(target=worker, args=(idx,), daemon=True)
        for idx in range(max(1, phase_workers))
    ]
    for thread in threads:
        thread.start()
    join_deadline = stop_at + request_timeout_seconds + 2.0
    for thread in threads:
        thread.join(max(0.0, join_deadline - time.perf_counter()))
    hung_workers = sum(1 for thread in threads if thread.is_alive())
    if hung_workers:
        abandoned.set()
        with lock:
            result.hung_workers += hung_workers
            result.errors += hung_workers
            remaining_samples = ERROR_SAMPLE_LIMIT - len(result.error_samples)
            if remaining_samples > 0:
                result.error_samples.extend(
                    ["hung worker exceeded phase join deadline"] * min(hung_workers, remaining_samples)
                )
    result.elapsed_seconds = max(0.001, time.perf_counter() - started)
    return result


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    idx = min(len(values) - 1, int(round((pct / 100.0) * (len(values) - 1))))
    return values[idx]


def summarize_phase(result: PhaseResult) -> dict[str, Any]:
    statuses = {str(status): count for status, count in sorted(result.statuses.items())}
    blocked = result.statuses.get(403, 0)
    limited = result.statuses.get(429, 0)
    allowed = sum(count for status, count in result.statuses.items() if 200 <= status < 300)
    total = max(1, result.requests)
    first_block = result.first_status_at.get(403)
    first_limit = result.first_status_at.get(429)
    return {
        "requests": result.requests,
        "errors": result.errors,
        "error_samples": result.error_samples,
        "hung_workers": result.hung_workers,
        "workers": result.workers,
        "requests_per_second": round(result.requests / max(0.001, result.elapsed_seconds), 2),
        "statuses": statuses,
        "allowed_percent": round((allowed / total) * 100, 2),
        "blocked_percent": round((blocked / total) * 100, 2),
        "limited_percent": round((limited / total) * 100, 2),
        "first_block_seconds": round(first_block, 3) if first_block is not None else None,
        "first_limit_seconds": round(first_limit, 3) if first_limit is not None else None,
        "latency_ms": {
            "p50": round(percentile(result.latencies_ms, 50), 3) if result.latencies_ms else None,
            "p95": round(percentile(result.latencies_ms, 95), 3) if result.latencies_ms else None,
            "p99": round(percentile(result.latencies_ms, 99), 3) if result.latencies_ms else None,
        },
    }


def write_config(
    base: Path,
    proxy_port: int,
    upstream_port: int,
    per_ip_rps: int,
    signature_threshold: int,
    adaptive_enabled: bool,
    trusted_xff: bool,
    static_filter: bool = False,
    limit_overrides: dict[str, Any] | None = None,
) -> tuple[Path, Path, Path]:
    filters = base / f"filters-{proxy_port}.json"
    events = base / f"events-{proxy_port}.jsonl"
    filters.write_text('{"filters": []}\n', encoding="utf-8")
    static_rules: list[dict[str, Any]] = []
    if static_filter:
        static_rules.append(
            {
                "id": "bench-static-api-filter",
                "enabled": True,
                "adaptive": False,
                "priority": 200,
                "condition": {"path_prefix": "/api/"},
                "action": {"kind": "block", "status": 403, "body": "blocked by static filter\n"},
            }
        )
    config: dict[str, Any] = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "bench-token",
            "downstream_keep_alive": True,
            "limits": {
                "per_ip_rps": per_ip_rps,
                "per_ip_burst": per_ip_rps,
                "global_rps": 100_000,
                "global_burst": 100_000,
                "per_ip_connects_per_second": 1_000_000,
                "per_ip_connect_burst": 1_000_000,
                "global_connects_per_second": 1_000_000,
                "global_connect_burst": 1_000_000,
                "max_connections": 20_000,
                "max_connections_per_ip": 20_000,
                "max_in_flight_requests": 20_000,
                "max_in_flight_requests_per_ip": 20_000,
                "max_tracked_ips": 65_536,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters),
            "reload_seconds": 1,
            "static_rules": static_rules,
        },
        "adaptive": {
            "enabled": adaptive_enabled,
            "signature_threshold_per_second": signature_threshold,
            "activation_ttl_seconds": 20,
            "event_log": str(events),
            "event_cooldown_seconds": 1,
        },
    }
    if trusted_xff:
        config["http"]["client_ip"] = {
            "header": "x-forwarded-for",
            "trusted_proxies": ["127.0.0.1/32"],
        }
        config["http"]["limits"]["trusted_proxy_rps"] = per_ip_rps
        config["http"]["limits"]["trusted_proxy_burst"] = per_ip_rps
    if limit_overrides:
        config["http"]["limits"].update(limit_overrides)
    path = base / f"config-{proxy_port}.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path, filters, events


def high_request_limit_overrides(value: int) -> dict[str, Any]:
    return {
        "global_rps": value,
        "global_burst": value,
        "trusted_proxy_rps": value,
        "trusted_proxy_burst": value,
        "signature_rps": value,
        "signature_burst": value,
        "max_tracked_signatures": 65_536,
        "path_shape_rps": value,
        "path_shape_burst": value,
        "max_tracked_path_shapes": 65_536,
    }


def start_proxy(binary: Path, config_path: Path, log_path: Path) -> subprocess.Popen[str]:
    log_file = log_path.open("w")
    try:
        process = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=log_file,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
    except Exception:
        log_file.close()
        raise
    process._altura_log_file = log_file  # type: ignore[attr-defined]
    return process


def stop_process(proc: subprocess.Popen[Any] | None) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    log_file = getattr(proc, "_altura_log_file", None)
    if log_file is not None:
        log_file.close()


def start_analyzer(
    args: argparse.Namespace,
    events_path: Path,
    filters_path: Path,
    log_path: Path,
    learn_observed: bool,
) -> subprocess.Popen[str]:
    tools_dir = Path(__file__).resolve().parent
    cmd = [
        sys.executable,
        str(tools_dir / "codexsdgate.py"),
        "--events",
        str(events_path),
        "--filters",
        str(filters_path),
        "--provider",
        args.provider,
        "--interval",
        "1",
        "--min-count",
        "1",
        "--ttl-seconds",
        "20",
    ]
    if args.no_codex:
        cmd.append("--no-codex")
    if learn_observed:
        cmd.append("--learn-observed")
    log_file = log_path.open("w")
    try:
        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
    except Exception:
        log_file.close()
        raise
    process._altura_log_file = log_file  # type: ignore[attr-defined]
    return process


def read_filters(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    filters = data.get("filters", []) if isinstance(data, dict) else []
    return [item for item in filters if isinstance(item, dict)]


def wait_for_filters(path: Path, started: float, timeout: float) -> tuple[list[dict[str, Any]], float | None]:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        filters = read_filters(path)
        if filters:
            return filters, time.perf_counter() - started
        time.sleep(0.25)
    return [], None


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def summarize_events(events: list[dict[str, Any]], start_unix_ms: int) -> dict[str, Any]:
    reasons: collections.Counter[str] = collections.Counter(str(event.get("reason")) for event in events)
    first = None
    bases_by_signature: dict[str, str] = {}
    for event in events:
        ts = event.get("ts_unix_ms")
        if isinstance(ts, int) and ts >= start_unix_ms:
            delta = (ts - start_unix_ms) / 1000
            first = delta if first is None else min(first, delta)
        signature = event.get("signature")
        basis = event.get("signature_basis")
        if isinstance(signature, str) and isinstance(basis, str):
            bases_by_signature.setdefault(signature, basis)
    signatures = {str(event.get("signature")) for event in events if event.get("signature")}
    return {
        "count": len(events),
        "reasons": dict(sorted(reasons.items())),
        "unique_signatures": len(signatures),
        "first_detection_seconds": round(first, 3) if first is not None else None,
        "signature_bases": dict(sorted(bases_by_signature.items())),
    }


def interpret_filters(filters: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bases: dict[str, str] = {}
    for event in events:
        signature = event.get("signature")
        basis = event.get("signature_basis")
        if isinstance(signature, str) and isinstance(basis, str):
            bases.setdefault(signature, basis)
    return [interpret_filter(item, bases) for item in filters]


def interpret_filter(item: dict[str, Any], bases: dict[str, str]) -> dict[str, Any]:
    condition = item.get("condition") if isinstance(item.get("condition"), dict) else {}
    signature = condition.get("signature")
    basis = bases.get(signature) if isinstance(signature, str) else None
    keys = sorted(str(key) for key in condition.keys())
    if isinstance(signature, str):
        kind = "normalized_signature" if basis and any(token in basis for token in [":num", ":uuid", ":hex", "cachebust,id"]) else "exact_signature"
        precision = "pattern" if kind == "normalized_signature" else "exact_request_shape"
    elif condition.get("path_exact"):
        kind = "exact_path"
        precision = "narrow"
    elif condition.get("path_shape"):
        kind = "path_shape"
        precision = "pattern"
    elif condition.get("path_prefix") or condition.get("path_contains"):
        kind = "path_pattern"
        precision = "medium"
    elif not condition:
        kind = "empty_condition"
        precision = "unsafe_broad"
    else:
        kind = "compound_condition"
        precision = "condition_based"
    return {
        "id": item.get("id"),
        "kind": kind,
        "precision": precision,
        "condition_keys": keys,
        "signature": signature,
        "signature_basis": basis,
        "not_ip_based": "client_ip" not in condition and "ip" not in condition,
        "adaptive": bool(item.get("adaptive")),
    }


def run_proxy_layer(
    args: argparse.Namespace,
    binary: Path,
    base: Path,
    upstream_port: int,
    scenario: str,
    layer: str,
    per_ip_rps: int,
    adaptive_enabled: bool,
    trusted_xff: bool,
    static_filter: bool = False,
    analyzer: bool = False,
    learn_observed: bool = False,
    limit_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    proxy: subprocess.Popen[str] | None = None
    startup_errors: list[str] = []
    for attempt in range(1, 4):
        proxy_port = free_port()
        config_path, filters_path, events_path = write_config(
            base,
            proxy_port,
            upstream_port,
            per_ip_rps,
            args.signature_threshold,
            adaptive_enabled,
            trusted_xff,
            static_filter,
            limit_overrides,
        )
        proxy_log = base / f"proxy-{layer}-{scenario}-attempt{attempt}.log"
        proxy = start_proxy(binary, config_path, proxy_log)
        try:
            wait_health(proxy_port, proxy, proxy_log)
            break
        except RuntimeError as err:
            startup_errors.append(f"attempt {attempt}: {err}")
            stop_process(proxy)
            proxy = None
            if attempt == 3:
                raise RuntimeError(
                    "proxy did not become ready after 3 attempts\n"
                    + "\n".join(startup_errors)
                ) from err
            time.sleep(0.2)
    metrics_before, metrics_before_error = try_fetch_metrics(proxy_port)
    metrics_errors = []
    if metrics_before_error is not None:
        metrics_errors.append(f"before: {metrics_before_error}")
    analyzer_proc: subprocess.Popen[str] | None = None
    try:
        analyzer_log = base / f"analyzer-{layer}-{scenario}.log"
        if analyzer:
            analyzer_proc = start_analyzer(args, events_path, filters_path, analyzer_log, learn_observed)
        collect_started_mono = time.perf_counter()
        collect_started_unix_ms = int(time.time() * 1000)
        collect = run_phase(
            proxy_port,
            scenario,
            args.duration,
            args.workers,
            per_request_sleep=scenario_per_request_sleep(scenario),
        )
        filters, filter_write_seconds = ([], None)
        if analyzer:
            filters, filter_write_seconds = wait_for_filters(filters_path, collect_started_mono, args.analyzer_wait)
            if filters:
                time.sleep(1.2)
        replay = (
            run_phase(
                proxy_port,
                scenario,
                args.duration,
                args.workers,
                per_request_sleep=scenario_per_request_sleep(scenario),
            )
            if analyzer
            else None
        )
        time.sleep(BYPASS_PROBE_REFILL_SECONDS)
        bypass = run_phase(
            proxy_port,
            scenario,
            BYPASS_PROBE_DURATION_SECONDS,
            BYPASS_PROBE_WORKERS,
            bypass=True,
            per_request_sleep=BYPASS_PROBE_SLEEP_SECONDS,
        )
        events = read_events(events_path)
        interpreted_filters = interpret_filters(filters, events)
        analyzer_tail: list[str] = []
        if analyzer_log.exists():
            analyzer_tail = analyzer_log.read_text(encoding="utf-8", errors="replace").splitlines()[-8:]
        metrics_after, metrics_after_error = try_fetch_metrics(proxy_port)
        if metrics_after_error is not None:
            metrics_errors.append(f"after: {metrics_after_error}")
        return {
            "layer": layer,
            "trusted_xff": trusted_xff,
            "learn_observed": learn_observed,
            "collect": summarize_phase(collect),
            "replay": summarize_phase(replay) if replay else None,
            "bypass_probe": summarize_phase(bypass) if bypass else None,
            "events": summarize_events(events, collect_started_unix_ms),
            "metrics_delta": selected_metrics_delta(metrics_before, metrics_after),
            "metrics_errors": metrics_errors,
            "filters_learned": len(filters),
            "filter_write_seconds": round(filter_write_seconds, 3) if filter_write_seconds is not None else None,
            "learned_filters": filters,
            "filter_interpretation": interpreted_filters,
            "analyzer_log_tail": analyzer_tail,
            "target_score": target_score(replay, bypass),
            "effective_target_score": target_score(replay or collect, bypass),
            "scenario_description": scenario_description(scenario),
        }
    finally:
        stop_process(analyzer_proc)
        stop_process(proxy)


def scenario_needs_xff_trust(scenario: str) -> bool:
    return scenario.startswith("xff-") or scenario in ADVANCED_SCENARIOS


def scenario_runs_observed_learning(scenario: str) -> bool:
    return scenario == "smart-api-mix" or scenario_needs_xff_trust(scenario)


def target_score(replay: PhaseResult | None, bypass: PhaseResult | None) -> dict[str, Any]:
    replay_summary = summarize_phase(replay) if replay else None
    bypass_summary = summarize_phase(bypass) if bypass else None
    attacker_blocked = replay_summary.get("blocked_percent", 0.0) if replay_summary else 0.0
    attacker_limited = replay_summary.get("limited_percent", 0.0) if replay_summary else 0.0
    replay_requests = replay.requests if replay else 0
    replay_errors = replay.errors if replay else 0
    blocked_or_limited_requests = (
        ((attacker_blocked + attacker_limited) / 100.0) * replay_requests
        if replay_requests
        else 0.0
    )
    attacker_attempts = replay_requests + replay_errors
    attacker_stopped = (
        min(100.0, ((blocked_or_limited_requests + replay_errors) / attacker_attempts) * 100.0)
        if attacker_attempts
        else 0.0
    )
    benign_allowed = bypass_summary.get("allowed_percent", None) if bypass_summary else None
    bypass_errors = bypass_summary.get("errors", 0) if bypass_summary else 0
    return {
        "attacker_block_target_percent": 90.0,
        "benign_allow_target_percent": 95.0,
        "attacker_blocked_percent": attacker_blocked,
        "attacker_limited_percent": attacker_limited,
        "attacker_blocked_or_limited_percent": attacker_stopped,
        "benign_allowed_percent": benign_allowed,
        "replay_errors": replay_errors,
        "bypass_errors": bypass_errors,
        "meets_attacker_block_target": attacker_stopped >= 90.0,
        "meets_benign_allow_target": (
            benign_allowed is not None and benign_allowed >= 95.0 and bypass_errors == 0
        ),
    }


def run_scenario(args: argparse.Namespace, binary: Path, base: Path, upstream_port: int, scenario: str) -> dict[str, Any]:
    direct = run_phase(
        upstream_port,
        scenario,
        args.duration,
        args.workers,
        direct_baseline=True,
    )
    high_rps = 1_000_000
    open_limit_overrides = high_request_limit_overrides(high_rps)
    path_shape_limit_overrides = {
        **open_limit_overrides,
        "path_shape_rps": args.path_shape_rps,
        "path_shape_burst": args.path_shape_rps,
    }
    result: dict[str, Any] = {
        "direct_upstream": summarize_phase(direct),
        "proxy_open": run_proxy_layer(
            args,
            binary,
            base,
            upstream_port,
            scenario,
            "proxy-open",
            high_rps,
            adaptive_enabled=False,
            trusted_xff=scenario_needs_xff_trust(scenario),
            limit_overrides=open_limit_overrides,
        ),
        "rate_limit": run_proxy_layer(
            args,
            binary,
            base,
            upstream_port,
            scenario,
            "rate-limit",
            args.per_ip_rps,
            adaptive_enabled=True,
            trusted_xff=scenario_needs_xff_trust(scenario),
        ),
        "path_shape_rate_limit": run_proxy_layer(
            args,
            binary,
            base,
            upstream_port,
            scenario,
            "path-shape-rate-limit",
            high_rps,
            adaptive_enabled=True,
            trusted_xff=scenario_needs_xff_trust(scenario),
            limit_overrides=path_shape_limit_overrides,
        ),
        "static_filter": run_proxy_layer(
            args,
            binary,
            base,
            upstream_port,
            scenario,
            "static-filter",
            high_rps,
            adaptive_enabled=True,
            trusted_xff=scenario_needs_xff_trust(scenario),
            static_filter=True,
            limit_overrides=open_limit_overrides,
        ),
        "learned_filter_strict": run_proxy_layer(
            args,
            binary,
            base,
            upstream_port,
            scenario,
            "learned-strict",
            args.per_ip_rps,
            adaptive_enabled=True,
            trusted_xff=scenario_needs_xff_trust(scenario),
            analyzer=True,
            learn_observed=False,
        ),
    }
    if scenario_runs_observed_learning(scenario):
        result["learned_filter_observed"] = run_proxy_layer(
            args,
            binary,
            base,
            upstream_port,
            scenario,
            "learned-observed",
            args.per_ip_rps,
            adaptive_enabled=True,
            trusted_xff=scenario_needs_xff_trust(scenario),
            analyzer=True,
            learn_observed=True,
        )
    return result


def layer_score(layer: dict[str, Any]) -> str:
    phase = layer.get("replay") or layer.get("collect") or {}
    blocked = phase.get("blocked_percent", 0)
    limited = phase.get("limited_percent", 0)
    allowed = phase.get("allowed_percent", 0)
    rps = phase.get("requests_per_second", 0)
    return f"allowed={allowed:>6.2f}% blocked={blocked:>6.2f}% limited={limited:>6.2f}% rps={rps}"


def print_table(report: dict[str, Any]) -> None:
    print("\nAlturaProt local defense benchmark")
    print(f"provider={report['provider']} workdir={report['workdir']}")
    for scenario, data in report["scenarios"].items():
        print(f"\n[{scenario}]")
        direct = data["direct_upstream"]
        print(f"direct_upstream     allowed={direct['allowed_percent']:>6.2f}% rps={direct['requests_per_second']}")
        for key in [
            "proxy_open",
            "rate_limit",
            "path_shape_rate_limit",
            "static_filter",
            "learned_filter_strict",
            "learned_filter_observed",
        ]:
            if key not in data:
                continue
            layer = data[key]
            events = layer.get("events", {})
            print(
                f"{key:<19} {layer_score(layer)} "
                f"detect={events.get('first_detection_seconds')}s "
                f"filters={layer.get('filters_learned')} write={layer.get('filter_write_seconds')}s"
            )
            for item in layer.get("filter_interpretation", []):
                print(
                    f"{'filter':<19} kind={item.get('kind')} precision={item.get('precision')} "
                    f"basis={item.get('signature_basis')}"
                )
            bypass = layer.get("bypass_probe")
            if bypass:
                print(
                    f"{'bypass_probe':<19} allowed={bypass['allowed_percent']:>6.2f}% "
                    f"blocked={bypass['blocked_percent']:>6.2f}% rps={bypass['requests_per_second']}"
                )


def main() -> None:
    args = parse_args()
    binary = Path(args.binary)
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary}; run cargo build --release first")
    scenarios = resolve_scenarios(args)
    unknown = [item for item in scenarios if item not in KNOWN_SCENARIOS]
    if unknown:
        raise SystemExit(f"unknown scenarios: {', '.join(unknown)}")

    with tempfile.TemporaryDirectory(dir=args.workdir) as tmp, UpstreamServer(("127.0.0.1", free_port()), UpstreamHandler) as upstream:
        base = Path(tmp)
        upstream_port = int(upstream.server_address[1])
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        report = {
            "generated_at_utc": generated_at_utc(),
            "provider": "deterministic" if args.no_codex else args.provider,
            "preset": args.preset or "custom",
            "source_tree": source_tree_metadata(Path.cwd()),
            "workdir": str(base),
            "duration_seconds": args.duration,
            "workers": args.workers,
            "analyzer_wait_seconds": args.analyzer_wait,
            "per_ip_rps": args.per_ip_rps,
            "path_shape_rps": args.path_shape_rps,
            "signature_threshold_per_second": args.signature_threshold,
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers from trusted localhost, not packet spoofing",
            "scenarios": {},
        }
        try:
            for scenario in scenarios:
                report["scenarios"][scenario] = run_scenario(args, binary, base, upstream_port, scenario)
            if not args.json_only:
                print_table(report)
            print(json.dumps(report, indent=2, sort_keys=True))
        finally:
            upstream.shutdown()


if __name__ == "__main__":
    main()
