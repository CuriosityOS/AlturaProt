#!/usr/bin/env python3
"""Bounded local HTTP flood/benchmark helper.

The default safety guard only permits loopback targets. Use --allow-non-loopback
only for owned private-LAN or link-local targets; public IPs are always refused.
"""

from __future__ import annotations

import argparse
import collections
import http.client
import ipaddress
import json
import socket
import ssl
import statistics
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

OWNED_LAN_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)
OWNED_LAN_IPV6_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("fc00::/7", "fe80::/10")
)


@dataclass
class WorkerResult:
    requests: int = 0
    errors: int = 0
    error_types: collections.Counter[str] = field(default_factory=collections.Counter)
    statuses: dict[int, int] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--workers", type=int, default=64)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--user-agent", default="altura-local-bench/1.0")
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="permit owned private-LAN/link-local targets; public IPs are still refused",
    )
    parser.add_argument("--timeout", type=float, default=2.0)
    return parser.parse_args()


def assert_loopback(url: str, allow_non_loopback: bool) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SystemExit("only http:// and https:// URLs are supported")
    if not parsed.hostname:
        raise SystemExit("URL must include a host")
    try:
        port = parsed.port or default_port(parsed.scheme)
    except ValueError as exc:
        raise SystemExit(f"invalid URL port: {exc}") from exc

    infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    resolved_ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        resolved_ips.append(str(ip))
        if ip.is_loopback:
            continue
        if allow_non_loopback and is_owned_lan_address(ip):
            continue
        if allow_non_loopback:
            raise SystemExit(
                f"refusing public or non-local target {parsed.hostname} resolved to {ip}; "
                "--allow-non-loopback only permits loopback, RFC1918/ULA, and link-local targets"
            )
        else:
            raise SystemExit(
                f"refusing non-loopback target {parsed.hostname} resolved to {ip}; "
                "pass --allow-non-loopback only for owned LAN tests"
            )
    if resolved_ips:
        return parsed
    raise SystemExit(
        f"refusing target {parsed.hostname}; no loopback addresses resolved"
    )


def is_owned_lan_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped_ipv4 = getattr(ip, "ipv4_mapped", None)
    if mapped_ipv4 is not None:
        ip = mapped_ipv4
    if ip.version == 4:
        return any(ip in network for network in OWNED_LAN_IPV4_NETWORKS)
    return any(ip in network for network in OWNED_LAN_IPV6_NETWORKS)


def default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def make_connection(parsed: urllib.parse.ParseResult, timeout: float) -> http.client.HTTPConnection:
    port = parsed.port or default_port(parsed.scheme)
    if parsed.scheme == "https":
        return http.client.HTTPSConnection(
            parsed.hostname,
            port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    return http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)


def worker(parsed: urllib.parse.ParseResult, args: argparse.Namespace, stop_at: float, result: WorkerResult) -> None:
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    conn: http.client.HTTPConnection | None = None
    headers = {"User-Agent": args.user_agent, "Accept": "*/*"}
    while time.perf_counter() < stop_at:
        started = time.perf_counter()
        try:
            if conn is None:
                conn = make_connection(parsed, args.timeout)
            conn.request(args.method.upper(), path, headers=headers)
            resp = conn.getresponse()
            resp.read()
            elapsed_ms = (time.perf_counter() - started) * 1000
            result.requests += 1
            result.statuses[resp.status] = result.statuses.get(resp.status, 0) + 1
            if len(result.latencies_ms) < 20_000:
                result.latencies_ms.append(elapsed_ms)
        except Exception as exc:
            result.errors += 1
            result.error_types[type(exc).__name__] += 1
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            conn = None
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    idx = min(len(values) - 1, int(round((pct / 100.0) * (len(values) - 1))))
    return values[idx]


def main() -> None:
    args = parse_args()
    parsed = assert_loopback(args.url, args.allow_non_loopback)
    stop_at = time.perf_counter() + args.duration
    results = [WorkerResult() for _ in range(max(1, args.workers))]
    threads = [
        threading.Thread(target=worker, args=(parsed, args, stop_at, result), daemon=True)
        for result in results
    ]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = max(0.001, time.perf_counter() - started)

    total_requests = sum(result.requests for result in results)
    total_errors = sum(result.errors for result in results)
    statuses: dict[int, int] = {}
    error_types: collections.Counter[str] = collections.Counter()
    latencies: list[float] = []
    for result in results:
        error_types.update(result.error_types)
        for status, count in result.statuses.items():
            statuses[status] = statuses.get(status, 0) + count
        latencies.extend(result.latencies_ms)

    report = {
        "url": args.url,
        "duration_seconds": round(elapsed, 3),
        "workers": args.workers,
        "requests": total_requests,
        "errors": total_errors,
        "error_types": dict(sorted(error_types.items())),
        "requests_per_second": round(total_requests / elapsed, 2),
        "statuses": dict(sorted(statuses.items())),
        "latency_ms": {
            "avg": round(statistics.fmean(latencies), 3) if latencies else None,
            "p50": round(percentile(latencies, 50), 3) if latencies else None,
            "p95": round(percentile(latencies, 95), 3) if latencies else None,
            "p99": round(percentile(latencies, 99), 3) if latencies else None,
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
