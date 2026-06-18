#!/usr/bin/env python3
"""Run loopback-only CodexSDGate end-to-end mitigation scenarios."""

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


@dataclass
class PhaseResult:
    requests: int = 0
    errors: int = 0
    statuses: collections.Counter[int] = field(default_factory=collections.Counter)


class UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        buf = b""
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            buf += data
            if b"\r\n\r\n" not in buf:
                continue
            buf = b""
            self.request.sendall(
                b"HTTP/1.1 204 No Content\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )


class UpstreamServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/release/altura-prot")
    parser.add_argument("--provider", default="codex", choices=["codex", "openai", "anthropic", "openrouter"])
    parser.add_argument("--no-codex", action="store_true")
    parser.add_argument("--duration", type=float, default=4.0)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--analyzer-wait", type=float, default=20.0)
    parser.add_argument("--verify-persistence", action="store_true")
    parser.add_argument("--workdir", default=None)
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_health(port: int) -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
            conn.request("GET", "/__altura/health")
            resp = conn.getresponse()
            resp.read()
            if resp.status == 200:
                return
        except Exception:
            time.sleep(0.1)
        finally:
            try:
                conn.close()  # type: ignore[name-defined]
            except Exception:
                pass
    raise RuntimeError("proxy did not become ready")


def run_phase(port: int, scenario: str, duration: float, workers: int) -> PhaseResult:
    stop_at = time.perf_counter() + duration
    result = PhaseResult()
    lock = threading.Lock()
    path_builder = scenario_path_builder(scenario)
    user_agents = scenario_user_agents(scenario)

    def worker(worker_id: int) -> None:
        conn: http.client.HTTPConnection | None = None
        rng = random.Random(worker_id)
        local = PhaseResult()
        while time.perf_counter() < stop_at:
            try:
                if conn is None:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
                path = path_builder(rng)
                headers = {"User-Agent": rng.choice(user_agents), "Accept": "*/*"}
                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                resp.read()
                local.requests += 1
                local.statuses[resp.status] += 1
            except Exception:
                local.errors += 1
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
        with lock:
            result.requests += local.requests
            result.errors += local.errors
            result.statuses.update(local.statuses)

    threads = [threading.Thread(target=worker, args=(idx,), daemon=True) for idx in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return result


def scenario_path_builder(scenario: str) -> Callable[[random.Random], str]:
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


def scenario_user_agents(scenario: str) -> list[str]:
    if scenario == "mixed-user-agent":
        return [
            "curl/8.0",
            "python-requests/2.32",
            "Mozilla/5.0 altura-e2e",
            "node-fetch/3",
        ]
    return ["curl/8.0"]


def write_config(base: Path, proxy_port: int, upstream_port: int) -> tuple[Path, Path, Path]:
    filters = base / "filters.json"
    events = base / "events.jsonl"
    filters.write_text('{"filters": []}\n', encoding="utf-8")
    config = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "e2e-token",
            "limits": {
                "per_ip_rps": 80,
                "per_ip_burst": 80,
                "global_rps": 100_000,
                "global_burst": 100_000,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters),
            "reload_seconds": 1,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 60,
            "activation_ttl_seconds": 20,
            "event_log": str(events),
            "event_cooldown_seconds": 1,
        },
    }
    path = base / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path, filters, events


def summarize_phase(result: PhaseResult) -> dict[str, Any]:
    return {
        "requests": result.requests,
        "errors": result.errors,
        "statuses": {str(status): count for status, count in sorted(result.statuses.items())},
    }


def wait_for_filters(path: Path, timeout: float) -> list[dict[str, Any]]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            filters = data.get("filters", [])
            if filters:
                return filters
        except Exception:
            pass
        time.sleep(0.5)
    return []


def read_event_reasons(path: Path) -> dict[str, int]:
    reasons: collections.Counter[str] = collections.Counter()
    if not path.exists():
        return {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            reasons[str(json.loads(line).get("reason"))] += 1
        except Exception:
            continue
    return dict(reasons)


def main() -> None:
    args = parse_args()
    binary = Path(args.binary)
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary}")
    scenarios = ["basic", "cachebuster", "rotating-path", "uuid-path", "mixed-user-agent"]
    proxy_port = free_port()
    upstream_port = free_port()

    with tempfile.TemporaryDirectory(dir=args.workdir) as tmp, UpstreamServer(("127.0.0.1", upstream_port), UpstreamHandler) as upstream:
        base = Path(tmp)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        config_path, filters_path, events_path = write_config(base, proxy_port, upstream_port)

        proxy_log = (base / "proxy.log").open("w")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=proxy_log,
            text=True,
        )
        analyzer_logs: list[str] = []
        try:
            wait_health(proxy_port)
            scenario_results = {}
            for scenario in scenarios:
                filters_path.write_text('{"filters": []}\n', encoding="utf-8")
                events_path.write_text("", encoding="utf-8")
                time.sleep(1.2)
                analyzer_log_path = base / f"analyzer-{scenario}.log"
                analyzer, analyzer_log = start_analyzer(args, events_path, filters_path, analyzer_log_path)
                collect = run_phase(proxy_port, scenario, args.duration, args.workers)
                filters = wait_for_filters(filters_path, args.analyzer_wait)
                replay = run_phase(proxy_port, scenario, args.duration, args.workers)
                persistent_replay = None
                filters_after_quiet = None
                if args.verify_persistence:
                    events_path.write_text("", encoding="utf-8")
                    time.sleep(2.2)
                    filters_after_quiet = json.loads(filters_path.read_text(encoding="utf-8")).get("filters", [])
                    persistent_replay = run_phase(proxy_port, scenario, args.duration, args.workers)
                stop_process(analyzer)
                analyzer_log.close()
                analyzer_logs.extend(
                    analyzer_log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                )
                result: dict[str, Any] = {
                    "collect": summarize_phase(collect),
                    "replay": summarize_phase(replay),
                    "filters_after_collect": len(filters),
                    "learned_filters": filters,
                }
                if args.verify_persistence:
                    result["filters_after_quiet"] = len(filters_after_quiet or [])
                    result["persistent_replay"] = summarize_phase(persistent_replay or PhaseResult())
                scenario_results[scenario] = result
            report = {
                "provider": "deterministic" if args.no_codex else args.provider,
                "workdir": str(base),
                "event_reasons": read_event_reasons(events_path),
                "filters": json.loads(filters_path.read_text(encoding="utf-8")).get("filters", []),
                "scenarios": scenario_results,
                "analyzer_log_tail": analyzer_logs[-40:],
            }
            print(json.dumps(report, indent=2, sort_keys=True))
        finally:
            stop_process(proxy)
            proxy_log.close()
            upstream.shutdown()

def start_analyzer(
    args: argparse.Namespace,
    events_path: Path,
    filters_path: Path,
    log_path: Path,
) -> tuple[subprocess.Popen[str], Any]:
    analyzer_cmd = [
        sys.executable,
        "tools/codexsdgate.py",
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
        analyzer_cmd.append("--no-codex")
    log_file = log_path.open("w")
    process = subprocess.Popen(
        analyzer_cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    return process, log_file


def stop_process(proc: subprocess.Popen[Any]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


if __name__ == "__main__":
    main()
