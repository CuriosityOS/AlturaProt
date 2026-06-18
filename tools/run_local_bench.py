#!/usr/bin/env python3
"""Run reproducible loopback benchmarks for AlturaProt.

This script starts a tiny local HTTP upstream, starts an AlturaProt binary with a
temporary loopback-only config, runs the local flood helper, and prints JSON.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


class FastHttpHandler(socketserver.BaseRequestHandler):
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


class FastHttpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/release/altura-prot")
    parser.add_argument("--workers", type=int, default=128)
    parser.add_argument("--duration", type=float, default=8.0)
    parser.add_argument("--per-ip-rps", type=int, default=1_000_000)
    parser.add_argument("--signature-threshold", type=int, default=1_000_000)
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(url_host: str, url_port: int, path: str = "/__altura/health") -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection(url_host, url_port, timeout=0.2)
            conn.request("GET", path)
            resp = conn.getresponse()
            resp.read()
            if resp.status < 500:
                return
        except Exception:
            time.sleep(0.1)
        finally:
            try:
                conn.close()  # type: ignore[name-defined]
            except Exception:
                pass
    raise RuntimeError("AlturaProt did not become ready")


def run_flood(url: str, workers: int, duration: float) -> dict[str, Any]:
    output = subprocess.check_output(
        [
            sys.executable,
            "tools/local_http_flood.py",
            "--url",
            url,
            "--workers",
            str(workers),
            "--duration",
            str(duration),
        ],
        text=True,
    )
    return json.loads(output)


def main() -> None:
    args = parse_args()
    binary = Path(args.binary)
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary}")

    proxy_port = free_port()
    upstream_port = free_port()
    with FastHttpServer(("127.0.0.1", upstream_port), FastHttpHandler) as upstream, tempfile.TemporaryDirectory() as tmp:
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()

        tmp_path = Path(tmp)
        filters_path = tmp_path / "filters.json"
        events_path = tmp_path / "events.jsonl"
        filters_path.write_text('{"filters": []}\n', encoding="utf-8")
        cfg = {
            "http": {
                "listen": f"127.0.0.1:{proxy_port}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "preserve_host": True,
                "admin_token": "bench-token",
                "limits": {
                    "per_ip_rps": args.per_ip_rps,
                    "per_ip_burst": args.per_ip_rps,
                    "global_rps": 1_000_000,
                    "global_burst": 1_000_000,
                    "max_tracked_ips": 1024,
                },
            },
            "tcp": [],
            "filters": {
                "runtime_file": str(filters_path),
                "reload_seconds": 1,
                "static_rules": [],
            },
            "adaptive": {
                "enabled": True,
                "signature_threshold_per_second": args.signature_threshold,
                "activation_ttl_seconds": 10,
                "event_log": str(events_path),
                "event_cooldown_seconds": 1,
            },
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")

        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            wait_http("127.0.0.1", proxy_port)
            result = {
                "proxy": run_flood(f"http://127.0.0.1:{proxy_port}/", args.workers, args.duration),
                "health": run_flood(
                    f"http://127.0.0.1:{proxy_port}/__altura/health",
                    args.workers,
                    args.duration,
                ),
            }
            print(json.dumps(result, indent=2, sort_keys=True))
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
            upstream.shutdown()


if __name__ == "__main__":
    main()
