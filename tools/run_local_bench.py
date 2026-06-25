#!/usr/bin/env python3
"""Run reproducible loopback benchmarks for AlturaProt.

This script starts a tiny local HTTP upstream, starts an AlturaProt binary with a
temporary loopback-only config, runs the local flood helper, and prints JSON.
"""

from __future__ import annotations

import argparse
import collections
import http.client
import json
import os
import signal
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

HTTP_HEADER_BUFFER_MAX_BYTES = 256 * 1024
HTTP_HEADER_COUNT_MAX = 1024
HTTP_HOST_MAX_BYTES_MAX = 1024
HTTP_REQUEST_TARGET_MAX_BYTES = 64 * 1024
HTTP_QUERY_PAIR_COUNT_MAX = 8_192
HTTP_PATH_SEGMENT_COUNT_MAX = 4_096
HTTP_HEADER_READ_TIMEOUT_MAX_MS = 60_000
HTTP_DOWNSTREAM_WRITE_TIMEOUT_MAX_MS = 60_000
HTTP_BODY_IDLE_TIMEOUT_MAX_MS = 60_000
HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX = 1_048_576
HTTP_BODY_MIN_RATE_GRACE_MAX_MS = 60_000
HTTP_MAX_BODY_BYTES_MAX = 1_073_741_824
HTTP_MAX_UPSTREAM_BODY_BYTES_MAX = 1_073_741_824
HTTP_TRAILER_BYTES_MAX = HTTP_HEADER_BUFFER_MAX_BYTES
HTTP_TRAILER_COUNT_MAX = HTTP_HEADER_COUNT_MAX
HTTP_FORWARDED_FOR_BYTES_MAX = 16 * 1024
HTTP_FORWARDED_FOR_HOPS_MAX = 256
HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS = 60_000
HTTP_UPSTREAM_TIMEOUT_MAX_MS = 60_000
HTTP_UPSTREAM_FAILURE_THRESHOLD_MAX = 1_024
HTTP_UPSTREAM_FAILURE_OPEN_MAX_MS = 300_000
HTTP_UPSTREAM_POOL_IDLE_TIMEOUT_MAX_MS = 60_000
HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST_MAX = 4_096
HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS = 3_600
HTTP_MAX_REQUESTS_PER_CONNECTION_MAX = 10_000
TCP_CONNECT_TIMEOUT_MAX_MS = 60_000
TCP_MIN_RATE_BYTES_PER_SECOND_MAX = 1_048_576
TCP_MAX_CONNECTION_DURATION_MAX_SECONDS = 3_600
FILTER_RUNTIME_FILE_MAX_BYTES_MAX = 16 * 1024 * 1024
FILTER_RULE_COUNT_MAX = 8_192
FILTER_TTL_MAX_SECONDS = 24 * 60 * 60
ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX = 1_073_741_824
ADAPTIVE_WINDOW_COUNT_MAX = 262_144
LIMITER_MAX_TRACKED_IPS_MAX = 1_048_576
LIMITER_MAX_TRACKED_SIGNATURES_MAX = 262_144
LIMITER_MAX_TRACKED_PATH_SHAPES_MAX = 262_144
EVENT_LOG_BACKUP_COUNT_MAX = 128
EVENT_LOG_QUEUE_CAPACITY_MAX = 8192
BENCH_HTTP_CONNECTION_LIMITS = {
    "per_ip_connects_per_second": 1_000_000,
    "per_ip_connect_burst": 1_000_000,
    "global_connects_per_second": 1_000_000,
    "global_connect_burst": 1_000_000,
}
PROCESS_STDERR_TAIL_CHARS = 4000


class FastHttpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self._handle()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def _handle(self) -> None:
        buf = b""
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            buf += data
            header_end = buf.find(b"\r\n\r\n")
            if header_end < 0:
                continue
            headers = buf[:header_end].decode("iso-8859-1", errors="replace")
            body = buf[header_end + 4 :]
            request_line = headers.splitlines()[0] if headers.splitlines() else ""
            content_length = header_value(headers, "content-length")
            transfer_encoding = header_value(headers, "transfer-encoding")
            if transfer_encoding and transfer_encoding.lower() == "chunked":
                while not chunked_message_complete(body):
                    data = self.request.recv(4096)
                    if not data:
                        return
                    body += data
                buf = b""
            else:
                expected_body = int(content_length) if content_length and content_length.isdigit() else 0
                while len(body) < expected_body:
                    data = self.request.recv(4096)
                    if not data:
                        return
                    body += data
                buf = body[expected_body:]
            if request_line.startswith("GET /headers "):
                response_body = json.dumps(
                    {
                        "forwarded": header_value(headers, "forwarded"),
                        "x_forwarded_for": header_value(headers, "x-forwarded-for"),
                        "x_forwarded_host": header_value(headers, "x-forwarded-host"),
                        "x_forwarded_proto": header_value(headers, "x-forwarded-proto"),
                        "x_forwarded_server": header_value(headers, "x-forwarded-server"),
                        "x_forwarded_port": header_value(headers, "x-forwarded-port"),
                        "x_forwarded_scheme": header_value(headers, "x-forwarded-scheme"),
                        "x_real_ip": header_value(headers, "x-real-ip"),
                        "x_forwarded": header_value(headers, "x-forwarded"),
                        "x_forwarded_prefix": header_value(headers, "x-forwarded-prefix"),
                        "x_forwarded_uri": header_value(headers, "x-forwarded-uri"),
                        "x_forwarded_path": header_value(headers, "x-forwarded-path"),
                        "x_original_forwarded_for": header_value(
                            headers, "x-original-forwarded-for"
                        ),
                        "x_original_host": header_value(headers, "x-original-host"),
                        "x_original_url": header_value(headers, "x-original-url"),
                        "x_rewrite_url": header_value(headers, "x-rewrite-url"),
                        "cf_connecting_ip": header_value(headers, "cf-connecting-ip"),
                        "true_client_ip": header_value(headers, "true-client-ip"),
                        "fastly_client_ip": header_value(headers, "fastly-client-ip"),
                        "client_ip": header_value(headers, "client-ip"),
                        "x_client_ip": header_value(headers, "x-client-ip"),
                        "x_cluster_client_ip": header_value(headers, "x-cluster-client-ip"),
                        "x_originating_ip": header_value(headers, "x-originating-ip"),
                        "x_remote_ip": header_value(headers, "x-remote-ip"),
                        "x_remote_addr": header_value(headers, "x-remote-addr"),
                        "accept_encoding": header_value(headers, "accept-encoding"),
                        "connection": header_value(headers, "connection"),
                        "proxy_connection": header_value(headers, "proxy-connection"),
                        "keep_alive": header_value(headers, "keep-alive"),
                        "te": header_value(headers, "te"),
                        "trailer": header_value(headers, "trailer"),
                        "upgrade": header_value(headers, "upgrade"),
                        "x_hop_by_hop_attack": header_value(headers, "x-hop-by-hop-attack"),
                    },
                    sort_keys=True,
                ).encode("utf-8")
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(response_body)}\r\n".encode("ascii")
                    + b"Content-Type: application/json\r\n"
                    + b"Connection: close\r\n\r\n"
                    + response_body
                )
                return
            status = b"204 No Content"
            if request_line.startswith("POST /drain "):
                status = b"200 OK"
            elif request_line.startswith("GET /slow "):
                time.sleep(0.35)
            elif request_line.startswith("GET /stalled-response "):
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 4\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                )
                time.sleep(2.0)
                return
            elif request_line.startswith("GET /slow-drip-response "):
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 3\r\n"
                    b"Connection: close\r\n\r\n"
                    b"a"
                )
                time.sleep(0.08)
                try:
                    self.request.sendall(b"b")
                except OSError:
                    pass
                time.sleep(0.08)
                try:
                    self.request.sendall(b"c")
                except OSError:
                    pass
                return
            elif request_line.startswith("GET /huge-response-headers "):
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"X-Huge-Origin-Header: "
                    + (b"x" * 12_000)
                    + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                return
            elif request_line.startswith("GET /hop-by-hop-response "):
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n"
                    b"Connection: X-Origin-Hop\r\n"
                    b"X-Origin-Hop: should-strip\r\n"
                    b"Proxy-Connection: keep-alive\r\n"
                    b"Keep-Alive: timeout=999\r\n"
                    b"TE: trailers\r\n"
                    b"Trailer: X-Origin-Trailer\r\n"
                    b"Upgrade: websocket\r\n\r\n"
                    b"ok"
                )
                return
            elif request_line.startswith("GET /many-response-headers "):
                headers_out = b"".join(
                    f"X-Origin-{idx}: {idx}\r\n".encode("ascii") for idx in range(16)
                )
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    + headers_out
                    + b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                return
            elif request_line.startswith("GET /large-response "):
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 16\r\n"
                    b"Connection: close\r\n\r\n"
                    b"0123456789abcdef"
                )
                return
            elif request_line.startswith("GET /huge-response "):
                total = 32 * 1024 * 1024
                chunk = b"x" * 65536
                self.request.settimeout(1.0)
                try:
                    self.request.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {total}\r\n".encode("ascii")
                        + b"Connection: close\r\n\r\n"
                    )
                    remaining = total
                    while remaining > 0:
                        part = chunk[: min(len(chunk), remaining)]
                        self.request.sendall(part)
                        remaining -= len(part)
                except OSError:
                    pass
                return
            elif request_line.startswith("GET /response-trailers "):
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Trailer: X-Origin-Trailer\r\n"
                    b"Connection: close\r\n\r\n"
                    b"5\r\nhello\r\n"
                    b"0\r\n"
                    b"X-Origin-Trailer: drop-me\r\n\r\n"
                )
                return
            self.request.sendall(
                b"HTTP/1.1 " + status + b"\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )


class FastHttpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 1024


class CountingHttpServer(FastHttpServer):
    def __init__(self, server_address: tuple[str, int], handler: type[socketserver.BaseRequestHandler]):
        self.connection_count = 0
        self.connection_count_lock = threading.Lock()
        super().__init__(server_address, handler)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, client_address = super().get_request()
        with self.connection_count_lock:
            self.connection_count += 1
        return request, client_address


class FastTcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            try:
                data = self.request.recv(4096)
                if not data:
                    return
                self.request.sendall(data)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                return


class FastTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 1024


class TcpHeadOfLineHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            try:
                self.request.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            except OSError:
                pass
            time.sleep(0.1)
            self.request.sendall(b"pong")
            time.sleep(1.0)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return


@dataclass
class TcpBenchResult:
    messages: int = 0
    errors: int = 0
    error_types: collections.Counter[str] = field(default_factory=collections.Counter)
    latencies_ms: list[float] = field(default_factory=list)
    elapsed_seconds: float = 0.0


@dataclass
class LoopbackBacklogSaturation:
    port: int
    listener: socket.socket
    held_connections: list[socket.socket]
    backlog_blocked: bool

    def close(self) -> None:
        for conn in self.held_connections:
            try:
                conn.close()
            except OSError:
                pass
        try:
            self.listener.close()
        except OSError:
            pass


def header_value(headers: str, name: str) -> str | None:
    prefix = name.lower() + ":"
    for line in headers.splitlines()[1:]:
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def chunked_message_complete(body: bytes) -> bool:
    idx = 0
    while True:
        line_end = body.find(b"\r\n", idx)
        if line_end < 0:
            return False
        size_token = body[idx:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            return False
        idx = line_end + 2
        if size == 0:
            trailer = body[idx:]
            return trailer.startswith(b"\r\n") or b"\r\n\r\n" in trailer
        if len(body) < idx + size + 2:
            return False
        idx += size
        if body[idx : idx + 2] != b"\r\n":
            return False
        idx += 2


def headers_from_raw_response(raw: bytes) -> dict[str, str]:
    header, _, _ = raw.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in header.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("ascii", errors="ignore").lower()] = value.decode(
            "ascii", errors="ignore"
        ).strip()
    return headers


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/release/altura-prot")
    parser.add_argument("--workers", type=int, default=128)
    parser.add_argument("--tcp-workers", type=int, default=32)
    parser.add_argument("--duration", type=float, default=8.0)
    parser.add_argument("--per-ip-rps", type=int, default=1_000_000)
    parser.add_argument("--signature-threshold", type=int, default=1_000_000)
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def saturate_loopback_backlog(
    backlog: int = 1, attempts: int = 64, connect_timeout: float = 0.05
) -> LoopbackBacklogSaturation:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    port = int(listener.getsockname()[1])
    listener.listen(backlog)
    held_connections: list[socket.socket] = []
    backlog_blocked = False
    for _ in range(attempts):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(connect_timeout)
        try:
            conn.connect(("127.0.0.1", port))
            held_connections.append(conn)
        except (TimeoutError, socket.timeout, OSError):
            conn.close()
            backlog_blocked = True
            break
    return LoopbackBacklogSaturation(port, listener, held_connections, backlog_blocked)


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


def stop_process_and_collect_stderr(
    process: subprocess.Popen[str],
    timeout_seconds: float = 5.0,
) -> str:
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        _, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            _, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            return "<stderr unavailable: process did not exit after SIGKILL>"
    return stderr or ""


def format_process_stderr_tail(stderr: str) -> str:
    stderr = stderr.strip()
    if not stderr:
        return "<empty>"
    if len(stderr) <= PROCESS_STDERR_TAIL_CHARS:
        return stderr
    return f"<truncated>\n{stderr[-PROCESS_STDERR_TAIL_CHARS:]}"


def startup_failure_with_stderr(
    reason: BaseException,
    process: subprocess.Popen[str],
    stderr: str,
) -> RuntimeError:
    return RuntimeError(
        "AlturaProt benchmark proxy startup failed: "
        f"{reason}; exit_status={process.returncode}; "
        f"stderr_tail={format_process_stderr_tail(stderr)}"
    )


def wait_tcp_port(port: int) -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("AlturaProt TCP listener did not become ready")


def run_flood(url: str, workers: int, duration: float) -> dict[str, Any]:
    flood_script = Path(__file__).resolve().parent / "local_http_flood.py"
    output = subprocess.check_output(
        [
            sys.executable,
            str(flood_script),
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


def run_tcp_echo_bench(port: int, workers: int, duration: float) -> dict[str, Any]:
    result = TcpBenchResult()
    lock = threading.Lock()
    deadline = time.perf_counter() + duration
    payload = b"altura-tcp-bench"

    def worker() -> None:
        local_messages = 0
        local_errors = 0
        local_error_types: collections.Counter[str] = collections.Counter()
        local_latencies: list[float] = []
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
                while time.perf_counter() < deadline:
                    started = time.perf_counter()
                    sock.settimeout(1.0)
                    sock.sendall(payload)
                    received = recv_exact(sock, len(payload))
                    if received != payload:
                        raise RuntimeError("tcp echo mismatch")
                    local_messages += 1
                    local_latencies.append((time.perf_counter() - started) * 1000)
        except Exception:
            local_errors += 1
            local_error_types[type(sys.exc_info()[1]).__name__] += 1
        with lock:
            result.messages += local_messages
            result.errors += local_errors
            result.error_types.update(local_error_types)
            result.latencies_ms.extend(local_latencies)

    started_all = time.perf_counter()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    result.elapsed_seconds = time.perf_counter() - started_all
    result.latencies_ms.sort()
    return {
        "connections": workers,
        "messages": result.messages,
        "messages_per_second": round(
            result.messages / result.elapsed_seconds if result.elapsed_seconds else 0.0,
            2,
        ),
        "duration_seconds": round(result.elapsed_seconds, 3),
        "errors": result.errors,
        "error_types": dict(sorted(result.error_types.items())),
        "latency_ms": {
            "avg": round(sum(result.latencies_ms) / len(result.latencies_ms), 3)
            if result.latencies_ms
            else 0.0,
            "p50": percentile(result.latencies_ms, 50),
            "p95": percentile(result.latencies_ms, 95),
            "p99": percentile(result.latencies_ms, 99),
        },
        "workers": workers,
    }


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    idx = min(len(values) - 1, int(round((pct / 100.0) * (len(values) - 1))))
    return round(values[idx], 3)


def get_status(
    port: int,
    method: str,
    path: str,
    body: bytes = b"",
    timeout: float = 2.0,
    headers: dict[str, str] | None = None,
) -> int | None:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        request_headers = {"User-Agent": "altura-guardrail-probe/1.0"}
        if headers:
            request_headers.update(headers)
        conn.request(method, path, body=body, headers=request_headers)
        resp = conn.getresponse()
        resp.read()
        return resp.status
    except Exception:
        return None
    finally:
        conn.close()


def get_status_and_headers(
    port: int,
    method: str,
    path: str,
    body: bytes = b"",
    timeout: float = 2.0,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        request_headers = {"User-Agent": "altura-guardrail-probe/1.0"}
        if headers:
            request_headers.update(headers)
        conn.request(method, path, body=body, headers=request_headers)
        resp = conn.getresponse()
        resp.read()
        return {
            "status": resp.status,
            "headers": {name.lower(): value for name, value in resp.getheaders()},
        }
    except Exception as exc:
        return {"status": None, "headers": {}, "error": type(exc).__name__}
    finally:
        conn.close()


def response_headers_for_status(
    responses: list[dict[str, Any]], header: str, status: int = 429
) -> list[str | None]:
    return [
        response["headers"].get(header)
        for response in responses
        if response["status"] == status
    ]


def read_http_response_on_socket(sock: socket.socket) -> dict[str, Any]:
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk
    header, sep, body = raw.partition(b"\r\n\r\n")
    status = None
    content_length = 0
    if header.startswith(b"HTTP/"):
        try:
            status = int(header.split(b" ", 2)[1])
        except Exception:
            status = None
    response_headers: dict[str, str] = {}
    for line in header.decode("iso-8859-1", errors="replace").splitlines()[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        response_headers[name] = value
        if name == "content-length":
            if value.isdigit():
                content_length = int(value)
    while len(body) < content_length:
        chunk = sock.recv(content_length - len(body))
        if not chunk:
            break
        body += chunk
    return {
        "status": status,
        "header_complete": bool(sep),
        "headers": response_headers,
        "body": body.decode("utf-8", errors="replace"),
        "body_bytes": len(body),
    }


def send_duplicate_admin_token_metrics_request(port: int) -> dict[str, Any]:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET /__altura/metrics HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-duplicate-admin-token-probe/1.0\r\n"
                b"x-altura-admin-token: bench-token\r\n"
                b"x-altura-admin-token: bench-token\r\n"
                b"\r\n"
            )
            return read_http_response_on_socket(sock)
    except Exception as exc:
        return {"status": None, "headers": {}, "error": type(exc).__name__}


def fetch_metrics(
    port: int, token: str = "bench-token", headers: dict[str, str] | None = None
) -> dict[str, int]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
    try:
        request_headers = {"x-altura-admin-token": token}
        if headers:
            request_headers.update(headers)
        conn.request("GET", "/__altura/metrics", headers=request_headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        metrics = {}
        if resp.status != 200:
            return metrics
        for line in body.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                metrics[parts[0]] = int(parts[1])
        return metrics
    finally:
        conn.close()


def run_slow_body_probe(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"POST /drain HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-slow-body-probe/1.0\r\n"
                b"Content-Length: 8\r\n"
                b"\r\n"
                b"aa"
            )
            time.sleep(0.2)
            try:
                sock.sendall(b"bbbbbb")
            except OSError:
                pass
            raw = sock.recv(4096)
    except Exception as exc:
        return {
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "error": type(exc).__name__,
            "status": None,
        }
    status = None
    if raw.startswith(b"HTTP/"):
        try:
            status = int(raw.split(b" ", 2)[1])
        except Exception:
            status = None
    headers = headers_from_raw_response(raw)
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": None,
        "status": status,
        "cache_control": headers.get("cache-control"),
        "connection": headers.get("connection"),
        "cache_control_no_store": headers.get("cache-control") == "no-store",
        "connection_close": headers.get("connection") == "close",
    }


def send_min_rate_body_request(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"POST /drain HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-body-min-rate-probe/1.0\r\n"
                b"Content-Length: 3\r\n"
                b"\r\n"
                b"a"
            )
            time.sleep(0.08)
            try:
                sock.sendall(b"b")
                time.sleep(0.08)
                sock.sendall(b"c")
            except OSError:
                pass
            raw = sock.recv(4096)
    except Exception as exc:
        error = type(exc).__name__
    status = None
    if raw.startswith(b"HTTP/"):
        try:
            status = int(raw.split(b" ", 2)[1])
        except Exception:
            status = None
    headers = headers_from_raw_response(raw)
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
        "status": status,
        "cache_control": headers.get("cache-control"),
        "connection": headers.get("connection"),
        "cache_control_no_store": headers.get("cache-control") == "no-store",
        "connection_close": headers.get("connection") == "close",
    }


def send_banked_min_rate_body_request(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    banked_bytes = 512
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"POST /drain HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-body-min-rate-bank-probe/1.0\r\n"
                b"Content-Length: 513\r\n"
                b"\r\n"
                + (b"a" * banked_bytes)
            )
            time.sleep(0.08)
            try:
                sock.sendall(b"b")
            except OSError:
                pass
            raw = sock.recv(4096)
    except Exception as exc:
        error = type(exc).__name__
    status = None
    if raw.startswith(b"HTTP/"):
        try:
            status = int(raw.split(b" ", 2)[1])
        except Exception:
            status = None
    headers = headers_from_raw_response(raw)
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
        "status": status,
        "banked_initial_bytes": banked_bytes,
        "cache_control": headers.get("cache-control"),
        "connection": headers.get("connection"),
        "cache_control_no_store": headers.get("cache-control") == "no-store",
        "connection_close": headers.get("connection") == "close",
    }


def run_request_content_encoding_probe(port: int) -> dict[str, Any]:
    metrics_before = fetch_metrics(port)
    gzip_response = request_with_content_encoding(port, "gzip")
    identity_response = request_with_content_encoding(port, "identity")
    metrics_after = fetch_metrics(port)
    rejected_delta = metrics_after.get(
        "altura_http_content_encoding_rejected", 0
    ) - metrics_before.get("altura_http_content_encoding_rejected", 0)
    return {
        "gzip_request": gzip_response,
        "identity_request": identity_response,
        "content_encoding_rejected_delta": rejected_delta,
        "compressed_request_rejected": gzip_response["status"] == 415,
        "accept_encoding_identity_advertised": gzip_response["accept_encoding"] == "identity",
        "compressed_request_not_stored": gzip_response["cache_control"] == "no-store",
        "compressed_request_closes_connection": gzip_response["connection_close"],
        "identity_request_allowed": identity_response["status"] == 200,
    }


def request_with_content_encoding(port: int, content_encoding: str) -> dict[str, Any]:
    started = time.perf_counter()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
    try:
        conn.request(
            "POST",
            "/drain",
            body=b"abc",
            headers={
                "User-Agent": "altura-content-encoding-probe/1.0",
                "Content-Encoding": content_encoding,
            },
        )
        resp = conn.getresponse()
        resp.read()
        return {
            "status": resp.status,
            "accept_encoding": resp.getheader("Accept-Encoding"),
            "cache_control": resp.getheader("Cache-Control"),
            "connection": resp.getheader("Connection"),
            "connection_close": (resp.getheader("Connection") or "").lower() == "close",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }
    except Exception as exc:
        return {
            "status": None,
            "accept_encoding": None,
            "cache_control": None,
            "connection": None,
            "connection_close": False,
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "error": type(exc).__name__,
        }
    finally:
        conn.close()


def run_expect_guard_probe(port: int) -> dict[str, Any]:
    metrics_before = fetch_metrics(port)
    expect_continue = send_raw_expect_request(port, "100-continue")
    unsupported = send_raw_expect_request(port, "wait-for-magic")
    no_expect = get_status(port, "POST", "/drain", b"abcd")
    metrics_after = fetch_metrics(port)
    rejected_delta = metrics_after.get("altura_http_expect_rejected", 0) - metrics_before.get(
        "altura_http_expect_rejected", 0
    )
    return {
        "expect_continue": expect_continue,
        "unsupported_expectation": unsupported,
        "no_expect_status": no_expect,
        "expect_rejected_delta": rejected_delta,
        "expect_continue_rejected": expect_continue["status"] == 417,
        "unsupported_expectation_rejected": unsupported["status"] == 417,
        "expect_rejections_not_stored": expect_continue["cache_control_no_store"]
        and unsupported["cache_control_no_store"],
        "normal_request_allowed": no_expect == 200,
    }


def send_raw_expect_request(port: int, expect_value: str) -> dict[str, Any]:
    started = time.perf_counter()
    status = None
    headers: dict[str, str] = {}
    body = ""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                (
                    "POST /drain HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "User-Agent: altura-expect-guard-probe/1.0\r\n"
                    "Content-Length: 4\r\n"
                    f"Expect: {expect_value}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            response = read_http_response_on_socket(sock)
            status = response["status"]
            headers = response["headers"]
            body = response["body"]
    except Exception as exc:
        error = type(exc).__name__
    return {
        "status": status,
        "cache_control": headers.get("cache-control"),
        "cache_control_no_store": headers.get("cache-control") == "no-store",
        "connection": headers.get("connection"),
        "connection_close": headers.get("connection") == "close",
        "body": body,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def run_range_guard_probe(port: int) -> dict[str, Any]:
    metrics_before = fetch_metrics(port)
    single_response = request_with_range(port, "bytes=0-0")
    multi_response = request_with_range(port, "bytes=0-0, 0-0")
    unsupported_response = request_with_range(port, "items=0-1")
    malformed_response = request_with_range(port, "bytes=10-1")
    metrics_after = fetch_metrics(port)
    rejected_delta = metrics_after.get("altura_http_range_rejected", 0) - metrics_before.get(
        "altura_http_range_rejected", 0
    )
    return {
        "single_range": single_response,
        "multi_range": multi_response,
        "unsupported_range": unsupported_response,
        "malformed_range": malformed_response,
        "range_rejected_delta": rejected_delta,
        "single_range_allowed": single_response["status"] == 204,
        "multi_range_rejected": multi_response["status"] == 416,
        "unsupported_range_rejected": unsupported_response["status"] == 416,
        "malformed_range_rejected": malformed_response["status"] == 416,
        "range_rejections_not_stored": all(
            response["cache_control_no_store"]
            for response in [multi_response, unsupported_response, malformed_response]
        ),
    }


def request_with_range(port: int, range_value: str) -> dict[str, Any]:
    started = time.perf_counter()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
    try:
        conn.request(
            "GET",
            "/",
            headers={
                "User-Agent": "altura-range-guard-probe/1.0",
                "Range": range_value,
            },
        )
        resp = conn.getresponse()
        resp.read()
        return {
            "status": resp.status,
            "cache_control": resp.getheader("Cache-Control"),
            "cache_control_no_store": resp.getheader("Cache-Control") == "no-store",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }
    except Exception as exc:
        return {
            "status": None,
            "cache_control": None,
            "cache_control_no_store": False,
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "error": type(exc).__name__,
        }
    finally:
        conn.close()


def run_accept_encoding_probe(port: int) -> dict[str, Any]:
    metrics_before = fetch_metrics(port)
    response = send_raw_accept_encoding_request(port)
    metrics_after = fetch_metrics(port)
    stripped_delta = metrics_after.get(
        "altura_http_accept_encoding_stripped", 0
    ) - metrics_before.get("altura_http_accept_encoding_stripped", 0)
    observed = response.get("observed") or {}
    return {
        "request": response,
        "accept_encoding_stripped_delta": stripped_delta,
        "origin_accept_encoding": observed.get("accept_encoding"),
        "origin_accept_encoding_stripped": response.get("status") == 200
        and observed.get("accept_encoding") is None,
    }


def send_raw_accept_encoding_request(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    status = None
    observed = None
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET /headers HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-accept-encoding-guard-probe/1.0\r\n"
                b"Accept-Encoding: gzip, br\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = read_http_response_on_socket(sock)
            status = response["status"]
            if response.get("body"):
                observed = json.loads(response["body"])
    except Exception as exc:
        error = type(exc).__name__
    return {
        "status": status,
        "observed": observed,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def send_slow_drip_response_request(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET /slow-drip-response HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-upstream-min-rate-probe/1.0\r\n"
                b"Connection: close\r\n\r\n"
            )
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
    except Exception as exc:
        error = type(exc).__name__
    header, _, body = raw.partition(b"\r\n\r\n")
    status = None
    if header.startswith(b"HTTP/"):
        try:
            status = int(header.split(b" ", 2)[1])
        except Exception:
            status = None
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
        "status": status,
        "body_bytes": len(body),
    }


def send_slow_downstream_reader_request(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            sock.settimeout(1.0)
            sock.sendall(
                b"GET /huge-response HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-slow-reader-probe/1.0\r\n"
                b"Connection: close\r\n\r\n"
            )
            time.sleep(0.25)
            try:
                raw = sock.recv(4096)
            except socket.timeout:
                error = "TimeoutError"
    except Exception as exc:
        error = type(exc).__name__
    header, _, body = raw.partition(b"\r\n\r\n")
    status = None
    if header.startswith(b"HTTP/"):
        try:
            status = int(header.split(b" ", 2)[1])
        except Exception:
            status = None
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
        "status": status,
        "first_read_bytes": len(raw),
        "first_body_bytes": len(body),
    }


def read_raw_response_bytes(port: int, path: str) -> bytes:
    raw = b""
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
        sock.settimeout(2.0)
        sock.sendall(
            f"GET {path} HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "User-Agent: altura-raw-response-probe/1.0\r\n"
            "TE: trailers\r\n"
            "Connection: close\r\n\r\n"
            .encode("ascii")
        )
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    return raw


def run_body_min_rate_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "body-min-rate-filters.json"
    events_path = tmp_path / "body-min-rate-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "body-min-rate-token",
            "max_body_bytes": 1024,
            "request_body_idle_timeout_ms": 500,
            "request_body_min_rate_bytes_per_second": 1_000,
            "request_body_min_rate_grace_ms": 10,
            "upstream_body_idle_timeout_ms": 500,
            "upstream_body_min_rate_bytes_per_second": 1_000,
            "upstream_body_min_rate_grace_ms": 10,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 2,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_log_flush_interval_ms": 1,
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "body-min-rate-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="body-min-rate-token")
        request_body_response = send_min_rate_body_request(proxy_port)
        metrics_after_request = fetch_metrics(proxy_port, token="body-min-rate-token")
        banked_request_body_response = send_banked_min_rate_body_request(proxy_port)
        metrics_after_banked_request = fetch_metrics(proxy_port, token="body-min-rate-token")
        upstream_response = send_slow_drip_response_request(proxy_port)
        metrics_after = fetch_metrics(proxy_port, token="body-min-rate-token")
        too_slow_delta = metrics_after_request.get(
            "altura_http_body_too_slow", 0
        ) - metrics_before.get("altura_http_body_too_slow", 0)
        banked_too_slow_delta = metrics_after_banked_request.get(
            "altura_http_body_too_slow", 0
        ) - metrics_after_request.get("altura_http_body_too_slow", 0)
        upstream_too_slow_delta = metrics_after.get(
            "altura_http_upstream_body_too_slow", 0
        ) - metrics_after_banked_request.get("altura_http_upstream_body_too_slow", 0)
        return {
            "configured_request_body_idle_timeout_ms": 500,
            "configured_request_body_min_rate_bytes_per_second": 1_000,
            "configured_request_body_min_rate_grace_ms": 10,
            "configured_upstream_body_idle_timeout_ms": 500,
            "configured_upstream_body_min_rate_bytes_per_second": 1_000,
            "configured_upstream_body_min_rate_grace_ms": 10,
            "request_body_response": request_body_response,
            "banked_request_body_response": banked_request_body_response,
            "upstream_response": upstream_response,
            "http_body_too_slow_delta": too_slow_delta,
            "http_body_banked_too_slow_delta": banked_too_slow_delta,
            "http_upstream_body_too_slow_delta": upstream_too_slow_delta,
            "request_min_rate_rejected": request_body_response["status"] == 408
            and request_body_response["cache_control_no_store"]
            and request_body_response["connection_close"]
            and too_slow_delta >= 1,
            "request_banked_min_rate_rejected": banked_request_body_response["status"] == 408
            and banked_request_body_response["cache_control_no_store"]
            and banked_request_body_response["connection_close"]
            and banked_too_slow_delta >= 1,
            "upstream_min_rate_rejected": upstream_too_slow_delta >= 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_runtime_nofile_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "runtime-nofile-filters.json"
    events_path = tmp_path / "runtime-nofile-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "runtime": {"min_nofile": 2048},
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "runtime-nofile-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "runtime-nofile-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    stderr_text = ""
    health_status = None
    try:
        wait_http("127.0.0.1", proxy_port)
        health_status = get_status(proxy_port, "GET", "/__altura/health")
    finally:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    runtime_lines = [
        line for line in stderr_text.splitlines() if line.startswith("runtime nofile limit ")
    ]
    return {
        "configured_min_nofile": 2048,
        "health_status": health_status,
        "runtime_status_line": runtime_lines[-1] if runtime_lines else None,
        "runtime_nofile_observed": health_status == 200 and bool(runtime_lines),
    }


def run_runtime_nofile_capacity_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "runtime-nofile-capacity-filters.json"
    events_path = tmp_path / "runtime-nofile-capacity-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    configured_min_nofile = 1024
    expected_required_nofile = 3_269
    cfg = {
        "runtime": {"min_nofile": configured_min_nofile},
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "runtime-nofile-capacity-token",
            "upstream_pool_max_idle_per_host": 512,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 1500,
                "max_connections_per_ip": 1500,
                "max_in_flight_requests": 1000,
                "max_in_flight_requests_per_ip": 1000,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "runtime-nofile-capacity-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [
            "/bin/sh",
            "-c",
            f"ulimit -n {configured_min_nofile}; exec \"$0\" --config \"$1\"",
            str(binary),
            str(config_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        _, stderr_text = proxy.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    stderr_lines = stderr_text.splitlines()
    return {
        "configured_min_nofile": configured_min_nofile,
        "expected_required_nofile": expected_required_nofile,
        "exit_code": proxy.returncode,
        "stderr_tail": stderr_lines[-8:],
        "capacity_rejected": proxy.returncode != 0
        and "runtime.min_nofile capacity check failed" in stderr_text
        and f"require at least {expected_required_nofile} file descriptors" in stderr_text,
    }


def run_trusted_proxy_global_trust_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "trusted-proxy-global-trust-filters.json"
    events_path = tmp_path / "trusted-proxy-global-trust-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"0.0.0.0:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "trusted-proxy-global-trust-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["0.0.0.0/0"],
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "trusted-proxy-global-trust-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        _, stderr_text = proxy.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    stderr_lines = stderr_text.splitlines()
    return {
        "exit_code": proxy.returncode,
        "stderr_tail": stderr_lines[-8:],
        "global_trusted_proxy_rejected": proxy.returncode != 0
        and "must not trust all IPv4 peers" in stderr_text
        and "non-loopback listener" in stderr_text,
    }


def run_negative_rate_startup_probe(
    binary: Path, upstream_port: int, tcp_upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(name: str, cfg: dict[str, Any], expected_path: str) -> dict[str, Any]:
        config_path = tmp_path / f"negative-rate-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": expected_path,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and expected_path in stderr_text
            and "must be finite and non-negative" in stderr_text,
        }

    http_port = free_port()
    tcp_port = free_port()
    http_cfg = {
        "http": {
            "listen": f"127.0.0.1:{http_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "limits": {"per_ip_rps": -1.0},
        },
        "tcp": [],
    }
    tcp_cfg = {
        "tcp": [
            {
                "name": "negative-rate-tcp",
                "listen": f"127.0.0.1:{tcp_port}",
                "upstream": f"127.0.0.1:{tcp_upstream_port}",
                "limits": {"global_connects_per_second": -1.0},
            }
        ]
    }
    http_case = run_case("http", http_cfg, "http.limits.per_ip_rps")
    tcp_case = run_case("tcp", tcp_cfg, "tcp[0].limits.global_connects_per_second")
    return {
        "http_negative_rate": http_case,
        "tcp_negative_rate": tcp_case,
        "negative_http_rate_rejected": http_case["startup_rejected"],
        "negative_tcp_rate_rejected": tcp_case["startup_rejected"],
    }


def run_admin_prefix_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        name: str, admin_path_prefix: str, expected_message: str
    ) -> dict[str, Any]:
        proxy_port = free_port()
        cfg = {
            "http": {
                "listen": f"127.0.0.1:{proxy_port}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "admin_path_prefix": admin_path_prefix,
            },
            "tcp": [],
        }
        config_path = tmp_path / f"admin-prefix-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_admin_path_prefix": admin_path_prefix,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and "http.admin_path_prefix" in stderr_text
            and expected_message in stderr_text,
        }

    root_case = run_case("root", "/", "non-root absolute path prefix")
    relative_case = run_case(
        "relative",
        "admin",
        "must start with '/' and use a non-root absolute path prefix",
    )
    query_case = run_case(
        "query",
        "/__altura?debug=true",
        "must not contain query or fragment",
    )
    return {
        "root_prefix": root_case,
        "relative_prefix": relative_case,
        "query_prefix": query_case,
        "root_prefix_rejected": root_case["startup_rejected"],
        "relative_prefix_rejected": relative_case["startup_rejected"],
        "query_prefix_rejected": query_case["startup_rejected"],
    }


def run_admin_token_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(name: str, admin_token: str, expected_message: str) -> dict[str, Any]:
        proxy_port = free_port()
        cfg = {
            "http": {
                "listen": f"127.0.0.1:{proxy_port}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "admin_token": admin_token,
            },
            "tcp": [],
        }
        config_path = tmp_path / f"admin-token-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_admin_token_repr": repr(admin_token),
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and "http.admin_token" in stderr_text
            and expected_message in stderr_text,
        }

    empty_case = run_case("empty", "", "must not be empty")
    blank_case = run_case("blank", "   ", "must not be blank")
    padded_case = run_case("padded", " secret", "must not start or end with whitespace")
    control_case = run_case("control", "line\nfeed", "must not contain control characters")
    long_case = run_case("long", "a" * 257, "above configured cap")
    return {
        "empty_token": empty_case,
        "blank_token": blank_case,
        "padded_token": padded_case,
        "control_token": control_case,
        "long_token": long_case,
        "empty_token_rejected": empty_case["startup_rejected"],
        "blank_token_rejected": blank_case["startup_rejected"],
        "padded_token_rejected": padded_case["startup_rejected"],
        "control_token_rejected": control_case["startup_rejected"],
        "long_token_rejected": long_case["startup_rejected"],
    }


def run_zero_capacity_startup_probe(
    binary: Path, upstream_port: int, tcp_upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(name: str, cfg: dict[str, Any], expected_path: str) -> dict[str, Any]:
        config_path = tmp_path / f"zero-capacity-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": expected_path,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and expected_path in stderr_text
            and "must be greater than zero" in stderr_text,
        }

    http_connection_port = free_port()
    http_metadata_port = free_port()
    http_forwarded_port = free_port()
    tcp_port = free_port()
    http_connection_case = run_case(
        "http-connection-cap",
        {
            "http": {
                "listen": f"127.0.0.1:{http_connection_port}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "limits": {"max_connections": 0},
            },
            "tcp": [],
        },
        "http.limits.max_connections",
    )
    http_metadata_case = run_case(
        "http-metadata-cap",
        {
            "http": {
                "listen": f"127.0.0.1:{http_metadata_port}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "max_header_bytes": 0,
            },
            "tcp": [],
        },
        "http.max_header_bytes",
    )
    http_forwarded_case = run_case(
        "http-forwarded-cap",
        {
            "http": {
                "listen": f"127.0.0.1:{http_forwarded_port}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "client_ip": {"max_forwarded_for_hops": 0},
            },
            "tcp": [],
        },
        "http.client_ip.max_forwarded_for_hops",
    )
    http_upstream_connect_timeout_case = run_case(
        "http-upstream-connect-timeout",
        {
            "http": {
                "listen": f"127.0.0.1:{free_port()}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "upstream_connect_timeout_ms": 0,
            },
            "tcp": [],
        },
        "http.upstream_connect_timeout_ms",
    )
    tcp_connection_case = run_case(
        "tcp-connection-cap",
        {
            "tcp": [
                {
                    "name": "zero-capacity-tcp",
                    "listen": f"127.0.0.1:{tcp_port}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "limits": {"max_connections": 0},
                }
            ]
        },
        "tcp[0].limits.max_connections",
    )
    return {
        "http_connection_cap": http_connection_case,
        "http_metadata_cap": http_metadata_case,
        "http_forwarded_cap": http_forwarded_case,
        "http_upstream_connect_timeout": http_upstream_connect_timeout_case,
        "tcp_connection_cap": tcp_connection_case,
        "http_connection_cap_rejected": http_connection_case["startup_rejected"],
        "http_metadata_cap_rejected": http_metadata_case["startup_rejected"],
        "http_forwarded_cap_rejected": http_forwarded_case["startup_rejected"],
        "http_upstream_connect_timeout_rejected": http_upstream_connect_timeout_case[
            "startup_rejected"
        ],
        "tcp_connection_cap_rejected": tcp_connection_case["startup_rejected"],
    }


def run_header_buffer_floor_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(name: str, field: str) -> dict[str, Any]:
        config_path = tmp_path / f"header-buffer-floor-{name}-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "http": {
                        "listen": f"127.0.0.1:{free_port()}",
                        "upstream": f"http://127.0.0.1:{upstream_port}",
                        field: 8191,
                    },
                    "tcp": [],
                }
            ),
            encoding="utf-8",
        )
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        expected_path = f"http.{field}"
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": expected_path,
            "configured_value": 8191,
            "minimum_bytes": 8192,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and expected_path in stderr_text
            and "must be at least 8192" in stderr_text,
        }

    downstream_case = run_case("downstream", "max_header_bytes")
    upstream_case = run_case("upstream", "upstream_max_header_bytes")
    return {
        "downstream_max_header_bytes": downstream_case,
        "upstream_max_header_bytes": upstream_case,
        "downstream_max_header_bytes_rejected": downstream_case["startup_rejected"],
        "upstream_max_header_bytes_rejected": upstream_case["startup_rejected"],
    }


def run_header_buffer_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    oversized = HTTP_HEADER_BUFFER_MAX_BYTES + 1

    def run_case(name: str, field: str) -> dict[str, Any]:
        config_path = tmp_path / f"header-buffer-ceiling-{name}-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "http": {
                        "listen": f"127.0.0.1:{free_port()}",
                        "upstream": f"http://127.0.0.1:{upstream_port}",
                        field: oversized,
                    },
                    "tcp": [],
                }
            ),
            encoding="utf-8",
        )
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        expected_path = f"http.{field}"
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": expected_path,
            "configured_value": oversized,
            "maximum_bytes": HTTP_HEADER_BUFFER_MAX_BYTES,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and expected_path in stderr_text
            and f"must be no higher than {HTTP_HEADER_BUFFER_MAX_BYTES}" in stderr_text,
        }

    downstream_case = run_case("downstream", "max_header_bytes")
    upstream_case = run_case("upstream", "upstream_max_header_bytes")
    return {
        "downstream_max_header_bytes": downstream_case,
        "upstream_max_header_bytes": upstream_case,
        "downstream_max_header_bytes_rejected": downstream_case["startup_rejected"],
        "upstream_max_header_bytes_rejected": upstream_case["startup_rejected"],
    }


def run_header_count_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    oversized = HTTP_HEADER_COUNT_MAX + 1

    def run_case(name: str, field: str) -> dict[str, Any]:
        config_path = tmp_path / f"header-count-ceiling-{name}-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "http": {
                        "listen": f"127.0.0.1:{free_port()}",
                        "upstream": f"http://127.0.0.1:{upstream_port}",
                        field: oversized,
                    },
                    "tcp": [],
                }
            ),
            encoding="utf-8",
        )
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        expected_path = f"http.{field}"
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": expected_path,
            "configured_value": oversized,
            "maximum_headers": HTTP_HEADER_COUNT_MAX,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and expected_path in stderr_text
            and f"must be no higher than {HTTP_HEADER_COUNT_MAX}" in stderr_text,
        }

    downstream_case = run_case("downstream", "max_headers")
    upstream_case = run_case("upstream", "upstream_max_headers")
    return {
        "downstream_max_headers": downstream_case,
        "upstream_max_headers": upstream_case,
        "downstream_max_headers_rejected": downstream_case["startup_rejected"],
        "upstream_max_headers_rejected": upstream_case["startup_rejected"],
    }


def run_http_metadata_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        name: str,
        field_path: str,
        ceiling: int,
        http_overrides: dict[str, Any],
    ) -> dict[str, Any]:
        config_path = tmp_path / f"http-metadata-ceiling-{name}.json"
        config_path.write_text(
            json.dumps(
                {
                    "http": {
                        "listen": f"127.0.0.1:{free_port()}",
                        "upstream": f"http://127.0.0.1:{upstream_port}",
                        **http_overrides,
                    },
                    "tcp": [],
                }
            ),
            encoding="utf-8",
        )
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": field_path,
            "configured_value": ceiling + 1,
            "maximum": ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and field_path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text,
        }

    cases = {
        "max_host_bytes": run_case(
            "max-host-bytes",
            "http.max_host_bytes",
            HTTP_HOST_MAX_BYTES_MAX,
            {"max_host_bytes": HTTP_HOST_MAX_BYTES_MAX + 1},
        ),
        "max_uri_bytes": run_case(
            "max-uri-bytes",
            "http.max_uri_bytes",
            HTTP_REQUEST_TARGET_MAX_BYTES,
            {"max_uri_bytes": HTTP_REQUEST_TARGET_MAX_BYTES + 1},
        ),
        "max_query_bytes": run_case(
            "max-query-bytes",
            "http.max_query_bytes",
            HTTP_REQUEST_TARGET_MAX_BYTES,
            {"max_query_bytes": HTTP_REQUEST_TARGET_MAX_BYTES + 1},
        ),
        "max_query_pairs": run_case(
            "max-query-pairs",
            "http.max_query_pairs",
            HTTP_QUERY_PAIR_COUNT_MAX,
            {"max_query_pairs": HTTP_QUERY_PAIR_COUNT_MAX + 1},
        ),
        "max_path_segments": run_case(
            "max-path-segments",
            "http.max_path_segments",
            HTTP_PATH_SEGMENT_COUNT_MAX,
            {"max_path_segments": HTTP_PATH_SEGMENT_COUNT_MAX + 1},
        ),
        "max_trailer_bytes": run_case(
            "max-trailer-bytes",
            "http.max_trailer_bytes",
            HTTP_TRAILER_BYTES_MAX,
            {"max_trailer_bytes": HTTP_TRAILER_BYTES_MAX + 1},
        ),
        "max_trailers": run_case(
            "max-trailers",
            "http.max_trailers",
            HTTP_TRAILER_COUNT_MAX,
            {"max_trailers": HTTP_TRAILER_COUNT_MAX + 1},
        ),
        "upstream_max_trailer_bytes": run_case(
            "upstream-max-trailer-bytes",
            "http.upstream_max_trailer_bytes",
            HTTP_TRAILER_BYTES_MAX,
            {"upstream_max_trailer_bytes": HTTP_TRAILER_BYTES_MAX + 1},
        ),
        "upstream_max_trailers": run_case(
            "upstream-max-trailers",
            "http.upstream_max_trailers",
            HTTP_TRAILER_COUNT_MAX,
            {"upstream_max_trailers": HTTP_TRAILER_COUNT_MAX + 1},
        ),
        "max_forwarded_for_bytes": run_case(
            "max-forwarded-for-bytes",
            "http.client_ip.max_forwarded_for_bytes",
            HTTP_FORWARDED_FOR_BYTES_MAX,
            {
                "client_ip": {
                    "max_forwarded_for_bytes": HTTP_FORWARDED_FOR_BYTES_MAX + 1
                }
            },
        ),
        "max_forwarded_for_hops": run_case(
            "max-forwarded-for-hops",
            "http.client_ip.max_forwarded_for_hops",
            HTTP_FORWARDED_FOR_HOPS_MAX,
            {
                "client_ip": {
                    "max_forwarded_for_hops": HTTP_FORWARDED_FOR_HOPS_MAX + 1
                }
            },
        ),
    }
    return {
        **cases,
        "all_http_metadata_ceilings_rejected": all(
            case["startup_rejected"] for case in cases.values()
        ),
    }


def run_header_read_timeout_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    oversized = HTTP_HEADER_READ_TIMEOUT_MAX_MS + 1
    config_path = tmp_path / "header-read-timeout-ceiling-config.json"
    config_path.write_text(
        json.dumps(
            {
                "http": {
                    "listen": f"127.0.0.1:{free_port()}",
                    "upstream": f"http://127.0.0.1:{upstream_port}",
                    "header_read_timeout_ms": oversized,
                },
                "tcp": [],
            }
        ),
        encoding="utf-8",
    )
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        _, stderr_text = proxy.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    expected_path = "http.header_read_timeout_ms"
    stderr_lines = stderr_text.splitlines()
    startup_rejected = (
        proxy.returncode != 0
        and expected_path in stderr_text
        and f"must be no higher than {HTTP_HEADER_READ_TIMEOUT_MAX_MS}" in stderr_text
    )
    return {
        "configured_field": expected_path,
        "configured_value": oversized,
        "maximum_ms": HTTP_HEADER_READ_TIMEOUT_MAX_MS,
        "exit_code": proxy.returncode,
        "stderr_tail": stderr_lines[-8:],
        "startup_rejected": startup_rejected,
        "header_read_timeout_rejected": startup_rejected,
    }


def run_upstream_timeout_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    oversized = HTTP_UPSTREAM_TIMEOUT_MAX_MS + 1
    config_path = tmp_path / "upstream-timeout-ceiling-config.json"
    config_path.write_text(
        json.dumps(
            {
                "http": {
                    "listen": f"127.0.0.1:{free_port()}",
                    "upstream": f"http://127.0.0.1:{upstream_port}",
                    "upstream_timeout_ms": oversized,
                },
                "tcp": [],
            }
        ),
        encoding="utf-8",
    )
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        _, stderr_text = proxy.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    expected_path = "http.upstream_timeout_ms"
    stderr_lines = stderr_text.splitlines()
    startup_rejected = (
        proxy.returncode != 0
        and expected_path in stderr_text
        and f"must be no higher than {HTTP_UPSTREAM_TIMEOUT_MAX_MS}" in stderr_text
    )
    return {
        "configured_field": expected_path,
        "configured_value": oversized,
        "maximum_ms": HTTP_UPSTREAM_TIMEOUT_MAX_MS,
        "exit_code": proxy.returncode,
        "stderr_tail": stderr_lines[-8:],
        "startup_rejected": startup_rejected,
        "upstream_timeout_rejected": startup_rejected,
    }


def run_upstream_failure_circuit_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        field: str, path: str, ceiling: int, maximum_key: str
    ) -> dict[str, Any]:
        config_path = tmp_path / f"upstream-failure-circuit-ceiling-{field}.json"
        config_path.write_text(
            json.dumps(
                {
                    "http": {
                        "listen": f"127.0.0.1:{free_port()}",
                        "upstream": f"http://127.0.0.1:{upstream_port}",
                        field: ceiling + 1,
                    },
                    "tcp": [],
                }
            ),
            encoding="utf-8",
        )
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": path,
            "configured_value": ceiling + 1,
            maximum_key: ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text,
        }

    threshold_case = run_case(
        "upstream_failure_threshold",
        "http.upstream_failure_threshold",
        HTTP_UPSTREAM_FAILURE_THRESHOLD_MAX,
        "maximum_failures",
    )
    open_window_case = run_case(
        "upstream_failure_open_ms",
        "http.upstream_failure_open_ms",
        HTTP_UPSTREAM_FAILURE_OPEN_MAX_MS,
        "maximum_ms",
    )
    return {
        "upstream_failure_threshold": threshold_case,
        "upstream_failure_open_ms": open_window_case,
        "upstream_failure_threshold_rejected": threshold_case["startup_rejected"],
        "upstream_failure_open_ms_rejected": open_window_case["startup_rejected"],
    }


def run_http_stream_timeout_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(field: str, path: str, ceiling: int) -> dict[str, Any]:
        config_path = tmp_path / f"http-stream-timeout-ceiling-{field}.json"
        config_path.write_text(
            json.dumps(
                {
                    "http": {
                        "listen": f"127.0.0.1:{free_port()}",
                        "upstream": f"http://127.0.0.1:{upstream_port}",
                        field: ceiling + 1,
                    },
                    "tcp": [],
                }
            ),
            encoding="utf-8",
        )
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": path,
            "configured_value": ceiling + 1,
            "maximum_ms": ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text,
        }

    cases = {
        "downstream_write_timeout": run_case(
            "downstream_write_timeout_ms",
            "http.downstream_write_timeout_ms",
            HTTP_DOWNSTREAM_WRITE_TIMEOUT_MAX_MS,
        ),
        "request_body_idle_timeout": run_case(
            "request_body_idle_timeout_ms",
            "http.request_body_idle_timeout_ms",
            HTTP_BODY_IDLE_TIMEOUT_MAX_MS,
        ),
        "upstream_body_idle_timeout": run_case(
            "upstream_body_idle_timeout_ms",
            "http.upstream_body_idle_timeout_ms",
            HTTP_BODY_IDLE_TIMEOUT_MAX_MS,
        ),
        "request_body_min_rate_grace": run_case(
            "request_body_min_rate_grace_ms",
            "http.request_body_min_rate_grace_ms",
            HTTP_BODY_MIN_RATE_GRACE_MAX_MS,
        ),
        "upstream_body_min_rate_grace": run_case(
            "upstream_body_min_rate_grace_ms",
            "http.upstream_body_min_rate_grace_ms",
            HTTP_BODY_MIN_RATE_GRACE_MAX_MS,
        ),
    }
    return {
        **cases,
        "downstream_write_timeout_rejected": cases["downstream_write_timeout"][
            "startup_rejected"
        ],
        "request_body_idle_timeout_rejected": cases["request_body_idle_timeout"][
            "startup_rejected"
        ],
        "upstream_body_idle_timeout_rejected": cases["upstream_body_idle_timeout"][
            "startup_rejected"
        ],
        "request_body_min_rate_grace_rejected": cases["request_body_min_rate_grace"][
            "startup_rejected"
        ],
        "upstream_body_min_rate_grace_rejected": cases["upstream_body_min_rate_grace"][
            "startup_rejected"
        ],
    }


def run_body_size_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(field: str, path: str, ceiling: int) -> dict[str, Any]:
        config_path = tmp_path / f"body-size-ceiling-{field}.json"
        config_path.write_text(
            json.dumps(
                {
                    "http": {
                        "listen": f"127.0.0.1:{free_port()}",
                        "upstream": f"http://127.0.0.1:{upstream_port}",
                        field: ceiling + 1,
                    },
                    "tcp": [],
                }
            ),
            encoding="utf-8",
        )
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": path,
            "configured_value": ceiling + 1,
            "maximum_bytes": ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text,
        }

    cases = {
        "max_body_bytes": run_case(
            "max_body_bytes", "http.max_body_bytes", HTTP_MAX_BODY_BYTES_MAX
        ),
        "max_upstream_body_bytes": run_case(
            "max_upstream_body_bytes",
            "http.max_upstream_body_bytes",
            HTTP_MAX_UPSTREAM_BODY_BYTES_MAX,
        ),
    }
    return {
        **cases,
        "max_body_bytes_rejected": cases["max_body_bytes"]["startup_rejected"],
        "max_upstream_body_bytes_rejected": cases["max_upstream_body_bytes"][
            "startup_rejected"
        ],
    }


def run_min_rate_ceiling_startup_probe(
    binary: Path, upstream_port: int, tcp_upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        name: str,
        field_path: str,
        ceiling: int,
        config_payload: dict[str, Any],
    ) -> dict[str, Any]:
        config_path = tmp_path / f"min-rate-ceiling-{name}.json"
        config_path.write_text(json.dumps(config_payload), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": field_path,
            "configured_value": ceiling + 1,
            "maximum_bytes_per_second": ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and field_path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text,
        }

    http_request_case = run_case(
        "http-request",
        "http.request_body_min_rate_bytes_per_second",
        HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX,
        {
            "http": {
                "listen": f"127.0.0.1:{free_port()}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "request_body_min_rate_bytes_per_second": HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX
                + 1,
            },
            "tcp": [],
        },
    )
    http_upstream_case = run_case(
        "http-upstream",
        "http.upstream_body_min_rate_bytes_per_second",
        HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX,
        {
            "http": {
                "listen": f"127.0.0.1:{free_port()}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "upstream_body_min_rate_bytes_per_second": HTTP_BODY_MIN_RATE_BYTES_PER_SECOND_MAX
                + 1,
            },
            "tcp": [],
        },
    )
    tcp_downstream_case = run_case(
        "tcp-downstream",
        "tcp[0].downstream_min_rate_bytes_per_second",
        TCP_MIN_RATE_BYTES_PER_SECOND_MAX,
        {
            "tcp": [
                {
                    "name": "tcp-downstream-min-rate-ceiling",
                    "listen": f"127.0.0.1:{free_port()}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "downstream_min_rate_bytes_per_second": TCP_MIN_RATE_BYTES_PER_SECOND_MAX
                    + 1,
                }
            ]
        },
    )
    tcp_upstream_case = run_case(
        "tcp-upstream",
        "tcp[0].upstream_min_rate_bytes_per_second",
        TCP_MIN_RATE_BYTES_PER_SECOND_MAX,
        {
            "tcp": [
                {
                    "name": "tcp-upstream-min-rate-ceiling",
                    "listen": f"127.0.0.1:{free_port()}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "upstream_min_rate_bytes_per_second": TCP_MIN_RATE_BYTES_PER_SECOND_MAX
                    + 1,
                }
            ]
        },
    )
    cases = {
        "http_request_body_min_rate": http_request_case,
        "http_upstream_body_min_rate": http_upstream_case,
        "tcp_downstream_min_rate": tcp_downstream_case,
        "tcp_upstream_min_rate": tcp_upstream_case,
    }
    return {
        **cases,
        "http_request_body_min_rate_rejected": http_request_case[
            "startup_rejected"
        ],
        "http_upstream_body_min_rate_rejected": http_upstream_case[
            "startup_rejected"
        ],
        "tcp_downstream_min_rate_rejected": tcp_downstream_case[
            "startup_rejected"
        ],
        "tcp_upstream_min_rate_rejected": tcp_upstream_case["startup_rejected"],
        "all_min_rate_ceilings_rejected": all(
            case["startup_rejected"] for case in cases.values()
        ),
    }


def run_upstream_idle_pool_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        field: str, path: str, ceiling: int, maximum_key: str
    ) -> dict[str, Any]:
        config_path = tmp_path / f"upstream-idle-pool-ceiling-{field}.json"
        config_path.write_text(
            json.dumps(
                {
                    "http": {
                        "listen": f"127.0.0.1:{free_port()}",
                        "upstream": f"http://127.0.0.1:{upstream_port}",
                        field: ceiling + 1,
                    },
                    "tcp": [],
                }
            ),
            encoding="utf-8",
        )
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": path,
            "configured_value": ceiling + 1,
            maximum_key: ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text,
        }

    timeout_case = run_case(
        "upstream_pool_idle_timeout_ms",
        "http.upstream_pool_idle_timeout_ms",
        HTTP_UPSTREAM_POOL_IDLE_TIMEOUT_MAX_MS,
        "maximum_ms",
    )
    max_idle_case = run_case(
        "upstream_pool_max_idle_per_host",
        "http.upstream_pool_max_idle_per_host",
        HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST_MAX,
        "maximum_connections",
    )
    return {
        "upstream_pool_idle_timeout": timeout_case,
        "upstream_pool_max_idle_per_host": max_idle_case,
        "upstream_pool_idle_timeout_rejected": timeout_case["startup_rejected"],
        "upstream_pool_max_idle_per_host_rejected": max_idle_case[
            "startup_rejected"
        ],
    }


def run_connect_timeout_ceiling_startup_probe(
    binary: Path, upstream_port: int, tcp_upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        name: str,
        field_path: str,
        ceiling: int,
        config_payload: dict[str, Any],
    ) -> dict[str, Any]:
        config_path = tmp_path / f"connect-timeout-ceiling-{name}.json"
        config_path.write_text(json.dumps(config_payload), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": field_path,
            "configured_value": ceiling + 1,
            "maximum_ms": ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and field_path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text,
        }

    http_case = run_case(
        "http",
        "http.upstream_connect_timeout_ms",
        HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS,
        {
            "http": {
                "listen": f"127.0.0.1:{free_port()}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "upstream_connect_timeout_ms": HTTP_UPSTREAM_CONNECT_TIMEOUT_MAX_MS
                + 1,
            },
            "tcp": [],
        },
    )
    tcp_case = run_case(
        "tcp",
        "tcp[0].connect_timeout_ms",
        TCP_CONNECT_TIMEOUT_MAX_MS,
        {
            "tcp": [
                {
                    "name": "connect-timeout-ceiling",
                    "listen": f"127.0.0.1:{free_port()}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "connect_timeout_ms": TCP_CONNECT_TIMEOUT_MAX_MS + 1,
                }
            ]
        },
    )
    return {
        "http_upstream_connect_timeout": http_case,
        "tcp_connect_timeout": tcp_case,
        "http_upstream_connect_timeout_rejected": http_case["startup_rejected"],
        "tcp_connect_timeout_rejected": tcp_case["startup_rejected"],
    }


def run_connection_duration_ceiling_startup_probe(
    binary: Path, upstream_port: int, tcp_upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        name: str,
        field_path: str,
        ceiling: int,
        config_payload: dict[str, Any],
    ) -> dict[str, Any]:
        config_path = tmp_path / f"connection-duration-ceiling-{name}.json"
        config_path.write_text(json.dumps(config_payload), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": field_path,
            "configured_value": ceiling + 1,
            "maximum_seconds": ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and field_path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text,
        }

    http_case = run_case(
        "http",
        "http.max_connection_duration_seconds",
        HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS,
        {
            "http": {
                "listen": f"127.0.0.1:{free_port()}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "max_connection_duration_seconds": HTTP_MAX_CONNECTION_DURATION_MAX_SECONDS + 1,
            },
            "tcp": [],
        },
    )
    tcp_case = run_case(
        "tcp",
        "tcp[0].max_connection_duration_seconds",
        TCP_MAX_CONNECTION_DURATION_MAX_SECONDS,
        {
            "tcp": [
                {
                    "name": "duration-ceiling",
                    "listen": f"127.0.0.1:{free_port()}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "max_connection_duration_seconds": TCP_MAX_CONNECTION_DURATION_MAX_SECONDS + 1,
                }
            ]
        },
    )
    return {
        "http_max_connection_duration": http_case,
        "tcp_max_connection_duration": tcp_case,
        "http_max_connection_duration_rejected": http_case["startup_rejected"],
        "tcp_max_connection_duration_rejected": tcp_case["startup_rejected"],
    }


def run_connection_request_count_ceiling_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    oversized = HTTP_MAX_REQUESTS_PER_CONNECTION_MAX + 1
    config_path = tmp_path / "connection-request-count-ceiling-config.json"
    config_path.write_text(
        json.dumps(
            {
                "http": {
                    "listen": f"127.0.0.1:{free_port()}",
                    "upstream": f"http://127.0.0.1:{upstream_port}",
                    "max_requests_per_connection": oversized,
                },
                "tcp": [],
            }
        ),
        encoding="utf-8",
    )
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        _, stderr_text = proxy.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    expected_path = "http.max_requests_per_connection"
    stderr_lines = stderr_text.splitlines()
    startup_rejected = (
        proxy.returncode != 0
        and expected_path in stderr_text
        and f"must be no higher than {HTTP_MAX_REQUESTS_PER_CONNECTION_MAX}" in stderr_text
    )
    return {
        "configured_field": expected_path,
        "configured_value": oversized,
        "maximum_requests": HTTP_MAX_REQUESTS_PER_CONNECTION_MAX,
        "exit_code": proxy.returncode,
        "stderr_tail": stderr_lines[-8:],
        "startup_rejected": startup_rejected,
        "max_requests_per_connection_rejected": startup_rejected,
    }


def run_event_log_backup_count_ceiling_startup_probe(
    binary: Path, tmp_path: Path
) -> dict[str, Any]:
    oversized = EVENT_LOG_BACKUP_COUNT_MAX + 1
    config_path = tmp_path / "event-log-backup-count-ceiling-config.json"
    config_path.write_text(
        json.dumps({"adaptive": {"event_log_backup_count": oversized}}),
        encoding="utf-8",
    )
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        _, stderr_text = proxy.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    expected_path = "adaptive.event_log_backup_count"
    stderr_lines = stderr_text.splitlines()
    startup_rejected = (
        proxy.returncode != 0
        and expected_path in stderr_text
        and f"must be no higher than {EVENT_LOG_BACKUP_COUNT_MAX}" in stderr_text
    )
    return {
        "configured_field": expected_path,
        "configured_value": oversized,
        "maximum_backups": EVENT_LOG_BACKUP_COUNT_MAX,
        "exit_code": proxy.returncode,
        "stderr_tail": stderr_lines[-8:],
        "startup_rejected": startup_rejected,
        "event_log_backup_count_rejected": startup_rejected,
    }


def run_event_log_queue_capacity_ceiling_startup_probe(
    binary: Path, tmp_path: Path
) -> dict[str, Any]:
    oversized = EVENT_LOG_QUEUE_CAPACITY_MAX + 1
    config_path = tmp_path / "event-log-queue-capacity-ceiling-config.json"
    config_path.write_text(
        json.dumps({"adaptive": {"event_log_queue_capacity": oversized}}),
        encoding="utf-8",
    )
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        _, stderr_text = proxy.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    expected_path = "adaptive.event_log_queue_capacity"
    stderr_lines = stderr_text.splitlines()
    startup_rejected = (
        proxy.returncode != 0
        and expected_path in stderr_text
        and f"must be no higher than {EVENT_LOG_QUEUE_CAPACITY_MAX}" in stderr_text
    )
    return {
        "configured_field": expected_path,
        "configured_value": oversized,
        "maximum_events": EVENT_LOG_QUEUE_CAPACITY_MAX,
        "exit_code": proxy.returncode,
        "stderr_tail": stderr_lines[-8:],
        "startup_rejected": startup_rejected,
        "event_log_queue_capacity_rejected": startup_rejected,
    }


def run_dynamic_state_ceiling_startup_probe(
    binary: Path, upstream_port: int, tcp_upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        name: str, cfg: dict[str, Any], expected_path: str, ceiling: int
    ) -> dict[str, Any]:
        config_path = tmp_path / f"dynamic-state-ceiling-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        startup_rejected = (
            proxy.returncode != 0
            and expected_path in stderr_text
            and f"must be no higher than {ceiling}" in stderr_text
        )
        return {
            "configured_field": expected_path,
            "configured_ceiling": ceiling,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": startup_rejected,
        }

    def http_config(limits: dict[str, Any]) -> dict[str, Any]:
        return {
            "http": {
                "listen": "127.0.0.1:0",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "limits": limits,
            }
        }

    def tcp_config(limits: dict[str, Any]) -> dict[str, Any]:
        return {
            "tcp": [
                {
                    "name": "dynamic-state-ceiling-tcp",
                    "listen": "127.0.0.1:0",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "limits": limits,
                }
            ]
        }

    cases = {
        "filter_runtime_file_bytes": run_case(
            "filter-runtime-file-bytes",
            {"filters": {"max_runtime_file_bytes": FILTER_RUNTIME_FILE_MAX_BYTES_MAX + 1}},
            "filters.max_runtime_file_bytes",
            FILTER_RUNTIME_FILE_MAX_BYTES_MAX,
        ),
        "filter_runtime_filters": run_case(
            "filter-runtime-filters",
            {"filters": {"max_runtime_filters": FILTER_RULE_COUNT_MAX + 1}},
            "filters.max_runtime_filters",
            FILTER_RULE_COUNT_MAX,
        ),
        "filter_static_filters": run_case(
            "filter-static-filters",
            {"filters": {"max_static_filters": FILTER_RULE_COUNT_MAX + 1}},
            "filters.max_static_filters",
            FILTER_RULE_COUNT_MAX,
        ),
        "static_filter_ttl_seconds": run_case(
            "static-filter-ttl-seconds",
            {
                "filters": {
                    "static_rules": [
                        {
                            "id": "ttl",
                            "ttl_seconds": FILTER_TTL_MAX_SECONDS + 1,
                            "condition": {"path_exact": "/blocked"},
                        }
                    ]
                }
            },
            "filters.static_rules[0].ttl_seconds",
            FILTER_TTL_MAX_SECONDS,
        ),
        "adaptive_activation_ttl_seconds": run_case(
            "adaptive-activation-ttl-seconds",
            {"adaptive": {"activation_ttl_seconds": FILTER_TTL_MAX_SECONDS + 1}},
            "adaptive.activation_ttl_seconds",
            FILTER_TTL_MAX_SECONDS,
        ),
        "adaptive_event_log_max_bytes": run_case(
            "adaptive-event-log-max-bytes",
            {"adaptive": {"event_log_max_bytes": ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX + 1}},
            "adaptive.event_log_max_bytes",
            ADAPTIVE_EVENT_LOG_MAX_BYTES_MAX,
        ),
        "adaptive_signature_windows": run_case(
            "adaptive-signature-windows",
            {"adaptive": {"max_signature_windows": ADAPTIVE_WINDOW_COUNT_MAX + 1}},
            "adaptive.max_signature_windows",
            ADAPTIVE_WINDOW_COUNT_MAX,
        ),
        "adaptive_path_shape_windows": run_case(
            "adaptive-path-shape-windows",
            {"adaptive": {"max_path_shape_windows": ADAPTIVE_WINDOW_COUNT_MAX + 1}},
            "adaptive.max_path_shape_windows",
            ADAPTIVE_WINDOW_COUNT_MAX,
        ),
        "http_max_tracked_ips": run_case(
            "http-max-tracked-ips",
            http_config({"max_tracked_ips": LIMITER_MAX_TRACKED_IPS_MAX + 1}),
            "http.limits.max_tracked_ips",
            LIMITER_MAX_TRACKED_IPS_MAX,
        ),
        "http_max_tracked_signatures": run_case(
            "http-max-tracked-signatures",
            http_config({"max_tracked_signatures": LIMITER_MAX_TRACKED_SIGNATURES_MAX + 1}),
            "http.limits.max_tracked_signatures",
            LIMITER_MAX_TRACKED_SIGNATURES_MAX,
        ),
        "http_max_tracked_path_shapes": run_case(
            "http-max-tracked-path-shapes",
            http_config({"max_tracked_path_shapes": LIMITER_MAX_TRACKED_PATH_SHAPES_MAX + 1}),
            "http.limits.max_tracked_path_shapes",
            LIMITER_MAX_TRACKED_PATH_SHAPES_MAX,
        ),
        "tcp_max_tracked_ips": run_case(
            "tcp-max-tracked-ips",
            tcp_config({"max_tracked_ips": LIMITER_MAX_TRACKED_IPS_MAX + 1}),
            "tcp[0].limits.max_tracked_ips",
            LIMITER_MAX_TRACKED_IPS_MAX,
        ),
    }
    cases["all_dynamic_state_ceilings_rejected"] = all(
        case["startup_rejected"] for case in cases.values()
    )
    return cases


def run_control_capacity_startup_probe(binary: Path, tmp_path: Path) -> dict[str, Any]:
    def run_case(name: str, cfg: dict[str, Any], expected_path: str) -> dict[str, Any]:
        config_path = tmp_path / f"control-capacity-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_field": expected_path,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0
            and expected_path in stderr_text
            and "must be greater than zero" in stderr_text,
        }

    filter_file_cap_case = run_case(
        "filter-file-cap",
        {"filters": {"max_runtime_file_bytes": 0}},
        "filters.max_runtime_file_bytes",
    )
    filter_rule_cap_case = run_case(
        "filter-rule-cap",
        {"filters": {"max_runtime_filters": 0}},
        "filters.max_runtime_filters",
    )
    adaptive_log_cap_case = run_case(
        "adaptive-log-cap",
        {"adaptive": {"event_log_max_bytes": 0}},
        "adaptive.event_log_max_bytes",
    )
    adaptive_queue_cap_case = run_case(
        "adaptive-queue-cap",
        {"adaptive": {"event_log_queue_capacity": 0}},
        "adaptive.event_log_queue_capacity",
    )
    adaptive_flush_case = run_case(
        "adaptive-flush-interval",
        {"adaptive": {"event_log_flush_interval_ms": 0}},
        "adaptive.event_log_flush_interval_ms",
    )
    adaptive_window_case = run_case(
        "adaptive-window-cap",
        {"adaptive": {"max_signature_windows": 0}},
        "adaptive.max_signature_windows",
    )
    return {
        "filter_file_cap": filter_file_cap_case,
        "filter_rule_cap": filter_rule_cap_case,
        "adaptive_log_cap": adaptive_log_cap_case,
        "adaptive_queue_cap": adaptive_queue_cap_case,
        "adaptive_flush_interval": adaptive_flush_case,
        "adaptive_window_cap": adaptive_window_case,
        "filter_file_cap_rejected": filter_file_cap_case["startup_rejected"],
        "filter_rule_cap_rejected": filter_rule_cap_case["startup_rejected"],
        "adaptive_log_cap_rejected": adaptive_log_cap_case["startup_rejected"],
        "adaptive_queue_cap_rejected": adaptive_queue_cap_case["startup_rejected"],
        "adaptive_flush_interval_rejected": adaptive_flush_case["startup_rejected"],
        "adaptive_window_cap_rejected": adaptive_window_case["startup_rejected"],
    }


def run_config_file_startup_probe(binary: Path, tmp_path: Path) -> dict[str, Any]:
    def run_case(config_path: Path, expected_text: str) -> dict[str, Any]:
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "config_path": str(config_path),
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0 and expected_text in stderr_text,
        }

    oversized_path = tmp_path / "oversized-startup-config.json"
    oversized_path.write_text(
        json.dumps({"padding": "x" * (1024 * 1024 + 1024)}),
        encoding="utf-8",
    )
    non_regular_path = tmp_path / "non-regular-startup-config.json"
    non_regular_path.mkdir()

    oversized_case = run_case(oversized_path, "above configured cap")
    non_regular_case = run_case(non_regular_path, "must be a regular file")
    return {
        "oversized_config": oversized_case,
        "non_regular_config": non_regular_case,
        "oversized_config_rejected": oversized_case["startup_rejected"],
        "non_regular_config_rejected": non_regular_case["startup_rejected"],
    }


def run_http_endpoint_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(name: str, http_cfg: dict[str, Any], expected_text: str) -> dict[str, Any]:
        config_path = tmp_path / f"http-endpoint-{name}-config.json"
        config_path.write_text(json.dumps({"http": http_cfg, "tcp": []}), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured": http_cfg,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0 and expected_text in stderr_text,
        }

    invalid_listen_case = run_case(
        "invalid-listen",
        {"listen": "not-a-socket", "upstream": f"http://127.0.0.1:{upstream_port}"},
        "invalid http.listen address",
    )
    missing_scheme_case = run_case(
        "missing-scheme",
        {"listen": f"127.0.0.1:{free_port()}", "upstream": "127.0.0.1:1"},
        "http.upstream must include http:// scheme",
    )
    https_scheme_case = run_case(
        "https-scheme",
        {"listen": f"127.0.0.1:{free_port()}", "upstream": "https://127.0.0.1:1"},
        "http.upstream must use http:// scheme",
    )
    userinfo_case = run_case(
        "userinfo",
        {
            "listen": f"127.0.0.1:{free_port()}",
            "upstream": "http://user@127.0.0.1:1",
        },
        "http.upstream must not contain URI userinfo",
    )
    query_case = run_case(
        "query",
        {
            "listen": f"127.0.0.1:{free_port()}",
            "upstream": "http://127.0.0.1:1/base?x=1",
        },
        "http.upstream must not include a query string",
    )
    return {
        "invalid_listen": invalid_listen_case,
        "missing_upstream_scheme": missing_scheme_case,
        "https_upstream_scheme": https_scheme_case,
        "upstream_userinfo": userinfo_case,
        "upstream_query": query_case,
        "invalid_listen_rejected": invalid_listen_case["startup_rejected"],
        "missing_upstream_scheme_rejected": missing_scheme_case["startup_rejected"],
        "https_upstream_scheme_rejected": https_scheme_case["startup_rejected"],
        "upstream_userinfo_rejected": userinfo_case["startup_rejected"],
        "upstream_query_rejected": query_case["startup_rejected"],
    }


def run_tcp_endpoint_startup_probe(binary: Path, tmp_path: Path) -> dict[str, Any]:
    def run_case(name: str, tcp_cfg: dict[str, Any], expected_text: str) -> dict[str, Any]:
        config_path = tmp_path / f"tcp-endpoint-{name}-config.json"
        config_path.write_text(json.dumps({"tcp": [tcp_cfg]}), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured": tcp_cfg,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0 and expected_text in stderr_text,
        }

    invalid_listen_case = run_case(
        "invalid-listen",
        {"name": "tcp", "listen": "not-a-socket", "upstream": "127.0.0.1:1"},
        "invalid tcp[0].listen address",
    )
    missing_port_case = run_case(
        "missing-port",
        {"name": "tcp", "listen": f"127.0.0.1:{free_port()}", "upstream": "127.0.0.1"},
        "tcp[0].upstream must include a numeric port",
    )
    scheme_case = run_case(
        "scheme",
        {
            "name": "tcp",
            "listen": f"127.0.0.1:{free_port()}",
            "upstream": "http://127.0.0.1:1",
        },
        "tcp[0].upstream must be host:port without a URL scheme",
    )
    userinfo_case = run_case(
        "userinfo",
        {
            "name": "tcp",
            "listen": f"127.0.0.1:{free_port()}",
            "upstream": "user@127.0.0.1:1",
        },
        "tcp[0].upstream must not contain URI userinfo",
    )
    path_case = run_case(
        "path",
        {
            "name": "tcp",
            "listen": f"127.0.0.1:{free_port()}",
            "upstream": "127.0.0.1:1/base",
        },
        "tcp[0].upstream must not include a path, query, or fragment",
    )
    zero_port_case = run_case(
        "zero-port",
        {
            "name": "tcp",
            "listen": f"127.0.0.1:{free_port()}",
            "upstream": "127.0.0.1:0",
        },
        "tcp[0].upstream port must be greater than zero",
    )
    return {
        "invalid_listen": invalid_listen_case,
        "missing_upstream_port": missing_port_case,
        "upstream_scheme": scheme_case,
        "upstream_userinfo": userinfo_case,
        "upstream_path": path_case,
        "upstream_zero_port": zero_port_case,
        "invalid_listen_rejected": invalid_listen_case["startup_rejected"],
        "missing_upstream_port_rejected": missing_port_case["startup_rejected"],
        "upstream_scheme_rejected": scheme_case["startup_rejected"],
        "upstream_userinfo_rejected": userinfo_case["startup_rejected"],
        "upstream_path_rejected": path_case["startup_rejected"],
        "upstream_zero_port_rejected": zero_port_case["startup_rejected"],
    }


def run_filter_rule_startup_probe(binary: Path, tmp_path: Path) -> dict[str, Any]:
    def run_case(name: str, cfg: dict[str, Any], expected_text: str) -> dict[str, Any]:
        config_path = tmp_path / f"filter-rule-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "config_path": str(config_path),
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0 and expected_text in stderr_text,
        }

    valid_rule = {"id": "one", "condition": {"path_exact": "/one"}}
    too_many_static_case = run_case(
        "static-count",
        {
            "filters": {
                "max_static_filters": 1,
                "static_rules": [
                    valid_rule,
                    {"id": "two", "condition": {"path_exact": "/two"}},
                ],
            }
        },
        "filters.static_rules contains 2 filters",
    )
    empty_condition_case = run_case(
        "empty-condition",
        {"filters": {"static_rules": [{"id": "catchall"}]}},
        "filters.static_rules[0].condition must include at least one matcher",
    )
    invalid_status_case = run_case(
        "invalid-status",
        {
            "filters": {
                "static_rules": [
                    {
                        "id": "invalid-status",
                        "condition": {"path_exact": "/bad"},
                        "action": {"kind": "block", "status": 200, "body": "blocked\n"},
                    }
                ]
            }
        },
        "filters.static_rules[0].action.status",
    )
    oversized_body_case = run_case(
        "oversized-body",
        {
            "filters": {
                "static_rules": [
                    {
                        "id": "oversized-body",
                        "condition": {"path_exact": "/bad"},
                        "action": {
                            "kind": "block",
                            "status": 403,
                            "body": "x" * 2048,
                        },
                    }
                ]
            }
        },
        "filters.static_rules[0].action.body",
    )
    return {
        "too_many_static_filters": too_many_static_case,
        "empty_condition": empty_condition_case,
        "invalid_status": invalid_status_case,
        "oversized_body": oversized_body_case,
        "too_many_static_filters_rejected": too_many_static_case["startup_rejected"],
        "empty_condition_rejected": empty_condition_case["startup_rejected"],
        "invalid_status_rejected": invalid_status_case["startup_rejected"],
        "oversized_body_rejected": oversized_body_case["startup_rejected"],
    }


def run_allowed_methods_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(name: str, methods: list[str], expected_text: str) -> dict[str, Any]:
        proxy_port = free_port()
        cfg = {
            "http": {
                "listen": f"127.0.0.1:{proxy_port}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "allowed_methods": methods,
            },
            "tcp": [],
        }
        config_path = tmp_path / f"allowed-methods-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_allowed_methods": methods,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0 and expected_text in stderr_text,
        }

    empty_case = run_case(
        "empty",
        [],
        "http.allowed_methods must contain at least one method",
    )
    invalid_token_case = run_case(
        "invalid-token",
        ["BAD METHOD"],
        "http.allowed_methods[0] is not a valid HTTP method token",
    )
    oversized_token_case = run_case(
        "oversized-token",
        ["A" * 33],
        "http.allowed_methods[0] is 33 bytes",
    )
    duplicate_case = run_case(
        "duplicate",
        ["GET", "GET"],
        "http.allowed_methods[1] duplicates 'GET'",
    )
    unsupported_connect_case = run_case(
        "unsupported-connect",
        ["GET", "CONNECT"],
        "http.allowed_methods[1] must not include unsupported tunnel or diagnostic method 'CONNECT'",
    )
    unsupported_trace_case = run_case(
        "unsupported-trace",
        ["GET", "TRACE"],
        "http.allowed_methods[1] must not include unsupported tunnel or diagnostic method 'TRACE'",
    )
    unsupported_track_case = run_case(
        "unsupported-track",
        ["GET", "TRACK"],
        "http.allowed_methods[1] must not include unsupported tunnel or diagnostic method 'TRACK'",
    )
    too_many_case = run_case(
        "too-many",
        [f"M{idx}" for idx in range(17)],
        "http.allowed_methods contains 17 methods",
    )
    return {
        "empty": empty_case,
        "invalid_token": invalid_token_case,
        "oversized_token": oversized_token_case,
        "duplicate": duplicate_case,
        "unsupported_connect": unsupported_connect_case,
        "unsupported_trace": unsupported_trace_case,
        "unsupported_track": unsupported_track_case,
        "too_many": too_many_case,
        "empty_rejected": empty_case["startup_rejected"],
        "invalid_token_rejected": invalid_token_case["startup_rejected"],
        "oversized_token_rejected": oversized_token_case["startup_rejected"],
        "duplicate_rejected": duplicate_case["startup_rejected"],
        "unsupported_connect_rejected": unsupported_connect_case["startup_rejected"],
        "unsupported_trace_rejected": unsupported_trace_case["startup_rejected"],
        "unsupported_track_rejected": unsupported_track_case["startup_rejected"],
        "too_many_rejected": too_many_case["startup_rejected"],
    }


def run_allowed_hosts_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        name: str,
        allowed_hosts: list[str],
        expected_text: str,
        max_host_bytes: int | None = None,
    ) -> dict[str, Any]:
        proxy_port = free_port()
        http_cfg: dict[str, Any] = {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "allowed_hosts": allowed_hosts,
        }
        if max_host_bytes is not None:
            http_cfg["max_host_bytes"] = max_host_bytes
        cfg = {"http": http_cfg, "tcp": []}
        config_path = tmp_path / f"allowed-hosts-{name}-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_allowed_hosts": allowed_hosts,
            "configured_max_host_bytes": max_host_bytes,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0 and expected_text in stderr_text,
        }

    blank_case = run_case(
        "blank",
        [""],
        "http.allowed_hosts[0] must not be empty",
    )
    whitespace_case = run_case(
        "whitespace",
        [" good.local"],
        "http.allowed_hosts[0] must not start or end with whitespace",
    )
    invalid_authority_case = run_case(
        "invalid-authority",
        ["http://good.local"],
        "http.allowed_hosts[0] is not a valid HTTP authority",
    )
    userinfo_case = run_case(
        "userinfo",
        ["user@good.local"],
        "http.allowed_hosts[0] must not contain URI userinfo",
    )
    wildcard_case = run_case(
        "wildcard",
        ["*.good.local"],
        "http.allowed_hosts[0] must be an exact host or host:port",
    )
    oversized_case = run_case(
        "oversized",
        ["too-long.local"],
        "http.allowed_hosts[0] is 14 bytes, above configured cap of 8 bytes",
        max_host_bytes=8,
    )
    duplicate_case = run_case(
        "duplicate",
        ["good.local", "GOOD.local"],
        "http.allowed_hosts[1] duplicates 'GOOD.local'",
    )
    too_many_case = run_case(
        "too-many",
        [f"h{idx}.good.local" for idx in range(129)],
        "http.allowed_hosts contains 129 hosts",
    )
    return {
        "blank": blank_case,
        "whitespace": whitespace_case,
        "invalid_authority": invalid_authority_case,
        "userinfo": userinfo_case,
        "wildcard": wildcard_case,
        "oversized": oversized_case,
        "duplicate": duplicate_case,
        "too_many": too_many_case,
        "blank_rejected": blank_case["startup_rejected"],
        "whitespace_rejected": whitespace_case["startup_rejected"],
        "invalid_authority_rejected": invalid_authority_case["startup_rejected"],
        "userinfo_rejected": userinfo_case["startup_rejected"],
        "wildcard_rejected": wildcard_case["startup_rejected"],
        "oversized_rejected": oversized_case["startup_rejected"],
        "duplicate_rejected": duplicate_case["startup_rejected"],
        "too_many_rejected": too_many_case["startup_rejected"],
    }


def run_client_ip_config_startup_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    def run_case(
        name: str, client_ip: dict[str, Any], expected_text: str
    ) -> dict[str, Any]:
        proxy_port = free_port()
        cfg = {
            "http": {
                "listen": f"127.0.0.1:{proxy_port}",
                "upstream": f"http://127.0.0.1:{upstream_port}",
                "client_ip": client_ip,
            },
            "tcp": [],
        }
        config_path = tmp_path / f"client-ip-config-{name}.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                _, stderr_text = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, stderr_text = proxy.communicate(timeout=5)
        stderr_lines = stderr_text.splitlines()
        return {
            "configured_client_ip": client_ip,
            "exit_code": proxy.returncode,
            "stderr_tail": stderr_lines[-8:],
            "startup_rejected": proxy.returncode != 0 and expected_text in stderr_text,
        }

    invalid_header_case = run_case(
        "invalid-header",
        {"header": "bad header"},
        "http.client_ip.header is not a valid HTTP field name",
    )
    oversized_header_case = run_case(
        "oversized-header",
        {"header": f"x-{'a' * 63}"},
        "http.client_ip.header is 65 bytes",
    )
    blank_trusted_proxy_case = run_case(
        "blank-trusted-proxy",
        {"trusted_proxies": [""]},
        "http.client_ip.trusted_proxies[0] must not be empty",
    )
    invalid_trusted_proxy_case = run_case(
        "invalid-trusted-proxy",
        {"trusted_proxies": ["not-a-cidr"]},
        "invalid http.client_ip.trusted_proxies entry 'not-a-cidr'",
    )
    oversized_trusted_proxy_case = run_case(
        "oversized-trusted-proxy",
        {"trusted_proxies": ["1" * 65]},
        "http.client_ip.trusted_proxies[0] is 65 bytes",
    )
    duplicate_trusted_proxy_case = run_case(
        "duplicate-trusted-proxy",
        {"trusted_proxies": ["127.0.0.1/32", "127.0.0.1/32"]},
        "http.client_ip.trusted_proxies[1] duplicates '127.0.0.1/32'",
    )
    too_many_trusted_proxies_case = run_case(
        "too-many-trusted-proxies",
        {"trusted_proxies": [f"2001:db8::{idx}" for idx in range(129)]},
        "http.client_ip.trusted_proxies contains 129 entries",
    )
    return {
        "invalid_header": invalid_header_case,
        "oversized_header": oversized_header_case,
        "blank_trusted_proxy": blank_trusted_proxy_case,
        "invalid_trusted_proxy": invalid_trusted_proxy_case,
        "oversized_trusted_proxy": oversized_trusted_proxy_case,
        "duplicate_trusted_proxy": duplicate_trusted_proxy_case,
        "too_many_trusted_proxies": too_many_trusted_proxies_case,
        "invalid_header_rejected": invalid_header_case["startup_rejected"],
        "oversized_header_rejected": oversized_header_case["startup_rejected"],
        "blank_trusted_proxy_rejected": blank_trusted_proxy_case["startup_rejected"],
        "invalid_trusted_proxy_rejected": invalid_trusted_proxy_case["startup_rejected"],
        "oversized_trusted_proxy_rejected": oversized_trusted_proxy_case[
            "startup_rejected"
        ],
        "duplicate_trusted_proxy_rejected": duplicate_trusted_proxy_case[
            "startup_rejected"
        ],
        "too_many_trusted_proxies_rejected": too_many_trusted_proxies_case[
            "startup_rejected"
        ],
    }


def run_runtime_sigterm_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "runtime-sigterm-filters.json"
    events_path = tmp_path / "runtime-sigterm-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "runtime": {"shutdown_grace_ms": 0},
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "runtime-sigterm-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "runtime-sigterm-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    health_status = None
    stderr_text = ""
    try:
        wait_http("127.0.0.1", proxy_port)
        health_status = get_status(proxy_port, "GET", "/__altura/health")
        os.kill(proxy.pid, signal.SIGTERM)
        _, stderr_text = proxy.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.kill()
        _, stderr_text = proxy.communicate(timeout=5)
    finally:
        if proxy.poll() is None:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    stderr_lines = stderr_text.splitlines()
    return {
        "health_status": health_status,
        "exit_code": proxy.returncode,
        "stderr_tail": stderr_lines[-8:],
        "sigterm_graceful": health_status == 200
        and proxy.returncode == 0
        and any(line == "shutdown signal received: SIGTERM" for line in stderr_lines),
    }


def run_downstream_write_timeout_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "downstream-write-timeout-filters.json"
    events_path = tmp_path / "downstream-write-timeout-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "downstream-write-timeout-token",
            "downstream_write_timeout_ms": 20,
            "upstream_timeout_ms": 2_000,
            "upstream_body_idle_timeout_ms": 2_000,
            "max_upstream_body_bytes": 64 * 1024 * 1024,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "downstream-write-timeout-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="downstream-write-timeout-token")
        slow_reader_response = send_slow_downstream_reader_request(proxy_port)
        time.sleep(0.05)
        metrics_after = fetch_metrics(proxy_port, token="downstream-write-timeout-token")
        write_timeout_delta = metrics_after.get(
            "altura_http_downstream_write_timeouts", 0
        ) - metrics_before.get("altura_http_downstream_write_timeouts", 0)
        return {
            "configured_downstream_write_timeout_ms": 20,
            "slow_reader_response": slow_reader_response,
            "http_downstream_write_timeouts_delta": write_timeout_delta,
            "downstream_write_timeout_observed": write_timeout_delta >= 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_upstream_connect_timeout_probe(binary: Path, tmp_path: Path) -> dict[str, Any]:
    saturation = saturate_loopback_backlog()
    proxy_port = free_port()
    filters_path = tmp_path / "upstream-connect-timeout-filters.json"
    events_path = tmp_path / "upstream-connect-timeout-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{saturation.port}",
            "preserve_host": True,
            "admin_token": "upstream-connect-timeout-token",
            "upstream_connect_timeout_ms": 75,
            "upstream_timeout_ms": 1000,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 1,
                "max_in_flight_requests_per_ip": 1,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "upstream-connect-timeout-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="upstream-connect-timeout-token")
        first = read_raw_response(proxy_port, "/connect-timeout")
        second = read_raw_response(proxy_port, "/connect-timeout")
        metrics_after = fetch_metrics(proxy_port, token="upstream-connect-timeout-token")
        upstream_errors_delta = metrics_after.get(
            "altura_http_upstream_errors", 0
        ) - metrics_before.get("altura_http_upstream_errors", 0)
        upstream_timeouts_delta = metrics_after.get(
            "altura_http_upstream_timeouts", 0
        ) - metrics_before.get("altura_http_upstream_timeouts", 0)
        in_flight_rejected_delta = metrics_after.get(
            "altura_http_upstream_in_flight_rejected", 0
        ) - metrics_before.get("altura_http_upstream_in_flight_rejected", 0)
        generated_502_not_stored = generated_response_header_matches(
            "cache-control", "no-store", first, second
        )
        generated_502_closes_connection = generated_response_header_matches(
            "connection", "close", first, second
        )
        return {
            "configured_upstream_connect_timeout_ms": 75,
            "configured_upstream_timeout_ms": 1000,
            "loopback_backlog_blocked": saturation.backlog_blocked,
            "held_backlog_connections": len(saturation.held_connections),
            "first_response": first,
            "second_response": second,
            "generated_502_not_stored": generated_502_not_stored,
            "generated_502_closes_connection": generated_502_closes_connection,
            "http_upstream_errors_delta": upstream_errors_delta,
            "http_upstream_timeouts_delta": upstream_timeouts_delta,
            "http_upstream_in_flight_rejected_delta": in_flight_rejected_delta,
            "upstream_connect_timeout_observed": saturation.backlog_blocked
            and first["status"] == 502
            and second["status"] == 502
            and generated_502_not_stored
            and generated_502_closes_connection
            and first["elapsed_seconds"] < 0.5
            and second["elapsed_seconds"] < 0.5
            and upstream_errors_delta >= 2
            and upstream_timeouts_delta == 0
            and in_flight_rejected_delta == 0,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)
        saturation.close()


def run_upstream_failure_circuit_probe(binary: Path, tmp_path: Path) -> dict[str, Any]:
    saturation = saturate_loopback_backlog()
    proxy_port = free_port()
    filters_path = tmp_path / "upstream-failure-circuit-filters.json"
    events_path = tmp_path / "upstream-failure-circuit-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    circuit_open_ms = 200
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{saturation.port}",
            "preserve_host": True,
            "admin_token": "upstream-failure-circuit-token",
            "upstream_connect_timeout_ms": 75,
            "upstream_timeout_ms": 1000,
            "upstream_failure_threshold": 2,
            "upstream_failure_open_ms": circuit_open_ms,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 2,
                "max_in_flight_requests_per_ip": 2,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "upstream-failure-circuit-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="upstream-failure-circuit-token")
        first = read_raw_response(proxy_port, "/failure-circuit")
        second = read_raw_response(proxy_port, "/failure-circuit")
        third = read_raw_response(proxy_port, "/failure-circuit")
        unrelated = read_raw_response(proxy_port, "/unrelated-circuit")
        time.sleep((circuit_open_ms + 75) / 1000.0)
        fourth = read_raw_response(proxy_port, "/failure-circuit")
        metrics_after = fetch_metrics(proxy_port, token="upstream-failure-circuit-token")
        upstream_errors_delta = metrics_after.get(
            "altura_http_upstream_errors", 0
        ) - metrics_before.get("altura_http_upstream_errors", 0)
        upstream_timeouts_delta = metrics_after.get(
            "altura_http_upstream_timeouts", 0
        ) - metrics_before.get("altura_http_upstream_timeouts", 0)
        circuit_open_delta = metrics_after.get(
            "altura_http_upstream_circuit_open", 0
        ) - metrics_before.get("altura_http_upstream_circuit_open", 0)
        generated_503_retry_after = response_headers_for_status(
            [third], "retry-after", 503
        )
        generated_503_cache_control = response_headers_for_status(
            [third], "cache-control", 503
        )
        return {
            "configured_upstream_connect_timeout_ms": 75,
            "configured_upstream_failure_threshold": 2,
            "configured_upstream_failure_open_ms": circuit_open_ms,
            "loopback_backlog_blocked": saturation.backlog_blocked,
            "first_response": first,
            "second_response": second,
            "third_response": third,
            "unrelated_shape_response_while_circuit_open": unrelated,
            "fourth_response_after_open_window": fourth,
            "generated_503_retry_after": generated_503_retry_after,
            "generated_503_cache_control": generated_503_cache_control,
            "http_upstream_errors_delta": upstream_errors_delta,
            "http_upstream_timeouts_delta": upstream_timeouts_delta,
            "http_upstream_circuit_open_delta": circuit_open_delta,
            "circuit_opened_after_consecutive_failures": saturation.backlog_blocked
            and first["status"] == 502
            and second["status"] == 502
            and third["status"] == 503
            and third["elapsed_seconds"] < 0.05
            and generated_503_retry_after == ["1"]
            and generated_503_cache_control == ["no-store"]
            and upstream_errors_delta == 4
            and upstream_timeouts_delta == 0
            and circuit_open_delta == 1,
            "circuit_scoped_to_path_shape": unrelated["status"] == 502
            and unrelated["elapsed_seconds"] >= 0.05,
            "circuit_reallowed_after_open_window": fourth["status"] == 502
            and fourth["elapsed_seconds"] >= 0.05,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)
        saturation.close()


def run_upstream_timeout_response_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "upstream-timeout-response-filters.json"
    events_path = tmp_path / "upstream-timeout-response-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "upstream-timeout-response-token",
            "upstream_connect_timeout_ms": 1000,
            "upstream_timeout_ms": 100,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "upstream-timeout-response-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="upstream-timeout-response-token")
        timeout_response = read_raw_response(proxy_port, "/slow")
        metrics_after = fetch_metrics(proxy_port, token="upstream-timeout-response-token")
        upstream_timeouts_delta = metrics_after.get(
            "altura_http_upstream_timeouts", 0
        ) - metrics_before.get("altura_http_upstream_timeouts", 0)
        upstream_errors_delta = metrics_after.get(
            "altura_http_upstream_errors", 0
        ) - metrics_before.get("altura_http_upstream_errors", 0)
        generated_504_not_stored = generated_response_header_matches(
            "cache-control", "no-store", timeout_response
        )
        generated_504_closes_connection = generated_response_header_matches(
            "connection", "close", timeout_response
        )
        return {
            "configured_upstream_connect_timeout_ms": 1000,
            "configured_upstream_timeout_ms": 100,
            "timeout_response": timeout_response,
            "generated_504_not_stored": generated_504_not_stored,
            "generated_504_closes_connection": generated_504_closes_connection,
            "http_upstream_timeouts_delta": upstream_timeouts_delta,
            "http_upstream_errors_delta": upstream_errors_delta,
            "upstream_timeout_response_observed": timeout_response["status"] == 504
            and generated_504_not_stored
            and generated_504_closes_connection
            and upstream_timeouts_delta >= 1
            and upstream_errors_delta == 0,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_upstream_header_guard_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "upstream-header-guard-filters.json"
    events_path = tmp_path / "upstream-header-guard-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "upstream-header-guard-token",
            "upstream_max_header_bytes": 8192,
            "upstream_max_headers": 8,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "upstream-header-guard-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="upstream-header-guard-token")
        huge_header = read_raw_response(proxy_port, "/huge-response-headers")
        many_headers = read_raw_response(proxy_port, "/many-response-headers")
        metrics_after = fetch_metrics(proxy_port, token="upstream-header-guard-token")
        header_rejected_delta = metrics_after.get(
            "altura_http_upstream_header_rejected", 0
        ) - metrics_before.get("altura_http_upstream_header_rejected", 0)
        upstream_errors_delta = metrics_after.get(
            "altura_http_upstream_errors", 0
        ) - metrics_before.get("altura_http_upstream_errors", 0)
        generated_502_not_stored = generated_response_header_matches(
            "cache-control", "no-store", huge_header, many_headers
        )
        generated_502_closes_connection = generated_response_header_matches(
            "connection", "close", huge_header, many_headers
        )
        return {
            "configured_upstream_max_header_bytes": 8192,
            "configured_upstream_max_headers": 8,
            "huge_header_response": huge_header,
            "many_headers_response": many_headers,
            "generated_502_not_stored": generated_502_not_stored,
            "generated_502_closes_connection": generated_502_closes_connection,
            "http_upstream_header_rejected_delta": header_rejected_delta,
            "http_upstream_errors_delta": upstream_errors_delta,
            "upstream_header_guard_observed": huge_header["status"] == 502
            and many_headers["status"] == 502
            and generated_502_not_stored
            and generated_502_closes_connection
            and header_rejected_delta >= 2,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_header_line_cap_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "header-line-cap-filters.json"
    events_path = tmp_path / "header-line-cap-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "header-line-cap-token",
            "downstream_keep_alive": True,
            "max_header_bytes": 8192,
            "max_header_line_bytes": 128,
            "max_headers": 32,
            "upstream_max_header_bytes": 32768,
            "upstream_max_header_line_bytes": 128,
            "upstream_max_headers": 32,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "header-line-cap-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="header-line-cap-token")
        raw_initial = send_raw_initial_header_line_too_large(proxy_port)
        keepalive_followup = send_keepalive_followup_framing_request(
            proxy_port,
            [
                "X-Oversized-Header: " + ("a" * 192),
                "Content-Length: 0",
            ],
        )
        upstream_response = read_raw_response(proxy_port, "/huge-response-headers")
        metrics_after = fetch_metrics(proxy_port, token="header-line-cap-token")
        initial_header_too_large_delta = metrics_after.get(
            "altura_http_initial_header_too_large", 0
        ) - metrics_before.get("altura_http_initial_header_too_large", 0)
        header_line_rejected_delta = metrics_after.get(
            "altura_http_header_line_rejected", 0
        ) - metrics_before.get("altura_http_header_line_rejected", 0)
        upstream_header_rejected_delta = metrics_after.get(
            "altura_http_upstream_header_rejected", 0
        ) - metrics_before.get("altura_http_upstream_header_rejected", 0)
        upstream_errors_delta = metrics_after.get(
            "altura_http_upstream_errors", 0
        ) - metrics_before.get("altura_http_upstream_errors", 0)
        raw_initial_ok = (
            raw_initial.get("status") == 431
            and raw_initial.get("cache_control_no_store") is True
            and raw_initial.get("connection_close") is True
        )
        keepalive_second = keepalive_followup.get("second", {})
        keepalive_ok = (
            keepalive_second.get("status") == 431
            and keepalive_second.get("cache_control_no_store") is True
            and keepalive_second.get("connection_close") is True
        )
        upstream_ok = (
            upstream_response.get("status") == 502
            and upstream_response.get("headers", {}).get("cache-control") == "no-store"
            and upstream_response.get("headers", {}).get("connection") == "close"
        )
        return {
            "configured_max_header_bytes": 8192,
            "configured_max_header_line_bytes": 128,
            "configured_upstream_max_header_bytes": 32768,
            "configured_upstream_max_header_line_bytes": 128,
            "raw_initial_response": raw_initial,
            "keepalive_followup_response": keepalive_followup,
            "upstream_response": upstream_response,
            "http_initial_header_too_large_delta": initial_header_too_large_delta,
            "http_header_line_rejected_delta": header_line_rejected_delta,
            "http_upstream_header_rejected_delta": upstream_header_rejected_delta,
            "http_upstream_errors_delta": upstream_errors_delta,
            "raw_initial_431": raw_initial_ok,
            "keepalive_second_431": keepalive_ok,
            "upstream_502": upstream_ok,
            "header_line_cap_observed": raw_initial_ok
            and keepalive_ok
            and upstream_ok
            and initial_header_too_large_delta >= 1
            and header_line_rejected_delta >= 1
            and upstream_header_rejected_delta >= 1
            and upstream_errors_delta >= 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_upstream_trailer_policy_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "upstream-trailer-policy-filters.json"
    events_path = tmp_path / "upstream-trailer-policy-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "upstream-trailer-policy-token",
            "forward_response_trailers": False,
            "upstream_max_trailer_bytes": 64,
            "upstream_max_trailers": 4,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "upstream-trailer-policy-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="upstream-trailer-policy-token")
        raw = read_raw_response_bytes(proxy_port, "/response-trailers")
        metrics_after = fetch_metrics(proxy_port, token="upstream-trailer-policy-token")
        dropped_delta = metrics_after.get(
            "altura_http_upstream_trailers_dropped", 0
        ) - metrics_before.get("altura_http_upstream_trailers_dropped", 0)
        rejected_delta = metrics_after.get(
            "altura_http_upstream_trailers_rejected", 0
        ) - metrics_before.get("altura_http_upstream_trailers_rejected", 0)
        body_seen = b"hello" in raw
        raw_lower = raw.lower()
        trailer_seen = b"\r\n0\r\nx-origin-trailer:" in raw_lower
        status = None
        if raw.startswith(b"HTTP/"):
            try:
                status = int(raw.split(b" ", 2)[1])
            except Exception:
                status = None
        return {
            "configured_forward_response_trailers": False,
            "configured_upstream_max_trailer_bytes": 64,
            "configured_upstream_max_trailers": 4,
            "status": status,
            "raw_response_bytes": len(raw),
            "body_seen": body_seen,
            "trailer_seen": trailer_seen,
            "http_upstream_trailers_dropped_delta": dropped_delta,
            "http_upstream_trailers_rejected_delta": rejected_delta,
            "upstream_trailer_policy_observed": status == 200
            and body_seen
            and not trailer_seen
            and dropped_delta >= 1
            and rejected_delta == 0,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_request_trailer_policy_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "request-trailer-policy-filters.json"
    events_path = tmp_path / "request-trailer-policy-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "request-trailer-policy-token",
            "downstream_keep_alive": True,
            "allow_chunked_request_bodies": True,
            "forward_request_trailers": True,
            "max_trailer_bytes": 8,
            "max_trailers": 1,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "request-trailer-policy-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="request-trailer-policy-token")
        oversized = send_oversized_request_trailer(proxy_port)
        metrics_after = fetch_metrics(proxy_port, token="request-trailer-policy-token")
        rejected_delta = metrics_after.get(
            "altura_http_request_trailers_rejected", 0
        ) - metrics_before.get("altura_http_request_trailers_rejected", 0)
        return {
            "configured_forward_request_trailers": True,
            "configured_max_trailer_bytes": 8,
            "configured_max_trailers": 1,
            "oversized_trailer": oversized,
            "http_request_trailers_rejected_delta": rejected_delta,
            "oversized_request_trailer_rejected": oversized.get("status") == 431,
            "generated_431_not_stored": oversized.get("cache_control") == "no-store",
            "generated_431_closes_connection": oversized.get("connection_close") is True,
            "connection_closed_before_followup": oversized.get("followup_response_bytes") == 0
            or oversized.get("followup_error")
            in {"BrokenPipeError", "ConnectionResetError"},
            "request_trailer_policy_observed": oversized.get("status") == 431
            and oversized.get("cache_control") == "no-store"
            and oversized.get("connection_close") is True
            and rejected_delta >= 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def send_oversized_request_trailer(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    first_response: dict[str, Any] | None = None
    followup_raw = b""
    followup_error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"POST /drain HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-request-trailer-policy-probe/1.0\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Trailer: X-Too-Large\r\n"
                b"Connection: keep-alive\r\n\r\n"
                b"3\r\nabc\r\n"
                b"0\r\n"
                b"X-Too-Large: 0123456789abcdef\r\n\r\n"
            )
            first_response = read_http_response_on_socket(sock)
            time.sleep(0.05)
            try:
                sock.sendall(
                    b"GET / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"User-Agent: altura-request-trailer-policy-probe/1.0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                followup_raw = sock.recv(4096)
            except Exception as exc:
                followup_error = type(exc).__name__
    except Exception as exc:
        return {
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "error": type(exc).__name__,
            "status": None,
        }
    headers = (first_response or {}).get("headers", {})
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": None,
        "status": (first_response or {}).get("status"),
        "cache_control": headers.get("cache-control"),
        "connection": headers.get("connection"),
        "connection_close": headers.get("connection") == "close",
        "body": (first_response or {}).get("body"),
        "followup_error": followup_error,
        "followup_response_bytes": len(followup_raw),
    }


def run_header_timeout_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "header-timeout-filters.json"
    events_path = tmp_path / "header-timeout-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "header-timeout-token",
            "header_read_timeout_ms": 100,
            "downstream_keep_alive": True,
            "max_connection_duration_seconds": 5,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "header-timeout-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="header-timeout-token")
        slow_header = run_slow_header_probe(proxy_port)
        idle_keepalive = run_idle_keepalive_probe(proxy_port)
        metrics_after = fetch_metrics(proxy_port, token="header-timeout-token")
        initial_header_timeouts_delta = metrics_after.get(
            "altura_http_initial_header_timeouts", 0
        ) - metrics_before.get("altura_http_initial_header_timeouts", 0)
        return {
            "configured_header_read_timeout_ms": 100,
            "slow_header": slow_header,
            "idle_keepalive": idle_keepalive,
            "http_initial_header_timeouts_delta": initial_header_timeouts_delta,
            "raw_initial_408_not_stored": slow_header.get("cache_control") == "no-store",
            "raw_initial_408_closes_connection": slow_header.get("connection") == "close",
            "slow_initial_header_timeout_observed": slow_header.get("status") == 408
            and slow_header.get("cache_control") == "no-store"
            and slow_header.get("connection") == "close"
            and initial_header_timeouts_delta >= 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def open_partial_header_connections(
    port: int, count: int, hold_seconds: float
) -> dict[str, Any]:
    sockets: list[socket.socket] = []
    errors: collections.Counter[str] = collections.Counter()
    for _ in range(count):
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            sock.settimeout(1.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-log-suppression-probe/1.0\r\n"
            )
            sockets.append(sock)
        except Exception as exc:
            errors[type(exc).__name__] += 1
    time.sleep(hold_seconds)
    for sock in sockets:
        try:
            sock.close()
        except Exception:
            pass
    return {
        "attempted": count,
        "opened": len(sockets),
        "errors": dict(sorted(errors.items())),
        "hold_seconds": hold_seconds,
    }


def run_log_suppression_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "log-suppression-filters.json"
    events_path = tmp_path / "log-suppression-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "log-suppression-token",
            "header_read_timeout_ms": 35,
            "max_connection_duration_seconds": 2,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                **BENCH_HTTP_CONNECTION_LIMITS,
                "max_connections": 1024,
                "max_connections_per_ip": 1024,
                "max_in_flight_requests": 256,
                "max_in_flight_requests_per_ip": 256,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "log-suppression-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    bursts: list[dict[str, Any]] = []
    stderr_text = ""
    try:
        wait_http("127.0.0.1", proxy_port)
        bursts.append(open_partial_header_connections(proxy_port, 48, 0.12))
        time.sleep(1.1)
        bursts.append(open_partial_header_connections(proxy_port, 1, 0.08))
        time.sleep(0.1)
    finally:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    stderr_lines = [line for line in stderr_text.splitlines() if line]
    timeout_lines = [
        line for line in stderr_lines if "initial http header timeout" in line
    ]
    return {
        "configured_header_read_timeout_ms": 35,
        "bursts": bursts,
        "stderr_line_count": len(stderr_lines),
        "timeout_log_line_count": len(timeout_lines),
        "timeout_log_lines_bounded": len(timeout_lines) <= 4,
        "suppressed_marker_seen": any("suppressed" in line for line in timeout_lines),
        "timeout_log_sample": timeout_lines[:4],
    }


def count_file_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for _ in handle)


def wait_file_line_count(path: Path, minimum: int, timeout_seconds: float) -> int:
    deadline = time.perf_counter() + timeout_seconds
    count = count_file_lines(path)
    while count < minimum and time.perf_counter() < deadline:
        time.sleep(0.02)
        count = count_file_lines(path)
    return count


def first_decodable_json_line(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return {}


def decodable_json_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def wait_for_jsonl_event(
    path: Path,
    predicate: Callable[[dict[str, Any]], bool],
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    deadline = time.perf_counter() + timeout_seconds
    events = decodable_json_lines(path)
    while not any(predicate(event) for event in events) and time.perf_counter() < deadline:
        time.sleep(0.02)
        events = decodable_json_lines(path)
    return events


def event_log_files(path: Path, backup_count: int) -> list[Path]:
    return [path] + [Path(f"{path}.{idx}") for idx in range(1, backup_count + 1)]


def jsonl_file_stats(paths: list[Path]) -> dict[str, Any]:
    sizes: dict[str, int] = {}
    line_counts: dict[str, int] = {}
    valid_json_lines = 0
    invalid_json_lines = 0
    for path in paths:
        if not path.exists():
            sizes[path.name] = 0
            line_counts[path.name] = 0
            continue
        sizes[path.name] = path.stat().st_size
        line_count = 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                line_count += 1
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    invalid_json_lines += 1
                    continue
                if isinstance(parsed, dict) and isinstance(parsed.get("signature"), str):
                    valid_json_lines += 1
                else:
                    invalid_json_lines += 1
        line_counts[path.name] = line_count
    return {
        "sizes": sizes,
        "line_counts": line_counts,
        "total_bytes": sum(sizes.values()),
        "total_lines": sum(line_counts.values()),
        "valid_json_lines": valid_json_lines,
        "invalid_json_lines": invalid_json_lines,
    }


def run_event_log_flush_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "event-log-flush-filters.json"
    events_path = tmp_path / "event-log-flush-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "event-log-flush-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 1024,
                "max_connections_per_ip": 1024,
                "max_in_flight_requests": 1024,
                "max_in_flight_requests_per_ip": 1024,
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
            "signature_threshold_per_second": 1,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_log_flush_interval_ms": 1000,
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "event-log-flush-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    statuses: list[int | None] = []
    stderr_text = ""
    try:
        wait_http("127.0.0.1", proxy_port)
        statuses.append(
            get_status(
                proxy_port,
                "GET",
                "/api/event-log/alpha",
                headers={"User-Agent": "altura-event-log-probe/1.0"},
            )
        )
        first_visible_lines = wait_file_line_count(events_path, 1, 1.0)
        for slug in [
            "bravo",
            "charlie",
            "delta",
            "echo",
            "foxtrot",
            "golf",
            "hotel",
            "india",
        ]:
            statuses.append(
                get_status(
                    proxy_port,
                    "GET",
                    f"/api/event-log/{slug}",
                    headers={"User-Agent": "altura-event-log-probe/1.0"},
                )
            )
        burst_visible_lines = count_file_lines(events_path)
        time.sleep(1.05)
        statuses.append(
            get_status(
                proxy_port,
                "GET",
                "/api/event-log/juliet",
                headers={"User-Agent": "altura-event-log-probe/1.0"},
            )
        )
        final_visible_lines = wait_file_line_count(events_path, 10, 1.0)
        return {
            "configured_event_log_flush_interval_ms": 1000,
            "statuses": statuses,
            "all_requests_ok": all(status == 204 for status in statuses),
            "first_visible_lines": first_visible_lines,
            "burst_visible_lines": burst_visible_lines,
            "final_visible_lines": final_visible_lines,
            "first_event_flushed_immediately": first_visible_lines >= 1,
            "burst_flush_batched": burst_visible_lines <= 2,
            "interval_flush_observed": final_visible_lines >= 10,
        }
    finally:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
        if stderr_text:
            # Preserve the stderr pipe drain behavior without making noisy logs part of the result.
            pass


def run_event_log_field_bounds_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "event-log-field-bounds-filters.json"
    events_path = tmp_path / "event-log-field-bounds-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "event-log-field-bounds-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                **BENCH_HTTP_CONNECTION_LIMITS,
                "max_connections": 4096,
                "max_connections_per_ip": 4096,
                "max_in_flight_requests": 4096,
                "max_in_flight_requests_per_ip": 4096,
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
            "signature_threshold_per_second": 1,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_log_flush_interval_ms": 1,
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "event-log-field-bounds-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    stderr_text = ""
    marker = "...[truncated]"
    field_limits = {
        "path": 1024,
        "query": 1024,
        "user_agent": 512,
        "x_forwarded_for": 512,
        "signature_basis": 1024,
    }
    try:
        wait_http("127.0.0.1", proxy_port)
        long_path = "/api/event-log-field-bounds/" + ("p" * 1400)
        query = "&".join(f"{'k' * 220}{idx}=v" for idx in range(16))
        long_header_name = "X-" + ("A" * 220)
        status = get_status(
            proxy_port,
            "GET",
            f"{long_path}?{query}",
            headers={
                "User-Agent": "u" * 900,
                "X-Forwarded-For": "203.0.113.1, " * 80,
                long_header_name: "1",
            },
        )
        visible_lines = wait_file_line_count(events_path, 1, 1.0)
        event = first_decodable_json_line(events_path)
        field_lengths = {
            name: len(event.get(name) or "") for name in field_limits
        }
        query_keys = event.get("query_keys") or []
        header_names = event.get("header_names") or []
        bounded_fields = all(
            isinstance(event.get(name), str)
            and len(event.get(name)) <= limit
            and event.get(name).endswith(marker)
            for name, limit in field_limits.items()
        )
        bounded_query_keys = bool(query_keys) and all(
            isinstance(key, str) and len(key) <= 128 and key.endswith(marker)
            for key in query_keys
        )
        bounded_header_name = any(
            isinstance(name, str) and len(name) <= 128 and name.endswith(marker)
            for name in header_names
        )
        return {
            "status": status,
            "visible_lines": visible_lines,
            "event_line_bytes": events_path.stat().st_size if events_path.exists() else 0,
            "field_lengths": field_lengths,
            "query_key_count": len(query_keys),
            "max_query_key_length": max((len(key) for key in query_keys), default=0),
            "bounded_fields": bounded_fields,
            "bounded_query_keys": bounded_query_keys,
            "bounded_header_name": bounded_header_name,
            "all_event_fields_bounded": bounded_fields
            and bounded_query_keys
            and bounded_header_name,
        }
    finally:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
        if stderr_text:
            pass


def run_adaptive_window_cap_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "adaptive-window-cap-filters.json"
    events_path = tmp_path / "adaptive-window-cap-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    request_count = 512
    configured_cap = 64
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "adaptive-window-cap-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                **BENCH_HTTP_CONNECTION_LIMITS,
                "max_connections": 1024,
                "max_connections_per_ip": 1024,
                "max_in_flight_requests": 1024,
                "max_in_flight_requests_per_ip": 1024,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
            "max_signature_windows": configured_cap,
            "max_path_shape_windows": configured_cap,
        },
    }
    config_path = tmp_path / "adaptive-window-cap-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    statuses: list[int | None] = []
    stderr_text = ""
    try:
        wait_http("127.0.0.1", proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="adaptive-window-cap-token")
        for idx in range(request_count):
            statuses.append(
                get_status(
                    proxy_port,
                    "GET",
                    f"/w{idx}?q={idx}",
                    timeout=1.0,
                    headers={
                        "User-Agent": f"altura-adaptive-window-cap/{idx}",
                        "Accept": f"application/x-altura-{idx}",
                    },
                )
            )
        metrics_after = fetch_metrics(proxy_port, token="adaptive-window-cap-token")
        signature_windows = metrics_after.get("altura_adaptive_signature_windows", 0)
        path_shape_windows = metrics_after.get("altura_adaptive_path_shape_windows", 0)
        signature_capacity = metrics_after.get("altura_adaptive_signature_window_capacity", 0)
        path_shape_capacity = metrics_after.get("altura_adaptive_path_shape_window_capacity", 0)
        return {
            "configured_max_signature_windows": configured_cap,
            "configured_max_path_shape_windows": configured_cap,
            "request_count": request_count,
            "completed_statuses": dict(collections.Counter(str(status) for status in statuses)),
            "signature_windows_before": metrics_before.get("altura_adaptive_signature_windows", 0),
            "path_shape_windows_before": metrics_before.get("altura_adaptive_path_shape_windows", 0),
            "signature_windows_after": signature_windows,
            "path_shape_windows_after": path_shape_windows,
            "signature_window_capacity": signature_capacity,
            "path_shape_window_capacity": path_shape_capacity,
            "all_requests_ok": all(status == 204 for status in statuses),
            "signature_windows_bounded": signature_windows <= signature_capacity == configured_cap,
            "path_shape_windows_bounded": path_shape_windows <= path_shape_capacity == configured_cap,
        }
    finally:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
        if stderr_text:
            pass


def run_adaptive_catalog_shape_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "adaptive-catalog-shape-filters.json"
    events_path = tmp_path / "adaptive-catalog-shape-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "adaptive-catalog-shape-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
            },
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "signature_rps": 1_000_000,
                "signature_burst": 1_000_000,
                "path_shape_rps": 1_000_000,
                "path_shape_burst": 1_000_000,
                "trusted_proxy_rps": 0.000001,
                "trusted_proxy_burst": 1,
                **BENCH_HTTP_CONNECTION_LIMITS,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
                "max_tracked_signatures": 1024,
                "max_tracked_path_shapes": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "static_rules": [
                {
                    "id": "catalog-shape",
                    "enabled": True,
                    "adaptive": True,
                    "priority": 10,
                    "ttl_seconds": 10,
                    "condition": {"path_shape": "/api/catalog/:num"},
                    "action": {
                        "kind": "block",
                        "status": 403,
                        "body": "blocked by catalog shape\n",
                    },
                }
            ],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 2,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "adaptive-catalog-shape-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="adaptive-catalog-shape-token")
        observed_paths = [f"/api/catalog/{idx}" for idx in range(1, 5)]
        observed_responses = [
            get_status_and_headers(
                proxy_port,
                "GET",
                path,
                headers={
                    "User-Agent": f"observed-catalog-{idx}/1.0",
                    "Accept": f"application/x-observed-{idx}",
                },
            )
            for idx, path in enumerate(observed_paths, start=1)
        ]
        metrics_after_observed = fetch_metrics(
            proxy_port, token="adaptive-catalog-shape-token"
        )
        strong_paths = ["/api/catalog/101", "/api/catalog/102", "/api/catalog/103"]
        strong_responses = [
            get_status_and_headers(
                proxy_port,
                "GET",
                path,
                headers={
                    "User-Agent": "strong-catalog/1.0",
                    "Accept": "application/json",
                    "X-Forwarded-For": f"198.51.100.{idx}",
                },
            )
            for idx, path in enumerate(strong_paths, start=1)
        ]
        final_response = get_status_and_headers(
            proxy_port,
            "GET",
            "/api/catalog/999",
            headers={
                "User-Agent": "fresh-catalog/1.0",
                "Accept": "application/x-final",
            },
        )
        metrics_after = fetch_metrics(proxy_port, token="adaptive-catalog-shape-token")
        observed_blocked_delta = metrics_after_observed.get(
            "altura_http_blocked", 0
        ) - metrics_before.get("altura_http_blocked", 0)
        blocked_delta = metrics_after.get("altura_http_blocked", 0) - metrics_before.get(
            "altura_http_blocked", 0
        )
        rate_limited_delta = metrics_after.get(
            "altura_http_trusted_proxy_rate_limited", 0
        ) - metrics_before.get("altura_http_trusted_proxy_rate_limited", 0)
        observed_statuses = [response["status"] for response in observed_responses]
        strong_statuses = [response["status"] for response in strong_responses]
        filter_headers = [
            final_response["headers"].get("x-altura-filter"),
        ]
        observed_only_not_activated = (
            all(status == 204 for status in observed_statuses)
            and observed_blocked_delta == 0
            and all(
                response["headers"].get("x-altura-filter") is None
                for response in observed_responses
            )
        )
        strong_evidence_activated = (
            strong_statuses == [204, 429, 429]
            and final_response["status"] == 403
            and final_response["headers"].get("x-altura-filter") == "catalog-shape"
            and blocked_delta >= 1
            and rate_limited_delta >= 2
        )
        return {
            "configured_signature_threshold_per_second": 2,
            "observed_paths": observed_paths,
            "observed_statuses": observed_statuses,
            "strong_paths": strong_paths,
            "strong_statuses": strong_statuses,
            "final_status": final_response["status"],
            "filter_headers": filter_headers,
            "observed_blocked_delta": observed_blocked_delta,
            "http_blocked_delta": blocked_delta,
            "trusted_proxy_rate_limited_delta": rate_limited_delta,
            "observed_only_not_activated": observed_only_not_activated,
            "strong_evidence_activated": strong_evidence_activated,
            "catalog_shape_activated": strong_evidence_activated,
            "catalog_shape_requires_strong_evidence": observed_only_not_activated
            and strong_evidence_activated,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def runtime_filter_payload(paths: list[str], body: str = "blocked\n") -> dict[str, Any]:
    return {
        "filters": [
            {
                "id": f"runtime-filter-{idx}",
                "enabled": True,
                "priority": 100,
                "condition": {"path_exact": path},
                "action": {"kind": "block", "status": 403, "body": body},
            }
            for idx, path in enumerate(paths)
        ]
    }


def runtime_filter_hot_path_payload(rule_count: int) -> dict[str, Any]:
    path_shape = "/filter-hot-path/:token/:num"
    header_name = "X-Altura-Signal"
    filters = [
        {
            "id": f"filter-hot-path-nonmatch-{idx:04d}",
            "enabled": True,
            "priority": 100,
            "condition": {
                "path_shape": path_shape,
                "user_agent_contains": "MIXEDBOT",
                "headers": [{"name": header_name, "contains": f"never-{idx:04d}"}],
            },
            "action": {"kind": "block", "status": 403, "body": "blocked\n"},
        }
        for idx in range(rule_count - 1)
    ]
    filters.append(
        {
            "id": "filter-hot-path-match",
            "enabled": True,
            "priority": 1,
            "condition": {
                "path_shape": path_shape,
                "user_agent_contains": "MIXEDBOT",
                "headers": [{"name": header_name, "contains": "FLOOD"}],
            },
            "action": {"kind": "block", "status": 403, "body": "blocked\n"},
        }
    )
    return {"filters": filters}


def adaptive_activation_nonblocking_rules(rule_count: int) -> list[dict[str, Any]]:
    filters = [
        {
            "id": f"activation-nonblocking-nonmatch-{idx:04d}",
            "enabled": True,
            "adaptive": True,
            "priority": 100,
            "condition": {
                "path_shape": f"/activation-nonblocking/nonmatch-{idx:04d}/:num"
            },
            "action": {"kind": "block", "status": 403, "body": "blocked\n"},
        }
        for idx in range(rule_count - 1)
    ]
    filters.append(
        {
            "id": "activation-nonblocking-match",
            "enabled": True,
            "adaptive": True,
            "priority": 1,
            "condition": {"path_shape": "/activation-nonblocking/:num"},
            "action": {"kind": "block", "status": 403, "body": "blocked\n"},
        }
    )
    return filters


def runtime_reload_nonblocking_payload(rule_count: int) -> dict[str, Any]:
    filters = [
        {
            "id": f"runtime-reload-nonblocking-nonmatch-{idx:04d}",
            "enabled": True,
            "priority": 100,
            "condition": {
                "path_shape": f"/runtime-reload-nonblocking/nonmatch-{idx:04d}/:num"
            },
            "action": {"kind": "block", "status": 403, "body": "blocked\n"},
        }
        for idx in range(rule_count - 1)
    ]
    filters.append(
        {
            "id": "runtime-reload-nonblocking-match",
            "enabled": True,
            "priority": 1,
            "condition": {"path_exact": "/runtime-reload-nonblocking/match"},
            "action": {"kind": "block", "status": 403, "body": "blocked\n"},
        }
    )
    return {"filters": filters}


def run_runtime_filter_bounds_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "runtime-filter-bounds-filters.json"
    events_path = tmp_path / "runtime-filter-bounds-events.jsonl"
    max_runtime_file_bytes = 4096
    max_runtime_filters = 4
    blocked_path = "/runtime-filter-bounds-blocked"
    filters_path.write_text(
        json.dumps(runtime_filter_payload([blocked_path]), sort_keys=True),
        encoding="utf-8",
    )
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "runtime-filter-bounds-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": max_runtime_file_bytes,
            "max_runtime_filters": max_runtime_filters,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "runtime-filter-bounds-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    result: dict[str, Any] = {}
    stderr_text = ""
    try:
        wait_http("127.0.0.1", proxy_port)
        initial_block_status = get_status(proxy_port, "GET", blocked_path)

        oversized_payload = runtime_filter_payload(
            ["/runtime-filter-bounds-oversized"], body="x" * (max_runtime_file_bytes * 2)
        )
        filters_path.write_text(json.dumps(oversized_payload, sort_keys=True), encoding="utf-8")
        oversized_file_bytes = filters_path.stat().st_size
        time.sleep(1.4)
        post_oversized_block_status = get_status(proxy_port, "GET", blocked_path)
        post_oversized_new_rule_status = get_status(
            proxy_port, "GET", "/runtime-filter-bounds-oversized"
        )

        too_many_paths = [f"/runtime-filter-bounds-many-{idx}" for idx in range(max_runtime_filters + 1)]
        filters_path.write_text(
            json.dumps(runtime_filter_payload(too_many_paths), sort_keys=True),
            encoding="utf-8",
        )
        too_many_file_bytes = filters_path.stat().st_size
        time.sleep(1.4)
        post_too_many_block_status = get_status(proxy_port, "GET", blocked_path)
        post_too_many_new_rule_status = get_status(proxy_port, "GET", too_many_paths[0])
        normal_status_after_errors = get_status(proxy_port, "GET", "/")
        metrics_after = fetch_metrics(proxy_port, token="runtime-filter-bounds-token")

        result = {
            "configured_max_runtime_file_bytes": max_runtime_file_bytes,
            "configured_max_runtime_filters": max_runtime_filters,
            "initial_block_status": initial_block_status,
            "oversized_file_bytes": oversized_file_bytes,
            "post_oversized_block_status": post_oversized_block_status,
            "post_oversized_new_rule_status": post_oversized_new_rule_status,
            "too_many_file_bytes": too_many_file_bytes,
            "post_too_many_block_status": post_too_many_block_status,
            "post_too_many_new_rule_status": post_too_many_new_rule_status,
            "normal_status_after_errors": normal_status_after_errors,
            "active_filters_after": metrics_after.get("altura_active_filters", 0),
            "oversized_file_rejected_and_last_good_preserved": initial_block_status == 403
            and post_oversized_block_status == 403
            and post_oversized_new_rule_status == 204,
            "too_many_rules_rejected_and_last_good_preserved": post_too_many_block_status == 403
            and post_too_many_new_rule_status == 204,
            "availability_ok": normal_status_after_errors == 204,
        }
    finally:
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
    result["reload_error_logged"] = (
        "above configured cap" in stderr_text and "contains 5 filters" in stderr_text
    )
    return result


def run_runtime_filter_hot_path_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "runtime-filter-hot-path-filters.json"
    events_path = tmp_path / "runtime-filter-hot-path-events.jsonl"
    rule_count = 512
    path = "/filter-hot-path/abcdefghij/123"
    filters_path.write_text(
        json.dumps(runtime_filter_hot_path_payload(rule_count), sort_keys=True),
        encoding="utf-8",
    )
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "runtime-filter-hot-path-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": 1024 * 1024,
            "max_runtime_filters": rule_count,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "runtime-filter-hot-path-config.json"
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
        metrics_after_start = fetch_metrics(proxy_port, token="runtime-filter-hot-path-token")
        normal_status = get_status(
            proxy_port,
            "GET",
            path,
            headers={
                "User-Agent": "legit mixedbot/1.0",
                "X-Altura-Signal": "benign baseline",
            },
        )
        matching_status = get_status(
            proxy_port,
            "GET",
            path,
            headers={
                "User-Agent": "legit mixedbot/1.0",
                "X-Altura-Signal": "prefix flood suffix",
            },
        )
        control_status = get_status(proxy_port, "GET", "/")
        active_filters = metrics_after_start.get("altura_active_filters", 0)
        return {
            "configured_rule_count": rule_count,
            "filter_file_bytes": filters_path.stat().st_size,
            "active_filters_after_start": active_filters,
            "normal_status": normal_status,
            "matching_status": matching_status,
            "control_status": control_status,
            "many_rules_loaded": active_filters == rule_count,
            "normal_request_allowed": normal_status == 204,
            "matching_request_blocked": matching_status == 403,
            "control_request_allowed": control_status == 204,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_filter_activation_nonblocking_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "filter-activation-nonblocking-filters.json"
    events_path = tmp_path / "filter-activation-nonblocking-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    rule_count = 512
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "filter-activation-nonblocking-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
            },
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "signature_rps": 1_000_000,
                "signature_burst": 1_000_000,
                "path_shape_rps": 1_000_000,
                "path_shape_burst": 1_000_000,
                "trusted_proxy_rps": 0.000001,
                "trusted_proxy_burst": 1,
                **BENCH_HTTP_CONNECTION_LIMITS,
                "max_connections": 2048,
                "max_connections_per_ip": 2048,
                "max_in_flight_requests": 2048,
                "max_in_flight_requests_per_ip": 2048,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": 1024 * 1024,
            "max_runtime_filters": rule_count,
            "max_static_filters": rule_count,
            "static_rules": adaptive_activation_nonblocking_rules(rule_count),
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 2,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "filter-activation-nonblocking-config.json"
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
        control_results: list[dict[str, Any]] = []
        stop = threading.Event()
        reload_write_result: dict[str, Any] = {}

        def control_loop() -> None:
            deadline = time.perf_counter() + 2.5
            while not stop.is_set() and time.perf_counter() < deadline:
                started = time.perf_counter()
                status = get_status(
                    proxy_port,
                    "GET",
                    "/activation-control",
                    headers={"User-Agent": "activation-control/1.0"},
                )
                control_results.append(
                    {
                        "status": status,
                        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                    }
                )

        def runtime_reload_writer() -> None:
            try:
                time.sleep(0.05)
                payload = runtime_reload_nonblocking_payload(rule_count)
                filters_path.write_text(
                    json.dumps(payload, sort_keys=True),
                    encoding="utf-8",
                )
                reload_write_result["bytes"] = filters_path.stat().st_size
                reload_write_result["rules"] = len(payload["filters"])
            except Exception as exc:
                reload_write_result["error"] = f"{type(exc).__name__}: {exc}"

        control_thread = threading.Thread(target=control_loop, daemon=True)
        control_thread.start()
        reload_thread = threading.Thread(target=runtime_reload_writer, daemon=True)
        reload_thread.start()
        trigger_statuses = [
            get_status(
                proxy_port,
                "GET",
                f"/activation-nonblocking/{idx}",
                headers={
                    "User-Agent": "activation-trigger/1.0",
                    "X-Forwarded-For": f"198.51.100.{idx}",
                },
            )
            for idx in range(1, 8)
        ]
        reload_thread.join(timeout=2.0)
        reload_deadline = time.perf_counter() + 2.5
        runtime_reload_status = None
        active_filters_after_reload = 0
        while time.perf_counter() < reload_deadline:
            runtime_reload_status = get_status(
                proxy_port,
                "GET",
                "/runtime-reload-nonblocking/match",
                headers={"User-Agent": "runtime-reload-probe/1.0"},
            )
            metrics_during_reload = fetch_metrics(
                proxy_port, token="filter-activation-nonblocking-token"
            )
            active_filters_after_reload = metrics_during_reload.get(
                "altura_active_filters", 0
            )
            if runtime_reload_status == 403 and active_filters_after_reload >= rule_count:
                break
            time.sleep(0.05)
        stop.set()
        control_thread.join(timeout=2.0)
        final_matching_status = get_status(
            proxy_port,
            "GET",
            "/activation-nonblocking/999",
            headers={"User-Agent": "activation-final/1.0"},
        )
        metrics_after = fetch_metrics(
            proxy_port, token="filter-activation-nonblocking-token"
        )
        max_control_latency_ms = max(
            (result["latency_ms"] for result in control_results), default=0.0
        )
        control_statuses = [result["status"] for result in control_results]
        return {
            "configured_rule_count": rule_count,
            "configured_runtime_rule_count": rule_count,
            "runtime_reload_file_bytes": reload_write_result.get("bytes", 0),
            "runtime_reload_write_error": reload_write_result.get("error"),
            "runtime_reload_status": runtime_reload_status,
            "trigger_statuses": trigger_statuses,
            "final_matching_status": final_matching_status,
            "control_request_count": len(control_results),
            "control_statuses": control_statuses[:16],
            "control_errors": sum(1 for status in control_statuses if status != 204),
            "max_control_latency_ms": max_control_latency_ms,
            "active_filters_after": metrics_after.get("altura_active_filters", 0),
            "active_filters_after_reload": active_filters_after_reload,
            "runtime_reload_loaded": runtime_reload_status == 403
            and active_filters_after_reload >= rule_count,
            "activation_nonblocking": trigger_statuses[:3] == [204, 429, 429]
            and final_matching_status == 403
            and len(control_results) > 0
            and all(status == 204 for status in control_statuses)
            and max_control_latency_ms < 500,
            "activation_reload_nonblocking": trigger_statuses[:3] == [204, 429, 429]
            and final_matching_status == 403
            and runtime_reload_status == 403
            and active_filters_after_reload >= rule_count
            and reload_write_result.get("error") is None
            and len(control_results) > 0
            and all(status == 204 for status in control_statuses)
            and max_control_latency_ms < 500,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_rate_limit_before_filter_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "rate-limit-before-filter-filters.json"
    events_path = tmp_path / "rate-limit-before-filter-events.jsonl"
    blocked_path = "/filter-before-rate-limit"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "rate-limit-before-filter-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
            },
            "limits": {
                "per_ip_rps": 0.000001,
                "per_ip_burst": 1,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "signature_rps": 1_000_000,
                "signature_burst": 1_000_000,
                "path_shape_rps": 1_000_000,
                "path_shape_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "static_rules": [
                {
                    "id": "rate-limit-before-filter",
                    "enabled": True,
                    "priority": 100,
                    "condition": {"path_exact": blocked_path},
                    "action": {"kind": "block", "status": 403, "body": "blocked\n"},
                }
            ],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "rate-limit-before-filter-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        wait_tcp_port(proxy_port)
        metrics_before = fetch_metrics(
            proxy_port,
            token="rate-limit-before-filter-token",
            headers={"X-Forwarded-For": "198.51.100.200"},
        )
        first_ip = "198.51.100.10"
        second_ip = "198.51.100.11"
        prime_status = get_status(
            proxy_port,
            "GET",
            "/rate-prime",
            headers={"X-Forwarded-For": first_ip},
        )
        over_limit_matching_status = get_status(
            proxy_port,
            "GET",
            blocked_path,
            headers={"X-Forwarded-For": first_ip},
        )
        fresh_matching_response = get_status_and_headers(
            proxy_port,
            "GET",
            blocked_path,
            headers={"X-Forwarded-For": second_ip},
        )
        metrics_after = fetch_metrics(
            proxy_port,
            token="rate-limit-before-filter-token",
            headers={"X-Forwarded-For": "198.51.100.201"},
        )
        blocked_delta = metrics_after.get("altura_http_blocked", 0) - metrics_before.get(
            "altura_http_blocked", 0
        )
        rate_limited_delta = metrics_after.get(
            "altura_http_rate_limited", 0
        ) - metrics_before.get("altura_http_rate_limited", 0)
        active_filters = metrics_after.get("altura_active_filters", 0)
        fresh_matching_status = fresh_matching_response["status"]
        fresh_filter_header = fresh_matching_response["headers"].get("x-altura-filter")
        return {
            "blocked_path": blocked_path,
            "prime_status": prime_status,
            "over_limit_matching_status": over_limit_matching_status,
            "fresh_matching_status": fresh_matching_status,
            "fresh_filter_header": fresh_filter_header,
            "http_blocked_delta": blocked_delta,
            "http_rate_limited_delta": rate_limited_delta,
            "active_filters_after": active_filters,
            "rate_limit_precedes_filter": prime_status == 204
            and over_limit_matching_status == 429
            and fresh_matching_status == 403
            and fresh_filter_header == "rate-limit-before-filter"
            and blocked_delta == 1
            and rate_limited_delta >= 1
            and active_filters >= 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_event_log_async_queue_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    if not hasattr(os, "mkfifo"):
        return {"skipped": True, "reason": "os.mkfifo unavailable"}
    proxy_port = free_port()
    filters_path = tmp_path / "event-log-async-filters.json"
    events_path = tmp_path / "event-log-async-events.fifo"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    os.mkfifo(events_path)
    reader_fd = os.open(events_path, os.O_RDONLY | os.O_NONBLOCK)
    request_count = 2_000
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "event-log-async-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                **BENCH_HTTP_CONNECTION_LIMITS,
                "max_connections": 4096,
                "max_connections_per_ip": 4096,
                "max_in_flight_requests": 4096,
                "max_in_flight_requests_per_ip": 4096,
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
            "signature_threshold_per_second": 1,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_log_flush_interval_ms": 1,
            "event_log_queue_capacity": 1,
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "event-log-async-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    statuses: list[int | None] = []
    stderr_text = ""
    drained_bytes = [0]
    stop_drain = threading.Event()

    def drain_fifo() -> None:
        while not stop_drain.is_set():
            try:
                chunk = os.read(reader_fd, 65536)
                if chunk:
                    drained_bytes[0] += len(chunk)
                    continue
            except BlockingIOError:
                pass
            except OSError:
                return
            time.sleep(0.005)

    drain_thread: threading.Thread | None = None
    try:
        wait_http("127.0.0.1", proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="event-log-async-token")
        started = time.perf_counter()
        for idx in range(request_count):
            statuses.append(
                get_status(
                    proxy_port,
                    "GET",
                    f"/api/event-log-async/slug{idx:04x}",
                    timeout=0.5,
                    headers={"User-Agent": f"altura-event-log-async-probe/{idx}"},
                )
            )
        elapsed = time.perf_counter() - started
        metrics_after = fetch_metrics(proxy_port, token="event-log-async-token")
        drain_thread = threading.Thread(target=drain_fifo, daemon=True)
        drain_thread.start()
        time.sleep(0.3)
        dropped_delta = metrics_after.get("altura_event_log_dropped", 0) - metrics_before.get(
            "altura_event_log_dropped", 0
        )
        return {
            "configured_event_log_queue_capacity": 1,
            "request_count": request_count,
            "completed_statuses": dict(collections.Counter(str(status) for status in statuses)),
            "requests_elapsed_seconds": round(elapsed, 3),
            "requests_per_second": round(request_count / elapsed if elapsed else 0.0, 2),
            "dropped_delta": dropped_delta,
            "drained_bytes": drained_bytes[0],
            "all_requests_completed": all(status is not None and status < 500 for status in statuses),
            "event_log_queue_dropped": dropped_delta > 0,
        }
    finally:
        if drain_thread is None:
            drain_thread = threading.Thread(target=drain_fifo, daemon=True)
            drain_thread.start()
            time.sleep(0.1)
        proxy.terminate()
        try:
            _, stderr_text = proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, stderr_text = proxy.communicate(timeout=5)
        stop_drain.set()
        try:
            os.close(reader_fd)
        except OSError:
            pass
        drain_thread.join(timeout=1)
        if stderr_text:
            pass


def run_event_log_rotation_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "event-log-rotation-filters.json"
    events_path = tmp_path / "event-log-rotation-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    max_bytes = 1_800
    backup_count = 1
    request_count = 24
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "event-log-rotation-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 256,
                "max_connections_per_ip": 256,
                "max_in_flight_requests": 256,
                "max_in_flight_requests_per_ip": 256,
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
            "signature_threshold_per_second": 1,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_log_flush_interval_ms": 1,
            "event_log_max_bytes": max_bytes,
            "event_log_backup_count": backup_count,
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "event-log-rotation-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    statuses: list[int | None] = []
    try:
        wait_http("127.0.0.1", proxy_port)
        for idx in range(request_count):
            statuses.append(
                get_status(
                    proxy_port,
                    "GET",
                    f"/api/event-log-rotation/{idx:02d}",
                    headers={"User-Agent": "altura-event-log-rotation-probe/1.0"},
                )
            )
        deadline = time.perf_counter() + 1.0
        paths = event_log_files(events_path, backup_count)
        while not paths[1].exists() and time.perf_counter() < deadline:
            time.sleep(0.02)
        stats = jsonl_file_stats(paths)
        return {
            "configured_event_log_max_bytes": max_bytes,
            "configured_event_log_backup_count": backup_count,
            "request_count": request_count,
            "statuses": statuses,
            "all_requests_ok": all(status == 204 for status in statuses),
            "backup_present": paths[1].exists(),
            "active_log_present": events_path.exists(),
            "jsonl_stats": stats,
            "jsonl_valid": stats["invalid_json_lines"] == 0 and stats["valid_json_lines"] > 0,
            "total_bytes_bounded": stats["total_bytes"] <= (max_bytes * (backup_count + 1) + 2_048),
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_http_connection_rate_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "http-connection-rate-filters.json"
    events_path = tmp_path / "http-connection-rate-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "http-connection-rate-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "per_ip_connects_per_second": 1.0,
                "per_ip_connect_burst": 4,
                "global_connects_per_second": 1_000_000,
                "global_connect_burst": 1_000_000,
                "max_connections": 256,
                "max_connections_per_ip": 256,
                "max_in_flight_requests": 256,
                "max_in_flight_requests_per_ip": 256,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "http-connection-rate-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    statuses: list[int | None] = []
    try:
        wait_http("127.0.0.1", proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="http-connection-rate-token")
        for idx in range(8):
            statuses.append(
                get_status(
                    proxy_port,
                    "GET",
                    f"/api/http-connection-rate/{idx}",
                    timeout=0.4,
                    headers={"User-Agent": "altura-http-connection-rate-probe/1.0"},
                )
            )
        time.sleep(1.1)
        metrics_after = fetch_metrics(proxy_port, token="http-connection-rate-token")
        rejected_delta = metrics_after.get("altura_http_connections_rejected", 0) - metrics_before.get(
            "altura_http_connections_rejected", 0
        )
        accepted = sum(1 for status in statuses if status == 204)
        rejected = sum(1 for status in statuses if status is None)
        return {
            "configured_per_ip_connects_per_second": 1.0,
            "configured_per_ip_connect_burst": 4,
            "statuses": statuses,
            "accepted_requests": accepted,
            "rejected_connection_attempts": rejected,
            "connections_rejected_metric_delta": rejected_delta,
            "connection_rate_limited": accepted >= 1
            and rejected >= 1
            and rejected_delta >= 1
            and accepted <= 4,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_slow_header_probe(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-slow-header-probe/1.0\r\n"
            )
            time.sleep(0.25)
            try:
                raw = sock.recv(4096)
            except Exception as exc:
                error = type(exc).__name__
    except Exception as exc:
        error = type(exc).__name__
    status = None
    if raw.startswith(b"HTTP/"):
        try:
            status = int(raw.split(b" ", 2)[1])
        except Exception:
            status = None
    headers = headers_from_raw_response(raw)
    return {
        "closed": raw == b"",
        "status": status,
        "cache_control": headers.get("cache-control"),
        "connection": headers.get("connection"),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
        "response_bytes": len(raw),
        "body_bytes": len(raw.partition(b"\r\n\r\n")[2]),
    }


def run_idle_keepalive_probe(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    error = None
    second_response = b""
    first_response: dict[str, Any] | None = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-idle-keepalive-probe/1.0\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            first_response = read_http_response_on_socket(sock)
            time.sleep(0.25)
            try:
                sock.sendall(
                    b"GET / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"User-Agent: altura-idle-keepalive-probe/1.0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                second_response = sock.recv(4096)
            except Exception as exc:
                error = type(exc).__name__
    except Exception as exc:
        error = type(exc).__name__
    return {
        "closed_before_reuse": second_response == b"",
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
        "first_response": first_response,
        "second_response_bytes": len(second_response),
    }


def run_downstream_keepalive_probe(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    first_response: dict[str, Any] | None = None
    second_error = None
    second_raw = b""
    metrics_before = fetch_metrics(port)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(1.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-downstream-keepalive-probe/1.0\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            first_response = read_http_response_on_socket(sock)
            time.sleep(0.05)
            try:
                sock.sendall(
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"User-Agent: altura-downstream-keepalive-probe/1.0\r\n"
                    b"Content-Length: 0\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                second_raw = sock.recv(4096)
            except Exception as exc:
                second_error = type(exc).__name__
    except Exception as exc:
        second_error = type(exc).__name__
    metrics_after = fetch_metrics(port)
    second_status = None
    if second_raw.startswith(b"HTTP/"):
        try:
            second_status = int(second_raw.split(b" ", 2)[1])
        except Exception:
            second_status = None
    return {
        "closed_before_second_response": second_raw == b""
        or second_error in {"BrokenPipeError", "ConnectionResetError"},
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "first_response": first_response,
        "framing_rejected_delta": metrics_after.get("altura_http_framing_rejected", 0)
        - metrics_before.get("altura_http_framing_rejected", 0),
        "second_error": second_error,
        "second_response_bytes": len(second_raw),
        "second_status": second_status,
    }


def run_connection_request_limit_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "connection-request-limit-filters.json"
    events_path = tmp_path / "connection-request-limit-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "connection-request-limit-token",
            "downstream_keep_alive": True,
            "max_requests_per_connection": 2,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "connection-request-limit-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="connection-request-limit-token")
        probe = send_connection_request_limit_sequence(proxy_port)
        metrics_after = fetch_metrics(proxy_port, token="connection-request-limit-token")
        limited_delta = metrics_after.get(
            "altura_http_request_limited", 0
        ) - metrics_before.get("altura_http_request_limited", 0)
        third_headers = probe.get("third_response", {}).get("headers", {})
        return {
            "configured_max_requests_per_connection": 2,
            "probe": probe,
            "http_request_limited_delta": limited_delta,
            "third_request_limited": probe.get("third_response", {}).get("status") == 429,
            "retry_after_header_matches": third_headers.get("retry-after") == "1",
            "cache_control_header_matches": third_headers.get("cache-control") == "no-store",
            "connection_close_header_matches": third_headers.get("connection") == "close",
            "connection_closed_before_fourth": probe.get("fourth_response_bytes") == 0
            or probe.get("fourth_error") in {"BrokenPipeError", "ConnectionResetError"},
            "connection_request_limit_observed": probe.get("first_response", {}).get("status")
            == 204
            and probe.get("second_response", {}).get("status") == 204
            and probe.get("third_response", {}).get("status") == 429
            and third_headers.get("retry-after") == "1"
            and third_headers.get("cache-control") == "no-store"
            and third_headers.get("connection") == "close"
            and limited_delta == 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def send_connection_request_limit_sequence(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    first_response: dict[str, Any] | None = None
    second_response: dict[str, Any] | None = None
    third_response: dict[str, Any] | None = None
    fourth_raw = b""
    fourth_error = None
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            for idx in range(1, 4):
                sock.sendall(
                    f"GET /request-limit/{idx} HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "User-Agent: altura-connection-request-limit-probe/1.0\r\n"
                    "Connection: keep-alive\r\n\r\n"
                    .encode("ascii")
                )
                response = read_http_response_on_socket(sock)
                if idx == 1:
                    first_response = response
                elif idx == 2:
                    second_response = response
                else:
                    third_response = response
            time.sleep(0.05)
            try:
                sock.sendall(
                    b"GET /request-limit/four HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"User-Agent: altura-connection-request-limit-probe/1.0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                fourth_raw = sock.recv(4096)
            except Exception as exc:
                fourth_error = type(exc).__name__
    except Exception as exc:
        error = type(exc).__name__
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
        "first_response": first_response,
        "second_response": second_response,
        "third_response": third_response,
        "fourth_error": fourth_error,
        "fourth_response_bytes": len(fourth_raw),
    }


def run_uri_guard_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "uri-guard-filters.json"
    events_path = tmp_path / "uri-guard-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "uri-guard-token",
            "max_uri_bytes": 64,
            "max_query_bytes": 16,
            "max_query_pairs": 2,
            "max_path_segments": 3,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "uri-guard-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="uri-guard-token")
        probes = {
            "long_uri": send_raw_get_target(proxy_port, "/long/" + ("x" * 80)),
            "long_query": send_raw_get_target(proxy_port, "/ok?x=" + ("y" * 32)),
            "many_query_pairs": send_raw_get_target(proxy_port, "/ok?a=1&b=2&c=3"),
            "many_path_segments": send_raw_get_target(proxy_port, "/a/b/c/d"),
        }
        rejected_probes = [probe for probe in probes.values() if probe["status"] == 414]
        cache_control_headers = [probe.get("cache_control") for probe in rejected_probes]
        connection_headers = [probe.get("connection") for probe in rejected_probes]
        metrics_after = fetch_metrics(proxy_port, token="uri-guard-token")
        return {
            "configured": {
                "max_uri_bytes": 64,
                "max_query_bytes": 16,
                "max_query_pairs": 2,
                "max_path_segments": 3,
            },
            "probes": probes,
            "cache_control_headers": cache_control_headers,
            "connection_headers": connection_headers,
            "generated_414_not_stored": cache_control_headers == ["no-store"] * 4,
            "generated_414_closes_connection": connection_headers == ["close"] * 4,
            "raw_initial_request_target_guard_observed": len(rejected_probes) == 4
            and cache_control_headers == ["no-store"] * 4
            and connection_headers == ["close"] * 4,
            "metrics_delta": {
                "altura_http_uri_rejected": metrics_after.get("altura_http_uri_rejected", 0)
                - metrics_before.get("altura_http_uri_rejected", 0),
                "altura_http_initial_request_target_rejected": metrics_after.get(
                    "altura_http_initial_request_target_rejected", 0
                )
                - metrics_before.get("altura_http_initial_request_target_rejected", 0),
            },
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_method_guard_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "method-guard-filters.json"
    events_path = tmp_path / "method-guard-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "method-guard-token",
            "allowed_methods": ["GET", "POST"],
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "method-guard-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="method-guard-token")
        probes = {
            "allowed_get": send_raw_method(proxy_port, "GET", "/"),
            "allowed_post": send_raw_method(proxy_port, "POST", "/drain"),
            "trace": send_raw_method(proxy_port, "TRACE", "/"),
            "connect": send_raw_method(proxy_port, "CONNECT", "127.0.0.1:443"),
            "track": send_raw_method(proxy_port, "TRACK", "/"),
            "arbitrary": send_raw_method(proxy_port, "JEFF", "/"),
        }
        rejected_probes = [probe for probe in probes.values() if probe["status"] == 405]
        cache_control_headers = [probe.get("cache_control") for probe in rejected_probes]
        allow_headers = [probe.get("allow") for probe in rejected_probes]
        metrics_after = fetch_metrics(proxy_port, token="method-guard-token")
        return {
            "configured": {"allowed_methods": ["GET", "POST"]},
            "probes": probes,
            "allow_headers": allow_headers,
            "cache_control_headers": cache_control_headers,
            "generated_405_not_stored": cache_control_headers == ["no-store"] * 4,
            "metrics_delta": {
                "altura_http_method_rejected": metrics_after.get(
                    "altura_http_method_rejected", 0
                )
                - metrics_before.get("altura_http_method_rejected", 0)
            },
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_method_override_header_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "method-override-filters.json"
    events_path = tmp_path / "method-override-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "method-override-token",
            "allowed_methods": ["GET", "POST"],
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "method-override-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="method-override-token")
        probes = {
            "x_http_method": get_status_and_headers(
                proxy_port,
                "GET",
                "/",
                headers={"X-HTTP-Method": "DELETE"},
            ),
            "x_http_method_override": get_status_and_headers(
                proxy_port,
                "GET",
                "/",
                headers={"X-HTTP-Method-Override": "DELETE"},
            ),
            "x_method_override": get_status_and_headers(
                proxy_port,
                "GET",
                "/",
                headers={"X-Method-Override": "DELETE"},
            ),
        }
        rejected = [probe for probe in probes.values() if probe["status"] == 400]
        metrics_after = fetch_metrics(proxy_port, token="method-override-token")
        method_rejected_delta = metrics_after.get(
            "altura_http_method_rejected", 0
        ) - metrics_before.get("altura_http_method_rejected", 0)
        return {
            "configured": {
                "allowed_methods": ["GET", "POST"],
                "allow_method_override_headers": False,
            },
            "probes": probes,
            "override_headers_rejected": len(rejected) == len(probes),
            "generated_400_not_stored": all(
                probe.get("headers", {}).get("cache-control") == "no-store"
                for probe in rejected
            ),
            "generated_400_closes_connection": all(
                probe.get("headers", {}).get("connection") == "close"
                for probe in rejected
            ),
            "method_rejected_delta": method_rejected_delta,
            "method_rejected_metric_matches": method_rejected_delta == len(probes),
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_early_rejection_close_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "early-rejection-close-filters.json"
    events_path = tmp_path / "early-rejection-close-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "early-rejection-close-token",
            "allowed_methods": ["GET", "POST"],
            "downstream_keep_alive": True,
            "max_uri_bytes": 64,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "signature_rps": 1_000_000,
                "signature_burst": 1_000_000,
                "path_shape_rps": 1_000_000,
                "path_shape_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "static_rules": [
                {
                    "id": "early-close-block",
                    "enabled": True,
                    "priority": 10,
                    "condition": {"path_exact": "/blocked-upload"},
                    "action": {
                        "kind": "block",
                        "status": 403,
                        "body": "blocked\n",
                    },
                }
            ],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "early-rejection-close-config.json"
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
        probes = {
            "method_with_body": send_keepalive_followup_request_with_body(
                proxy_port, "TRACE", "/", b"blocked-method-body"
            ),
            "filter_with_body": send_keepalive_followup_request_with_body(
                proxy_port, "POST", "/blocked-upload", b"blocked-filter-body"
            ),
            "uri_with_body": send_keepalive_followup_request_with_body(
                proxy_port, "POST", "/long/" + ("x" * 80), b"blocked-uri-body"
            ),
        }
        expected_statuses = {
            "method_with_body": 405,
            "filter_with_body": 403,
            "uri_with_body": 414,
        }
        return {
            "probes": probes,
            "body_bearing_early_rejections_close_connection": all(
                probes[name]["first"]["status"] in (200, 204)
                and probes[name]["second"]["status"] == expected_status
                and probes[name]["second"]["connection_close"]
                for name, expected_status in expected_statuses.items()
            ),
            "body_bearing_early_rejections_not_stored": all(
                probes[name]["second"].get("cache_control_no_store") is True
                for name in expected_statuses
            ),
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_host_guard_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    metrics_host = f"127.0.0.1:{proxy_port}"
    filters_path = tmp_path / "host-guard-filters.json"
    events_path = tmp_path / "host-guard-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "host-guard-token",
            "max_host_bytes": 32,
            "allowed_hosts": ["good.local", "api.good.local:8080", metrics_host],
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "host-guard-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="host-guard-token")
        probes = {
            "allowed_host": send_raw_host_request(proxy_port, ["good.local"]),
            "allowed_host_port": send_raw_host_request(
                proxy_port, ["api.good.local:8080"]
            ),
            "unlisted_port_host": send_raw_host_request(
                proxy_port, ["good.local:8080"]
            ),
            "missing_host": send_raw_host_request(proxy_port, []),
            "duplicate_host": send_raw_host_request(
                proxy_port, ["good.local", "evil.local"]
            ),
            "invalid_host": send_raw_host_request(proxy_port, ["http://evil.local"]),
            "long_host": send_raw_host_request(proxy_port, [("a" * 40) + ".local"]),
            "disallowed_host": send_raw_host_request(proxy_port, ["evil.local"]),
            "absolute_form_allowed_authority": send_raw_host_request(
                proxy_port, ["evil.local"], target="http://good.local/"
            ),
            "absolute_form_disallowed_authority": send_raw_host_request(
                proxy_port, ["good.local"], target="http://evil.local/"
            ),
            "absolute_form_unlisted_port_authority": send_raw_host_request(
                proxy_port, ["good.local"], target="http://good.local:8080/"
            ),
            "absolute_form_unsupported_scheme": send_raw_host_request(
                proxy_port, ["good.local"], target="ftp://good.local/"
            ),
        }
        metrics_after = fetch_metrics(proxy_port, token="host-guard-token")
        return {
            "configured": {
                "max_host_bytes": 32,
                "allowed_hosts": ["good.local", "api.good.local:8080"],
            },
            "probes": probes,
            "metrics_delta": {
                "altura_http_host_rejected": metrics_after.get("altura_http_host_rejected", 0)
                - metrics_before.get("altura_http_host_rejected", 0)
            },
            "host_rejections_not_stored": all(
                probes[name].get("cache_control_no_store") is True
                for name in [
                    "missing_host",
                    "duplicate_host",
                    "invalid_host",
                    "long_host",
                    "disallowed_host",
                    "unlisted_port_host",
                    "absolute_form_disallowed_authority",
                    "absolute_form_unlisted_port_authority",
                    "absolute_form_unsupported_scheme",
                ]
            ),
            "bare_host_does_not_allow_unlisted_port": probes["unlisted_port_host"].get("status")
            == 400,
            "absolute_form_bare_host_does_not_allow_unlisted_port": probes[
                "absolute_form_unlisted_port_authority"
            ].get("status")
            == 400,
            "absolute_form_unsupported_scheme_rejected": probes[
                "absolute_form_unsupported_scheme"
            ].get("status")
            == 400,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_framing_guard_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "framing-guard-filters.json"
    events_path = tmp_path / "framing-guard-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "framing-guard-token",
            "downstream_keep_alive": True,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "framing-guard-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="framing-guard-token")
        probes = {
            "valid_content_length": send_raw_framing_request(
                proxy_port, ["Content-Length: 0"]
            ),
            "default_chunked_rejected": send_raw_framing_request(
                proxy_port,
                ["Transfer-Encoding: chunked"],
                body=b"0\r\n\r\n",
            ),
            "duplicate_identical_content_length": send_raw_framing_request(
                proxy_port, ["Content-Length: 0", "Content-Length: 0"]
            ),
            "conflicting_content_length": send_raw_framing_request(
                proxy_port, ["Content-Length: 0", "Content-Length: 1"]
            ),
            "comma_content_length": send_raw_framing_request(
                proxy_port, ["Content-Length: 0, 0"]
            ),
            "invalid_content_length": send_raw_framing_request(
                proxy_port, ["Content-Length: nope"]
            ),
            "te_and_content_length": send_raw_framing_request(
                proxy_port,
                ["Transfer-Encoding: chunked", "Content-Length: 0"],
                body=b"0\r\n\r\n",
            ),
            "duplicate_transfer_encoding": send_raw_framing_request(
                proxy_port,
                ["Transfer-Encoding: chunked", "Transfer-Encoding: chunked"],
                body=b"0\r\n\r\n",
            ),
            "unsupported_transfer_encoding": send_raw_framing_request(
                proxy_port, ["Transfer-Encoding: gzip"]
            ),
            "transfer_encoding_comma_spray": send_raw_framing_request(
                proxy_port,
                ["Transfer-Encoding: " + ", ".join(["gzip"] * 64)],
            ),
            "transfer_encoding_empty_comma_spray": send_raw_framing_request(
                proxy_port,
                ["Transfer-Encoding: " + ", ".join([""] * 64)],
            ),
            "keepalive_followup_chunked_rejected": send_keepalive_followup_framing_request(
                proxy_port,
                ["Transfer-Encoding: chunked"],
                body=b"0\r\n\r\n",
            ),
        }
        metrics_after = fetch_metrics(proxy_port, token="framing-guard-token")
        keepalive_followup = probes["keepalive_followup_chunked_rejected"]
        return {
            "probes": probes,
            "metrics_delta": {
                "altura_http_framing_rejected": metrics_after.get(
                    "altura_http_framing_rejected", 0
                )
                - metrics_before.get("altura_http_framing_rejected", 0)
            },
            "generated_framing_rejection_not_stored": keepalive_followup.get("second", {}).get(
                "cache_control_no_store"
            )
            is True,
            "generated_framing_rejection_closes_connection": keepalive_followup.get("second", {}).get(
                "connection_close"
            )
            is True,
            "transfer_encoding_comma_spray_rejected": probes[
                "transfer_encoding_comma_spray"
            ].get("status")
            == 400,
            "transfer_encoding_empty_comma_spray_rejected": probes[
                "transfer_encoding_empty_comma_spray"
            ].get("status")
            == 400,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_initial_framing_precheck_response_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "initial-framing-precheck-response-filters.json"
    events_path = tmp_path / "initial-framing-precheck-response-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "initial-framing-precheck-response-token",
            "max_header_bytes": 8192,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "initial-framing-precheck-response-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        wait_tcp_port(proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="initial-framing-precheck-response-token")
        response = send_raw_initial_framing_precheck_rejection(proxy_port)
        header_too_large_response = send_raw_initial_header_too_large(proxy_port)
        late_terminator_response = send_raw_initial_header_late_terminator_over_cap(proxy_port)
        metrics_after = fetch_metrics(proxy_port, token="initial-framing-precheck-response-token")
        framing_rejected_delta = metrics_after.get(
            "altura_http_framing_rejected", 0
        ) - metrics_before.get("altura_http_framing_rejected", 0)
        initial_header_too_large_delta = metrics_after.get(
            "altura_http_initial_header_too_large", 0
        ) - metrics_before.get("altura_http_initial_header_too_large", 0)
        return {
            "response": response,
            "header_too_large_response": header_too_large_response,
            "late_terminator_response": late_terminator_response,
            "http_framing_rejected_delta": framing_rejected_delta,
            "http_initial_header_too_large_delta": initial_header_too_large_delta,
            "raw_initial_400_not_stored": response.get("cache_control_no_store") is True,
            "raw_initial_400_closes_connection": response.get("connection_close") is True,
            "raw_initial_431_not_stored": header_too_large_response.get(
                "cache_control_no_store"
            )
            is True,
            "raw_initial_431_closes_connection": header_too_large_response.get(
                "connection_close"
            )
            is True,
            "raw_initial_late_terminator_431_not_stored": late_terminator_response.get(
                "cache_control_no_store"
            )
            is True,
            "raw_initial_late_terminator_431_closes_connection": late_terminator_response.get(
                "connection_close"
            )
            is True,
            "initial_framing_precheck_response_observed": response.get("status") == 400
            and response.get("cache_control_no_store") is True
            and response.get("connection_close") is True
            and framing_rejected_delta >= 1,
            "initial_header_too_large_response_observed": header_too_large_response.get(
                "status"
            )
            == 431
            and header_too_large_response.get("cache_control_no_store") is True
            and header_too_large_response.get("connection_close") is True
            and initial_header_too_large_delta >= 1,
            "initial_header_late_terminator_over_cap_observed": late_terminator_response.get(
                "status"
            )
            == 431
            and late_terminator_response.get("cache_control_no_store") is True
            and late_terminator_response.get("connection_close") is True
            and initial_header_too_large_delta >= 2,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def send_raw_initial_framing_precheck_rejection(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-initial-framing-precheck-probe/1.0\r\n"
                b" X-Obsolete-Fold: rejected\r\n\r\n"
            )
            raw = sock.recv(4096)
    except Exception as exc:
        error = type(exc).__name__
    return parse_raw_initial_precheck_response(raw, started, error)


def send_raw_initial_header_too_large(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-initial-header-too-large-probe/1.0\r\n"
                b"X-Oversized-Header: "
                + (b"a" * 9000)
                + b"\r\n"
            )
            raw = sock.recv(4096)
    except Exception as exc:
        error = type(exc).__name__
    return parse_raw_initial_precheck_response(raw, started, error)


def send_raw_initial_header_late_terminator_over_cap(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-initial-header-late-terminator-probe/1.0\r\n"
                b"X-Oversized-Header: "
                + (b"a" * 8300)
                + b"\r\n\r\n"
            )
            raw = sock.recv(4096)
    except Exception as exc:
        error = type(exc).__name__
    return parse_raw_initial_precheck_response(raw, started, error)


def send_raw_initial_header_line_too_large(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"X-Oversized-Header: "
                + (b"a" * 192)
                + b"\r\n\r\n"
            )
            raw = sock.recv(4096)
    except Exception as exc:
        error = type(exc).__name__
    return parse_raw_initial_precheck_response(raw, started, error)


def parse_raw_initial_precheck_response(
    raw: bytes, started: float, error: Any
) -> dict[str, Any]:
    status = None
    if raw.startswith(b"HTTP/"):
        try:
            status = int(raw.split(b" ", 2)[1])
        except Exception:
            status = None
    headers = headers_from_raw_response(raw)
    return {
        "status": status,
        "cache_control": headers.get("cache-control"),
        "cache_control_no_store": headers.get("cache-control") == "no-store",
        "connection": headers.get("connection"),
        "connection_close": headers.get("connection") == "close",
        "body_bytes": len(raw.partition(b"\r\n\r\n")[2]),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def run_chunked_request_body_opt_in_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "chunked-request-opt-in-filters.json"
    events_path = tmp_path / "chunked-request-opt-in-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "chunked-request-opt-in-token",
            "allow_chunked_request_bodies": True,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "chunked-request-opt-in-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="chunked-request-opt-in-token")
        chunked = send_raw_framing_request(
            proxy_port,
            ["Transfer-Encoding: chunked"],
            body=b"0\r\n\r\n",
        )
        metrics_after = fetch_metrics(proxy_port, token="chunked-request-opt-in-token")
        return {
            "configured_allow_chunked_request_bodies": True,
            "chunked_request": chunked,
            "http_framing_rejected_delta": metrics_after.get(
                "altura_http_framing_rejected", 0
            )
            - metrics_before.get("altura_http_framing_rejected", 0),
            "chunked_request_allowed": chunked["status"] == 200,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_forwarded_headers_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    def run_case(
        name: str, trusted_proxy: bool, client_ip_header: str = "x-forwarded-for"
    ) -> dict[str, Any]:
        proxy_port = free_port()
        filters_path = tmp_path / f"{name}-forwarded-filters.json"
        events_path = tmp_path / f"{name}-forwarded-events.jsonl"
        filters_path.write_text('{"filters": []}\n', encoding="utf-8")
        http_cfg: dict[str, Any] = {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": f"{name}-forwarded-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        }
        if trusted_proxy:
            http_cfg["client_ip"] = {
                "header": client_ip_header,
                "trusted_proxies": ["127.0.0.1/32"],
            }
        cfg = {
            "http": http_cfg,
            "tcp": [],
            "filters": {
                "runtime_file": str(filters_path),
                "reload_seconds": 1,
                "max_runtime_file_bytes": 1024 * 1024,
                "max_runtime_filters": 1024,
                "static_rules": [],
            },
            "adaptive": {
                "enabled": True,
                "signature_threshold_per_second": 1_000_000,
                "activation_ttl_seconds": 10,
                "event_log": str(events_path),
                "event_cooldown_seconds": 1,
            },
        }
        config_path = tmp_path / f"{name}-forwarded-config.json"
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
            metrics_before = fetch_metrics(proxy_port, token=f"{name}-forwarded-token")
            probe = send_raw_forwarded_headers_request(proxy_port)
            duplicate_custom_identity = None
            comma_custom_identity = None
            if trusted_proxy and client_ip_header != "x-forwarded-for":
                duplicate_custom_identity = send_raw_custom_identity_header_request(
                    proxy_port,
                    [
                        "203.0.113.203",
                        "203.0.113.204",
                    ],
                )
                comma_custom_identity = send_raw_custom_identity_header_request(
                    proxy_port,
                    ["203.0.113.203, 203.0.113.204"],
                )
            metrics_after = fetch_metrics(proxy_port, token=f"{name}-forwarded-token")
            observed = probe.get("observed") or {}
            if trusted_proxy and client_ip_header == "x-forwarded-for":
                expected_xff = "203.0.113.200, 198.51.100.77, 127.0.0.1"
                expected_real_ip = "198.51.100.77"
            elif trusted_proxy:
                expected_xff = "203.0.113.203, 127.0.0.1"
                expected_real_ip = "203.0.113.203"
            else:
                expected_xff = "127.0.0.1"
                expected_real_ip = "127.0.0.1"
            return {
                "trusted_proxy": trusted_proxy,
                "client_ip_header": client_ip_header,
                "probe": probe,
                "canonical_headers_valid": observed.get("forwarded") is None
                and observed.get("x_forwarded_for") == expected_xff
                and observed.get("x_forwarded_host") == "good.local"
                and observed.get("x_forwarded_proto") == "http"
                and observed.get("x_real_ip") == expected_real_ip,
                "duplicate_xff_chain_preserved": client_ip_header == "x-forwarded-for"
                and trusted_proxy
                and observed.get("x_forwarded_for")
                == expected_xff
                and observed.get("x_real_ip") == expected_real_ip,
                "custom_identity_xff_synthesized": client_ip_header
                != "x-forwarded-for"
                and observed.get("x_forwarded_for") == expected_xff
                and observed.get("x_real_ip") == expected_real_ip,
                "duplicate_custom_identity_status": (
                    duplicate_custom_identity or {}
                ).get("status"),
                "comma_custom_identity_status": (comma_custom_identity or {}).get(
                    "status"
                ),
                "duplicate_custom_identity_rejected": duplicate_custom_identity
                is not None
                and duplicate_custom_identity.get("status") == 400,
                "comma_custom_identity_rejected": comma_custom_identity is not None
                and comma_custom_identity.get("status") == 400,
                "custom_identity_rejected_delta": metrics_after.get(
                    "altura_http_forwarded_rejected", 0
                )
                - metrics_before.get("altura_http_forwarded_rejected", 0),
                "custom_identity_rejected_metric_matches": client_ip_header
                != "x-forwarded-for"
                and metrics_after.get("altura_http_forwarded_rejected", 0)
                - metrics_before.get("altura_http_forwarded_rejected", 0)
                == 2,
                "spoof_headers_stripped": spoofed_forwarded_headers_absent(observed),
                "hop_by_hop_headers_stripped": hop_by_hop_headers_absent(observed),
                "metrics_delta": {
                    "altura_http_forwarded_sanitized": metrics_after.get(
                        "altura_http_forwarded_sanitized", 0
                    )
                    - metrics_before.get("altura_http_forwarded_sanitized", 0)
                },
            }
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()

    return {
        "untrusted_direct": run_case("untrusted", trusted_proxy=False),
        "trusted_proxy": run_case("trusted", trusted_proxy=True),
        "custom_identity_header": run_case(
            "custom-identity",
            trusted_proxy=True,
            client_ip_header="cf-connecting-ip",
        ),
    }


def send_raw_custom_identity_header_request(
    port: int, cf_connecting_ip_values: list[str]
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            lines = [
                "GET /headers HTTP/1.1",
                "Host: good.local",
                "User-Agent: altura-custom-identity-guard-probe/1.0",
                "X-Forwarded-For: 198.51.100.77",
            ]
            for value in cf_connecting_ip_values:
                lines.append(f"CF-Connecting-IP: {value}")
            lines.extend(["Connection: close", "", ""])
            sock.sendall("\r\n".join(lines).encode("ascii"))
            response = read_http_response_on_socket(sock)
            response["elapsed_seconds"] = round(time.perf_counter() - started, 3)
            return response
    except Exception as exc:
        return {
            "status": None,
            "headers": {},
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "error": type(exc).__name__,
        }


def run_forwarded_header_bounds_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "forwarded-header-bounds-filters.json"
    events_path = tmp_path / "forwarded-header-bounds-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    max_forwarded_for_bytes = 64
    max_forwarded_for_hops = 2
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "forwarded-header-bounds-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
                "max_forwarded_for_bytes": max_forwarded_for_bytes,
                "max_forwarded_for_hops": max_forwarded_for_hops,
            },
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": 1024 * 1024,
            "max_runtime_filters": 1024,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "forwarded-header-bounds-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="forwarded-header-bounds-token")
        valid_response = get_status_and_headers(
            proxy_port,
            "GET",
            "/",
            headers={"X-Forwarded-For": "203.0.113.10"},
        )
        too_long_response = get_status_and_headers(
            proxy_port,
            "GET",
            "/",
            headers={
                "X-Forwarded-For": "203.0.113.10, "
                + ", ".join(f"198.51.100.{idx}" for idx in range(1, 8))
            },
        )
        too_many_hops_response = get_status_and_headers(
            proxy_port,
            "GET",
            "/",
            headers={
                "X-Forwarded-For": "203.0.113.10, 198.51.100.20, 192.0.2.30"
            },
        )
        malformed_response = get_status_and_headers(
            proxy_port,
            "GET",
            "/",
            headers={"X-Forwarded-For": "not-an-ip"},
        )
        metrics_after = fetch_metrics(proxy_port, token="forwarded-header-bounds-token")
        rejected_delta = metrics_after.get("altura_http_forwarded_rejected", 0) - metrics_before.get(
            "altura_http_forwarded_rejected", 0
        )
        return {
            "configured_max_forwarded_for_bytes": max_forwarded_for_bytes,
            "configured_max_forwarded_for_hops": max_forwarded_for_hops,
            "valid_response": valid_response,
            "too_long_response": too_long_response,
            "too_many_hops_response": too_many_hops_response,
            "malformed_response": malformed_response,
            "rejected_delta": rejected_delta,
            "valid_chain_allowed": valid_response["status"] == 204,
            "oversized_chain_rejected": too_long_response["status"] == 400,
            "too_many_hops_rejected": too_many_hops_response["status"] == 400,
            "malformed_chain_rejected": malformed_response["status"] == 400,
            "forwarded_rejections_not_stored": all(
                response["headers"].get("cache-control") == "no-store"
                for response in [too_long_response, too_many_hops_response, malformed_response]
            ),
            "rejection_metric_matches": rejected_delta == 3,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_trusted_proxy_aggregate_rate_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "trusted-proxy-aggregate-rate-filters.json"
    events_path = tmp_path / "trusted-proxy-aggregate-rate-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    trusted_proxy_rps = 0.000001
    trusted_proxy_burst = 2
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "trusted-proxy-aggregate-rate-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
            },
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "trusted_proxy_rps": trusted_proxy_rps,
                "trusted_proxy_burst": trusted_proxy_burst,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": 1024 * 1024,
            "max_runtime_filters": 1024,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "trusted-proxy-aggregate-rate-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="trusted-proxy-aggregate-rate-token")
        responses = [
            get_status_and_headers(
                proxy_port,
                "GET",
                "/",
                headers={"X-Forwarded-For": f"198.51.100.{idx}"},
            )
            for idx in range(10, 14)
        ]
        statuses = [response["status"] for response in responses]
        retry_after_headers = response_headers_for_status(responses, "retry-after")
        cache_control_headers = response_headers_for_status(responses, "cache-control")
        metrics_after = fetch_metrics(proxy_port, token="trusted-proxy-aggregate-rate-token")
        trusted_proxy_delta = metrics_after.get(
            "altura_http_trusted_proxy_rate_limited", 0
        ) - metrics_before.get("altura_http_trusted_proxy_rate_limited", 0)
        rate_limited_delta = metrics_after.get("altura_http_rate_limited", 0) - metrics_before.get(
            "altura_http_rate_limited", 0
        )
        return {
            "configured_trusted_proxy_rps": trusted_proxy_rps,
            "configured_trusted_proxy_burst": trusted_proxy_burst,
            "statuses": statuses,
            "retry_after_headers": retry_after_headers,
            "cache_control_headers": cache_control_headers,
            "trusted_proxy_rate_limited_delta": trusted_proxy_delta,
            "http_rate_limited_delta": rate_limited_delta,
            "first_burst_allowed": statuses[:2] == [204, 204],
            "rotating_xff_aggregate_limited": statuses[2:] == [429, 429],
            "retry_after_header_matches": retry_after_headers == ["1", "1"],
            "cache_control_header_matches": cache_control_headers == ["no-store", "no-store"],
            "trusted_proxy_metric_matches": trusted_proxy_delta == 2,
            "rate_limited_metric_includes_proxy_limit": rate_limited_delta == 2,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_trusted_proxy_in_flight_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "trusted-proxy-in-flight-filters.json"
    events_path = tmp_path / "trusted-proxy-in-flight-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    trusted_proxy_max_in_flight = 1
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "trusted-proxy-in-flight-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
            },
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "trusted_proxy_rps": 1_000_000,
                "trusted_proxy_burst": 1_000_000,
                "trusted_proxy_max_in_flight_requests": trusted_proxy_max_in_flight,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": 1024 * 1024,
            "max_runtime_filters": 1024,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "trusted-proxy-in-flight-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    first_status: list[int | None] = [None]
    try:
        wait_http("127.0.0.1", proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="trusted-proxy-in-flight-token")

        def first_request() -> None:
            first_status[0] = get_status(
                proxy_port,
                "GET",
                "/slow",
                timeout=2.0,
                headers={"X-Forwarded-For": "198.51.100.10"},
            )

        first_thread = threading.Thread(target=first_request, daemon=True)
        first_thread.start()
        time.sleep(0.05)
        second_response = get_status_and_headers(
            proxy_port,
            "GET",
            "/slow",
            timeout=2.0,
            headers={"X-Forwarded-For": "198.51.100.11"},
        )
        first_thread.join(timeout=3.0)
        metrics_after = fetch_metrics(proxy_port, token="trusted-proxy-in-flight-token")
        overload_responses = [second_response]
        retry_after_headers = response_headers_for_status(overload_responses, "retry-after", 503)
        cache_control_headers = response_headers_for_status(
            overload_responses, "cache-control", 503
        )
        trusted_proxy_delta = metrics_after.get(
            "altura_http_trusted_proxy_in_flight_rejected", 0
        ) - metrics_before.get("altura_http_trusted_proxy_in_flight_rejected", 0)
        upstream_delta = metrics_after.get(
            "altura_http_upstream_in_flight_rejected", 0
        ) - metrics_before.get("altura_http_upstream_in_flight_rejected", 0)
        return {
            "configured_trusted_proxy_max_in_flight_requests": trusted_proxy_max_in_flight,
            "first_status": first_status[0],
            "second_status": second_response["status"],
            "retry_after_headers": retry_after_headers,
            "cache_control_headers": cache_control_headers,
            "trusted_proxy_in_flight_rejected_delta": trusted_proxy_delta,
            "http_upstream_in_flight_rejected_delta": upstream_delta,
            "rotating_xff_peer_concurrency_limited": second_response["status"] == 503,
            "first_slow_request_completed": first_status[0] == 204,
            "retry_after_header_matches": retry_after_headers == ["1"],
            "cache_control_header_matches": cache_control_headers == ["no-store"],
            "trusted_proxy_metric_matches": trusted_proxy_delta == 1,
            "upstream_metric_includes_proxy_limit": upstream_delta == 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_ip_prefix_aggregation_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "ip-prefix-aggregation-filters.json"
    events_path = tmp_path / "ip-prefix-aggregation-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "ip-prefix-aggregation-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
            },
            "limits": {
                "per_ip_rps": 0.000001,
                "per_ip_burst": 1,
                "ipv4_prefix_len": 32,
                "ipv6_prefix_len": 64,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "trusted_proxy_rps": 1_000_000,
                "trusted_proxy_burst": 1_000_000,
                "signature_rps": 1_000_000,
                "signature_burst": 1_000_000,
                "path_shape_rps": 1_000_000,
                "path_shape_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": 1024 * 1024,
            "max_runtime_filters": 1024,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "ip-prefix-aggregation-config.json"
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
        metrics_before = fetch_metrics(
            proxy_port,
            token="ip-prefix-aggregation-token",
            headers={"X-Forwarded-For": "2001:db8:ffff::1"},
        )
        cases = [
            ("ipv6_first", "2001:db8:100::1"),
            ("ipv6_same_prefix", "2001:db8:100::2"),
            ("ipv6_different_prefix", "2001:db8:101::1"),
            ("ipv4_first", "198.51.100.10"),
            ("ipv4_neighbor", "198.51.100.11"),
        ]
        responses = {
            name: get_status_and_headers(
                proxy_port,
                "GET",
                "/",
                headers={"X-Forwarded-For": ip},
            )
            for name, ip in cases
        }
        metrics_after = fetch_metrics(
            proxy_port,
            token="ip-prefix-aggregation-token",
            headers={"X-Forwarded-For": "2001:db8:fffe::1"},
        )
        rate_limited_delta = metrics_after.get(
            "altura_http_rate_limited", 0
        ) - metrics_before.get("altura_http_rate_limited", 0)
        statuses = {name: response["status"] for name, response in responses.items()}
        retry_after_headers = response_headers_for_status(
            list(responses.values()), "retry-after"
        )
        cache_control_headers = response_headers_for_status(
            list(responses.values()), "cache-control"
        )
        return {
            "configured_ipv4_prefix_len": 32,
            "configured_ipv6_prefix_len": 64,
            "statuses": statuses,
            "http_rate_limited_delta": rate_limited_delta,
            "retry_after_headers": retry_after_headers,
            "cache_control_headers": cache_control_headers,
            "same_ipv6_prefix_limited": statuses["ipv6_same_prefix"] == 429,
            "different_ipv6_prefix_allowed": statuses["ipv6_different_prefix"] == 204,
            "ipv4_exact_default_allows_neighbor": statuses["ipv4_first"] == 204
            and statuses["ipv4_neighbor"] == 204,
            "rate_limited_metric_matches": rate_limited_delta == 1,
            "retry_after_header_matches": retry_after_headers == ["1"],
            "cache_control_header_matches": cache_control_headers == ["no-store"],
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_signature_rate_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "signature-rate-filters.json"
    events_path = tmp_path / "signature-rate-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    signature_rps = 0.000001
    signature_burst = 2
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "signature-rate-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "signature_rps": signature_rps,
                "signature_burst": signature_burst,
                "max_tracked_signatures": 64,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": 1024 * 1024,
            "max_runtime_filters": 1024,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "signature-rate-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="signature-rate-token")
        hot_responses = [get_status_and_headers(proxy_port, "GET", "/hot") for _ in range(4)]
        hot_statuses = [response["status"] for response in hot_responses]
        retry_after_headers = response_headers_for_status(hot_responses, "retry-after")
        cache_control_headers = response_headers_for_status(hot_responses, "cache-control")
        cold_status = get_status(proxy_port, "GET", "/cold")
        metrics_after = fetch_metrics(proxy_port, token="signature-rate-token")
        signature_delta = metrics_after.get(
            "altura_http_signature_rate_limited", 0
        ) - metrics_before.get("altura_http_signature_rate_limited", 0)
        rate_limited_delta = metrics_after.get(
            "altura_http_rate_limited", 0
        ) - metrics_before.get("altura_http_rate_limited", 0)
        return {
            "configured_signature_rps": signature_rps,
            "configured_signature_burst": signature_burst,
            "hot_statuses": hot_statuses,
            "cold_status": cold_status,
            "retry_after_headers": retry_after_headers,
            "cache_control_headers": cache_control_headers,
            "signature_rate_limited_delta": signature_delta,
            "http_rate_limited_delta": rate_limited_delta,
            "hot_signature_limited": hot_statuses[:2] == [204, 204]
            and hot_statuses[2:] == [429, 429],
            "other_signature_allowed": cold_status == 204,
            "retry_after_header_matches": retry_after_headers == ["1", "1"],
            "cache_control_header_matches": cache_control_headers == ["no-store", "no-store"],
            "signature_metric_matches": signature_delta == 2,
            "rate_limited_metric_includes_signature_limit": rate_limited_delta == 2,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_path_shape_rate_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "path-shape-rate-filters.json"
    events_path = tmp_path / "path-shape-rate-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    path_shape_rps = 0.000001
    path_shape_burst = 2
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "path-shape-rate-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "signature_rps": 1_000_000,
                "signature_burst": 1_000_000,
                "max_tracked_signatures": 4096,
                "path_shape_rps": path_shape_rps,
                "path_shape_burst": path_shape_burst,
                "max_tracked_path_shapes": 64,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "max_runtime_file_bytes": 1024 * 1024,
            "max_runtime_filters": 1024,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 2,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_log_flush_interval_ms": 1,
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "path-shape-rate-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="path-shape-rate-token")
        hot_paths = [
            "/api/abcdefghij/123",
            "/api/klmnopqrst/456",
            "/api/ZYXWVUTSRQ/789",
            "/api/qwertyuiop/321",
        ]
        hot_responses = [get_status_and_headers(proxy_port, "GET", path) for path in hot_paths]
        hot_statuses = [response["status"] for response in hot_responses]
        short_token_paths = ["/api/ab", "/api/cd", "/api/ef", "/api/gh"]
        short_token_responses = [
            get_status_and_headers(proxy_port, "GET", path) for path in short_token_paths
        ]
        short_token_statuses = [response["status"] for response in short_token_responses]
        limited_responses = hot_responses + short_token_responses
        retry_after_headers = response_headers_for_status(limited_responses, "retry-after")
        cache_control_headers = response_headers_for_status(limited_responses, "cache-control")
        other_shape_status = get_status(proxy_port, "GET", "/api/catalog/123")
        version_shape_status = get_status(proxy_port, "GET", "/api/v1/users")
        metrics_after = fetch_metrics(proxy_port, token="path-shape-rate-token")
        events = wait_for_jsonl_event(
            events_path,
            lambda event: event.get("reason") == "path_shape_rate_limited"
            and event.get("path_shape") == "/api/:short-token",
            1.0,
        )
        path_shape_event_shapes = [
            event.get("path_shape")
            for event in events
            if event.get("reason") == "path_shape_rate_limited"
        ]
        path_shape_delta = metrics_after.get(
            "altura_http_path_shape_rate_limited", 0
        ) - metrics_before.get("altura_http_path_shape_rate_limited", 0)
        rate_limited_delta = metrics_after.get(
            "altura_http_rate_limited", 0
        ) - metrics_before.get("altura_http_rate_limited", 0)
        return {
            "configured_path_shape_rps": path_shape_rps,
            "configured_path_shape_burst": path_shape_burst,
            "hot_paths": hot_paths,
            "hot_statuses": hot_statuses,
            "short_token_paths": short_token_paths,
            "short_token_statuses": short_token_statuses,
            "path_shape_rate_limited_event_shapes": path_shape_event_shapes,
            "other_shape_status": other_shape_status,
            "version_shape_status": version_shape_status,
            "retry_after_headers": retry_after_headers,
            "cache_control_headers": cache_control_headers,
            "path_shape_rate_limited_delta": path_shape_delta,
            "http_rate_limited_delta": rate_limited_delta,
            "hot_path_shape_limited": hot_statuses[:2] == [204, 204]
            and hot_statuses[2:] == [429, 429],
            "short_token_path_shape_limited": short_token_statuses[:2] == [204, 204]
            and short_token_statuses[2:] == [429, 429],
            "short_token_sibling_churn_limited": short_token_statuses[:2]
            == [204, 204]
            and short_token_statuses[2:] == [429, 429],
            "short_token_sibling_event_shape_recorded": "/api/:short-token"
            in path_shape_event_shapes,
            "other_shape_allowed": other_shape_status == 204,
            "version_shape_allowed": version_shape_status == 204,
            "retry_after_header_matches": retry_after_headers == ["1", "1", "1", "1"],
            "cache_control_header_matches": cache_control_headers
            == ["no-store", "no-store", "no-store", "no-store"],
            "path_shape_metric_matches": path_shape_delta == 4,
            "rate_limited_metric_includes_path_shape_limit": rate_limited_delta == 4,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def send_raw_forwarded_headers_request(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    status = None
    observed = None
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET /headers HTTP/1.1\r\n"
                b"Host: good.local\r\n"
                b"User-Agent: altura-forwarded-guard-probe/1.0\r\n"
                b"X-Forwarded-For: 203.0.113.200\r\n"
                b"X-Forwarded-For: 198.51.100.77\r\n"
                b"X-Forwarded-Host: attacker.local\r\n"
                b"X-Forwarded-Proto: https\r\n"
                b"X-Forwarded-Server: edge-attacker\r\n"
                b"X-Forwarded-Port: 443\r\n"
                b"X-Forwarded-Scheme: https\r\n"
                b"X-Forwarded-Prefix: /admin\r\n"
                b"X-Forwarded-URI: /admin\r\n"
                b"X-Forwarded-Path: /admin\r\n"
                b"X-Forwarded: for=203.0.113.209\r\n"
                b"X-Real-IP: 203.0.113.201\r\n"
                b"X-Original-Forwarded-For: 203.0.113.213\r\n"
                b"X-Original-Host: attacker.local\r\n"
                b"X-Original-URL: /admin\r\n"
                b"X-Rewrite-URL: /admin\r\n"
                b"CF-Connecting-IP: 203.0.113.203\r\n"
                b"True-Client-IP: 203.0.113.204\r\n"
                b"Fastly-Client-IP: 203.0.113.205\r\n"
                b"Client-IP: 203.0.113.206\r\n"
                b"X-Client-IP: 203.0.113.207\r\n"
                b"X-Cluster-Client-IP: 203.0.113.208\r\n"
                b"X-Originating-IP: 203.0.113.210\r\n"
                b"X-Remote-IP: 203.0.113.211\r\n"
                b"X-Remote-Addr: 203.0.113.212\r\n"
                b"Forwarded: for=203.0.113.202;host=attacker.local;proto=https\r\n"
                b"Connection: close\r\n"
                b"Connection: X-Hop-By-Hop-Attack\r\n"
                b"X-Hop-By-Hop-Attack: should-strip\r\n"
                b"Proxy-Connection: keep-alive\r\n"
                b"Keep-Alive: timeout=999\r\n"
                b"TE: trailers\r\n"
                b"Trailer: X-Trailer-Attack\r\n"
                b"Upgrade: websocket\r\n\r\n"
            )
            response = read_http_response_on_socket(sock)
            status = response["status"]
            if response.get("body"):
                observed = json.loads(response["body"])
    except Exception as exc:
        error = type(exc).__name__
    return {
        "status": status,
        "observed": observed,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def spoofed_forwarded_headers_absent(observed: dict[str, Any]) -> bool:
    return all(
        observed.get(name) is None
        for name in [
            "x_forwarded",
            "x_forwarded_server",
            "x_forwarded_port",
            "x_forwarded_scheme",
            "x_forwarded_prefix",
            "x_forwarded_uri",
            "x_forwarded_path",
            "x_original_forwarded_for",
            "x_original_host",
            "x_original_url",
            "x_rewrite_url",
            "cf_connecting_ip",
            "true_client_ip",
            "fastly_client_ip",
            "client_ip",
            "x_client_ip",
            "x_cluster_client_ip",
            "x_originating_ip",
            "x_remote_ip",
            "x_remote_addr",
        ]
    )


def hop_by_hop_headers_absent(observed: dict[str, Any]) -> bool:
    return all(
        observed.get(name) is None
        for name in [
            "connection",
            "proxy_connection",
            "keep_alive",
            "te",
            "trailer",
            "upgrade",
            "x_hop_by_hop_attack",
        ]
    )


def send_raw_get_target(port: int, target: str) -> dict[str, Any]:
    started = time.perf_counter()
    status = None
    body = b""
    headers: dict[str, str] = {}
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                f"GET {target} HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "User-Agent: altura-uri-guard-probe/1.0\r\n"
                "Connection: close\r\n\r\n"
                .encode("ascii")
            )
            response = read_http_response_on_socket(sock)
            status = response["status"]
            body = b"x" * response["body_bytes"]
            headers = response["headers"]
    except Exception as exc:
        error = type(exc).__name__
    return {
        "target_bytes": len(target),
        "status": status,
        "cache_control": headers.get("cache-control"),
        "connection": headers.get("connection"),
        "connection_close": headers.get("connection") == "close",
        "body_bytes": len(body),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def send_raw_framing_request(
    port: int, framing_headers: list[str], body: bytes = b""
) -> dict[str, Any]:
    started = time.perf_counter()
    status = None
    response_body = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            lines = [
                "POST /drain HTTP/1.1",
                "Host: 127.0.0.1",
                "User-Agent: altura-framing-guard-probe/1.0",
                "Connection: close",
                *framing_headers,
            ]
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
            response = read_http_response_on_socket(sock)
            status = response["status"]
            response_body = b"x" * response["body_bytes"]
            cache_control = response["headers"].get("cache-control")
            connection = response["headers"].get("connection")
    except Exception as exc:
        error = type(exc).__name__
        cache_control = None
        connection = None
    return {
        "headers": framing_headers,
        "status": status,
        "cache_control": cache_control,
        "cache_control_no_store": cache_control == "no-store",
        "connection": connection,
        "connection_close": connection == "close",
        "body_bytes": len(response_body),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def send_keepalive_followup_framing_request(
    port: int, framing_headers: list[str], body: bytes = b""
) -> dict[str, Any]:
    started = time.perf_counter()
    result: dict[str, Any] = {
        "first": {"status": None, "connection": None, "connection_close": False},
        "second": {"status": None, "connection": None, "connection_close": False},
        "elapsed_seconds": None,
        "error": None,
    }
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"POST /drain HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-framing-keepalive-probe/1.0\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            first = read_http_response_on_socket(sock)
            first_connection = first["headers"].get("connection")
            result["first"] = {
                "status": first["status"],
                "connection": first_connection,
                "connection_close": first_connection == "close",
            }

            lines = [
                "POST /drain HTTP/1.1",
                "Host: 127.0.0.1",
                "User-Agent: altura-framing-keepalive-probe/1.0",
                *framing_headers,
            ]
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
            second = read_http_response_on_socket(sock)
            second_connection = second["headers"].get("connection")
            second_cache_control = second["headers"].get("cache-control")
            result["second"] = {
                "status": second["status"],
                "cache_control": second_cache_control,
                "cache_control_no_store": second_cache_control == "no-store",
                "connection": second_connection,
                "connection_close": second_connection == "close",
                "body_bytes": second["body_bytes"],
            }
    except Exception as exc:
        result["error"] = type(exc).__name__
    result["headers"] = framing_headers
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result


def send_keepalive_followup_request_with_body(
    port: int, method: str, target: str, body: bytes
) -> dict[str, Any]:
    started = time.perf_counter()
    result: dict[str, Any] = {
        "first": {"status": None, "connection": None, "connection_close": False},
        "second": {"status": None, "connection": None, "connection_close": False},
        "elapsed_seconds": None,
        "error": None,
    }
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-early-close-probe/1.0\r\n\r\n"
            )
            first = read_http_response_on_socket(sock)
            first_connection = first["headers"].get("connection")
            result["first"] = {
                "status": first["status"],
                "connection": first_connection,
                "connection_close": first_connection == "close",
            }
            lines = [
                f"{method} {target} HTTP/1.1",
                "Host: 127.0.0.1",
                "User-Agent: altura-early-close-probe/1.0",
                f"Content-Length: {len(body)}",
            ]
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
            second = read_http_response_on_socket(sock)
            second_connection = second["headers"].get("connection")
            second_cache_control = second["headers"].get("cache-control")
            result["second"] = {
                "status": second["status"],
                "cache_control": second_cache_control,
                "cache_control_no_store": second_cache_control == "no-store",
                "connection": second_connection,
                "connection_close": second_connection == "close",
                "body_bytes": second["body_bytes"],
            }
    except Exception as exc:
        result["error"] = type(exc).__name__
    result["method"] = method
    result["target_bytes"] = len(target)
    result["body_bytes_sent"] = len(body)
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result


def send_body_bearing_admin_keepalive_request(
    port: int, path: str, headers: dict[str, str] | None = None
) -> dict[str, Any]:
    started = time.perf_counter()
    body = b"admin-body"
    result: dict[str, Any] = {
        "path": path,
        "first": {
            "status": None,
            "cache_control": None,
            "cache_control_no_store": False,
            "connection": None,
            "connection_close": False,
        },
        "followup": {
            "status": None,
            "header_complete": False,
            "response_received": False,
            "closed_without_response": False,
            "error": None,
        },
        "body_bytes_sent": len(body),
        "elapsed_seconds": None,
        "error": None,
    }
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            lines = [
                f"GET {path} HTTP/1.1",
                "Host: 127.0.0.1",
                "User-Agent: altura-admin-close-probe/1.0",
                "Connection: keep-alive",
                f"Content-Length: {len(body)}",
            ]
            if headers:
                for name, value in headers.items():
                    lines.append(f"{name}: {value}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)

            first = read_http_response_on_socket(sock)
            first_connection = first["headers"].get("connection")
            first_cache_control = first["headers"].get("cache-control")
            result["first"] = {
                "status": first["status"],
                "cache_control": first_cache_control,
                "cache_control_no_store": first_cache_control == "no-store",
                "connection": first_connection,
                "connection_close": first_connection == "close",
                "body_bytes": first["body_bytes"],
            }

            time.sleep(0.05)
            try:
                sock.sendall(
                    b"GET /__altura/health HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"User-Agent: altura-admin-close-probe/1.0\r\n\r\n"
                )
                followup = read_http_response_on_socket(sock)
                response_received = bool(
                    followup["status"] is not None
                    or followup["header_complete"]
                    or followup["body_bytes"]
                )
                result["followup"] = {
                    "status": followup["status"],
                    "header_complete": followup["header_complete"],
                    "response_received": response_received,
                    "closed_without_response": not response_received,
                    "error": None,
                }
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError) as exc:
                result["followup"] = {
                    "status": None,
                    "header_complete": False,
                    "response_received": False,
                    "closed_without_response": True,
                    "error": type(exc).__name__,
                }
            except socket.timeout as exc:
                result["followup"] = {
                    "status": None,
                    "header_complete": False,
                    "response_received": False,
                    "closed_without_response": False,
                    "error": type(exc).__name__,
                }
    except Exception as exc:
        result["error"] = type(exc).__name__
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result


def send_raw_host_request(
    port: int, hosts: list[str], target: str = "/"
) -> dict[str, Any]:
    started = time.perf_counter()
    status = None
    body = b""
    headers: dict[str, str] = {}
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            lines = [f"GET {target} HTTP/1.1"]
            for host in hosts:
                lines.append(f"Host: {host}")
            lines.extend(
                [
                    "User-Agent: altura-host-guard-probe/1.0",
                    "Connection: close",
                ]
            )
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            response = read_http_response_on_socket(sock)
            status = response["status"]
            body = b"x" * response["body_bytes"]
            headers = response["headers"]
    except Exception as exc:
        error = type(exc).__name__
    return {
        "hosts": hosts,
        "target": target,
        "status": status,
        "cache_control": headers.get("cache-control"),
        "cache_control_no_store": headers.get("cache-control") == "no-store",
        "body_bytes": len(body),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def send_raw_method(port: int, method: str, target: str) -> dict[str, Any]:
    started = time.perf_counter()
    status = None
    headers: dict[str, str] = {}
    body = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                f"{method} {target} HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "User-Agent: altura-method-guard-probe/1.0\r\n"
                "Connection: close\r\n\r\n"
                .encode("ascii")
            )
            response = read_http_response_on_socket(sock)
            status = response["status"]
            headers = response["headers"]
            body = b"x" * response["body_bytes"]
    except Exception as exc:
        error = type(exc).__name__
    return {
        "method": method,
        "target": target,
        "status": status,
        "allow": headers.get("allow"),
        "cache_control": headers.get("cache-control"),
        "body_bytes": len(body),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def run_tcp_global_cap_probe(port: int) -> dict[str, Any]:
    held: list[socket.socket] = []
    try:
        for _ in range(2):
            sock = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            sock.settimeout(1.0)
            held.append(sock)
        time.sleep(0.1)
        rejected = socket.create_connection(("127.0.0.1", port), timeout=1.0)
        try:
            rejected.settimeout(1.0)
            rejected.sendall(b"probe")
            data = rejected.recv(16)
            rejected_closed = data == b""
            rejected_error = None
        except Exception as exc:
            rejected_closed = True
            rejected_error = type(exc).__name__
        finally:
            rejected.close()
        return {
            "held_connections": len(held),
            "rejected_closed": rejected_closed,
            "rejected_error": rejected_error,
        }
    finally:
        for sock in held:
            sock.close()


def run_tcp_global_connection_rate_probe(port: int, metrics_port: int) -> dict[str, Any]:
    metrics_before = fetch_metrics(metrics_port)
    attempts: list[dict[str, Any]] = []
    for idx in range(8):
        payload = f"tcp-rate-{idx}".encode("ascii")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
                sock.settimeout(1.0)
                try:
                    sock.sendall(payload)
                    data = sock.recv(len(payload))
                    attempts.append(
                        {
                            "echoed": data == payload,
                            "closed": data == b"",
                            "error": None,
                        }
                    )
                except Exception as exc:
                    attempts.append(
                        {
                            "echoed": False,
                            "closed": True,
                            "error": type(exc).__name__,
                        }
                    )
        except Exception as exc:
            attempts.append(
                {
                    "echoed": False,
                    "closed": True,
                    "error": type(exc).__name__,
                }
            )
        time.sleep(0.01)
    metrics_after = fetch_metrics(metrics_port)
    accepted_echoes = sum(1 for attempt in attempts if attempt["echoed"])
    rejected_attempts = len(attempts) - accepted_echoes
    rejected_delta = metrics_after.get("altura_tcp_rejected", 0) - metrics_before.get(
        "altura_tcp_rejected", 0
    )
    global_rate_delta = metrics_after.get(
        "altura_tcp_global_connect_rate_limited", 0
    ) - metrics_before.get("altura_tcp_global_connect_rate_limited", 0)
    return {
        "configured_global_connects_per_second": 1.0,
        "configured_global_connect_burst": 2,
        "attempts": len(attempts),
        "accepted_echoes": accepted_echoes,
        "rejected_attempts": rejected_attempts,
        "tcp_rejected_delta": rejected_delta,
        "tcp_global_connect_rate_limited_delta": global_rate_delta,
        "global_connection_rate_limited": accepted_echoes <= 2
        and rejected_attempts >= 1
        and global_rate_delta >= 1,
        "attempt_results": attempts,
    }


def run_tcp_idle_timeout_probe(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
            sock.settimeout(2.0)
            time.sleep(1.2)
            try:
                sock.sendall(b"idle-probe")
                data = sock.recv(32)
                closed = data == b""
                error = None
            except Exception as exc:
                closed = True
                error = type(exc).__name__
    except Exception as exc:
        return {
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "closed": True,
            "error": type(exc).__name__,
        }
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "closed": closed,
        "error": error,
    }


def run_tcp_relay_head_of_line_probe(binary: Path, tmp_path: Path) -> dict[str, Any]:
    tcp_proxy_port = free_port()
    tcp_upstream_port = free_port()
    filters_path = tmp_path / "tcp-relay-head-of-line-filters.json"
    events_path = tmp_path / "tcp-relay-head-of-line-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": None,
        "tcp": [
            {
                "name": "tcp-relay-head-of-line",
                "listen": f"127.0.0.1:{tcp_proxy_port}",
                "upstream": f"127.0.0.1:{tcp_upstream_port}",
                "connect_timeout_ms": 500,
                "idle_timeout_seconds": 2,
                "downstream_min_rate_bytes_per_second": 0,
                "upstream_min_rate_bytes_per_second": 0,
                "max_connection_duration_seconds": 5,
                "limits": {
                    "per_ip_connects_per_second": 1_000_000,
                    "per_ip_connect_burst": 1_000_000,
                    "global_connects_per_second": 1_000_000,
                    "global_connect_burst": 1_000_000,
                    "max_connections": 128,
                    "max_connections_per_ip": 128,
                    "max_tracked_ips": 1024,
                },
            }
        ],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": False,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "tcp-relay-head-of-line-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    with FastTcpServer(
        ("127.0.0.1", tcp_upstream_port), TcpHeadOfLineHandler
    ) as upstream:
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        sock: socket.socket | None = None
        send_error: str | None = None
        send_done = False

        def sender(client: socket.socket) -> None:
            nonlocal send_done, send_error
            try:
                client.sendall(b"x" * (16 * 1024 * 1024))
                send_done = True
            except Exception as exc:
                send_error = type(exc).__name__

        started = time.perf_counter()
        try:
            wait_tcp_port(tcp_proxy_port)
            sock = socket.create_connection(("127.0.0.1", tcp_proxy_port), timeout=1.0)
            sock.settimeout(1.0)
            send_thread = threading.Thread(target=sender, args=(sock,), daemon=True)
            send_thread.start()
            received = recv_exact(sock, 4)
            elapsed = time.perf_counter() - started
            delivered = received == b"pong" and elapsed < 1.0
            return {
                "received_bytes": len(received),
                "received": received.decode("ascii", errors="replace"),
                "elapsed_seconds": round(elapsed, 3),
                "sender_completed_during_probe": send_done,
                "sender_error": send_error,
                "upstream_response_delivered_while_downstream_write_blocked": delivered,
            }
        except Exception as exc:
            return {
                "received_bytes": 0,
                "received": "",
                "elapsed_seconds": round(time.perf_counter() - started, 3),
                "sender_completed_during_probe": send_done,
                "sender_error": send_error,
                "error": type(exc).__name__,
                "upstream_response_delivered_while_downstream_write_blocked": False,
            }
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            proxy.terminate()
            try:
                proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.communicate(timeout=5)
            upstream.shutdown()


def send_http_max_connection_duration_probe(
    port: int, wait_seconds: float = 1.3
) -> dict[str, Any]:
    started = time.perf_counter()
    first_status = None
    second_status = None
    second_closed = False
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"User-Agent: altura-http-max-duration-probe/1.0\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            first = read_http_response_on_socket(sock)
            first_status = first["status"]
            time.sleep(wait_seconds)
            try:
                sock.sendall(
                    b"GET / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"User-Agent: altura-http-max-duration-probe/1.0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                second = read_http_response_on_socket(sock)
                second_status = second["status"]
                second_closed = (
                    not second["header_complete"]
                    and second["status"] is None
                    and second["body_bytes"] == 0
                )
            except Exception as exc:
                second_closed = True
                error = type(exc).__name__
    except Exception as exc:
        error = type(exc).__name__
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "configured_max_connection_duration_seconds": 1,
        "first_status": first_status,
        "second_status": second_status,
        "second_closed_or_reset": second_closed,
        "error": error,
    }


def send_tcp_max_connection_duration_probe(
    port: int, wait_seconds: float = 1.3
) -> dict[str, Any]:
    started = time.perf_counter()
    first_echo = b""
    second_echo = b""
    closed_or_reset = False
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(b"duration-one")
            first_echo = recv_exact(sock, len(b"duration-one"))
            time.sleep(wait_seconds)
            try:
                sock.sendall(b"duration-two")
                second_echo = sock.recv(32)
                closed_or_reset = second_echo == b""
            except Exception as exc:
                closed_or_reset = True
                error = type(exc).__name__
    except Exception as exc:
        error = type(exc).__name__
        closed_or_reset = True
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "configured_max_connection_duration_seconds": 1,
        "first_echo_bytes": len(first_echo),
        "second_echo_bytes": len(second_echo),
        "closed_or_reset": closed_or_reset,
        "error": error,
    }


def run_connection_duration_runtime_probe(
    binary: Path, http_upstream_port: int, tcp_upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    tcp_proxy_port = free_port()
    filters_path = tmp_path / "connection-duration-runtime-filters.json"
    events_path = tmp_path / "connection-duration-runtime-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{http_upstream_port}",
            "preserve_host": True,
            "admin_token": "connection-duration-token",
            "downstream_keep_alive": True,
            "max_connection_duration_seconds": 1,
            "max_requests_per_connection": 100,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "signature_rps": 1_000_000,
                "signature_burst": 1_000_000,
                "path_shape_rps": 1_000_000,
                "path_shape_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [
            {
                "name": "tcp-max-duration",
                "listen": f"127.0.0.1:{tcp_proxy_port}",
                "upstream": f"127.0.0.1:{tcp_upstream_port}",
                "connect_timeout_ms": 500,
                "idle_timeout_seconds": 10,
                "downstream_min_rate_bytes_per_second": 0,
                "upstream_min_rate_bytes_per_second": 0,
                "max_connection_duration_seconds": 1,
                "limits": {
                    "per_ip_connects_per_second": 1_000_000,
                    "per_ip_connect_burst": 1_000_000,
                    "global_connects_per_second": 1_000_000,
                    "global_connect_burst": 1_000_000,
                    "max_connections": 128,
                    "max_connections_per_ip": 128,
                    "max_tracked_ips": 1024,
                },
            }
        ],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "connection-duration-runtime-config.json"
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
        wait_tcp_port(tcp_proxy_port)
        http_probe = send_http_max_connection_duration_probe(proxy_port)
        tcp_probe = send_tcp_max_connection_duration_probe(tcp_proxy_port)
        return {
            "http": http_probe,
            "tcp": tcp_probe,
            "http_max_connection_duration_enforced": (
                http_probe["first_status"] == 204
                and http_probe["second_closed_or_reset"]
            ),
            "tcp_max_connection_duration_enforced": (
                tcp_probe["first_echo_bytes"] == len(b"duration-one")
                and tcp_probe["closed_or_reset"]
            ),
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def send_tcp_slow_drip(port: int) -> dict[str, Any]:
    started = time.perf_counter()
    first_echo = b""
    second_echo = b""
    third_echo = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
            sock.settimeout(1.0)
            sock.sendall(b"a")
            first_echo = recv_exact(sock, 1)
            time.sleep(0.08)
            try:
                sock.sendall(b"b")
                second_echo = sock.recv(1)
                time.sleep(0.08)
                sock.sendall(b"c")
                third_echo = sock.recv(1)
            except Exception as exc:
                error = type(exc).__name__
    except Exception as exc:
        error = type(exc).__name__
    return {
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "first_echo_bytes": len(first_echo),
        "second_echo_bytes": len(second_echo),
        "third_echo_bytes": len(third_echo),
        "closed_or_reset": third_echo == b"" or error in {"BrokenPipeError", "ConnectionResetError"},
        "error": error,
    }


def run_tcp_min_rate_probe(
    binary: Path, http_upstream_port: int, tcp_upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    tcp_proxy_port = free_port()
    tcp_default_proxy_port = free_port()
    filters_path = tmp_path / "tcp-min-rate-filters.json"
    events_path = tmp_path / "tcp-min-rate-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{http_upstream_port}",
            "preserve_host": True,
            "admin_token": "tcp-min-rate-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_connections": 128,
                "max_connections_per_ip": 128,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [
            {
                "name": "tcp-min-rate",
                "listen": f"127.0.0.1:{tcp_proxy_port}",
                "upstream": f"127.0.0.1:{tcp_upstream_port}",
                "connect_timeout_ms": 500,
                "idle_timeout_seconds": 2,
                "downstream_min_rate_bytes_per_second": 1_000,
                "upstream_min_rate_bytes_per_second": 0,
                "min_rate_grace_ms": 10,
                "max_connection_duration_seconds": 5,
                "limits": {
                    "per_ip_connects_per_second": 1_000_000,
                    "per_ip_connect_burst": 1_000_000,
                    "max_connections": 128,
                    "max_connections_per_ip": 128,
                    "max_tracked_ips": 1024,
                },
            },
            {
                "name": "tcp-default-min-rate",
                "listen": f"127.0.0.1:{tcp_default_proxy_port}",
                "upstream": f"127.0.0.1:{tcp_upstream_port}",
                "connect_timeout_ms": 500,
                "idle_timeout_seconds": 2,
                "min_rate_grace_ms": 10,
                "max_connection_duration_seconds": 5,
                "limits": {
                    "per_ip_connects_per_second": 1_000_000,
                    "per_ip_connect_burst": 1_000_000,
                    "max_connections": 128,
                    "max_connections_per_ip": 128,
                    "max_tracked_ips": 1024,
                },
            }
        ],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "tcp-min-rate-config.json"
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
        wait_tcp_port(tcp_proxy_port)
        wait_tcp_port(tcp_default_proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="tcp-min-rate-token")
        slow_drip = send_tcp_slow_drip(tcp_proxy_port)
        time.sleep(0.05)
        metrics_after_explicit = fetch_metrics(proxy_port, token="tcp-min-rate-token")
        default_slow_drip = send_tcp_slow_drip(tcp_default_proxy_port)
        time.sleep(0.05)
        metrics_after_default = fetch_metrics(proxy_port, token="tcp-min-rate-token")
        downstream_delta = metrics_after_explicit.get(
            "altura_tcp_downstream_too_slow", 0
        ) - metrics_before.get("altura_tcp_downstream_too_slow", 0)
        upstream_delta = metrics_after_explicit.get(
            "altura_tcp_upstream_too_slow", 0
        ) - metrics_before.get("altura_tcp_upstream_too_slow", 0)
        default_downstream_delta = metrics_after_default.get(
            "altura_tcp_downstream_too_slow", 0
        ) - metrics_after_explicit.get("altura_tcp_downstream_too_slow", 0)
        default_upstream_delta = metrics_after_default.get(
            "altura_tcp_upstream_too_slow", 0
        ) - metrics_after_explicit.get("altura_tcp_upstream_too_slow", 0)
        return {
            "configured_downstream_min_rate_bytes_per_second": 1_000,
            "configured_upstream_min_rate_bytes_per_second": 0,
            "configured_min_rate_grace_ms": 10,
            "slow_drip": slow_drip,
            "tcp_downstream_too_slow_delta": downstream_delta,
            "tcp_upstream_too_slow_delta": upstream_delta,
            "tcp_min_rate_rejected": slow_drip["closed_or_reset"] and downstream_delta >= 1,
            "default_configured_downstream_min_rate_bytes_per_second": 512,
            "default_configured_upstream_min_rate_bytes_per_second": 512,
            "default_configured_min_rate_grace_ms": 10,
            "default_slow_drip": default_slow_drip,
            "default_tcp_downstream_too_slow_delta": default_downstream_delta,
            "default_tcp_upstream_too_slow_delta": default_upstream_delta,
            "default_tcp_min_rate_rejected": default_slow_drip["closed_or_reset"]
            and default_downstream_delta >= 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.communicate(timeout=5)


def run_admin_rate_limit_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "admin-guard-filters.json"
    events_path = tmp_path / "admin-guard-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "admin-guard-token",
            "limits": {
                "per_ip_rps": 0.01,
                "per_ip_burst": 1,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "admin-guard-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        wait_tcp_port(proxy_port)
        responses = [
            get_status_and_headers(proxy_port, "GET", "/__altura/health"),
            get_status_and_headers(proxy_port, "GET", "/__altura/health"),
        ]
        statuses = [response["status"] for response in responses]
        retry_after_headers = response_headers_for_status(responses, "retry-after")
        cache_control_headers = response_headers_for_status(responses, "cache-control")
        return {
            "statuses": statuses,
            "retry_after_headers": retry_after_headers,
            "cache_control_headers": cache_control_headers,
            "retry_after_header_matches": retry_after_headers == ["1"],
            "cache_control_header_matches": cache_control_headers == ["no-store"],
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_admin_signature_rate_probe(
    binary: Path, upstream_port: int, tmp_path: Path
) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "admin-signature-rate-filters.json"
    events_path = tmp_path / "admin-signature-rate-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    signature_rps = 0.000001
    signature_burst = 2
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "admin-signature-rate-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "signature_rps": signature_rps,
                "signature_burst": signature_burst,
                "max_tracked_signatures": 64,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "admin-signature-rate-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        wait_tcp_port(proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="admin-signature-rate-token")
        responses = [
            get_status_and_headers(proxy_port, "GET", "/__altura/health") for _ in range(4)
        ]
        statuses = [response["status"] for response in responses]
        retry_after_headers = response_headers_for_status(responses, "retry-after")
        cache_control_headers = response_headers_for_status(responses, "cache-control")
        metrics_after = fetch_metrics(proxy_port, token="admin-signature-rate-token")
        signature_delta = metrics_after.get(
            "altura_http_signature_rate_limited", 0
        ) - metrics_before.get("altura_http_signature_rate_limited", 0)
        rate_limited_delta = metrics_after.get(
            "altura_http_rate_limited", 0
        ) - metrics_before.get("altura_http_rate_limited", 0)
        return {
            "configured_signature_rps": signature_rps,
            "configured_signature_burst": signature_burst,
            "statuses": statuses,
            "retry_after_headers": retry_after_headers,
            "cache_control_headers": cache_control_headers,
            "signature_rate_limited_delta": signature_delta,
            "http_rate_limited_delta": rate_limited_delta,
            "admin_health_signature_limited": statuses[:2] == [200, 200]
            and statuses[2:] == [429, 429],
            "retry_after_header_matches": retry_after_headers == ["1", "1"],
            "cache_control_header_matches": cache_control_headers == ["no-store", "no-store"],
            "signature_metric_matches": signature_delta == 2,
            "rate_limited_metric_includes_signature_limit": rate_limited_delta == 2,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_upstream_in_flight_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "in-flight-filters.json"
    events_path = tmp_path / "in-flight-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "in-flight-token",
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 1,
                "max_in_flight_requests_per_ip": 10,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "in-flight-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    first_status: list[int | None] = [None]
    try:
        wait_http("127.0.0.1", proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="in-flight-token")

        def first_request() -> None:
            first_status[0] = get_status(proxy_port, "GET", "/slow", timeout=2.0)

        first_thread = threading.Thread(target=first_request, daemon=True)
        first_thread.start()
        time.sleep(0.05)
        second_response = get_status_and_headers(proxy_port, "GET", "/slow", timeout=2.0)
        second_status = second_response["status"]
        first_thread.join(timeout=3.0)
        metrics_after = fetch_metrics(proxy_port, token="in-flight-token")
        overload_responses = [second_response]
        retry_after_headers = response_headers_for_status(overload_responses, "retry-after", 503)
        cache_control_headers = response_headers_for_status(
            overload_responses, "cache-control", 503
        )
        return {
            "first_status": first_status[0],
            "second_status": second_status,
            "retry_after_headers": retry_after_headers,
            "cache_control_headers": cache_control_headers,
            "retry_after_header_matches": retry_after_headers == ["1"],
            "cache_control_header_matches": cache_control_headers == ["no-store"],
            "metrics_delta": {
                "altura_http_upstream_in_flight_rejected": metrics_after.get(
                    "altura_http_upstream_in_flight_rejected", 0
                )
                - metrics_before.get("altura_http_upstream_in_flight_rejected", 0)
            },
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_upstream_response_guard_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "response-guard-filters.json"
    events_path = tmp_path / "response-guard-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "response-guard-token",
            "upstream_body_idle_timeout_ms": 100,
            "max_upstream_body_bytes": 8,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "response-guard-config.json"
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
        metrics_before = fetch_metrics(proxy_port, token="response-guard-token")
        stalled = read_raw_response(proxy_port, "/stalled-response")
        oversized = read_raw_response(proxy_port, "/large-response")
        hop_by_hop = read_raw_response(proxy_port, "/hop-by-hop-response")
        time.sleep(0.1)
        metrics_after = fetch_metrics(proxy_port, token="response-guard-token")
        return {
            "stalled_response": stalled,
            "oversized_response": oversized,
            "hop_by_hop_response": hop_by_hop,
            "hop_by_hop_headers_stripped": response_hop_by_hop_headers_absent(
                hop_by_hop.get("headers", {})
            ),
            "metrics_delta": {
                "altura_http_upstream_body_timeouts": metrics_after.get(
                    "altura_http_upstream_body_timeouts", 0
                )
                - metrics_before.get("altura_http_upstream_body_timeouts", 0),
                "altura_http_upstream_body_rejected": metrics_after.get(
                    "altura_http_upstream_body_rejected", 0
                )
                - metrics_before.get("altura_http_upstream_body_rejected", 0),
            },
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def read_raw_response(port: int, path: str) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(
                f"GET {path} HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "User-Agent: altura-response-guard-probe/1.0\r\n"
                "Connection: close\r\n\r\n"
                .encode("ascii")
            )
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
    except Exception as exc:
        error = type(exc).__name__
    header, _, body = raw.partition(b"\r\n\r\n")
    status = None
    headers: dict[str, str] = {}
    if header.startswith(b"HTTP/"):
        try:
            status = int(header.split(b" ", 2)[1])
        except Exception:
            status = None
        for line in header.split(b"\r\n")[1:]:
            name, sep, value = line.partition(b":")
            if sep:
                headers[name.decode("iso-8859-1", errors="replace").lower()] = value.strip().decode(
                    "iso-8859-1", errors="replace"
                )
    return {
        "status": status,
        "headers": headers,
        "body_bytes": len(body),
        "closed": True,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def generated_response_header_matches(
    header: str, expected: str, *responses: dict[str, Any]
) -> bool:
    return all(response.get("headers", {}).get(header) == expected for response in responses)


def response_hop_by_hop_headers_absent(headers: dict[str, str]) -> bool:
    connection = headers.get("connection")
    return all(
        headers.get(name) is None
        for name in [
            "proxy-connection",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
            "x-origin-hop",
        ]
    ) and (connection is None or connection.lower() == "close")


def run_header_count_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "header-count-filters.json"
    events_path = tmp_path / "header-count-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "header-count-token",
            "max_headers": 8,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "header-count-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        wait_tcp_port(proxy_port)
        metrics_before = fetch_metrics(proxy_port, token="header-count-token")
        response = send_many_headers(proxy_port, header_count=24)
        metrics_after = fetch_metrics(proxy_port, token="header-count-token")
        initial_headers_too_many_delta = metrics_after.get(
            "altura_http_initial_headers_too_many", 0
        ) - metrics_before.get("altura_http_initial_headers_too_many", 0)
        return {
            **response,
            "http_initial_headers_too_many_delta": initial_headers_too_many_delta,
            "raw_initial_431_not_stored": response.get("cache_control") == "no-store",
            "raw_initial_431_closes_connection": response.get("connection") == "close",
            "header_count_guard_observed": response.get("status") == 431
            and response.get("cache_control") == "no-store"
            and response.get("connection") == "close"
            and initial_headers_too_many_delta >= 1,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def send_many_headers(port: int, header_count: int) -> dict[str, Any]:
    started = time.perf_counter()
    raw = b""
    error = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            lines = [
                "GET / HTTP/1.1",
                "Host: 127.0.0.1",
                "User-Agent: altura-header-count-probe/1.0",
                "Connection: close",
            ]
            for idx in range(header_count):
                lines.append(f"X-Altura-Probe-{idx}: {idx}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
    except Exception as exc:
        error = type(exc).__name__
    status = None
    if raw.startswith(b"HTTP/"):
        try:
            status = int(raw.split(b" ", 2)[1])
        except Exception:
            status = None
    headers = headers_from_raw_response(raw)
    return {
        "sent_headers": header_count + 3,
        "status": status,
        "cache_control": headers.get("cache-control"),
        "connection": headers.get("connection"),
        "closed": True,
        "body_bytes": len(raw.partition(b"\r\n\r\n")[2]),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "error": error,
    }


def run_upstream_pool_probe(binary: Path, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    upstream_port = free_port()
    filters_path = tmp_path / "upstream-pool-filters.json"
    events_path = tmp_path / "upstream-pool-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "upstream-pool-token",
            "upstream_pool_idle_timeout_ms": 30_000,
            "upstream_pool_max_idle_per_host": 0,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "upstream-pool-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    with CountingHttpServer(("127.0.0.1", upstream_port), FastHttpHandler) as upstream:
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        proxy = subprocess.Popen(
            [str(binary), "--config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "RUST_BACKTRACE": "0"},
        )
        try:
            wait_http("127.0.0.1", proxy_port)
            statuses = [
                get_status(proxy_port, "GET", "/", timeout=2.0),
                get_status(proxy_port, "GET", "/", timeout=2.0),
            ]
            time.sleep(0.05)
            return {
                "statuses": statuses,
                "accepted_upstream_connections": upstream.connection_count,
            }
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
            upstream.shutdown()


def run_listen_backlog_probe(
    binary: Path,
    upstream_port: int,
    tcp_upstream_port: int,
    tmp_path: Path,
) -> dict[str, Any]:
    proxy_port = free_port()
    tcp_proxy_port = free_port()
    filters_path = tmp_path / "listen-backlog-filters.json"
    events_path = tmp_path / "listen-backlog-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "listen-backlog-token",
            "listen_backlog": 128,
            "accept_shards": 2,
            "limits": {
                "per_ip_rps": 1_000_000,
                "per_ip_burst": 1_000_000,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 1024,
            },
        },
        "tcp": [
            {
                "name": "listen-backlog-tcp",
                "listen": f"127.0.0.1:{tcp_proxy_port}",
                "upstream": f"127.0.0.1:{tcp_upstream_port}",
                "listen_backlog": 128,
                "accept_shards": 2,
                "connect_timeout_ms": 500,
                "idle_timeout_seconds": 5,
                "max_connection_duration_seconds": 5,
                "limits": {
                    "per_ip_connects_per_second": 1_000_000,
                    "per_ip_connect_burst": 1_000_000,
                    "max_connections": 128,
                    "max_connections_per_ip": 128,
                    "max_tracked_ips": 1024,
                },
            }
        ],
        "filters": {
            "runtime_file": str(filters_path),
            "reload_seconds": 1,
            "static_rules": [],
        },
        "adaptive": {
            "enabled": True,
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "listen-backlog-config.json"
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
        wait_tcp_port(tcp_proxy_port)
        http_status = get_status(proxy_port, "GET", "/", timeout=2.0)
        tcp_echo_ok = False
        with socket.create_connection(("127.0.0.1", tcp_proxy_port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            sock.sendall(b"listen-backlog")
            tcp_echo_ok = recv_exact(sock, len(b"listen-backlog")) == b"listen-backlog"
        return {
            "configured_backlog": 128,
            "configured_accept_shards": 2,
            "http_status": http_status,
            "tcp_echo_ok": tcp_echo_ok,
            "accept_shards_started": http_status == 204 and tcp_echo_ok,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_rate_limiter_fairness_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "rate-fairness-filters.json"
    events_path = tmp_path / "rate-fairness-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "rate-fairness-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
            },
            "limits": {
                "per_ip_rps": 0.000001,
                "per_ip_burst": 1,
                "global_rps": 0.000001,
                "global_burst": 2,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "rate-fairness-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        wait_tcp_port(proxy_port)
        statuses = [
            get_status(
                proxy_port,
                "GET",
                "/",
                headers={"X-Forwarded-For": "198.51.100.10"},
            ),
            get_status(
                proxy_port,
                "GET",
                "/",
                headers={"X-Forwarded-For": "198.51.100.10"},
            ),
            get_status(
                proxy_port,
                "GET",
                "/",
                headers={"X-Forwarded-For": "198.51.100.11"},
            ),
        ]
        return {"statuses": statuses}
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def run_tracked_ip_cap_probe(binary: Path, upstream_port: int, tmp_path: Path) -> dict[str, Any]:
    proxy_port = free_port()
    filters_path = tmp_path / "tracked-ip-cap-filters.json"
    events_path = tmp_path / "tracked-ip-cap-events.jsonl"
    filters_path.write_text('{"filters": []}\n', encoding="utf-8")
    cfg = {
        "http": {
            "listen": f"127.0.0.1:{proxy_port}",
            "upstream": f"http://127.0.0.1:{upstream_port}",
            "preserve_host": True,
            "admin_token": "tracked-ip-cap-token",
            "client_ip": {
                "header": "x-forwarded-for",
                "trusted_proxies": ["127.0.0.1/32"],
            },
            "limits": {
                "per_ip_rps": 0.000001,
                "per_ip_burst": 1,
                "global_rps": 1_000_000,
                "global_burst": 1_000_000,
                "max_in_flight_requests": 128,
                "max_in_flight_requests_per_ip": 128,
                "max_tracked_ips": 64,
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
            "signature_threshold_per_second": 1_000_000,
            "activation_ttl_seconds": 10,
            "event_log": str(events_path),
            "event_cooldown_seconds": 1,
        },
    }
    config_path = tmp_path / "tracked-ip-cap-config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    proxy = subprocess.Popen(
        [str(binary), "--config", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "RUST_BACKTRACE": "0"},
    )
    try:
        wait_tcp_port(proxy_port)
        first_ip = "198.51.100.10"
        first_status = get_status(proxy_port, "GET", "/", headers={"X-Forwarded-For": first_ip})
        first_limited = get_status(proxy_port, "GET", "/", headers={"X-Forwarded-For": first_ip})
        admitted_new_clients = 0
        denied_new_client = None
        denied_new_status = None
        for host_octet in range(1, 130):
            candidate = f"198.51.100.{host_octet}"
            if candidate == first_ip:
                continue
            status = get_status(
                proxy_port,
                "GET",
                "/",
                headers={"X-Forwarded-For": candidate},
            )
            if status == 429:
                denied_new_client = candidate
                denied_new_status = status
                break
            admitted_new_clients += 1
        first_after_cap = get_status(
            proxy_port, "GET", "/", headers={"X-Forwarded-For": first_ip}
        )
        statuses = [first_status, first_limited, denied_new_status, first_after_cap]
        return {
            "statuses": statuses,
            "first_client_initial_allowed": first_status == 204,
            "first_client_rate_limited": first_limited == 429,
            "new_client_denied_when_active_shard_full": denied_new_status == 429,
            "first_client_bucket_not_evicted": first_after_cap == 429,
            "admitted_new_clients_before_cap": admitted_new_clients,
            "denied_new_client": denied_new_client,
        }
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()


def edge_nft_template(
    elements: str,
    include_udp_drop: bool = True,
    ipv6_prefix_syn: bool = True,
    ipv6_prefix_connlimit: bool = True,
    ipv6_syn_l4proto: bool = True,
    ipv6_connlimit_l4proto: bool = True,
    ipv6_icmp_l4proto: bool = True,
    generic_tcp_l4proto: bool = True,
    include_icmpv4_control_exemption: bool = True,
    icmpv4_control_after_drop: bool = False,
    include_icmpv6_control_exemption: bool = True,
    icmpv6_control_after_drop: bool = False,
    connlimit_set_size: bool = True,
    connlimit_count: int = 128,
    syn_rate_set_size: bool = True,
    syn_rate_set_timeout: bool = True,
) -> str:
    udp_drop = (
        "    meta l4proto udp udp dport @protected_tcp_ports drop\n"
        if include_udp_drop
        else ""
    )
    connlimit_size = "    size 65535\n" if connlimit_set_size else ""
    syn_rate_size = "    size 65535\n" if syn_rate_set_size else ""
    syn_rate_timeout_flag = "dynamic,timeout" if syn_rate_set_timeout else "dynamic"
    syn_rate_timeout = "    timeout 10s\n" if syn_rate_set_timeout else ""
    syn_key = (
        "ip6 saddr and ffff:ffff:ffff:ffff:: . tcp dport"
        if ipv6_prefix_syn
        else "ip6 saddr . tcp dport"
    )
    connlimit_key = (
        "ip6 saddr and ffff:ffff:ffff:ffff:: . tcp dport"
        if ipv6_prefix_connlimit
        else "ip6 saddr . tcp dport"
    )
    syn_protocol = (
        "meta nfproto ipv6 meta l4proto tcp" if ipv6_syn_l4proto else "ip6 nexthdr tcp"
    )
    connlimit_protocol = (
        "meta nfproto ipv6 meta l4proto tcp"
        if ipv6_connlimit_l4proto
        else "ip6 nexthdr tcp"
    )
    generic_tcp_protocol = "meta l4proto tcp" if generic_tcp_l4proto else ""
    generic_tcp_prefix = (
        f"{generic_tcp_protocol} " if generic_tcp_protocol else ""
    )
    icmp_protocol = (
        "meta nfproto ipv6 meta l4proto ipv6-icmp"
        if ipv6_icmp_l4proto
        else "ip6 nexthdr ipv6-icmp"
    )
    icmpv4_control_rule = (
        "    ip protocol icmp icmp type { destination-unreachable, "
        "time-exceeded, parameter-problem } accept\n"
        if include_icmpv4_control_exemption
        else ""
    )
    icmpv4_drop_rule = "    ip protocol icmp limit rate over 100/second burst 200 packets drop\n"
    icmpv4_rules = (
        icmpv4_drop_rule + icmpv4_control_rule
        if icmpv4_control_after_drop
        else icmpv4_control_rule + icmpv4_drop_rule
    )
    icmpv6_control_rule = (
        "    meta nfproto ipv6 meta l4proto ipv6-icmp icmpv6 type { "
        "destination-unreachable, packet-too-big, time-exceeded, parameter-problem, "
        "nd-router-solicit, nd-router-advert, nd-neighbor-solicit, "
        "nd-neighbor-advert } accept\n"
        if include_icmpv6_control_exemption
        else ""
    )
    icmpv6_drop_rule = f"    {icmp_protocol} limit rate over 100/second burst 200 packets drop\n"
    icmpv6_rules = (
        icmpv6_drop_rule + icmpv6_control_rule
        if icmpv6_control_after_drop
        else icmpv6_control_rule + icmpv6_drop_rule
    )
    icmp_rules = icmpv4_rules + icmpv6_rules
    return f"""#!/usr/sbin/nft -f
table inet altura_prot_edge {{
  set protected_tcp_ports {{
    type inet_service
    elements = {elements}
  }}

  set tcp4_connlimit {{
    type ipv4_addr . inet_service
{connlimit_size}    flags dynamic
  }}

  set tcp6_connlimit {{
    type ipv6_addr . inet_service
{connlimit_size}    flags dynamic
  }}

  set tcp4_syn_rate {{
    type ipv4_addr . inet_service
{syn_rate_size}    flags {syn_rate_timeout_flag}
{syn_rate_timeout}  }}

  set tcp6_syn_rate {{
    type ipv6_addr . inet_service
{syn_rate_size}    flags {syn_rate_timeout_flag}
{syn_rate_timeout}  }}

  chain preraw {{
    type filter hook prerouting priority raw; policy accept;
    {generic_tcp_prefix}tcp dport @protected_tcp_ports tcp flags & (fin|syn|rst|ack) == 0 drop
    {generic_tcp_prefix}tcp dport @protected_tcp_ports tcp flags & (fin|syn|rst|psh|ack|urg) == fin|psh|urg drop
{udp_drop}    ip protocol tcp tcp dport @protected_tcp_ports tcp flags & (fin|syn|rst|ack) == syn update @tcp4_syn_rate {{ ip saddr . tcp dport limit rate over 200/second burst 400 packets }} drop
    {syn_protocol} tcp dport @protected_tcp_ports tcp flags & (fin|syn|rst|ack) == syn update @tcp6_syn_rate {{ {syn_key} limit rate over 200/second burst 400 packets }} drop
    {generic_tcp_prefix}tcp dport @protected_tcp_ports tcp flags & (fin|syn|rst|ack) == syn limit rate over 5000/second burst 10000 packets drop
  }}

  chain input {{
    type filter hook input priority filter; policy accept;
    {generic_tcp_prefix}tcp dport @protected_tcp_ports ct state new tcp flags & (fin|syn|rst|ack) != syn drop
    ip protocol tcp tcp dport @protected_tcp_ports ct state new add @tcp4_connlimit {{ ip saddr . tcp dport ct count over {connlimit_count} }} drop
    {connlimit_protocol} tcp dport @protected_tcp_ports ct state new add @tcp6_connlimit {{ {connlimit_key} ct count over {connlimit_count} }} drop
    {generic_tcp_prefix}tcp dport @protected_tcp_ports ct state new limit rate over 5000/second burst 10000 packets drop
{icmp_rules.rstrip()}
  }}
}}
"""


def edge_sysctl_template(overrides: dict[str, str] | None = None) -> str:
    assignments = {
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.tcp_max_syn_backlog": "16384",
        "net.ipv4.tcp_synack_retries": "3",
        "net.core.somaxconn": "65535",
        "net.core.netdev_max_backlog": "250000",
        "net.ipv4.tcp_fin_timeout": "15",
        "net.netfilter.nf_conntrack_max": "1048576",
        "net.netfilter.nf_conntrack_tcp_timeout_syn_recv": "30",
        "net.ipv4.ipfrag_high_thresh": "4194304",
        "net.ipv4.ipfrag_time": "15",
        "net.ipv4.ipfrag_max_dist": "64",
        "net.ipv6.ip6frag_high_thresh": "4194304",
        "net.ipv6.ip6frag_low_thresh": "3145728",
        "net.ipv6.ip6frag_time": "15",
    }
    if overrides:
        assignments.update(overrides)
    return "".join(f"{key} = {value}\n" for key, value in assignments.items())


def edge_systemd_unit_template(overrides: dict[str, str] | None = None) -> str:
    service_values = {
        "Type": "simple",
        "User": "altura-prot",
        "Group": "altura-prot",
        "WorkingDirectory": "/var/lib/altura-prot",
        "ExecStart": "/usr/local/bin/altura-prot --config /etc/altura-prot/config.json",
        "Restart": "on-failure",
        "RestartSec": "2s",
        "TimeoutStopSec": "15s",
        "LimitNOFILE": "1048576",
        "TasksMax": "32768",
        "MemoryAccounting": "true",
        "MemoryHigh": "2G",
        "MemoryMax": "3G",
        "ConfigurationDirectory": "altura-prot",
        "StateDirectory": "altura-prot",
        "LogsDirectory": "altura-prot",
        "ReadWritePaths": "/var/lib/altura-prot /var/log/altura-prot",
        "AmbientCapabilities": "CAP_NET_BIND_SERVICE",
        "CapabilityBoundingSet": "CAP_NET_BIND_SERVICE",
        "NoNewPrivileges": "true",
        "PrivateTmp": "true",
        "PrivateDevices": "true",
        "ProtectSystem": "strict",
        "ProtectHome": "true",
        "ProtectKernelTunables": "true",
        "ProtectKernelModules": "true",
        "ProtectControlGroups": "true",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "RestrictNamespaces": "true",
        "RestrictRealtime": "true",
        "RestrictSUIDSGID": "true",
        "LockPersonality": "true",
        "MemoryDenyWriteExecute": "true",
        "SystemCallArchitectures": "native",
    }
    if overrides:
        service_values.update(overrides)
    service_lines = "\n".join(f"{key}={value}" for key, value in service_values.items())
    return f"""[Unit]
Description=AlturaProt L7 DDoS protection proxy
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
{service_lines}

[Install]
WantedBy=multi-user.target
"""


def run_edge_template_port_coverage_probe(tmp_path: Path) -> dict[str, Any]:
    config_path = tmp_path / "edge-port-coverage-config.json"
    nft_path = tmp_path / "edge-port-coverage.nft"
    sysctl_path = tmp_path / "edge-port-coverage-sysctl.conf"
    systemd_path = tmp_path / "altura-prot.service"
    sysctl_path.write_text(edge_sysctl_template(), encoding="utf-8")
    systemd_path.write_text(edge_systemd_unit_template(), encoding="utf-8")

    public_config = {
        "http": {"listen": "0.0.0.0:8080", "listen_backlog": 4096},
        "tcp": [{"listen": "[::]:7000", "listen_backlog": 4096}],
    }
    config_path.write_text(json.dumps(public_config), encoding="utf-8")

    def run_validator() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "tools/validate_edge_templates.py",
                "--config",
                str(config_path),
                "--nft",
                str(nft_path),
                "--sysctl",
                str(sysctl_path),
                "--systemd",
                str(systemd_path),
                "--skip-nft-syntax-check",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    nft_path.write_text(edge_nft_template("{ 80, 443, 8080 }"), encoding="utf-8")
    missing = run_validator()

    nft_path.write_text(edge_nft_template("{ 80, 443, 7000, 8080 }"), encoding="utf-8")
    covered = run_validator()

    high_capacity_config = {
        "runtime": {"min_nofile": 65536},
        "http": {
            "listen": "0.0.0.0:8080",
            "listen_backlog": 4096,
            "upstream_pool_max_idle_per_host": 1000,
            "limits": {
                "max_connections": 40000,
                "max_in_flight_requests": 40000,
            },
        },
        "tcp": [
            {
                "listen": "[::]:7000",
                "listen_backlog": 4096,
                "limits": {"max_connections": 20000},
            }
        ],
    }
    config_path.write_text(json.dumps(high_capacity_config), encoding="utf-8")
    systemd_path.write_text(
        edge_systemd_unit_template({"LimitNOFILE": "65536"}),
        encoding="utf-8",
    )
    insufficient_systemd_capacity = run_validator()
    systemd_path.write_text(
        edge_systemd_unit_template({"LimitNOFILE": "200000"}),
        encoding="utf-8",
    )
    aligned_systemd_capacity = run_validator()
    systemd_path.write_text(edge_systemd_unit_template(), encoding="utf-8")
    config_path.write_text(json.dumps(public_config), encoding="utf-8")

    low_cap_public_config = {
        "http": {"listen": "0.0.0.0:8080", "listen_backlog": 4096},
        "tcp": [
            {
                "listen": "[::]:7000",
                "listen_backlog": 4096,
                "limits": {"max_connections_per_ip": 64},
            }
        ],
    }
    config_path.write_text(json.dumps(low_cap_public_config), encoding="utf-8")
    nft_path.write_text(edge_nft_template("{ 80, 443, 7000, 8080 }"), encoding="utf-8")
    excessive_connlimit_threshold = run_validator()
    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", connlimit_count=64),
        encoding="utf-8",
    )
    aligned_low_cap_connlimit_threshold = run_validator()
    config_path.write_text(json.dumps(public_config), encoding="utf-8")

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", include_udp_drop=False),
        encoding="utf-8",
    )
    missing_udp_drop = run_validator()

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", generic_tcp_l4proto=False),
        encoding="utf-8",
    )
    missing_generic_tcp_l4proto = run_validator()

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", ipv6_prefix_syn=False),
        encoding="utf-8",
    )
    missing_ipv6_prefix_syn = run_validator()

    nft_path.write_text(
        edge_nft_template(
            "{ 80, 443, 7000, 8080 }",
            ipv6_prefix_connlimit=False,
        ),
        encoding="utf-8",
    )
    missing_ipv6_prefix_connlimit = run_validator()

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", ipv6_syn_l4proto=False),
        encoding="utf-8",
    )
    missing_ipv6_syn_l4proto = run_validator()

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", ipv6_connlimit_l4proto=False),
        encoding="utf-8",
    )
    missing_ipv6_connlimit_l4proto = run_validator()

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", ipv6_icmp_l4proto=False),
        encoding="utf-8",
    )
    missing_ipv6_icmp_l4proto = run_validator()

    nft_path.write_text(
        edge_nft_template(
            "{ 80, 443, 7000, 8080 }",
            include_icmpv4_control_exemption=False,
        ),
        encoding="utf-8",
    )
    missing_icmpv4_control_exemption = run_validator()

    nft_path.write_text(
        edge_nft_template(
            "{ 80, 443, 7000, 8080 }",
            icmpv4_control_after_drop=True,
        ),
        encoding="utf-8",
    )
    late_icmpv4_control_exemption = run_validator()

    nft_path.write_text(
        edge_nft_template(
            "{ 80, 443, 7000, 8080 }",
            include_icmpv6_control_exemption=False,
        ),
        encoding="utf-8",
    )
    missing_icmpv6_control_exemption = run_validator()

    nft_path.write_text(
        edge_nft_template(
            "{ 80, 443, 7000, 8080 }",
            icmpv6_control_after_drop=True,
        ),
        encoding="utf-8",
    )
    late_icmpv6_control_exemption = run_validator()

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", connlimit_set_size=False),
        encoding="utf-8",
    )
    missing_connlimit_set_size = run_validator()

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", syn_rate_set_size=False),
        encoding="utf-8",
    )
    missing_syn_rate_set_size = run_validator()

    nft_path.write_text(
        edge_nft_template("{ 80, 443, 7000, 8080 }", syn_rate_set_timeout=False),
        encoding="utf-8",
    )
    missing_syn_rate_set_timeout = run_validator()

    nft_path.write_text(edge_nft_template("{ 80, 443, 7000, 8080 }"), encoding="utf-8")

    sysctl_path.write_text("net.core.somaxconn = 65535\n", encoding="utf-8")
    missing_fragment_sysctls = run_validator()

    sysctl_path.write_text(
        edge_sysctl_template({"net.ipv4.ipfrag_time": "60"}),
        encoding="utf-8",
    )
    excessive_fragment_time = run_validator()

    sysctl_path.write_text(
        edge_sysctl_template(
            {
                "net.ipv6.ip6frag_low_thresh": "8388608",
                "net.ipv6.ip6frag_high_thresh": "4194304",
            }
        ),
        encoding="utf-8",
    )
    invalid_fragment_thresholds = run_validator()

    sysctl_path.write_text(edge_sysctl_template(), encoding="utf-8")

    systemd_path.write_text(
        edge_systemd_unit_template({"LimitNOFILE": "1024"}),
        encoding="utf-8",
    )
    insufficient_systemd_nofile = run_validator()

    systemd_path.write_text(
        edge_systemd_unit_template({"ProtectSystem": "false"}),
        encoding="utf-8",
    )
    weak_systemd_sandbox = run_validator()

    systemd_path.write_text(
        edge_systemd_unit_template(
            {"AmbientCapabilities": "CAP_NET_BIND_SERVICE CAP_NET_RAW"}
        ),
        encoding="utf-8",
    )
    excessive_systemd_capabilities = run_validator()

    systemd_path.write_text(edge_systemd_unit_template(), encoding="utf-8")

    config_path.write_text(
        json.dumps(
            {
                "http": {"listen": "127.0.0.1:8080", "listen_backlog": 4096},
                "tcp": [{"listen": "[::1]:7000", "listen_backlog": 4096}],
            }
        ),
        encoding="utf-8",
    )
    nft_path.write_text(edge_nft_template("{ 80, 443, 8080 }"), encoding="utf-8")
    loopback = run_validator()

    missing_public_port_rejected = missing.returncode != 0 and "7000" in missing.stderr
    missing_udp_drop_rejected = (
        missing_udp_drop.returncode != 0
        and "protected TCP service ports" in missing_udp_drop.stderr
    )
    missing_generic_tcp_l4proto_rejected = (
        missing_generic_tcp_l4proto.returncode != 0
        and "generic TCP extension-safe" in missing_generic_tcp_l4proto.stderr
    )
    missing_ipv6_prefix_syn_rejected = (
        missing_ipv6_prefix_syn.returncode != 0
        and "IPv6 /64 SYN backstop" in missing_ipv6_prefix_syn.stderr
    )
    missing_ipv6_prefix_connlimit_rejected = (
        missing_ipv6_prefix_connlimit.returncode != 0
        and "IPv6 /64 connection-count backstop"
        in missing_ipv6_prefix_connlimit.stderr
    )
    missing_ipv6_syn_l4proto_rejected = (
        missing_ipv6_syn_l4proto.returncode != 0
        and "extension-safe SYN protocol match" in missing_ipv6_syn_l4proto.stderr
    )
    missing_ipv6_connlimit_l4proto_rejected = (
        missing_ipv6_connlimit_l4proto.returncode != 0
        and "extension-safe connection-count protocol match"
        in missing_ipv6_connlimit_l4proto.stderr
    )
    missing_ipv6_icmp_l4proto_rejected = (
        missing_ipv6_icmp_l4proto.returncode != 0
        and "extension-safe ICMPv6 flood protocol match" in missing_ipv6_icmp_l4proto.stderr
    )
    missing_icmpv4_control_exemption_rejected = (
        missing_icmpv4_control_exemption.returncode != 0
        and "ICMPv4 control exemption" in missing_icmpv4_control_exemption.stderr
    )
    late_icmpv4_control_exemption_rejected = (
        late_icmpv4_control_exemption.returncode != 0
        and "must appear before" in late_icmpv4_control_exemption.stderr
    )
    missing_icmpv6_control_exemption_rejected = (
        missing_icmpv6_control_exemption.returncode != 0
        and "ICMPv6 control exemption" in missing_icmpv6_control_exemption.stderr
    )
    late_icmpv6_control_exemption_rejected = (
        late_icmpv6_control_exemption.returncode != 0
        and "must appear before" in late_icmpv6_control_exemption.stderr
    )
    missing_connlimit_set_size_rejected = (
        missing_connlimit_set_size.returncode != 0
        and "connlimit set" in missing_connlimit_set_size.stderr
    )
    missing_syn_rate_set_size_rejected = (
        missing_syn_rate_set_size.returncode != 0
        and "SYN rate set" in missing_syn_rate_set_size.stderr
    )
    missing_syn_rate_set_timeout_rejected = (
        missing_syn_rate_set_timeout.returncode != 0
        and "SYN rate set" in missing_syn_rate_set_timeout.stderr
    )
    missing_fragment_sysctls_rejected = (
        missing_fragment_sysctls.returncode != 0
        and "missing fragment reassembly sysctl bounds" in missing_fragment_sysctls.stderr
    )
    excessive_fragment_time_rejected = (
        excessive_fragment_time.returncode != 0
        and "fragment queue retention cap" in excessive_fragment_time.stderr
    )
    invalid_fragment_thresholds_rejected = (
        invalid_fragment_thresholds.returncode != 0
        and "ip6frag_low_thresh must be less than or equal"
        in invalid_fragment_thresholds.stderr
    )
    insufficient_systemd_nofile_rejected = (
        insufficient_systemd_nofile.returncode != 0
        and "LimitNOFILE=1024" in insufficient_systemd_nofile.stderr
    )
    weak_systemd_sandbox_rejected = (
        weak_systemd_sandbox.returncode != 0
        and "ProtectSystem=false" in weak_systemd_sandbox.stderr
    )
    excessive_systemd_capabilities_rejected = (
        excessive_systemd_capabilities.returncode != 0
        and "AmbientCapabilities" in excessive_systemd_capabilities.stderr
    )
    insufficient_systemd_capacity_rejected = (
        insufficient_systemd_capacity.returncode != 0
        and "required descriptor budget" in insufficient_systemd_capacity.stderr
    )
    excessive_connlimit_threshold_rejected = (
        excessive_connlimit_threshold.returncode != 0
        and "connection cap 64" in excessive_connlimit_threshold.stderr
    )

    return {
        "missing_public_port_status": missing.returncode,
        "missing_public_port_stderr": missing.stderr.strip(),
        "covered_public_ports_status": covered.returncode,
        "insufficient_systemd_capacity_status": insufficient_systemd_capacity.returncode,
        "insufficient_systemd_capacity_stderr": (
            insufficient_systemd_capacity.stderr.strip()
        ),
        "aligned_systemd_capacity_status": aligned_systemd_capacity.returncode,
        "aligned_systemd_capacity_stderr": aligned_systemd_capacity.stderr.strip(),
        "excessive_connlimit_threshold_status": excessive_connlimit_threshold.returncode,
        "excessive_connlimit_threshold_stderr": (
            excessive_connlimit_threshold.stderr.strip()
        ),
        "aligned_low_cap_connlimit_threshold_status": (
            aligned_low_cap_connlimit_threshold.returncode
        ),
        "aligned_low_cap_connlimit_threshold_stderr": (
            aligned_low_cap_connlimit_threshold.stderr.strip()
        ),
        "missing_udp_drop_status": missing_udp_drop.returncode,
        "missing_udp_drop_stderr": missing_udp_drop.stderr.strip(),
        "missing_generic_tcp_l4proto_status": missing_generic_tcp_l4proto.returncode,
        "missing_generic_tcp_l4proto_stderr": (
            missing_generic_tcp_l4proto.stderr.strip()
        ),
        "missing_ipv6_prefix_syn_status": missing_ipv6_prefix_syn.returncode,
        "missing_ipv6_prefix_syn_stderr": missing_ipv6_prefix_syn.stderr.strip(),
        "missing_ipv6_prefix_connlimit_status": missing_ipv6_prefix_connlimit.returncode,
        "missing_ipv6_prefix_connlimit_stderr": missing_ipv6_prefix_connlimit.stderr.strip(),
        "missing_ipv6_syn_l4proto_status": missing_ipv6_syn_l4proto.returncode,
        "missing_ipv6_syn_l4proto_stderr": missing_ipv6_syn_l4proto.stderr.strip(),
        "missing_ipv6_connlimit_l4proto_status": missing_ipv6_connlimit_l4proto.returncode,
        "missing_ipv6_connlimit_l4proto_stderr": (
            missing_ipv6_connlimit_l4proto.stderr.strip()
        ),
        "missing_ipv6_icmp_l4proto_status": missing_ipv6_icmp_l4proto.returncode,
        "missing_ipv6_icmp_l4proto_stderr": missing_ipv6_icmp_l4proto.stderr.strip(),
        "missing_icmpv4_control_exemption_status": (
            missing_icmpv4_control_exemption.returncode
        ),
        "missing_icmpv4_control_exemption_stderr": (
            missing_icmpv4_control_exemption.stderr.strip()
        ),
        "late_icmpv4_control_exemption_status": late_icmpv4_control_exemption.returncode,
        "late_icmpv4_control_exemption_stderr": (
            late_icmpv4_control_exemption.stderr.strip()
        ),
        "missing_icmpv6_control_exemption_status": (
            missing_icmpv6_control_exemption.returncode
        ),
        "missing_icmpv6_control_exemption_stderr": (
            missing_icmpv6_control_exemption.stderr.strip()
        ),
        "late_icmpv6_control_exemption_status": late_icmpv6_control_exemption.returncode,
        "late_icmpv6_control_exemption_stderr": (
            late_icmpv6_control_exemption.stderr.strip()
        ),
        "missing_connlimit_set_size_status": missing_connlimit_set_size.returncode,
        "missing_connlimit_set_size_stderr": missing_connlimit_set_size.stderr.strip(),
        "missing_syn_rate_set_size_status": missing_syn_rate_set_size.returncode,
        "missing_syn_rate_set_size_stderr": missing_syn_rate_set_size.stderr.strip(),
        "missing_syn_rate_set_timeout_status": missing_syn_rate_set_timeout.returncode,
        "missing_syn_rate_set_timeout_stderr": (
            missing_syn_rate_set_timeout.stderr.strip()
        ),
        "missing_fragment_sysctls_status": missing_fragment_sysctls.returncode,
        "missing_fragment_sysctls_stderr": missing_fragment_sysctls.stderr.strip(),
        "excessive_fragment_time_status": excessive_fragment_time.returncode,
        "excessive_fragment_time_stderr": excessive_fragment_time.stderr.strip(),
        "invalid_fragment_thresholds_status": invalid_fragment_thresholds.returncode,
        "invalid_fragment_thresholds_stderr": invalid_fragment_thresholds.stderr.strip(),
        "insufficient_systemd_nofile_status": insufficient_systemd_nofile.returncode,
        "insufficient_systemd_nofile_stderr": insufficient_systemd_nofile.stderr.strip(),
        "weak_systemd_sandbox_status": weak_systemd_sandbox.returncode,
        "weak_systemd_sandbox_stderr": weak_systemd_sandbox.stderr.strip(),
        "excessive_systemd_capabilities_status": (
            excessive_systemd_capabilities.returncode
        ),
        "excessive_systemd_capabilities_stderr": (
            excessive_systemd_capabilities.stderr.strip()
        ),
        "loopback_missing_port_status": loopback.returncode,
        "missing_public_port_rejected": missing_public_port_rejected,
        "covered_public_ports_allowed": covered.returncode == 0,
        "aligned_systemd_capacity_allowed": aligned_systemd_capacity.returncode == 0,
        "insufficient_systemd_capacity_rejected": (
            insufficient_systemd_capacity_rejected
        ),
        "aligned_low_cap_connlimit_threshold_allowed": (
            aligned_low_cap_connlimit_threshold.returncode == 0
        ),
        "excessive_connlimit_threshold_rejected": (
            excessive_connlimit_threshold_rejected
        ),
        "missing_udp_drop_rejected": missing_udp_drop_rejected,
        "generic_tcp_backstops_allowed": covered.returncode == 0,
        "missing_generic_tcp_l4proto_rejected": missing_generic_tcp_l4proto_rejected,
        "missing_ipv6_prefix_syn_backstop_rejected": missing_ipv6_prefix_syn_rejected,
        "missing_ipv6_prefix_connlimit_rejected": missing_ipv6_prefix_connlimit_rejected,
        "ipv6_prefix_backstops_allowed": covered.returncode == 0,
        "missing_ipv6_syn_l4proto_rejected": missing_ipv6_syn_l4proto_rejected,
        "missing_ipv6_connlimit_l4proto_rejected": missing_ipv6_connlimit_l4proto_rejected,
        "missing_ipv6_icmp_l4proto_rejected": missing_ipv6_icmp_l4proto_rejected,
        "ipv6_extension_safe_protocols_allowed": covered.returncode == 0,
        "icmpv4_control_exemption_allowed": covered.returncode == 0,
        "missing_icmpv4_control_exemption_rejected": (
            missing_icmpv4_control_exemption_rejected
        ),
        "late_icmpv4_control_exemption_rejected": late_icmpv4_control_exemption_rejected,
        "icmpv6_control_exemption_allowed": covered.returncode == 0,
        "missing_icmpv6_control_exemption_rejected": (
            missing_icmpv6_control_exemption_rejected
        ),
        "late_icmpv6_control_exemption_rejected": late_icmpv6_control_exemption_rejected,
        "connlimit_set_sizes_allowed": covered.returncode == 0,
        "missing_connlimit_set_size_rejected": missing_connlimit_set_size_rejected,
        "syn_rate_set_bounds_allowed": covered.returncode == 0,
        "missing_syn_rate_set_size_rejected": missing_syn_rate_set_size_rejected,
        "missing_syn_rate_set_timeout_rejected": missing_syn_rate_set_timeout_rejected,
        "fragment_sysctls_allowed": covered.returncode == 0,
        "missing_fragment_sysctls_rejected": missing_fragment_sysctls_rejected,
        "excessive_fragment_time_rejected": excessive_fragment_time_rejected,
        "invalid_fragment_thresholds_rejected": invalid_fragment_thresholds_rejected,
        "systemd_unit_allowed": covered.returncode == 0,
        "insufficient_systemd_nofile_rejected": insufficient_systemd_nofile_rejected,
        "weak_systemd_sandbox_rejected": weak_systemd_sandbox_rejected,
        "excessive_systemd_capabilities_rejected": (
            excessive_systemd_capabilities_rejected
        ),
        "loopback_missing_port_allowed": loopback.returncode == 0,
    }


def main() -> None:
    args = parse_args()
    binary = Path(args.binary)
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary}")
    bench_tcp_max_connection_seconds = max(5, int(args.duration) + 5)

    proxy_port = free_port()
    upstream_port = free_port()
    tcp_proxy_port = free_port()
    tcp_guard_port = free_port()
    tcp_rate_port = free_port()
    tcp_idle_port = free_port()
    tcp_upstream_port = free_port()
    with FastHttpServer(
        ("127.0.0.1", upstream_port), FastHttpHandler
    ) as upstream, FastTcpServer(
        ("127.0.0.1", tcp_upstream_port), FastTcpHandler
    ) as tcp_upstream, tempfile.TemporaryDirectory() as tmp:
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        tcp_upstream_thread = threading.Thread(target=tcp_upstream.serve_forever, daemon=True)
        tcp_upstream_thread.start()

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
                "downstream_keep_alive": False,
                "max_body_bytes": 1024,
                "request_body_idle_timeout_ms": 50,
                "upstream_body_idle_timeout_ms": 1000,
                "max_upstream_body_bytes": 1024,
                "limits": {
                    "per_ip_rps": args.per_ip_rps,
                    "per_ip_burst": args.per_ip_rps,
                    "global_rps": 1_000_000,
                    "global_burst": 1_000_000,
                    **BENCH_HTTP_CONNECTION_LIMITS,
                    "signature_rps": 1_000_000,
                    "signature_burst": 1_000_000,
                    "max_tracked_signatures": 1024,
                    "path_shape_rps": 1_000_000,
                    "path_shape_burst": 1_000_000,
                    "max_tracked_path_shapes": 1024,
                    "max_in_flight_requests": 8192,
                    "max_in_flight_requests_per_ip": 1024,
                    "max_tracked_ips": 1024,
                },
            },
            "tcp": [
                {
                    "name": "bench-tcp",
                    "listen": f"127.0.0.1:{tcp_proxy_port}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "connect_timeout_ms": 500,
                    "idle_timeout_seconds": bench_tcp_max_connection_seconds,
                    "max_connection_duration_seconds": bench_tcp_max_connection_seconds,
                    "limits": {
                        "per_ip_connects_per_second": 1_000_000,
                        "per_ip_connect_burst": 1_000_000,
                        "global_connects_per_second": 1_000_000,
                        "global_connect_burst": 1_000_000,
                        "max_connections": 1024,
                        "max_connections_per_ip": 1024,
                        "max_tracked_ips": 1024,
                    },
                },
                {
                    "name": "guard-tcp",
                    "listen": f"127.0.0.1:{tcp_guard_port}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "connect_timeout_ms": 500,
                    "idle_timeout_seconds": 5,
                    "max_connection_duration_seconds": 5,
                    "limits": {
                        "per_ip_connects_per_second": 1_000_000,
                        "per_ip_connect_burst": 1_000_000,
                        "global_connects_per_second": 1_000_000,
                        "global_connect_burst": 1_000_000,
                        "max_connections": 2,
                        "max_connections_per_ip": 1024,
                        "max_tracked_ips": 1024,
                    },
                },
                {
                    "name": "tcp-connect-rate",
                    "listen": f"127.0.0.1:{tcp_rate_port}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "connect_timeout_ms": 500,
                    "idle_timeout_seconds": 5,
                    "max_connection_duration_seconds": 5,
                    "limits": {
                        "per_ip_connects_per_second": 1_000_000,
                        "per_ip_connect_burst": 1_000_000,
                        "global_connects_per_second": 1.0,
                        "global_connect_burst": 2,
                        "max_connections": 128,
                        "max_connections_per_ip": 128,
                        "max_tracked_ips": 1024,
                    },
                },
                {
                    "name": "idle-tcp",
                    "listen": f"127.0.0.1:{tcp_idle_port}",
                    "upstream": f"127.0.0.1:{tcp_upstream_port}",
                    "connect_timeout_ms": 500,
                    "idle_timeout_seconds": 1,
                    "max_connection_duration_seconds": 10,
                    "limits": {
                        "per_ip_connects_per_second": 1_000_000,
                        "per_ip_connect_burst": 1_000_000,
                        "global_connects_per_second": 1_000_000,
                        "global_connect_burst": 1_000_000,
                        "max_connections": 128,
                        "max_connections_per_ip": 128,
                        "max_tracked_ips": 1024,
                    },
                },
            ],
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
        proxy_stopped = False
        try:
            try:
                wait_http("127.0.0.1", proxy_port)
                wait_tcp_port(tcp_proxy_port)
            except Exception as err:
                stderr = stop_process_and_collect_stderr(proxy)
                proxy_stopped = True
                raise startup_failure_with_stderr(err, proxy, stderr) from err
            result = {
                "generated_at_utc": generated_at_utc(),
                "source_tree": source_tree_metadata(Path.cwd()),
                "workdir": str(tmp_path),
                "binary": str(binary),
                "duration_seconds": args.duration,
                "workers": args.workers,
                "tcp_workers": args.tcp_workers,
                "proxy": run_flood(f"http://127.0.0.1:{proxy_port}/", args.workers, args.duration),
                "health": run_flood(
                    f"http://127.0.0.1:{proxy_port}/__altura/health",
                    args.workers,
                    args.duration,
                ),
                "tcp": run_tcp_echo_bench(tcp_proxy_port, args.tcp_workers, args.duration),
            }
            metrics_before = fetch_metrics(proxy_port)
            oversized_response = get_status_and_headers(proxy_port, "POST", "/drain", b"x" * 2048)
            oversized_status = oversized_response["status"]
            oversized_cache_control = oversized_response["headers"].get("cache-control")
            oversized_connection = oversized_response["headers"].get("connection")
            admin_health_response = get_status_and_headers(
                proxy_port, "GET", "/__altura/health"
            )
            metrics_without_token_response = get_status_and_headers(
                proxy_port, "GET", "/__altura/metrics"
            )
            metrics_with_token_response = get_status_and_headers(
                proxy_port,
                "GET",
                "/__altura/metrics",
                headers={"x-altura-admin-token": "bench-token"},
            )
            duplicate_metrics_token_response = (
                send_duplicate_admin_token_metrics_request(proxy_port)
            )
            admin_body_health_response = send_body_bearing_admin_keepalive_request(
                proxy_port, "/__altura/health"
            )
            admin_body_metrics_without_token_response = (
                send_body_bearing_admin_keepalive_request(
                    proxy_port, "/__altura/metrics"
                )
            )
            admin_body_metrics_with_token_response = (
                send_body_bearing_admin_keepalive_request(
                    proxy_port,
                    "/__altura/metrics",
                    headers={"x-altura-admin-token": "bench-token"},
                )
            )
            metrics_without_token = metrics_without_token_response["status"]
            slow_body = run_slow_body_probe(proxy_port)
            request_content_encoding = run_request_content_encoding_probe(proxy_port)
            expect_guard = run_expect_guard_probe(proxy_port)
            range_guard = run_range_guard_probe(proxy_port)
            accept_encoding = run_accept_encoding_probe(proxy_port)
            runtime_nofile = run_runtime_nofile_probe(binary, upstream_port, tmp_path)
            runtime_nofile_capacity = run_runtime_nofile_capacity_probe(
                binary, upstream_port, tmp_path
            )
            runtime_sigterm = run_runtime_sigterm_probe(binary, upstream_port, tmp_path)
            body_min_rate = run_body_min_rate_probe(binary, upstream_port, tmp_path)
            downstream_write_timeout = run_downstream_write_timeout_probe(
                binary, upstream_port, tmp_path
            )
            upstream_connect_timeout = run_upstream_connect_timeout_probe(binary, tmp_path)
            upstream_failure_circuit = run_upstream_failure_circuit_probe(binary, tmp_path)
            upstream_timeout_response = run_upstream_timeout_response_probe(
                binary, upstream_port, tmp_path
            )
            upstream_header_guard = run_upstream_header_guard_probe(
                binary, upstream_port, tmp_path
            )
            header_line_cap = run_header_line_cap_probe(binary, upstream_port, tmp_path)
            upstream_trailer_policy = run_upstream_trailer_policy_probe(
                binary, upstream_port, tmp_path
            )
            request_trailer_policy = run_request_trailer_policy_probe(
                binary, upstream_port, tmp_path
            )
            header_timeout = run_header_timeout_probe(binary, upstream_port, tmp_path)
            log_suppression = run_log_suppression_probe(binary, upstream_port, tmp_path)
            event_log_flush = run_event_log_flush_probe(binary, upstream_port, tmp_path)
            event_log_field_bounds = run_event_log_field_bounds_probe(
                binary, upstream_port, tmp_path
            )
            adaptive_window_cap = run_adaptive_window_cap_probe(binary, upstream_port, tmp_path)
            adaptive_catalog_shape = run_adaptive_catalog_shape_probe(
                binary, upstream_port, tmp_path
            )
            runtime_filter_bounds = run_runtime_filter_bounds_probe(
                binary, upstream_port, tmp_path
            )
            runtime_filter_hot_path = run_runtime_filter_hot_path_probe(
                binary, upstream_port, tmp_path
            )
            filter_activation_nonblocking = run_filter_activation_nonblocking_probe(
                binary, upstream_port, tmp_path
            )
            rate_limit_before_filter = run_rate_limit_before_filter_probe(
                binary, upstream_port, tmp_path
            )
            event_log_async_queue = run_event_log_async_queue_probe(binary, upstream_port, tmp_path)
            event_log_rotation = run_event_log_rotation_probe(binary, upstream_port, tmp_path)
            trusted_proxy_global_trust_startup = (
                run_trusted_proxy_global_trust_startup_probe(
                    binary, upstream_port, tmp_path
                )
            )
            negative_rate_startup = run_negative_rate_startup_probe(
                binary, upstream_port, tcp_upstream_port, tmp_path
            )
            admin_prefix_startup = run_admin_prefix_startup_probe(
                binary, upstream_port, tmp_path
            )
            admin_token_startup = run_admin_token_startup_probe(binary, upstream_port, tmp_path)
            zero_capacity_startup = run_zero_capacity_startup_probe(
                binary, upstream_port, tcp_upstream_port, tmp_path
            )
            header_buffer_floor_startup = run_header_buffer_floor_startup_probe(
                binary, upstream_port, tmp_path
            )
            header_buffer_ceiling_startup = run_header_buffer_ceiling_startup_probe(
                binary, upstream_port, tmp_path
            )
            header_count_ceiling_startup = run_header_count_ceiling_startup_probe(
                binary, upstream_port, tmp_path
            )
            http_metadata_ceiling_startup = run_http_metadata_ceiling_startup_probe(
                binary, upstream_port, tmp_path
            )
            header_read_timeout_ceiling_startup = (
                run_header_read_timeout_ceiling_startup_probe(
                    binary, upstream_port, tmp_path
                )
            )
            upstream_timeout_ceiling_startup = (
                run_upstream_timeout_ceiling_startup_probe(
                    binary, upstream_port, tmp_path
                )
            )
            upstream_failure_circuit_ceiling_startup = (
                run_upstream_failure_circuit_ceiling_startup_probe(
                    binary, upstream_port, tmp_path
                )
            )
            http_stream_timeout_ceiling_startup = (
                run_http_stream_timeout_ceiling_startup_probe(
                    binary, upstream_port, tmp_path
                )
            )
            body_size_ceiling_startup = run_body_size_ceiling_startup_probe(
                binary, upstream_port, tmp_path
            )
            min_rate_ceiling_startup = run_min_rate_ceiling_startup_probe(
                binary, upstream_port, tcp_upstream_port, tmp_path
            )
            upstream_idle_pool_ceiling_startup = (
                run_upstream_idle_pool_ceiling_startup_probe(
                    binary, upstream_port, tmp_path
                )
            )
            connect_timeout_ceiling_startup = run_connect_timeout_ceiling_startup_probe(
                binary, upstream_port, tcp_upstream_port, tmp_path
            )
            connection_duration_ceiling_startup = (
                run_connection_duration_ceiling_startup_probe(
                    binary, upstream_port, tcp_upstream_port, tmp_path
                )
            )
            connection_duration_runtime = run_connection_duration_runtime_probe(
                binary, upstream_port, tcp_upstream_port, tmp_path
            )
            connection_request_count_ceiling_startup = (
                run_connection_request_count_ceiling_startup_probe(
                    binary, upstream_port, tmp_path
                )
            )
            event_log_backup_count_ceiling_startup = (
                run_event_log_backup_count_ceiling_startup_probe(binary, tmp_path)
            )
            event_log_queue_capacity_ceiling_startup = (
                run_event_log_queue_capacity_ceiling_startup_probe(binary, tmp_path)
            )
            dynamic_state_ceiling_startup = run_dynamic_state_ceiling_startup_probe(
                binary, upstream_port, tcp_upstream_port, tmp_path
            )
            control_capacity_startup = run_control_capacity_startup_probe(binary, tmp_path)
            config_file_startup = run_config_file_startup_probe(binary, tmp_path)
            http_endpoint_startup = run_http_endpoint_startup_probe(
                binary, upstream_port, tmp_path
            )
            tcp_endpoint_startup = run_tcp_endpoint_startup_probe(binary, tmp_path)
            filter_rule_startup = run_filter_rule_startup_probe(binary, tmp_path)
            allowed_methods_startup = run_allowed_methods_startup_probe(
                binary, upstream_port, tmp_path
            )
            allowed_hosts_startup = run_allowed_hosts_startup_probe(
                binary, upstream_port, tmp_path
            )
            client_ip_config_startup = run_client_ip_config_startup_probe(
                binary, upstream_port, tmp_path
            )
            http_connection_rate = run_http_connection_rate_probe(binary, upstream_port, tmp_path)
            method_guard = run_method_guard_probe(binary, upstream_port, tmp_path)
            method_override_headers = run_method_override_header_probe(
                binary, upstream_port, tmp_path
            )
            early_rejection_close = run_early_rejection_close_probe(
                binary, upstream_port, tmp_path
            )
            host_guard = run_host_guard_probe(binary, upstream_port, tmp_path)
            framing_guard = run_framing_guard_probe(binary, upstream_port, tmp_path)
            initial_framing_precheck_response = run_initial_framing_precheck_response_probe(
                binary, upstream_port, tmp_path
            )
            chunked_request_body_opt_in = run_chunked_request_body_opt_in_probe(
                binary, upstream_port, tmp_path
            )
            forwarded_headers = run_forwarded_headers_probe(binary, upstream_port, tmp_path)
            forwarded_header_bounds = run_forwarded_header_bounds_probe(
                binary, upstream_port, tmp_path
            )
            trusted_proxy_aggregate_rate = run_trusted_proxy_aggregate_rate_probe(
                binary, upstream_port, tmp_path
            )
            trusted_proxy_in_flight = run_trusted_proxy_in_flight_probe(
                binary, upstream_port, tmp_path
            )
            ip_prefix_aggregation = run_ip_prefix_aggregation_probe(
                binary, upstream_port, tmp_path
            )
            signature_rate = run_signature_rate_probe(binary, upstream_port, tmp_path)
            path_shape_rate = run_path_shape_rate_probe(binary, upstream_port, tmp_path)
            uri_guard = run_uri_guard_probe(binary, upstream_port, tmp_path)
            tcp_guard = run_tcp_global_cap_probe(tcp_guard_port)
            tcp_global_connection_rate = run_tcp_global_connection_rate_probe(
                tcp_rate_port, proxy_port
            )
            tcp_idle_timeout = run_tcp_idle_timeout_probe(tcp_idle_port)
            tcp_relay_head_of_line = run_tcp_relay_head_of_line_probe(binary, tmp_path)
            tcp_min_rate = run_tcp_min_rate_probe(
                binary, upstream_port, tcp_upstream_port, tmp_path
            )
            admin_rate_limit = run_admin_rate_limit_probe(binary, upstream_port, tmp_path)
            admin_signature_rate = run_admin_signature_rate_probe(binary, upstream_port, tmp_path)
            upstream_in_flight = run_upstream_in_flight_probe(binary, upstream_port, tmp_path)
            upstream_response_guard = run_upstream_response_guard_probe(binary, upstream_port, tmp_path)
            header_count = run_header_count_probe(binary, upstream_port, tmp_path)
            upstream_pool = run_upstream_pool_probe(binary, tmp_path)
            listen_backlog = run_listen_backlog_probe(binary, upstream_port, tcp_upstream_port, tmp_path)
            rate_limiter_fairness = run_rate_limiter_fairness_probe(binary, upstream_port, tmp_path)
            tracked_ip_cap = run_tracked_ip_cap_probe(binary, upstream_port, tmp_path)
            edge_template_port_coverage = run_edge_template_port_coverage_probe(tmp_path)
            downstream_keep_alive = run_downstream_keepalive_probe(proxy_port)
            connection_request_limit = run_connection_request_limit_probe(
                binary, upstream_port, tmp_path
            )
            time.sleep(0.1)
            metrics_after = fetch_metrics(proxy_port)
            result["guardrails"] = {
                "oversized_content_length": {
                    "status": oversized_status,
                    "cache_control": oversized_cache_control,
                    "cache_control_no_store": oversized_cache_control == "no-store",
                    "connection": oversized_connection,
                    "connection_close": oversized_connection == "close",
                },
                "oversized_content_length_status": oversized_status,
                "admin_control_plane": {
                    "health_status": admin_health_response["status"],
                    "health_cache_control": admin_health_response["headers"].get(
                        "cache-control"
                    ),
                    "health_connection": admin_health_response["headers"].get(
                        "connection"
                    ),
                    "health_connection_close": admin_health_response["headers"].get(
                        "connection"
                    )
                    == "close",
                    "metrics_without_token_status": metrics_without_token_response["status"],
                    "metrics_without_token_cache_control": metrics_without_token_response[
                        "headers"
                    ].get("cache-control"),
                    "metrics_without_token_connection": metrics_without_token_response[
                        "headers"
                    ].get("connection"),
                    "metrics_without_token_connection_close": metrics_without_token_response[
                        "headers"
                    ].get("connection")
                    == "close",
                    "metrics_with_token_status": metrics_with_token_response["status"],
                    "metrics_with_token_cache_control": metrics_with_token_response[
                        "headers"
                    ].get("cache-control"),
                    "metrics_with_token_connection": metrics_with_token_response[
                        "headers"
                    ].get("connection"),
                    "metrics_with_token_connection_close": metrics_with_token_response[
                        "headers"
                    ].get("connection")
                    == "close",
                    "duplicate_metrics_token_status": duplicate_metrics_token_response[
                        "status"
                    ],
                    "duplicate_metrics_token_cache_control": duplicate_metrics_token_response[
                        "headers"
                    ].get("cache-control"),
                    "duplicate_metrics_token_connection": duplicate_metrics_token_response[
                        "headers"
                    ].get("connection"),
                    "duplicate_metrics_token_rejected": duplicate_metrics_token_response[
                        "status"
                    ]
                    == 403,
                    "duplicate_metrics_token_connection_close": duplicate_metrics_token_response[
                        "headers"
                    ].get("connection")
                    == "close",
                    "body_bearing_health": admin_body_health_response,
                    "body_bearing_metrics_without_token": admin_body_metrics_without_token_response,
                    "body_bearing_metrics_with_token": admin_body_metrics_with_token_response,
                    "body_bearing_health_closes_connection": admin_body_health_response[
                        "first"
                    ]["connection_close"]
                    and admin_body_health_response["followup"]["closed_without_response"],
                    "body_bearing_metrics_without_token_closes_connection": admin_body_metrics_without_token_response[
                        "first"
                    ][
                        "connection_close"
                    ]
                    and admin_body_metrics_without_token_response["followup"][
                        "closed_without_response"
                    ],
                    "body_bearing_metrics_with_token_closes_connection": admin_body_metrics_with_token_response[
                        "first"
                    ][
                        "connection_close"
                    ]
                    and admin_body_metrics_with_token_response["followup"][
                        "closed_without_response"
                    ],
                    "admin_responses_not_stored": all(
                        response["headers"].get("cache-control") == "no-store"
                        for response in [
                            admin_health_response,
                            metrics_without_token_response,
                            metrics_with_token_response,
                            duplicate_metrics_token_response,
                        ]
                    ),
                    "body_bearing_admin_responses_not_stored": all(
                        response["first"]["cache_control_no_store"]
                        for response in [
                            admin_body_health_response,
                            admin_body_metrics_without_token_response,
                            admin_body_metrics_with_token_response,
                        ]
                    ),
                    "admin_responses_close_connection": all(
                        response["headers"].get("connection") == "close"
                        for response in [
                            admin_health_response,
                            metrics_without_token_response,
                            metrics_with_token_response,
                            duplicate_metrics_token_response,
                        ]
                    )
                    and all(
                        response["first"]["connection_close"]
                        and response["followup"]["closed_without_response"]
                        for response in [
                            admin_body_health_response,
                            admin_body_metrics_without_token_response,
                            admin_body_metrics_with_token_response,
                        ]
                    ),
                },
                "metrics_without_token_status": metrics_without_token,
                "slow_body": slow_body,
                "request_content_encoding": request_content_encoding,
                "expect_guard": expect_guard,
                "range_guard": range_guard,
                "accept_encoding": accept_encoding,
                "runtime_nofile": runtime_nofile,
                "runtime_nofile_capacity": runtime_nofile_capacity,
                "runtime_sigterm": runtime_sigterm,
                "body_min_rate": body_min_rate,
                "downstream_write_timeout": downstream_write_timeout,
                "upstream_connect_timeout": upstream_connect_timeout,
                "upstream_failure_circuit": upstream_failure_circuit,
                "upstream_timeout_response": upstream_timeout_response,
                "upstream_header_guard": upstream_header_guard,
                "header_line_cap": header_line_cap,
                "upstream_trailer_policy": upstream_trailer_policy,
                "request_trailer_policy": request_trailer_policy,
                "header_timeout": header_timeout,
                "log_suppression": log_suppression,
                "event_log_flush": event_log_flush,
                "event_log_field_bounds": event_log_field_bounds,
                "adaptive_window_cap": adaptive_window_cap,
                "adaptive_catalog_shape": adaptive_catalog_shape,
                "runtime_filter_bounds": runtime_filter_bounds,
                "runtime_filter_hot_path": runtime_filter_hot_path,
                "filter_activation_nonblocking": filter_activation_nonblocking,
                "rate_limit_before_filter": rate_limit_before_filter,
                "event_log_async_queue": event_log_async_queue,
                "event_log_rotation": event_log_rotation,
                "trusted_proxy_global_trust_startup": trusted_proxy_global_trust_startup,
                "negative_rate_startup": negative_rate_startup,
                "admin_prefix_startup": admin_prefix_startup,
                "admin_token_startup": admin_token_startup,
                "zero_capacity_startup": zero_capacity_startup,
                "header_buffer_floor_startup": header_buffer_floor_startup,
                "header_buffer_ceiling_startup": header_buffer_ceiling_startup,
                "header_count_ceiling_startup": header_count_ceiling_startup,
                "http_metadata_ceiling_startup": http_metadata_ceiling_startup,
                "header_read_timeout_ceiling_startup": header_read_timeout_ceiling_startup,
                "upstream_timeout_ceiling_startup": upstream_timeout_ceiling_startup,
                "upstream_failure_circuit_ceiling_startup": upstream_failure_circuit_ceiling_startup,
                "http_stream_timeout_ceiling_startup": http_stream_timeout_ceiling_startup,
                "body_size_ceiling_startup": body_size_ceiling_startup,
                "min_rate_ceiling_startup": min_rate_ceiling_startup,
                "upstream_idle_pool_ceiling_startup": upstream_idle_pool_ceiling_startup,
                "connect_timeout_ceiling_startup": connect_timeout_ceiling_startup,
                "connection_duration_ceiling_startup": connection_duration_ceiling_startup,
                "connection_duration_runtime": connection_duration_runtime,
                "connection_request_count_ceiling_startup": connection_request_count_ceiling_startup,
                "event_log_backup_count_ceiling_startup": event_log_backup_count_ceiling_startup,
                "event_log_queue_capacity_ceiling_startup": event_log_queue_capacity_ceiling_startup,
                "dynamic_state_ceiling_startup": dynamic_state_ceiling_startup,
                "control_capacity_startup": control_capacity_startup,
                "config_file_startup": config_file_startup,
                "http_endpoint_startup": http_endpoint_startup,
                "tcp_endpoint_startup": tcp_endpoint_startup,
                "filter_rule_startup": filter_rule_startup,
                "allowed_methods_startup": allowed_methods_startup,
                "allowed_hosts_startup": allowed_hosts_startup,
                "client_ip_config_startup": client_ip_config_startup,
                "http_connection_rate": http_connection_rate,
                "method_guard": method_guard,
                "method_override_headers": method_override_headers,
                "early_rejection_close": early_rejection_close,
                "host_guard": host_guard,
                "framing_guard": framing_guard,
                "initial_framing_precheck_response": initial_framing_precheck_response,
                "chunked_request_body_opt_in": chunked_request_body_opt_in,
                "forwarded_headers": forwarded_headers,
                "forwarded_header_bounds": forwarded_header_bounds,
                "trusted_proxy_aggregate_rate": trusted_proxy_aggregate_rate,
                "trusted_proxy_in_flight": trusted_proxy_in_flight,
                "ip_prefix_aggregation": ip_prefix_aggregation,
                "signature_rate": signature_rate,
                "path_shape_rate": path_shape_rate,
                "uri_guard": uri_guard,
                "tcp_global_connection_cap": tcp_guard,
                "tcp_global_connection_rate": tcp_global_connection_rate,
                "tcp_idle_timeout": tcp_idle_timeout,
                "tcp_relay_head_of_line": tcp_relay_head_of_line,
                "tcp_min_rate": tcp_min_rate,
                "admin_rate_limit": admin_rate_limit,
                "admin_signature_rate": admin_signature_rate,
                "upstream_in_flight": upstream_in_flight,
                "upstream_response_guard": upstream_response_guard,
                "header_count": header_count,
                "upstream_pool": upstream_pool,
                "listen_backlog": listen_backlog,
                "rate_limiter_fairness": rate_limiter_fairness,
                "tracked_ip_cap": tracked_ip_cap,
                "edge_template_port_coverage": edge_template_port_coverage,
                "downstream_keep_alive": downstream_keep_alive,
                "connection_request_limit": connection_request_limit,
                "metrics_delta": {
                    key: metrics_after.get(key, 0) - metrics_before.get(key, 0)
                    for key in [
                        "altura_http_rate_limited",
                        "altura_http_body_rejected",
                        "altura_http_body_timeouts",
                        "altura_http_body_too_slow",
                        "altura_http_request_trailers_dropped",
                        "altura_http_request_trailers_rejected",
                        "altura_http_downstream_write_timeouts",
                        "altura_http_connections_rejected",
                        "altura_http_method_rejected",
                        "altura_http_host_rejected",
                        "altura_http_framing_rejected",
                        "altura_http_header_line_rejected",
                        "altura_http_initial_header_too_large",
                        "altura_http_initial_header_timeouts",
                        "altura_http_initial_headers_too_many",
                        "altura_http_forwarded_sanitized",
                        "altura_http_forwarded_rejected",
                        "altura_http_trusted_proxy_rate_limited",
                        "altura_http_trusted_proxy_in_flight_rejected",
                        "altura_http_signature_rate_limited",
                        "altura_http_path_shape_rate_limited",
                        "altura_http_content_encoding_rejected",
                        "altura_http_expect_rejected",
                        "altura_http_range_rejected",
                        "altura_http_accept_encoding_stripped",
                        "altura_http_uri_rejected",
                        "altura_http_initial_request_target_rejected",
                        "altura_http_upstream_errors",
                        "altura_http_upstream_timeouts",
                        "altura_http_upstream_circuit_open",
                        "altura_http_upstream_header_rejected",
                        "altura_http_upstream_body_rejected",
                        "altura_http_upstream_body_timeouts",
                        "altura_http_upstream_body_too_slow",
                        "altura_http_upstream_trailers_dropped",
                        "altura_http_upstream_trailers_rejected",
                        "altura_http_upstream_in_flight_rejected",
                        "altura_tcp_idle_timeouts",
                        "altura_tcp_downstream_too_slow",
                        "altura_tcp_upstream_too_slow",
                        "altura_tcp_rejected",
                        "altura_tcp_global_connect_rate_limited",
                    ]
                },
            }
            print(json.dumps(result, indent=2, sort_keys=True))
        finally:
            if not proxy_stopped:
                stop_process_and_collect_stderr(proxy)
            upstream.shutdown()


if __name__ == "__main__":
    main()
