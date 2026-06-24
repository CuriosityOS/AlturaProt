#!/usr/bin/env python3
"""Load the host-edge nftables template inside a temporary network namespace."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from bench_provenance import generated_at_utc, provenance_errors, source_tree_metadata

NAMESPACE_SMOKE_TIMEOUT_SECONDS = 15
PACKET_PROBE_CONNLIMIT_ATTEMPTS = 140
PACKET_PROBE_CONNLIMIT_MAX_ACCEPTED = 128


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Smoke-test the nftables edge template in an isolated network namespace. "
            "No host firewall rules are modified."
        )
    )
    parser.add_argument("--nft", default="ops/nftables/altura-prot-edge.nft")
    parser.add_argument(
        "--require",
        action="store_true",
        help="fail instead of skip when Linux namespace prerequisites are unavailable",
    )
    parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="fail unless the JSON report includes current Git provenance metadata",
    )
    parser.add_argument(
        "--packet-probe",
        action="store_true",
        help="also create isolated client/server namespaces and test protected-port packet behavior",
    )
    parser.add_argument(
        "--require-packet-probe",
        action="store_true",
        help="fail unless packet behavior probes run and pass; implies --packet-probe",
    )
    return parser.parse_args()


def command_path(name: str) -> str | None:
    return shutil.which(name)


def missing_prerequisites() -> list[str]:
    missing = []
    if platform.system() != "Linux":
        missing.append("Linux")
    for command in ("nft", "unshare", "ip"):
        if command_path(command) is None:
            missing.append(command)
    return missing


def nft_smoke_script(nft_path: Path) -> str:
    return "\n".join(
        [
            "set -eu",
            "ip link set lo up",
            f"nft -f {str(nft_path)!r}",
            "nft list table inet altura_prot_edge",
        ]
    )


def timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run(
    command: list[str],
    timeout_seconds: int = NAMESPACE_SMOKE_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
    )


def run_namespace_smoke(
    nft_path: Path,
    timeout_seconds: int = NAMESPACE_SMOKE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    command = [
        command_path("unshare") or "unshare",
        "--net",
        "--",
        "/bin/sh",
        "-c",
        nft_smoke_script(nft_path.resolve()),
    ]
    try:
        result = run(command, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        return {
            "skipped": False,
            "command": command,
            "returncode": None,
            "stdout": timeout_output(exc.stdout),
            "stderr": timeout_output(exc.stderr),
            "timed_out": True,
            "timeout_seconds": timeout_seconds,
            "nft_loaded": False,
        }
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    source = nft_path.read_text(encoding="utf-8")
    ipv6_prefix_mask = bool(re.search(r"ip6 saddr\s*(?:and|&)\s*ffff:ffff:ffff:ffff::", stdout))
    udp_extension_safe_source = bool(
        re.search(
            r"\bmeta\s+l4proto\s+udp\s+udp\s+dport\s+@protected_tcp_ports\s+drop\b",
            re.sub(r"\s+", " ", source),
        )
    )
    protected_syn_match = (
        "tcp dport @protected_tcp_ports tcp flags & (fin | syn | rst | ack) == syn"
    )
    protected_new_match = (
        "tcp dport @protected_tcp_ports ct state new tcp flags & (fin | syn | rst | ack)"
    )
    return {
        "skipped": False,
        "command": command,
        "returncode": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "nft_loaded": result.returncode == 0,
        "listed_edge_table": "table inet altura_prot_edge" in stdout,
        "protected_tcp_ports_present": "set protected_tcp_ports" in stdout,
        "tcp4_connlimit_present": "set tcp4_connlimit" in stdout,
        "tcp6_connlimit_present": "set tcp6_connlimit" in stdout,
        "syn_rate_sets_timeout_bounded": stdout.count("timeout 10s") >= 2,
        "tcp_invalid_null_drop_present": (
            "tcp dport @protected_tcp_ports tcp flags ! fin,syn,rst,ack drop" in stdout
        ),
        "tcp_invalid_xmas_drop_present": (
            "tcp flags & (fin | syn | rst | psh | ack | urg) == fin | psh | urg drop"
            in stdout
        ),
        "ipv6_prefix_syn_backstop_present": ipv6_prefix_mask
        and "update @tcp6_syn_rate" in stdout,
        "tcp4_syn_backstop_present": protected_syn_match in stdout
        and "update @tcp4_syn_rate" in stdout,
        "global_syn_backstop_present": protected_syn_match in stdout
        and "limit rate over 5000/second burst 10000 packets drop" in stdout,
        "ct_invalid_drop_present": "ct state invalid drop" in stdout,
        "new_non_syn_drop_present": protected_new_match in stdout
        and "!= syn drop" in stdout,
        "tcp4_connlimit_rule_present": "add @tcp4_connlimit" in stdout
        and "ct count over 128" in stdout,
        "ipv6_prefix_connlimit_present": ipv6_prefix_mask
        and "add @tcp6_connlimit" in stdout,
        "tcp6_connlimit_rule_present": ipv6_prefix_mask
        and "add @tcp6_connlimit" in stdout
        and "ct count over 128" in stdout,
        "udp_protected_port_drop_present": "udp dport @protected_tcp_ports drop" in stdout,
        "udp_protected_port_drop_extension_safe_source": udp_extension_safe_source,
        "icmpv4_control_exemption_present": "icmp type" in stdout
        and "destination-unreachable" in stdout,
        "icmpv4_flood_drop_present": (
            "ip protocol icmp limit rate over 100/second burst 200 packets drop" in stdout
        ),
        "icmpv6_control_exemption_present": "icmpv6 type" in stdout
        and "packet-too-big" in stdout,
        "icmpv6_flood_drop_present": (
            "meta l4proto ipv6-icmp limit rate over 100/second burst 200 packets drop"
            in stdout
        ),
    }


def run_checked(
    command: list[str],
    cleanup: list[list[str]],
    timeout_seconds: int = NAMESPACE_SMOKE_TIMEOUT_SECONDS,
) -> tuple[bool, str]:
    try:
        result = run(command, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        return False, f"{command!r} timed out: {timeout_output(exc.stderr)}"
    if result.returncode != 0:
        for cleanup_command in cleanup:
            run(cleanup_command)
        return False, f"{command!r} failed: {result.stderr.strip()}"
    return True, ""


def read_line_with_timeout(stream: TextIO, timeout_seconds: float) -> str | None:
    readable, _, _ = select.select([stream], [], [], timeout_seconds)
    if not readable:
        return None
    return stream.readline()


TCP_PACKET_SERVER_TEMPLATE = """
import socket
import time

SOCKET_FAMILY = __SOCKET_FAMILY__
TARGET = __TARGET__

held = []
s = socket.socket(SOCKET_FAMILY, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if SOCKET_FAMILY == socket.AF_INET6:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(TARGET)
s.listen(256)
print("ready", flush=True)
conn, _ = s.accept()
conn.sendall(b"ok")
conn.close()
end = time.time() + 10.0
while time.time() < end:
    try:
        s.settimeout(0.5)
        conn, _ = s.accept()
        held.append(conn)
    except socket.timeout:
        pass
for conn in held:
    try:
        conn.close()
    except OSError:
        pass
s.close()
"""


PACKET_CLIENT_TEMPLATE = """
import json
import socket
import time

SOCKET_FAMILY = __SOCKET_FAMILY__
TARGET = __TARGET__

result = {}
try:
    s = socket.socket(SOCKET_FAMILY, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(TARGET)
    result["tcp_clean_connect_payload"] = s.recv(2).decode("ascii", errors="replace")
    s.close()
except Exception as exc:
    result["tcp_clean_connect_error"] = f"{exc.__class__.__name__}:{exc}"

u = socket.socket(SOCKET_FAMILY, socket.SOCK_DGRAM)
u.settimeout(0.4)
try:
    u.connect(TARGET)
    u.send(b"x")
    u.recv(1)
except socket.timeout:
    result["udp_protected_port_result"] = "timeout"
except OSError as exc:
    result["udp_protected_port_result"] = f"oserror:{exc.errno}:{exc.__class__.__name__}"
else:
    result["udp_protected_port_result"] = "unexpected_data"
finally:
    u.close()

connlimit_results = []
connlimit_sockets = []
for _ in range(__CONNLIMIT_ATTEMPTS__):
    c = socket.socket(SOCKET_FAMILY, socket.SOCK_STREAM)
    c.settimeout(0.25)
    try:
        c.connect(TARGET)
        connlimit_sockets.append(c)
        connlimit_results.append("ok")
    except Exception as exc:
        connlimit_results.append(f"{exc.__class__.__name__}:{exc}")
        try:
            c.close()
        except OSError:
            pass

result["tcp_connlimit_attempts"] = len(connlimit_results)
result["tcp_connlimit_successes"] = connlimit_results.count("ok")
result["tcp_connlimit_failures"] = len(connlimit_results) - connlimit_results.count("ok")
result["tcp_connlimit_failure_tail"] = connlimit_results[-12:]
time.sleep(0.1)
for c in connlimit_sockets:
    try:
        c.close()
    except OSError:
        pass

print(json.dumps(result, sort_keys=True))
"""


HOP_BY_HOP_UDP_CLIENT_TEMPLATE = """
import ipaddress
import json
import socket
import struct
import time

INTERFACE = __INTERFACE__
SOURCE_MAC = bytes.fromhex(__SOURCE_MAC__.replace(":", ""))
DESTINATION_MAC = bytes.fromhex(__DESTINATION_MAC__.replace(":", ""))
SOURCE_ADDRESS = ipaddress.IPv6Address("fd00:230::2").packed
DESTINATION_ADDRESS = ipaddress.IPv6Address("fd00:230::1").packed
ETHERTYPE_IPV6 = 0x86DD
IPPROTO_HOPOPTS = 0
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
ICMPV6_DESTINATION_UNREACHABLE = 1
ICMPV6_PORT_UNREACHABLE = 4
PAYLOAD = b"x"


def checksum(data):
    if len(data) % 2:
        data += b"\\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


udp_length = 8 + len(PAYLOAD)
udp_header = struct.pack("!HHHH", 54321, 8080, udp_length, 0) + PAYLOAD
udp_pseudo_header = SOURCE_ADDRESS + DESTINATION_ADDRESS + struct.pack(
    "!I3xB",
    udp_length,
    IPPROTO_UDP,
)
udp_checksum = checksum(udp_pseudo_header + udp_header)
udp_header = struct.pack("!HHHH", 54321, 8080, udp_length, udp_checksum) + PAYLOAD
hop_by_hop_header = struct.pack("!BB", IPPROTO_UDP, 0) + bytes([1, 4, 0, 0, 0, 0])
ipv6_payload = hop_by_hop_header + udp_header
ipv6_header = struct.pack(
    "!IHBB16s16s",
    0x60000000,
    len(ipv6_payload),
    IPPROTO_HOPOPTS,
    64,
    SOURCE_ADDRESS,
    DESTINATION_ADDRESS,
)
frame = (
    DESTINATION_MAC
    + SOURCE_MAC
    + struct.pack("!H", ETHERTYPE_IPV6)
    + ipv6_header
    + ipv6_payload
)

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_IPV6))
sock.bind((INTERFACE, 0))
sock.settimeout(0.8)
sock.send(frame)

icmpv6_replies = []
port_unreachable_replies = []
end = time.time() + 0.8
while time.time() < end:
    try:
        packet = sock.recv(65535)
    except socket.timeout:
        break
    if len(packet) < 54:
        continue
    ethertype = struct.unpack("!H", packet[12:14])[0]
    if ethertype != ETHERTYPE_IPV6:
        continue
    ipv6 = packet[14:54]
    next_header = ipv6[6]
    source = str(ipaddress.IPv6Address(ipv6[8:24]))
    destination = str(ipaddress.IPv6Address(ipv6[24:40]))
    if next_header != IPPROTO_ICMPV6 or source != "fd00:230::1":
        continue
    icmpv6 = packet[54:]
    if len(icmpv6) < 2:
        continue
    reply = {
        "type": icmpv6[0],
        "code": icmpv6[1],
        "source": source,
        "destination": destination,
    }
    icmpv6_replies.append(reply)
    if (
        icmpv6[0] == ICMPV6_DESTINATION_UNREACHABLE
        and icmpv6[1] == ICMPV6_PORT_UNREACHABLE
        and destination == "fd00:230::2"
    ):
        port_unreachable_replies.append(reply)

print(
    json.dumps(
        {
            "sent_bytes": len(frame),
            "icmpv6_replies": icmpv6_replies,
            "icmpv6_port_unreachable_replies": port_unreachable_replies,
        },
        sort_keys=True,
    )
)
"""


def packet_socket_family_expr(family: str) -> str:
    if family == "ipv6":
        return "socket.AF_INET6"
    return "socket.AF_INET"


def packet_target(family: str) -> tuple[str, int] | tuple[str, int, int, int]:
    if family == "ipv6":
        return ("fd00:230::1", 8080, 0, 0)
    return ("10.230.0.1", 8080)


def packet_script(template: str, family: str) -> str:
    return (
        template.replace("__SOCKET_FAMILY__", packet_socket_family_expr(family))
        .replace("__TARGET__", repr(packet_target(family)))
        .replace("__CONNLIMIT_ATTEMPTS__", str(PACKET_PROBE_CONNLIMIT_ATTEMPTS))
    )


def ipv6_hop_by_hop_udp_script(
    interface: str,
    source_mac: str,
    destination_mac: str,
) -> str:
    return (
        HOP_BY_HOP_UDP_CLIENT_TEMPLATE.replace("__INTERFACE__", repr(interface))
        .replace("__SOURCE_MAC__", repr(source_mac))
        .replace("__DESTINATION_MAC__", repr(destination_mac))
    )


def terminate_server(server: subprocess.Popen[str] | None) -> None:
    if server is None or server.poll() is not None:
        return
    server.terminate()
    try:
        server.wait(timeout=1)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=1)


def packet_result_from_client_report(client_report: dict[str, Any]) -> dict[str, Any]:
    tcp_payload = client_report.get("tcp_clean_connect_payload")
    udp_result = client_report.get("udp_protected_port_result")
    connlimit_attempts = client_report.get("tcp_connlimit_attempts")
    connlimit_successes = client_report.get("tcp_connlimit_successes")
    connlimit_failures = client_report.get("tcp_connlimit_failures")
    connlimit_enforced = (
        connlimit_attempts == PACKET_PROBE_CONNLIMIT_ATTEMPTS
        and isinstance(connlimit_successes, int)
        and isinstance(connlimit_failures, int)
        and connlimit_successes <= PACKET_PROBE_CONNLIMIT_MAX_ACCEPTED
        and connlimit_failures > 0
    )
    return {
        "skipped": False,
        "tcp_clean_connect_allowed": tcp_payload == "ok",
        "tcp_clean_connect_payload": tcp_payload,
        "tcp_clean_connect_error": client_report.get("tcp_clean_connect_error"),
        "udp_protected_port_silently_dropped": udp_result == "timeout",
        "udp_protected_port_result": udp_result,
        "tcp_connlimit_enforced": connlimit_enforced,
        "tcp_connlimit_attempts": connlimit_attempts,
        "tcp_connlimit_successes": connlimit_successes,
        "tcp_connlimit_failures": connlimit_failures,
        "tcp_connlimit_failure_tail": client_report.get("tcp_connlimit_failure_tail"),
    }


def prefixed_packet_report(prefix: str, report: dict[str, Any]) -> dict[str, Any]:
    if not prefix:
        return report
    return {f"{prefix}_{key}": value for key, value in report.items() if key != "skipped"}


def run_packet_family_probe(
    ip: str,
    victim: str,
    attacker: str,
    family: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    server: subprocess.Popen[str] | None = None
    try:
        server = subprocess.Popen(
            [
                ip,
                "netns",
                "exec",
                victim,
                sys.executable,
                "-u",
                "-c",
                packet_script(TCP_PACKET_SERVER_TEMPLATE, family),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ready_line = (
            read_line_with_timeout(server.stdout, min(3.0, float(timeout_seconds)))
            if server.stdout
            else None
        )
        if ready_line is None:
            stderr = server.stderr.read() if server.poll() is not None and server.stderr else ""
            return {
                "skipped": False,
                "server_ready_timeout": True,
                "server_error": stderr.strip(),
            }
        ready = ready_line.strip()
        if ready != "ready":
            stderr = server.stderr.read() if server.poll() is not None and server.stderr else ""
            return {"skipped": False, "server_ready": ready, "server_error": stderr.strip()}

        client = run(
            [
                ip,
                "netns",
                "exec",
                attacker,
                sys.executable,
                "-c",
                packet_script(PACKET_CLIENT_TEMPLATE, family),
            ],
            timeout_seconds,
        )
        if client.returncode != 0:
            return {
                "skipped": False,
                "client_status": client.returncode,
                "client_stdout": client.stdout.strip(),
                "client_stderr": client.stderr.strip(),
            }
        try:
            client_report = json.loads(client.stdout)
        except json.JSONDecodeError as exc:
            return {
                "skipped": False,
                "client_stdout": client.stdout.strip(),
                "client_parse_error": str(exc),
            }
        return packet_result_from_client_report(client_report)
    finally:
        terminate_server(server)


def namespace_interface_mac(
    ip: str,
    namespace: str,
    interface: str,
    timeout_seconds: int,
) -> tuple[str | None, str | None]:
    result = run(
        [ip, "netns", "exec", namespace, "cat", f"/sys/class/net/{interface}/address"],
        timeout_seconds,
    )
    if result.returncode != 0:
        return None, result.stderr.strip()
    return result.stdout.strip(), None


def run_ipv6_hop_by_hop_udp_probe(
    ip: str,
    victim: str,
    attacker: str,
    victim_if: str,
    attacker_if: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    victim_mac, victim_error = namespace_interface_mac(ip, victim, victim_if, timeout_seconds)
    if victim_error is not None:
        return {"ipv6_hop_by_hop_udp_mac_error": victim_error}
    attacker_mac, attacker_error = namespace_interface_mac(ip, attacker, attacker_if, timeout_seconds)
    if attacker_error is not None:
        return {"ipv6_hop_by_hop_udp_mac_error": attacker_error}

    client = run(
        [
            ip,
            "netns",
            "exec",
            attacker,
            sys.executable,
            "-c",
            ipv6_hop_by_hop_udp_script(attacker_if, attacker_mac or "", victim_mac or ""),
        ],
        timeout_seconds,
    )
    if client.returncode != 0:
        return {
            "ipv6_hop_by_hop_udp_client_status": client.returncode,
            "ipv6_hop_by_hop_udp_client_stdout": client.stdout.strip(),
            "ipv6_hop_by_hop_udp_client_stderr": client.stderr.strip(),
        }
    try:
        client_report = json.loads(client.stdout)
    except json.JSONDecodeError as exc:
        return {
            "ipv6_hop_by_hop_udp_client_stdout": client.stdout.strip(),
            "ipv6_hop_by_hop_udp_client_parse_error": str(exc),
        }

    sent_bytes = client_report.get("sent_bytes")
    port_unreachable_replies = client_report.get("icmpv6_port_unreachable_replies")
    if not isinstance(port_unreachable_replies, list):
        port_unreachable_replies = []
    return {
        "ipv6_hop_by_hop_udp_packet_sent": isinstance(sent_bytes, int) and sent_bytes > 0,
        "ipv6_hop_by_hop_udp_sent_bytes": sent_bytes,
        "ipv6_hop_by_hop_udp_protected_port_silently_dropped": not port_unreachable_replies,
        "ipv6_hop_by_hop_udp_icmpv6_replies": client_report.get("icmpv6_replies"),
        "ipv6_hop_by_hop_udp_port_unreachable_replies": port_unreachable_replies,
    }


def run_packet_probe(
    nft_path: Path,
    timeout_seconds: int = NAMESPACE_SMOKE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    ip = command_path("ip") or "ip"
    namespace_suffix = f"{os.getpid()}x{int(time.time() * 1000) % 100000}"
    victim = f"apv{namespace_suffix}"
    attacker = f"apa{namespace_suffix}"
    interface_suffix = f"{os.getpid() % 100000:05d}"
    victim_if = f"v{interface_suffix}v"
    attacker_if = f"v{interface_suffix}a"
    cleanup = [
        [ip, "link", "del", victim_if],
        [ip, "link", "del", attacker_if],
        [ip, "netns", "del", attacker],
        [ip, "netns", "del", victim],
    ]
    try:
        for command in ([ip, "netns", "add", victim], [ip, "netns", "add", attacker]):
            ok, error = run_checked(command, cleanup, timeout_seconds)
            if not ok:
                return {"skipped": True, "reason": error}

        setup_commands = [
            [ip, "link", "add", victim_if, "type", "veth", "peer", "name", attacker_if],
            [ip, "link", "set", victim_if, "netns", victim],
            [ip, "link", "set", attacker_if, "netns", attacker],
            [ip, "-n", victim, "addr", "add", "10.230.0.1/24", "dev", victim_if],
            [ip, "-n", attacker, "addr", "add", "10.230.0.2/24", "dev", attacker_if],
            [ip, "-n", victim, "addr", "add", "fd00:230::1/64", "dev", victim_if, "nodad"],
            [ip, "-n", attacker, "addr", "add", "fd00:230::2/64", "dev", attacker_if, "nodad"],
            [ip, "-n", victim, "link", "set", "lo", "up"],
            [ip, "-n", attacker, "link", "set", "lo", "up"],
            [ip, "-n", victim, "link", "set", victim_if, "up"],
            [ip, "-n", attacker, "link", "set", attacker_if, "up"],
            [ip, "netns", "exec", victim, command_path("nft") or "nft", "-f", str(nft_path.resolve())],
        ]
        for command in setup_commands:
            ok, error = run_checked(command, cleanup, timeout_seconds)
            if not ok:
                return {"skipped": False, "setup_error": error}

        report: dict[str, Any] = {"skipped": False}
        report.update(
            prefixed_packet_report(
                "",
                run_packet_family_probe(ip, victim, attacker, "ipv4", timeout_seconds),
            )
        )
        report.update(
            prefixed_packet_report(
                "ipv6",
                run_packet_family_probe(ip, victim, attacker, "ipv6", timeout_seconds),
            )
        )
        report.update(
            run_ipv6_hop_by_hop_udp_probe(
                ip,
                victim,
                attacker,
                victim_if,
                attacker_if,
                timeout_seconds,
            )
        )
        return report
    finally:
        for command in cleanup:
            run(command)


def with_provenance(report: dict[str, Any], cwd: Path) -> dict[str, Any]:
    return {
        "generated_at_utc": generated_at_utc(),
        "source_tree": source_tree_metadata(cwd),
        **report,
    }


def assert_smoke_result(
    report: dict[str, Any],
    require_provenance: bool = False,
    require_packet_probe: bool = False,
) -> list[str]:
    errors = provenance_errors(report) if require_provenance else []
    if report.get("skipped"):
        if require_packet_probe:
            errors.append("packet probe required but edge namespace smoke was skipped")
        return errors
    required_true = [
        "nft_loaded",
        "listed_edge_table",
        "protected_tcp_ports_present",
        "tcp4_connlimit_present",
        "tcp6_connlimit_present",
        "syn_rate_sets_timeout_bounded",
        "tcp_invalid_null_drop_present",
        "tcp_invalid_xmas_drop_present",
        "tcp4_syn_backstop_present",
        "ipv6_prefix_syn_backstop_present",
        "global_syn_backstop_present",
        "ct_invalid_drop_present",
        "new_non_syn_drop_present",
        "tcp4_connlimit_rule_present",
        "ipv6_prefix_connlimit_present",
        "tcp6_connlimit_rule_present",
        "udp_protected_port_drop_present",
        "udp_protected_port_drop_extension_safe_source",
        "icmpv4_control_exemption_present",
        "icmpv4_flood_drop_present",
        "icmpv6_control_exemption_present",
        "icmpv6_flood_drop_present",
    ]
    for key in required_true:
        if report.get(key) is not True:
            errors.append(f"{key}: expected true, found {report.get(key)!r}")
    packet_probe = report.get("packet_probe")
    if require_packet_probe and not isinstance(packet_probe, dict):
        errors.append("packet probe required but report missing packet_probe object")
    if isinstance(packet_probe, dict):
        if packet_probe.get("skipped"):
            if require_packet_probe:
                errors.append(f"packet probe skipped: {packet_probe.get('reason')!r}")
        else:
            for key in [
                "tcp_clean_connect_allowed",
                "udp_protected_port_silently_dropped",
                "tcp_connlimit_enforced",
                "ipv6_tcp_clean_connect_allowed",
                "ipv6_udp_protected_port_silently_dropped",
                "ipv6_tcp_connlimit_enforced",
                "ipv6_hop_by_hop_udp_packet_sent",
                "ipv6_hop_by_hop_udp_protected_port_silently_dropped",
            ]:
                if packet_probe.get(key) is not True:
                    errors.append(
                        f"packet_probe.{key}: expected true, found {packet_probe.get(key)!r}"
                    )
    return errors


def skip_report(missing: list[str]) -> dict[str, Any]:
    return {
        "skipped": True,
        "missing_prerequisites": missing,
        "reason": "edge namespace smoke requires Linux plus nft, unshare, and ip",
    }


def main() -> None:
    args = parse_args()
    nft_path = Path(args.nft)
    if not nft_path.exists():
        report = with_provenance(
            {"skipped": False, "error": f"missing nft template: {nft_path}"},
            Path.cwd(),
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        raise SystemExit(1)

    missing = missing_prerequisites()
    if missing:
        report = with_provenance(skip_report(missing), Path.cwd())
        errors = assert_smoke_result(
            report,
            args.require_provenance,
            args.require_packet_probe,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            raise SystemExit(1)
        if args.require:
            raise SystemExit(1)
        return

    report = with_provenance(run_namespace_smoke(nft_path), Path.cwd())
    if args.packet_probe or args.require_packet_probe:
        report["packet_probe"] = run_packet_probe(nft_path)
    errors = assert_smoke_result(report, args.require_provenance, args.require_packet_probe)
    print(json.dumps(report, indent=2, sort_keys=True))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
