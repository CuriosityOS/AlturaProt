#!/usr/bin/env python3
"""Validate AlturaProt host-edge templates without installing them."""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

REQUIRED_FRAGMENT_SYSCTLS = {
    "net.ipv4.ipfrag_high_thresh",
    "net.ipv4.ipfrag_time",
    "net.ipv4.ipfrag_max_dist",
    "net.ipv6.ip6frag_high_thresh",
    "net.ipv6.ip6frag_low_thresh",
    "net.ipv6.ip6frag_time",
}
DDOS_SYSCTL_RULES = {
    "net.ipv4.tcp_syncookies": {"exact": 1},
    "net.ipv4.tcp_max_syn_backlog": {"min": 8192},
    "net.ipv4.tcp_synack_retries": {"min": 1, "max": 5},
    "net.core.somaxconn": {"min": 4096},
    "net.core.netdev_max_backlog": {"min": 10000},
    "net.ipv4.tcp_fin_timeout": {"min": 1, "max": 60},
    "net.netfilter.nf_conntrack_max": {"min": 262144},
    "net.netfilter.nf_conntrack_tcp_timeout_syn_recv": {"min": 1, "max": 60},
}
OPTIONAL_MODULE_SYSCTL_KEYS = {
    "net.netfilter.nf_conntrack_max",
    "net.netfilter.nf_conntrack_tcp_timeout_syn_recv",
}
MAX_FRAGMENT_REASSEMBLY_BYTES = 64 * 1024 * 1024
MAX_FRAGMENT_QUEUE_SECONDS = 30
MAX_FRAGMENT_DISTANCE = 4096
MAX_CONNLIMIT_SET_SIZE = 1_048_576
MAX_PROTECTED_PORT_CONNLIMIT = 128
NOFILE_BASE_RESERVE = 256
DEFAULT_ACCEPT_SHARDS = 1
DEFAULT_HTTP_MAX_CONNECTIONS = 10_000
DEFAULT_HTTP_MAX_CONNECTIONS_PER_IP = 1024
DEFAULT_HTTP_MAX_IN_FLIGHT_REQUESTS = 8_192
DEFAULT_HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST = 256
DEFAULT_TCP_MAX_CONNECTIONS = 10_000
DEFAULT_TCP_MAX_CONNECTIONS_PER_IP = 128
MAX_SYN_RATE_SET_SIZE = 1_048_576
MAX_SYN_RATE_SET_TIMEOUT_SECONDS = 60
MIN_SYSTEMD_LIMIT_NOFILE = 65536
MAX_SYSTEMD_TASKS = 32768
REQUIRED_SYSTEMD_SERVICE_VALUES = {
    "Type": {"simple"},
    "Restart": {"on-failure", "always"},
    "NoNewPrivileges": {"true", "yes"},
    "PrivateTmp": {"true", "yes"},
    "PrivateDevices": {"true", "yes"},
    "ProtectSystem": {"strict"},
    "ProtectHome": {"true", "yes", "read-only", "tmpfs"},
    "ProtectKernelTunables": {"true", "yes"},
    "ProtectKernelModules": {"true", "yes"},
    "ProtectControlGroups": {"true", "yes", "strict"},
    "RestrictNamespaces": {"true", "yes"},
    "RestrictRealtime": {"true", "yes"},
    "RestrictSUIDSGID": {"true", "yes"},
    "LockPersonality": {"true", "yes"},
    "MemoryDenyWriteExecute": {"true", "yes"},
    "SystemCallArchitectures": {"native"},
}
REQUIRED_SYSTEMD_DIRECTIVES = {
    "User",
    "Group",
    "ExecStart",
    "LimitNOFILE",
    "TimeoutStopSec",
    "TasksMax",
    "MemoryHigh",
    "MemoryMax",
    "AmbientCapabilities",
    "CapabilityBoundingSet",
    "RestrictAddressFamilies",
    "StateDirectory",
    "LogsDirectory",
    "ConfigurationDirectory",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/example.json")
    parser.add_argument("--nft", default="ops/nftables/altura-prot-edge.nft")
    parser.add_argument("--sysctl", default="ops/sysctl.d/99-altura-prot-ddos.conf")
    parser.add_argument("--systemd", default="ops/systemd/altura-prot.service")
    return parser.parse_args()


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def validate_nft(path: Path) -> list[str]:
    if not path.exists():
        return [f"missing nftables template: {path}"]
    nft = shutil.which("nft")
    if nft is None:
        return ["nft not found; skipped nftables syntax check"]
    result = run([nft, "-c", "-f", str(path)])
    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        return [f"nftables syntax check failed for {path}: {details}"]
    return []


def strip_nft_comments(raw: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in raw.splitlines())


def named_block(raw: str, name: str) -> str | None:
    stripped = strip_nft_comments(raw)
    match = re.search(rf"\b{re.escape(name)}\b\s*\{{", stripped)
    if match is None:
        return None
    start = match.end() - 1
    depth = 0
    for idx in range(start, len(stripped)):
        char = stripped[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return stripped[start + 1 : idx]
    return None


def nft_set_block(raw: str, name: str) -> str | None:
    stripped = strip_nft_comments(raw)
    match = re.search(rf"\bset\s+{re.escape(name)}\s*\{{", stripped)
    if match is None:
        return None
    start = match.end() - 1
    depth = 0
    for idx in range(start, len(stripped)):
        char = stripped[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return stripped[start + 1 : idx]
    return None


def nft_directive(block: str, key: str) -> str | None:
    for raw_line in strip_nft_comments(block).splitlines():
        line = raw_line.strip().rstrip(";")
        if line.startswith(key + " "):
            return line[len(key) :].strip()
    return None


def parse_service_port(value: str) -> int:
    token = value.strip().strip('"').strip("'")
    if not token:
        raise ValueError("empty port element")
    if token.isdigit():
        port = int(token)
    else:
        try:
            port = socket.getservbyname(token, "tcp")
        except OSError as err:
            raise ValueError(f"unsupported protected_tcp_ports element: {value}") from err
    if port < 1 or port > 65535:
        raise ValueError(f"port out of range in protected_tcp_ports: {value}")
    return port


def parse_port_element(value: str) -> tuple[int, int]:
    token = value.strip()
    if "-" in token:
        start, end = token.split("-", 1)
        start_port = parse_service_port(start)
        end_port = parse_service_port(end)
        if start_port > end_port:
            raise ValueError(f"invalid descending port range in protected_tcp_ports: {value}")
        return start_port, end_port
    port = parse_service_port(token)
    return port, port


def protected_tcp_port_ranges(path: Path) -> tuple[list[tuple[int, int]], list[str]]:
    if not path.exists():
        return [], []
    block = named_block(path.read_text(encoding="utf-8"), "set protected_tcp_ports")
    if block is None:
        return [], [f"missing protected_tcp_ports set in {path}"]
    elements = re.search(r"\belements\s*=\s*\{(?P<items>[^}]*)\}", block, re.DOTALL)
    if elements is None:
        return [], [f"missing protected_tcp_ports elements in {path}"]

    ranges: list[tuple[int, int]] = []
    errors: list[str] = []
    for item in elements.group("items").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            ranges.append(parse_port_element(item))
        except ValueError as err:
            errors.append(str(err))
    if not ranges and not errors:
        errors.append(f"protected_tcp_ports set in {path} has no elements")
    return ranges, errors


def validate_protected_tcp_ports(path: Path) -> list[str]:
    _, errors = protected_tcp_port_ranges(path)
    return errors


def compact_rule_text(raw: str) -> str:
    return re.sub(r"\s+", " ", strip_nft_comments(raw)).strip()


def validate_udp_protected_port_drop(path: Path) -> list[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    preraw = named_block(raw, "chain preraw")
    if preraw is None:
        return [f"missing preraw chain with protected-port UDP drop in {path}"]
    compact = compact_rule_text(preraw)
    if re.search(
        r"\bmeta\s+l4proto\s+udp\s+udp\s+dport\s+@protected_tcp_ports\s+drop\b",
        compact,
    ):
        return []
    return [
        "missing raw UDP drop for protected TCP service ports: "
        "expected `meta l4proto udp udp dport @protected_tcp_ports drop` "
        "in chain preraw"
    ]


IPV6_PREFIX64_SELECTOR_PATTERN = (
    r"\(?\s*ip6\s+saddr\s*(?:and|&)\s*ffff:ffff:ffff:ffff::"
    r"\s*\)?\s*\.\s*tcp\s+dport"
)
GENERIC_TCP_L4PROTO_PATTERN = r"\bmeta\s+l4proto\s+tcp\b"
IPV6_TCP_L4PROTO_PATTERN = r"\bmeta\s+nfproto\s+(?:ipv6|ip6)\s+meta\s+l4proto\s+tcp\b"
IPV4_ICMP_PROTOCOL_PATTERN = r"\bip\s+protocol\s+icmp\b"
IPV6_ICMP_L4PROTO_PATTERN = (
    r"\bmeta\s+nfproto\s+(?:ipv6|ip6)\s+meta\s+l4proto\s+ipv6-icmp\b"
)
REQUIRED_ICMPV4_CONTROL_TYPES = {
    "destination-unreachable",
    "time-exceeded",
    "parameter-problem",
}
REQUIRED_ICMPV6_CONTROL_TYPES = {
    "destination-unreachable",
    "packet-too-big",
    "time-exceeded",
    "parameter-problem",
    "nd-router-solicit",
    "nd-router-advert",
    "nd-neighbor-solicit",
    "nd-neighbor-advert",
}


def validate_generic_tcp_backstop_protocol_matches(path: Path) -> list[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    errors: list[str] = []

    preraw = named_block(raw, "chain preraw")
    preraw_compact = compact_rule_text(preraw or "")
    if preraw is None:
        errors.append(f"missing preraw chain with generic TCP backstops in {path}")
    else:
        required_preraw = {
            "null TCP flag drop": (
                r"tcp\s+dport\s+@protected_tcp_ports\s+tcp\s+flags\s+&\s*"
                r"\(\s*fin\s*\|\s*syn\s*\|\s*rst\s*\|\s*ack\s*\)\s*==\s*0\s+drop\b"
            ),
            "Xmas TCP flag drop": (
                r"tcp\s+dport\s+@protected_tcp_ports\s+tcp\s+flags\s+&\s*"
                r"\(\s*fin\s*\|\s*syn\s*\|\s*rst\s*\|\s*psh\s*\|\s*ack\s*\|\s*urg\s*\)"
                r"\s*==\s*fin\s*\|\s*psh\s*\|\s*urg\s+drop\b"
            ),
            "global SYN flood drop": (
                r"tcp\s+dport\s+@protected_tcp_ports\s+tcp\s+flags\s+&\s*"
                r"\(\s*fin\s*\|\s*syn\s*\|\s*rst\s*\|\s*ack\s*\)\s*==\s*syn\s+"
                r"limit\s+rate\s+over\b.*\bdrop\b"
            ),
        }
        for label, rule_tail in required_preraw.items():
            if not re.search(
                GENERIC_TCP_L4PROTO_PATTERN + r"\s+" + rule_tail,
                preraw_compact,
            ):
                errors.append(
                    f"missing generic TCP extension-safe {label}: expected "
                    "`meta l4proto tcp` before protected-port TCP match"
                )

    input_chain = named_block(raw, "chain input")
    input_compact = compact_rule_text(input_chain or "")
    if input_chain is None:
        errors.append(f"missing input chain with generic TCP backstops in {path}")
    else:
        required_input = {
            "new non-SYN drop": (
                r"tcp\s+dport\s+@protected_tcp_ports\s+ct\s+state\s+new\s+"
                r"tcp\s+flags\s+&\s*\(\s*fin\s*\|\s*syn\s*\|\s*rst\s*\|\s*ack\s*\)"
                r"\s*!=\s*syn\s+drop\b"
            ),
            "global new-connection flood drop": (
                r"tcp\s+dport\s+@protected_tcp_ports\s+ct\s+state\s+new\s+"
                r"limit\s+rate\s+over\b.*\bdrop\b"
            ),
        }
        for label, rule_tail in required_input.items():
            if not re.search(
                GENERIC_TCP_L4PROTO_PATTERN + r"\s+" + rule_tail,
                input_compact,
            ):
                errors.append(
                    f"missing generic TCP extension-safe {label}: expected "
                    "`meta l4proto tcp` before protected-port TCP match"
                )

    return errors


def validate_ipv6_prefix_backstops(path: Path) -> list[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    errors: list[str] = []

    preraw = named_block(raw, "chain preraw")
    if preraw is None:
        errors.append(f"missing preraw chain with IPv6 /64 SYN backstop in {path}")
    else:
        syn_meter = named_block(preraw, "tcp6_syn_rate")
        syn_compact = compact_rule_text(syn_meter or "")
        if syn_meter is None or not re.search(
            IPV6_PREFIX64_SELECTOR_PATTERN + r"\s+timeout\s+\S+\s+limit\s+rate\s+over\b",
            syn_compact,
        ) and not re.search(
            IPV6_PREFIX64_SELECTOR_PATTERN + r"\s+limit\s+rate\s+over\b",
            syn_compact,
        ):
            errors.append(
                "missing IPv6 /64 SYN backstop: expected "
                "`ip6 saddr and ffff:ffff:ffff:ffff:: . tcp dport` "
                "inside tcp6_syn_rate"
            )

    input_chain = named_block(raw, "chain input")
    input_compact = compact_rule_text(input_chain or "")
    if input_chain is None:
        errors.append(f"missing input chain with IPv6 /64 connection-count backstop in {path}")
    elif not re.search(
        r"\badd\s+@tcp6_connlimit\s*\{\s*"
        + IPV6_PREFIX64_SELECTOR_PATTERN
        + r"\s+ct\s+count\s+over\b",
        input_compact,
    ):
        errors.append(
            "missing IPv6 /64 connection-count backstop: expected "
            "`ip6 saddr and ffff:ffff:ffff:ffff:: . tcp dport ct count over ...` "
            "in chain input"
        )

    return errors


def validate_ipv6_extension_safe_protocol_matches(path: Path) -> list[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    errors: list[str] = []

    preraw = named_block(raw, "chain preraw")
    preraw_compact = compact_rule_text(preraw or "")
    if preraw is None:
        errors.append(f"missing preraw chain with IPv6 extension-safe SYN backstop in {path}")
    elif not re.search(
        IPV6_TCP_L4PROTO_PATTERN + r".*\b(?:meter\s+|update\s+@)tcp6_syn_rate\b",
        preraw_compact,
    ):
        errors.append(
            "missing IPv6 extension-safe SYN protocol match: expected "
            "`meta nfproto ipv6 meta l4proto tcp` before meter tcp6_syn_rate"
        )

    input_chain = named_block(raw, "chain input")
    input_compact = compact_rule_text(input_chain or "")
    if input_chain is None:
        errors.append(
            f"missing input chain with IPv6 extension-safe connection backstops in {path}"
        )
    else:
        if not re.search(
            IPV6_TCP_L4PROTO_PATTERN + r".*\badd\s+@tcp6_connlimit\b",
            input_compact,
        ):
            errors.append(
                "missing IPv6 extension-safe connection-count protocol match: "
                "expected `meta nfproto ipv6 meta l4proto tcp` before add @tcp6_connlimit"
            )
        if not re.search(
            IPV6_ICMP_L4PROTO_PATTERN + r"\s+limit\s+rate\s+over\b",
            input_compact,
        ):
            errors.append(
                "missing IPv6 extension-safe ICMPv6 flood protocol match: expected "
                "`meta nfproto ipv6 meta l4proto ipv6-icmp`"
            )

    return errors


def validate_icmpv4_control_exemption(path: Path) -> list[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    input_chain = named_block(raw, "chain input")
    if input_chain is None:
        return [f"missing input chain with ICMPv4 control exemption in {path}"]

    errors: list[str] = []
    compact = compact_rule_text(input_chain)
    accept_match = re.search(
        IPV4_ICMP_PROTOCOL_PATTERN
        + r"\s+icmp\s+type\s+\{(?P<types>[^}]*)\}\s+accept\b",
        compact,
    )
    if accept_match is None:
        errors.append(
            "missing ICMPv4 control exemption before flood backstop: expected "
            "`ip protocol icmp icmp type { ... } accept`"
        )
        return errors

    configured = {
        item.strip()
        for item in accept_match.group("types").split(",")
        if item.strip()
    }
    missing = sorted(REQUIRED_ICMPV4_CONTROL_TYPES - configured)
    if missing:
        errors.append(
            "ICMPv4 control exemption is missing required types: " + ", ".join(missing)
        )

    drop_match = re.search(
        IPV4_ICMP_PROTOCOL_PATTERN + r"\s+limit\s+rate\s+over\b.*\bdrop\b",
        compact,
    )
    if drop_match is None:
        errors.append("missing generic ICMPv4 flood drop after control exemption")
    elif accept_match.start() > drop_match.start():
        errors.append("ICMPv4 control exemption must appear before generic ICMPv4 flood drop")

    return errors


def validate_icmpv6_control_exemption(path: Path) -> list[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    input_chain = named_block(raw, "chain input")
    if input_chain is None:
        return [f"missing input chain with ICMPv6 control exemption in {path}"]

    errors: list[str] = []
    compact = compact_rule_text(input_chain)
    accept_match = re.search(
        IPV6_ICMP_L4PROTO_PATTERN
        + r"\s+icmpv6\s+type\s+\{(?P<types>[^}]*)\}\s+accept\b",
        compact,
    )
    if accept_match is None:
        errors.append(
            "missing ICMPv6 control exemption before flood backstop: expected "
            "`meta nfproto ipv6 meta l4proto ipv6-icmp icmpv6 type { ... } accept`"
        )
        return errors

    configured = {
        item.strip()
        for item in accept_match.group("types").split(",")
        if item.strip()
    }
    missing = sorted(REQUIRED_ICMPV6_CONTROL_TYPES - configured)
    if missing:
        errors.append(
            "ICMPv6 control exemption is missing required types: " + ", ".join(missing)
        )

    drop_match = re.search(
        IPV6_ICMP_L4PROTO_PATTERN + r"\s+limit\s+rate\s+over\b.*\bdrop\b",
        compact,
    )
    if drop_match is None:
        errors.append("missing generic ICMPv6 flood drop after control exemption")
    elif accept_match.start() > drop_match.start():
        errors.append("ICMPv6 control exemption must appear before generic ICMPv6 flood drop")

    return errors


def validate_connlimit_set_sizes(path: Path) -> list[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    errors: list[str] = []

    for set_name in ("tcp4_connlimit", "tcp6_connlimit"):
        block = nft_set_block(raw, set_name)
        if block is None:
            errors.append(f"missing nftables connlimit set: {set_name}")
            continue
        flags = nft_directive(block, "flags") or ""
        if "dynamic" not in {
            item.strip() for item in re.split(r"[, ]+", flags) if item.strip()
        }:
            errors.append(f"connlimit set {set_name} must use flags dynamic")
        size_text = nft_directive(block, "size")
        if size_text is None or not size_text.isdigit():
            errors.append(
                f"connlimit set {set_name} must define an explicit positive size"
            )
            continue
        size = int(size_text)
        if size <= 0:
            errors.append(f"connlimit set {set_name} size must be greater than zero")
        elif size > MAX_CONNLIMIT_SET_SIZE:
            errors.append(
                f"connlimit set {set_name} size {size} exceeds "
                f"{MAX_CONNLIMIT_SET_SIZE}"
            )

    return errors


def positive_int_config_value(
    value: Any,
    *,
    default: int,
    label: str,
) -> tuple[int | None, str | None]:
    if value is None:
        return default, None
    if isinstance(value, bool) or not isinstance(value, int):
        return None, f"{label} must be an integer"
    if value <= 0:
        return None, f"{label} must be greater than zero"
    return value, None


def public_listener_connection_caps(config: Path) -> tuple[list[tuple[str, int]], list[str]]:
    if not config.exists():
        return [], []
    try:
        data: dict[str, Any] = json.loads(config.read_text(encoding="utf-8"))
    except Exception as err:
        return [], [f"failed to read config {config}: {err}"]

    caps: list[tuple[str, int]] = []
    errors: list[str] = []
    http = data.get("http")
    if isinstance(http, dict) and isinstance(http.get("listen"), str):
        try:
            ip, _ = parse_listen(http["listen"])
        except ValueError as err:
            errors.append(f"http.listen: {err}")
        else:
            if not ip.is_loopback:
                limits = http.get("limits") if isinstance(http.get("limits"), dict) else {}
                value, error = positive_int_config_value(
                    limits.get("max_connections_per_ip"),
                    default=DEFAULT_HTTP_MAX_CONNECTIONS_PER_IP,
                    label="http.limits.max_connections_per_ip",
                )
                if error:
                    errors.append(error)
                elif value is not None:
                    caps.append(("http.listen", value))

    tcp = data.get("tcp")
    if isinstance(tcp, list):
        for idx, item in enumerate(tcp):
            if not isinstance(item, dict) or not isinstance(item.get("listen"), str):
                continue
            label = f"tcp[{idx}]"
            try:
                ip, _ = parse_listen(item["listen"])
            except ValueError as err:
                errors.append(f"{label}.listen: {err}")
                continue
            if ip.is_loopback:
                continue
            limits = item.get("limits") if isinstance(item.get("limits"), dict) else {}
            value, error = positive_int_config_value(
                limits.get("max_connections_per_ip"),
                default=DEFAULT_TCP_MAX_CONNECTIONS_PER_IP,
                label=f"{label}.limits.max_connections_per_ip",
            )
            if error:
                errors.append(error)
            elif value is not None:
                caps.append((f"{label}.listen", value))

    return caps, errors


def protected_port_connlimit_ceiling(config: Path | None = None) -> tuple[int, list[str]]:
    if config is None:
        return MAX_PROTECTED_PORT_CONNLIMIT, []
    caps, errors = public_listener_connection_caps(config)
    if errors:
        return MAX_PROTECTED_PORT_CONNLIMIT, errors
    if not caps:
        return MAX_PROTECTED_PORT_CONNLIMIT, []
    return min(cap for _, cap in caps), []


def validate_connlimit_thresholds(path: Path, config: Path | None = None) -> list[str]:
    if not path.exists():
        return []
    max_allowed, cap_errors = protected_port_connlimit_ceiling(config)
    if cap_errors:
        return cap_errors
    raw = path.read_text(encoding="utf-8")
    input_chain = named_block(raw, "chain input")
    if input_chain is None:
        return [f"missing input chain with protected-port connlimit rules in {path}"]
    compact = compact_rule_text(input_chain)
    errors: list[str] = []
    for set_name in ("tcp4_connlimit", "tcp6_connlimit"):
        match = re.search(
            rf"\badd\s+@{set_name}\s*\{{[^}}]*\bct\s+count\s+over\s+(\d+)\b",
            compact,
        )
        if match is None:
            errors.append(f"missing protected-port connection-count rule for {set_name}")
            continue
        threshold = int(match.group(1))
        if threshold > max_allowed:
            errors.append(
                f"{set_name} ct count over {threshold} exceeds tightest public "
                f"userspace per-IP connection cap {max_allowed}"
            )
    return errors


def nft_duration_seconds(value: str, unit: str) -> int:
    scale = {
        "": 1,
        "s": 1,
        "m": 60,
        "h": 60 * 60,
        "d": 24 * 60 * 60,
    }.get(unit)
    if scale is None:
        raise ValueError(f"unsupported nft duration unit: {unit}")
    return int(value) * scale


def validate_syn_rate_set_bounds(path: Path) -> list[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    errors: list[str] = []

    for set_name in ("tcp4_syn_rate", "tcp6_syn_rate"):
        block = nft_set_block(raw, set_name)
        if block is None:
            errors.append(f"missing nftables SYN rate set: {set_name}")
            continue
        flags_text = nft_directive(block, "flags") or ""
        flags = {
            item.strip()
            for item in re.split(r"[, ]+", flags_text)
            if item.strip()
        }
        if "dynamic" not in flags:
            errors.append(f"SYN rate set {set_name} must use flags dynamic")
        if "timeout" not in flags:
            errors.append(f"SYN rate set {set_name} must use flags timeout")

        size_text = nft_directive(block, "size")
        if size_text is None or not size_text.isdigit():
            errors.append(f"SYN rate set {set_name} must define an explicit positive size")
        else:
            size = int(size_text)
            if size <= 0:
                errors.append(f"SYN rate set {set_name} size must be greater than zero")
            elif size > MAX_SYN_RATE_SET_SIZE:
                errors.append(
                    f"SYN rate set {set_name} size {size} exceeds {MAX_SYN_RATE_SET_SIZE}"
                )

        timeout_text = nft_directive(block, "timeout") or ""
        timeout_match = re.fullmatch(r"(?P<value>\d+)(?P<unit>[smhd]?)", timeout_text)
        if timeout_match is None:
            errors.append(f"SYN rate set {set_name} must define a positive timeout")
        else:
            seconds = nft_duration_seconds(
                timeout_match.group("value"), timeout_match.group("unit")
            )
            if seconds <= 0:
                errors.append(f"SYN rate set {set_name} timeout must be greater than zero")
            elif seconds > MAX_SYN_RATE_SET_TIMEOUT_SECONDS:
                errors.append(
                    f"SYN rate set {set_name} timeout {seconds}s exceeds "
                    f"{MAX_SYN_RATE_SET_TIMEOUT_SECONDS}s"
                )

    return errors


def sysctl_assignments(path: Path) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise ValueError(f"invalid sysctl line: {line}")
        key, value = line.split("=", 1)
        assignments[key.strip()] = value.strip()
    return assignments


def validate_sysctl(path: Path) -> list[str]:
    if not path.exists():
        return [f"missing sysctl template: {path}"]
    try:
        assignments = sysctl_assignments(path)
    except ValueError as err:
        return [str(err)]

    if platform.system() != "Linux":
        return ["non-Linux host; skipped sysctl key existence check"]

    errors: list[str] = []
    sysctl = shutil.which("sysctl")
    if sysctl is None:
        return ["sysctl not found; skipped sysctl key existence check"]
    for key in assignments:
        result = run([sysctl, "-n", key])
        if result.returncode != 0:
            if key in OPTIONAL_MODULE_SYSCTL_KEYS:
                errors.append(
                    f"optional module sysctl key is unavailable on this host; "
                    f"skipped key existence check: {key}"
                )
            else:
                errors.append(f"sysctl key is unavailable on this host: {key}")
    return errors


def validate_ddos_sysctls(sysctl_path: Path) -> list[str]:
    try:
        assignments = sysctl_assignments(sysctl_path)
    except Exception as err:
        return [f"failed to read DDoS sysctls from {sysctl_path}: {err}"]

    errors: list[str] = []
    missing = sorted(set(DDOS_SYSCTL_RULES) - assignments.keys())
    if missing:
        errors.append("missing DDoS host sysctl guardrails: " + ", ".join(missing))

    for key, rule in DDOS_SYSCTL_RULES.items():
        raw_value = assignments.get(key)
        if raw_value is None:
            continue
        try:
            value = int(raw_value)
        except ValueError:
            errors.append(f"{key} must be an integer")
            continue
        exact = rule.get("exact")
        if exact is not None and value != exact:
            errors.append(f"{key}={value} must be exactly {exact}")
            continue
        minimum = rule.get("min")
        if minimum is not None and value < minimum:
            errors.append(f"{key}={value} is lower than DDoS guardrail minimum {minimum}")
        maximum = rule.get("max")
        if maximum is not None and value > maximum:
            errors.append(f"{key}={value} exceeds DDoS guardrail maximum {maximum}")

    return errors


def parse_listen(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or end + 1 >= len(value) or value[end + 1] != ":":
            raise ValueError(f"invalid bracketed listen address: {value}")
        host = value[1:end]
        port_text = value[end + 2 :]
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator or not host or ":" in host:
            raise ValueError(f"invalid listen address: {value}")
    if not port_text.isdigit():
        raise ValueError(f"invalid listen port: {value}")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ValueError(f"listen port out of range: {value}")
    return ipaddress.ip_address(host), port


def config_public_listener_ports(config: Path) -> tuple[set[int], list[str]]:
    if not config.exists():
        return set(), []
    try:
        data: dict[str, Any] = json.loads(config.read_text(encoding="utf-8"))
    except Exception as err:
        return set(), [f"failed to read config {config}: {err}"]

    listeners: list[tuple[str, str]] = []
    http = data.get("http")
    if isinstance(http, dict) and isinstance(http.get("listen"), str):
        listeners.append(("http.listen", http["listen"]))
    tcp = data.get("tcp")
    if isinstance(tcp, list):
        for idx, item in enumerate(tcp):
            if isinstance(item, dict) and isinstance(item.get("listen"), str):
                listeners.append((f"tcp[{idx}].listen", item["listen"]))

    ports: set[int] = set()
    errors: list[str] = []
    for label, listen in listeners:
        try:
            ip, port = parse_listen(listen)
        except ValueError as err:
            errors.append(f"{label}: {err}")
            continue
        if not ip.is_loopback:
            ports.add(port)
    return ports, errors


def port_in_ranges(port: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= port <= end for start, end in ranges)


def validate_edge_port_coverage(config: Path, nft_path: Path) -> list[str]:
    required, config_errors = config_public_listener_ports(config)
    if config_errors:
        return config_errors
    ranges, nft_errors = protected_tcp_port_ranges(nft_path)
    if nft_errors:
        return nft_errors
    missing = sorted(port for port in required if not port_in_ranges(port, ranges))
    if missing:
        return [
            "protected_tcp_ports is missing public AlturaProt listener ports: "
            + ", ".join(str(port) for port in missing)
        ]
    return []


def max_config_backlog(config: Path) -> int | None:
    if not config.exists():
        return None
    data: dict[str, Any] = json.loads(config.read_text(encoding="utf-8"))
    backlogs: list[int] = []
    http = data.get("http")
    if isinstance(http, dict) and isinstance(http.get("listen_backlog"), int):
        backlogs.append(http["listen_backlog"])
    tcp = data.get("tcp")
    if isinstance(tcp, list):
        for item in tcp:
            if isinstance(item, dict) and isinstance(item.get("listen_backlog"), int):
                backlogs.append(item["listen_backlog"])
    return max(backlogs) if backlogs else None


def validate_backlog(config: Path, sysctl_path: Path) -> list[str]:
    try:
        required = max_config_backlog(config)
    except Exception as err:
        return [f"failed to read config {config}: {err}"]
    if required is None:
        return []
    try:
        configured = int(sysctl_assignments(sysctl_path).get("net.core.somaxconn", "0"))
    except Exception as err:
        return [f"failed to read net.core.somaxconn from {sysctl_path}: {err}"]
    if configured < required:
        return [
            f"net.core.somaxconn={configured} is lower than configured listener backlog {required}"
        ]
    return []


def validate_fragment_sysctls(sysctl_path: Path) -> list[str]:
    try:
        assignments = sysctl_assignments(sysctl_path)
    except Exception as err:
        return [f"failed to read fragment sysctls from {sysctl_path}: {err}"]

    errors: list[str] = []
    missing = sorted(REQUIRED_FRAGMENT_SYSCTLS - assignments.keys())
    if missing:
        errors.append(
            "missing fragment reassembly sysctl bounds: " + ", ".join(missing)
        )
        return errors

    parsed: dict[str, int] = {}
    for key in REQUIRED_FRAGMENT_SYSCTLS:
        try:
            value = int(assignments[key])
        except ValueError:
            errors.append(f"{key} must be an integer")
            continue
        if value <= 0:
            errors.append(f"{key} must be greater than zero")
            continue
        parsed[key] = value

    for key in ("net.ipv4.ipfrag_high_thresh", "net.ipv6.ip6frag_high_thresh"):
        value = parsed.get(key)
        if value is not None and value > MAX_FRAGMENT_REASSEMBLY_BYTES:
            errors.append(
                f"{key}={value} exceeds fragment reassembly memory cap "
                f"{MAX_FRAGMENT_REASSEMBLY_BYTES}"
            )

    for key in ("net.ipv4.ipfrag_time", "net.ipv6.ip6frag_time"):
        value = parsed.get(key)
        if value is not None and value > MAX_FRAGMENT_QUEUE_SECONDS:
            errors.append(
                f"{key}={value} exceeds fragment queue retention cap "
                f"{MAX_FRAGMENT_QUEUE_SECONDS}s"
            )

    value = parsed.get("net.ipv4.ipfrag_max_dist")
    if value is not None and value > MAX_FRAGMENT_DISTANCE:
        errors.append(
            f"net.ipv4.ipfrag_max_dist={value} exceeds fragment distance cap "
            f"{MAX_FRAGMENT_DISTANCE}"
        )

    ipv6_low = parsed.get("net.ipv6.ip6frag_low_thresh")
    ipv6_high = parsed.get("net.ipv6.ip6frag_high_thresh")
    if ipv6_low is not None and ipv6_high is not None and ipv6_low > ipv6_high:
        errors.append(
            "net.ipv6.ip6frag_low_thresh must be less than or equal to "
            "net.ipv6.ip6frag_high_thresh"
        )

    return errors


def parse_systemd_unit(path: Path) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if current is None or "=" not in line:
            raise ValueError(f"invalid systemd unit line: {raw_line}")
        key, value = line.split("=", 1)
        sections[current].setdefault(key.strip(), []).append(value.strip())
    return sections


def first_systemd_value(
    section: dict[str, list[str]], key: str, default: str = ""
) -> str:
    values = section.get(key)
    return values[-1] if values else default


def parse_systemd_size(value: str) -> int | None:
    token = value.strip()
    if token.lower() == "infinity":
        return None
    match = re.fullmatch(r"(?P<num>\d+)(?P<unit>[KkMmGgTt]?)", token)
    if match is None:
        raise ValueError(f"invalid systemd size: {value}")
    scale = {
        "": 1,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
    }[match.group("unit").upper()]
    return int(match.group("num")) * scale


def parse_systemd_nofile_hard_limit(value: str) -> int | None:
    token = value.strip()
    if ":" in token:
        parts = [part.strip() for part in token.split(":")]
        if len(parts) != 2 or not all(parts):
            raise ValueError(f"invalid systemd LimitNOFILE: {value}")
        token = parts[1]
    if token.lower() == "infinity":
        return None
    if not re.fullmatch(r"\d+", token):
        raise ValueError(f"invalid systemd LimitNOFILE: {value}")
    return int(token)


def parse_systemd_seconds(value: str) -> float:
    token = value.strip()
    if token.lower() == "infinity":
        return float("inf")
    match = re.fullmatch(r"(?P<num>\d+(?:\.\d+)?)(?P<unit>ms|s|sec|min|m|h|d|w|y)?", token)
    if match is None:
        raise ValueError(f"invalid systemd duration: {value}")
    number = float(match.group("num"))
    unit = match.group("unit") or "s"
    scale = {
        "ms": 0.001,
        "s": 1,
        "sec": 1,
        "min": 60,
        "m": 60,
        "h": 60 * 60,
        "d": 24 * 60 * 60,
        "w": 7 * 24 * 60 * 60,
        "y": 365.25 * 24 * 60 * 60,
    }[unit]
    return number * scale


def config_shutdown_grace_seconds(config: Path) -> float:
    if not config.exists():
        return 0
    data: dict[str, Any] = json.loads(config.read_text(encoding="utf-8"))
    runtime = data.get("runtime")
    if not isinstance(runtime, dict):
        return 0
    value = runtime.get("shutdown_grace_ms", 0)
    return float(value) / 1000 if isinstance(value, (int, float)) else 0


def config_min_nofile(config: Path) -> int:
    if not config.exists():
        return MIN_SYSTEMD_LIMIT_NOFILE
    data: dict[str, Any] = json.loads(config.read_text(encoding="utf-8"))
    runtime = data.get("runtime")
    if not isinstance(runtime, dict):
        return MIN_SYSTEMD_LIMIT_NOFILE
    value = runtime.get("min_nofile", 0)
    if not isinstance(value, int):
        return MIN_SYSTEMD_LIMIT_NOFILE
    return max(MIN_SYSTEMD_LIMIT_NOFILE, value)


def config_capacity_value(
    item: dict[str, Any],
    key: str,
    *,
    default: int,
    label: str,
) -> tuple[int | None, str | None]:
    return positive_int_config_value(
        item.get(key),
        default=default,
        label=label,
    )


def config_nofile_capacity_requirement(config: Path) -> tuple[int | None, list[str]]:
    if not config.exists():
        return None, []
    try:
        data: dict[str, Any] = json.loads(config.read_text(encoding="utf-8"))
    except Exception as err:
        return None, [f"failed to read config {config}: {err}"]

    required = NOFILE_BASE_RESERVE
    errors: list[str] = []

    http = data.get("http")
    if isinstance(http, dict):
        accept_shards, error = config_capacity_value(
            http,
            "accept_shards",
            default=DEFAULT_ACCEPT_SHARDS,
            label="http.accept_shards",
        )
        if error:
            errors.append(error)
        else:
            required += accept_shards or 0

        limits = http.get("limits") if isinstance(http.get("limits"), dict) else {}
        max_connections, error = config_capacity_value(
            limits,
            "max_connections",
            default=DEFAULT_HTTP_MAX_CONNECTIONS,
            label="http.limits.max_connections",
        )
        if error:
            errors.append(error)
        else:
            required += max_connections or 0

        max_in_flight, error = config_capacity_value(
            limits,
            "max_in_flight_requests",
            default=DEFAULT_HTTP_MAX_IN_FLIGHT_REQUESTS,
            label="http.limits.max_in_flight_requests",
        )
        if error:
            errors.append(error)
        else:
            required += max_in_flight or 0

        upstream_idle_pool, error = config_capacity_value(
            http,
            "upstream_pool_max_idle_per_host",
            default=DEFAULT_HTTP_UPSTREAM_POOL_MAX_IDLE_PER_HOST,
            label="http.upstream_pool_max_idle_per_host",
        )
        if error:
            errors.append(error)
        else:
            required += upstream_idle_pool or 0

    tcp = data.get("tcp")
    if isinstance(tcp, list):
        for idx, item in enumerate(tcp):
            if not isinstance(item, dict):
                continue
            accept_shards, error = config_capacity_value(
                item,
                "accept_shards",
                default=DEFAULT_ACCEPT_SHARDS,
                label=f"tcp[{idx}].accept_shards",
            )
            if error:
                errors.append(error)
            else:
                required += accept_shards or 0

            limits = item.get("limits") if isinstance(item.get("limits"), dict) else {}
            max_connections, error = config_capacity_value(
                limits,
                "max_connections",
                default=DEFAULT_TCP_MAX_CONNECTIONS,
                label=f"tcp[{idx}].limits.max_connections",
            )
            if error:
                errors.append(error)
            else:
                active = max_connections or 0
                required += active * 2

    if errors:
        return None, errors
    return required, []


def validate_systemd_unit(path: Path, config: Path) -> list[str]:
    if not path.exists():
        return [f"missing systemd unit template: {path}"]
    try:
        sections = parse_systemd_unit(path)
    except ValueError as err:
        return [str(err)]

    errors: list[str] = []
    service = sections.get("Service")
    if service is None:
        return [f"missing [Service] section in {path}"]

    missing = sorted(key for key in REQUIRED_SYSTEMD_DIRECTIVES if key not in service)
    if missing:
        errors.append("missing systemd service directives: " + ", ".join(missing))

    for key, allowed in REQUIRED_SYSTEMD_SERVICE_VALUES.items():
        value = first_systemd_value(service, key)
        if not value:
            errors.append(f"missing systemd service directive: {key}")
            continue
        if value.lower() not in allowed:
            errors.append(f"{key}={value} is weaker than required values: {sorted(allowed)}")

    user = first_systemd_value(service, "User")
    group = first_systemd_value(service, "Group")
    if user in ("", "root", "0"):
        errors.append("systemd unit must run AlturaProt as a non-root User")
    if group in ("", "root", "0"):
        errors.append("systemd unit must run AlturaProt as a non-root Group")

    try:
        raw_nofile = first_systemd_value(service, "LimitNOFILE", "0")
        nofile = parse_systemd_nofile_hard_limit(raw_nofile)
        capacity_required, capacity_errors = config_nofile_capacity_requirement(config)
        errors.extend(capacity_errors)
        required_nofile = config_min_nofile(config)
        if capacity_required is not None:
            required_nofile = max(required_nofile, capacity_required)
        if nofile is not None and nofile < required_nofile:
            errors.append(
                f"LimitNOFILE={raw_nofile} hard limit {nofile} is lower than "
                f"required descriptor budget {required_nofile}"
            )
    except Exception as err:
        errors.append(f"failed to read systemd LimitNOFILE: {err}")

    try:
        stop_seconds = parse_systemd_seconds(first_systemd_value(service, "TimeoutStopSec", "0"))
        shutdown_grace = config_shutdown_grace_seconds(config)
        if stop_seconds <= shutdown_grace:
            errors.append(
                f"TimeoutStopSec={stop_seconds:g}s must exceed runtime.shutdown_grace_ms "
                f"{shutdown_grace:g}s"
            )
    except Exception as err:
        errors.append(f"failed to read systemd TimeoutStopSec: {err}")

    try:
        tasks = int(first_systemd_value(service, "TasksMax", "0"))
        if tasks <= 0 or tasks > MAX_SYSTEMD_TASKS:
            errors.append(
                f"TasksMax={tasks} must be positive and no higher than {MAX_SYSTEMD_TASKS}"
            )
    except Exception as err:
        errors.append(f"failed to read systemd TasksMax: {err}")

    try:
        memory_high = parse_systemd_size(first_systemd_value(service, "MemoryHigh", ""))
        memory_max = parse_systemd_size(first_systemd_value(service, "MemoryMax", ""))
        if memory_high is None or memory_max is None:
            errors.append("MemoryHigh and MemoryMax must be finite systemd memory limits")
        elif memory_high > memory_max:
            errors.append("MemoryHigh must be less than or equal to MemoryMax")
    except Exception as err:
        errors.append(f"failed to read systemd memory limits: {err}")

    address_families = set(
        first_systemd_value(service, "RestrictAddressFamilies").split()
    )
    required_families = {"AF_UNIX", "AF_INET", "AF_INET6"}
    if not required_families.issubset(address_families):
        errors.append(
            "RestrictAddressFamilies must allow AF_UNIX AF_INET AF_INET6 for "
            "logging, local sockets, and TCP proxying"
        )
    if "AF_PACKET" in address_families or "AF_NETLINK" in address_families:
        errors.append(
            "RestrictAddressFamilies should not allow raw packet/netlink families"
        )

    for key in ("AmbientCapabilities", "CapabilityBoundingSet"):
        caps = set(first_systemd_value(service, key).split())
        if caps != {"CAP_NET_BIND_SERVICE"}:
            errors.append(
                f"{key} must be exactly CAP_NET_BIND_SERVICE so the proxy can bind "
                "privileged ports without broader root capabilities"
            )

    for key in ("StateDirectory", "LogsDirectory", "ConfigurationDirectory"):
        if first_systemd_value(service, key) != "altura-prot":
            errors.append(f"{key} must be set to altura-prot")

    unit = sections.get("Unit", {})
    for key in ("StartLimitIntervalSec", "StartLimitBurst"):
        if key not in unit:
            errors.append(f"missing [Unit] restart storm guard: {key}")

    install = sections.get("Install", {})
    if "multi-user.target" not in first_systemd_value(install, "WantedBy").split():
        errors.append("systemd unit should install into multi-user.target")

    return errors


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    errors.extend(validate_nft(Path(args.nft)))
    errors.extend(validate_protected_tcp_ports(Path(args.nft)))
    errors.extend(validate_udp_protected_port_drop(Path(args.nft)))
    errors.extend(validate_generic_tcp_backstop_protocol_matches(Path(args.nft)))
    errors.extend(validate_ipv6_prefix_backstops(Path(args.nft)))
    errors.extend(validate_ipv6_extension_safe_protocol_matches(Path(args.nft)))
    errors.extend(validate_icmpv4_control_exemption(Path(args.nft)))
    errors.extend(validate_icmpv6_control_exemption(Path(args.nft)))
    errors.extend(validate_connlimit_set_sizes(Path(args.nft)))
    errors.extend(validate_connlimit_thresholds(Path(args.nft), Path(args.config)))
    errors.extend(validate_syn_rate_set_bounds(Path(args.nft)))
    errors.extend(validate_sysctl(Path(args.sysctl)))
    errors.extend(validate_ddos_sysctls(Path(args.sysctl)))
    errors.extend(validate_backlog(Path(args.config), Path(args.sysctl)))
    errors.extend(validate_fragment_sysctls(Path(args.sysctl)))
    errors.extend(validate_systemd_unit(Path(args.systemd), Path(args.config)))
    errors.extend(validate_edge_port_coverage(Path(args.config), Path(args.nft)))

    hard_errors = [item for item in errors if "skipped" not in item]
    for item in errors:
        print(item, file=sys.stderr if item in hard_errors else sys.stdout)
    if hard_errors:
        return 1
    print("edge templates validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
