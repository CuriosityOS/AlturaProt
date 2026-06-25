#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socketserver
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import assert_local_bench
import bench_provenance
import codex_analyzer
import assert_defense_bench
import local_http_flood
import run_local_bench
import run_edge_namespace_smoke
import run_defense_bench
import validate_edge_templates


class CiWorkflowTests(unittest.TestCase):
    def test_ci_lints_all_rust_targets(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("cargo clippy --all-targets -- -D warnings", workflow)

    def test_ci_audits_rust_dependencies(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("cargo install cargo-audit --locked", workflow)
        self.assertIn("cargo audit", workflow)

    def test_ci_requires_defense_bench_provenance(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("tools/assert_defense_bench.py", workflow)
        self.assertIn("--require-provenance", workflow)

    def test_ci_requires_local_bench_provenance(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("tools/bench_provenance.py", workflow)
        self.assertIn("tools/assert_local_bench.py", workflow)
        self.assertIn("--require-provenance", workflow)
        self.assertIn("--min-duration 1", workflow)
        self.assertIn("--min-workers 8", workflow)
        self.assertIn("--min-tcp-workers 4", workflow)
        self.assertIn("--expect-binary target/release/altura-prot", workflow)

    def test_ci_requires_defense_bench_run_strength(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("--expect-provider deterministic", workflow)
        self.assertIn("--expect-preset all", workflow)
        self.assertIn("--min-analyzer-wait 8", workflow)
        self.assertIn("--expect-per-ip-rps 80", workflow)
        self.assertIn("--expect-path-shape-rps 80", workflow)
        self.assertIn("--expect-signature-threshold 60", workflow)
        self.assertIn("--expect-scenario-set \"$expected_scenarios\"", workflow)
        self.assertIn("basic,cachebuster,rotating-path,uuid-path", workflow)
        self.assertIn("catalog-mimic-xff,dictionary-slug-xff", workflow)
        self.assertIn("--expect-common-layer-set \"$expected_common_layers\"", workflow)
        self.assertIn("direct_upstream,proxy_open,rate_limit", workflow)
        self.assertIn(
            "--expect-observed-learning-scenarios \"$expected_observed_learning_scenarios\"",
            workflow,
        )
        self.assertIn("--expect-static-only-scenarios \"$expected_static_only_scenarios\"", workflow)
        self.assertIn("expected_observed_learning_scenarios=smart-api-mix,xff-single", workflow)
        self.assertIn("expected_static_only_scenarios=\n", workflow)
        self.assertIn("--require-direct-baseline", workflow)
        self.assertIn("--require-layer-traffic", workflow)
        self.assertIn("--require-open-proxy-negative-control", workflow)
        self.assertIn("--require-score-consistency", workflow)
        self.assertIn("--require-measured-benign", workflow)

    def test_ci_requires_strict_edge_namespace_smoke(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("sudo apt-get install -y nftables iproute2 util-linux", workflow)
        self.assertIn('sudo git config --global --add safe.directory "$GITHUB_WORKSPACE"', workflow)
        self.assertIn("sudo python3 tools/run_edge_namespace_smoke.py", workflow)
        self.assertIn("--require-provenance \\", workflow)
        self.assertIn("--require-packet-probe > edge-namespace-smoke.json", workflow)

    def test_ci_uploads_benchmark_reports(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("uses: actions/upload-artifact@v4", workflow)
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertIn("name: altura-prot-ci-benchmark-reports", workflow)
        self.assertIn("if-no-files-found: warn", workflow)
        self.assertIn("edge-namespace-smoke.json", workflow)
        self.assertIn("local-bench.json", workflow)
        self.assertIn("defense-bench.json", workflow)

    def test_ci_audits_tracked_defense_artifact_manifest(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertIn("--audit-tracked-artifacts benchmark_results", workflow)
        self.assertIn(
            "--artifact-manifest benchmark_results/defense_artifacts_manifest.json",
            workflow,
        )


class ExampleConfigTests(unittest.TestCase):
    def test_http_connection_open_per_ip_budget_is_below_global_budget(self) -> None:
        cfg = json.loads(Path("configs/example.json").read_text(encoding="utf-8"))
        limits = cfg["http"]["limits"]

        self.assertLess(limits["per_ip_connects_per_second"], limits["global_connects_per_second"])
        self.assertLess(limits["per_ip_connect_burst"], limits["global_connect_burst"])
        self.assertLessEqual(limits["per_ip_connects_per_second"], 200)
        self.assertLessEqual(limits["per_ip_connect_burst"], 400)


class LocalBenchTests(unittest.TestCase):
    def test_local_bench_high_request_configs_override_http_connection_rate(self) -> None:
        source = Path("tools/run_local_bench.py").read_text(encoding="utf-8")

        self.assertEqual(
            run_local_bench.BENCH_HTTP_CONNECTION_LIMITS["per_ip_connects_per_second"],
            1_000_000,
        )
        self.assertEqual(
            run_local_bench.BENCH_HTTP_CONNECTION_LIMITS["per_ip_connect_burst"],
            1_000_000,
        )
        self.assertGreaterEqual(source.count("**BENCH_HTTP_CONNECTION_LIMITS"), 2)

    def test_local_http_flood_default_allows_loopback_literal(self) -> None:
        parsed = local_http_flood.assert_loopback(
            "http://127.0.0.1:8080/path", allow_non_loopback=False
        )

        self.assertEqual(parsed.hostname, "127.0.0.1")

    def test_local_http_flood_default_rejects_owned_lan_literal(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            local_http_flood.assert_loopback(
                "http://192.168.1.20:8080/path", allow_non_loopback=False
            )

        self.assertIn("refusing non-loopback target", str(raised.exception))

    def test_local_http_flood_override_allows_owned_lan_literal(self) -> None:
        parsed = local_http_flood.assert_loopback(
            "http://192.168.1.20:8080/path", allow_non_loopback=True
        )

        self.assertEqual(parsed.hostname, "192.168.1.20")

    def test_local_http_flood_override_rejects_public_literal(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            local_http_flood.assert_loopback(
                "http://8.8.8.8:8080/path", allow_non_loopback=True
            )

        self.assertIn("refusing public or non-local target", str(raised.exception))

    def test_edge_sysctl_template_contains_required_ddos_sysctls(self) -> None:
        template = run_local_bench.edge_sysctl_template()

        for key in validate_edge_templates.DDOS_SYSCTL_RULES:
            self.assertIn(f"{key} = ", template)

    def test_chunked_message_complete_accepts_empty_and_nonempty_trailers(self) -> None:
        self.assertTrue(run_local_bench.chunked_message_complete(b"0\r\n\r\n"))
        self.assertTrue(
            run_local_bench.chunked_message_complete(
                b"5\r\nhello\r\n0\r\nX-Test: ok\r\n\r\n"
            )
        )

    def test_chunked_message_complete_rejects_partial_or_malformed_chunks(self) -> None:
        self.assertFalse(run_local_bench.chunked_message_complete(b"0\r\n"))
        self.assertFalse(
            run_local_bench.chunked_message_complete(b"5\r\nhello0\r\n\r\n")
        )
        self.assertFalse(run_local_bench.chunked_message_complete(b"nope\r\n\r\n"))

    def test_run_flood_resolves_helper_relative_to_benchmark_script(self) -> None:
        calls: list[list[str]] = []
        real_check_output = run_local_bench.subprocess.check_output

        def fake_check_output(cmd: list[str], text: bool) -> str:
            calls.append(cmd)
            self.assertTrue(text)
            return "{}"

        run_local_bench.subprocess.check_output = fake_check_output
        try:
            self.assertEqual(
                run_local_bench.run_flood("http://127.0.0.1:8080/", 4, 1.0),
                {},
            )
        finally:
            run_local_bench.subprocess.check_output = real_check_output

        expected_helper = (
            Path(run_local_bench.__file__).resolve().parent / "local_http_flood.py"
        )
        self.assertEqual(calls[0][1], str(expected_helper))

    def test_first_decodable_json_line_skips_partial_event_log_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(
                '{"partial": true\n{"signature": "valid"}\n',
                encoding="utf-8",
            )

            event = run_local_bench.first_decodable_json_line(path)

        self.assertEqual(event, {"signature": "valid"})

    def test_wait_for_jsonl_event_waits_for_matching_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"path_shape": "/api/:id"}\n', encoding="utf-8")

            def append_target_event() -> None:
                path.write_text(
                    '{"path_shape": "/api/:id"}\n'
                    '{"path_shape": "/api/:short-token"}\n',
                    encoding="utf-8",
                )

            timer = threading.Timer(0.05, append_target_event)
            timer.start()
            try:
                events = run_local_bench.wait_for_jsonl_event(
                    path,
                    lambda event: event.get("path_shape") == "/api/:short-token",
                    1.0,
                )
            finally:
                timer.cancel()

        self.assertTrue(
            any(event.get("path_shape") == "/api/:short-token" for event in events)
        )

    def test_http_max_connection_duration_probe_detects_closed_connection(self) -> None:
        class CloseAfterOneHttp(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                raw = b""
                while b"\r\n\r\n" not in raw:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    raw += chunk
                self.request.sendall(
                    b"HTTP/1.1 204 No Content\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                )

        with socketserver.TCPServer(("127.0.0.1", 0), CloseAfterOneHttp) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = run_local_bench.send_http_max_connection_duration_probe(
                    server.server_address[1], wait_seconds=0.05
                )
            finally:
                server.shutdown()
                thread.join(timeout=1)

        self.assertEqual(result["first_status"], 204)
        self.assertTrue(result["second_closed_or_reset"])

    def test_tcp_max_connection_duration_probe_detects_closed_connection(self) -> None:
        class EchoOnceThenClose(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data = self.request.recv(4096)
                if data:
                    self.request.sendall(data)

        with socketserver.TCPServer(("127.0.0.1", 0), EchoOnceThenClose) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = run_local_bench.send_tcp_max_connection_duration_probe(
                    server.server_address[1], wait_seconds=0.05
                )
            finally:
                server.shutdown()
                thread.join(timeout=1)

        self.assertEqual(result["first_echo_bytes"], len(b"duration-one"))
        self.assertTrue(result["closed_or_reset"])


class LocalBenchAssertionTests(unittest.TestCase):
    @staticmethod
    def valid_provenance() -> dict[str, object]:
        return {
            "generated_at_utc": "2026-06-22T18:26:39Z",
            "source_tree": {
                "cwd": "/repo",
                "git_root": "/repo",
                "git_commit": "0123456789abcdef0123456789abcdef01234567",
                "git_commit_short": "0123456789ab",
                "git_branch": "main",
                "git_dirty": True,
            },
        }

    @staticmethod
    def valid_report() -> dict:
        report = {
            "proxy": {"errors": 0, "requests": 1},
            "health": {"errors": 0, "requests": 1},
            "tcp": {"errors": 0, "messages": 1},
            "guardrails": {},
        }
        for dotted_path, _ in assert_local_bench.REQUIRED_TRUE_CHECKS:
            target = report
            parts = dotted_path.split(".")
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = True
        for dotted_path, expected, _ in assert_local_bench.REQUIRED_VALUE_CHECKS:
            target = report
            parts = dotted_path.split(".")
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = expected
        return report

    def test_assert_local_bench_accepts_required_guardrails(self) -> None:
        report = self.valid_report()

        self.assertEqual(assert_local_bench.assert_report(report), [])
        summary = assert_local_bench.passing_guardrail_summary(report)
        self.assertTrue(
            any("short_token_sibling_churn_limited" in line for line in summary)
        )

    def test_assert_local_bench_accepts_required_provenance(self) -> None:
        report = {**self.valid_report(), **self.valid_provenance()}

        self.assertEqual(assert_local_bench.assert_report(report, require_provenance=True), [])

    def test_assert_local_bench_accepts_required_run_strength(self) -> None:
        report = {
            **self.valid_report(),
            "duration_seconds": 1.0,
            "workers": 8,
            "tcp_workers": 4,
            "binary": "target/release/altura-prot",
        }

        self.assertEqual(
            assert_local_bench.assert_report(
                report,
                min_duration=1,
                min_workers=8,
                min_tcp_workers=4,
                expect_binary="target/release/altura-prot",
            ),
            [],
        )

    def test_assert_local_bench_rejects_weak_run_strength(self) -> None:
        report = {
            **self.valid_report(),
            "duration_seconds": 0.5,
            "workers": 7,
            "tcp_workers": 3,
            "binary": "target/debug/altura-prot",
        }

        errors = assert_local_bench.assert_report(
            report,
            min_duration=1,
            min_workers=8,
            min_tcp_workers=4,
            expect_binary="target/release/altura-prot",
        )

        self.assertIn("report duration_seconds must be >= 1, found 0.5", errors)
        self.assertIn("report workers must be >= 8, found 7", errors)
        self.assertIn("report tcp_workers must be >= 4, found 3", errors)
        self.assertIn(
            "report binary expected 'target/release/altura-prot', found 'target/debug/altura-prot'",
            errors,
        )

    def test_assert_local_bench_rejects_missing_required_provenance(self) -> None:
        report = self.valid_report()

        errors = assert_local_bench.assert_report(report, require_provenance=True)

        self.assertIn("report missing generated_at_utc provenance timestamp", errors)
        self.assertIn("report missing source_tree provenance object", errors)

    def test_assert_local_bench_rejects_copied_tree_when_provenance_required(self) -> None:
        report = {
            **self.valid_report(),
            "generated_at_utc": "2026-06-22T18:26:39Z",
            "source_tree": {
                "cwd": "/copied-tree",
                "git_root": None,
                "git_commit": None,
                "git_commit_short": None,
                "git_branch": None,
                "git_dirty": None,
            },
        }

        errors = assert_local_bench.assert_report(report, require_provenance=True)

        self.assertIn("report source_tree.git_root must be a non-empty string", errors)
        self.assertIn("report source_tree.git_commit must be a full Git object id", errors)
        self.assertIn("report source_tree.git_dirty must be a boolean", errors)

    def test_assert_local_bench_rejects_failed_guardrail(self) -> None:
        report = self.valid_report()
        report["guardrails"]["path_shape_rate"][
            "short_token_sibling_churn_limited"
        ] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("short_token_sibling_churn_limited", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_failed_runtime_sigterm_probe(self) -> None:
        report = self.valid_report()
        report["guardrails"]["runtime_sigterm"]["sigterm_graceful"] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("runtime_sigterm.sigterm_graceful", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_failed_event_log_rotation_probe(self) -> None:
        report = self.valid_report()
        report["guardrails"]["event_log_rotation"]["total_bytes_bounded"] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("event_log_rotation.total_bytes_bounded", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_missing_edge_udp_drop_guardrail(self) -> None:
        report = self.valid_report()
        report["guardrails"]["edge_template_port_coverage"][
            "missing_udp_drop_rejected"
        ] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("missing_udp_drop_rejected", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_missing_ipv6_l4proto_guardrail(self) -> None:
        report = self.valid_report()
        report["guardrails"]["edge_template_port_coverage"][
            "missing_ipv6_connlimit_l4proto_rejected"
        ] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("missing_ipv6_connlimit_l4proto_rejected", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_invalid_fragment_sysctl_guardrail(self) -> None:
        report = self.valid_report()
        report["guardrails"]["edge_template_port_coverage"][
            "invalid_fragment_thresholds_rejected"
        ] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("invalid_fragment_thresholds_rejected", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_admin_rate_limit_bypass(self) -> None:
        report = self.valid_report()
        report["guardrails"]["admin_rate_limit"]["statuses"] = [200, 200]

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("admin_rate_limit.statuses", errors[0])
        self.assertIn("expected [200, 429]", errors[0])

    def test_assert_local_bench_rejects_admin_signature_rate_bypass(self) -> None:
        report = self.valid_report()
        report["guardrails"]["admin_signature_rate"][
            "admin_health_signature_limited"
        ] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("admin_health_signature_limited", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_post_grace_tcp_echo(self) -> None:
        report = self.valid_report()
        report["guardrails"]["tcp_min_rate"]["slow_drip"]["second_echo_bytes"] = 1

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("slow_drip.second_echo_bytes", errors[0])
        self.assertIn("expected 0", errors[0])

    def test_assert_local_bench_rejects_banked_body_min_rate_bypass(self) -> None:
        report = self.valid_report()
        report["guardrails"]["body_min_rate"]["request_banked_min_rate_rejected"] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("request_banked_min_rate_rejected", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_unbounded_adaptive_windows(self) -> None:
        report = self.valid_report()
        report["guardrails"]["adaptive_window_cap"]["signature_windows_bounded"] = False

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("signature_windows_bounded", errors[0])
        self.assertIn("expected true", errors[0])

    def test_assert_local_bench_rejects_surface_errors(self) -> None:
        report = self.valid_report()
        report["proxy"]["errors"] = 1
        report["tcp"]["messages"] = 0

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 2)
        self.assertTrue(any("proxy: expected errors=0" in error for error in errors))
        self.assertTrue(any("tcp: expected messages>0" in error for error in errors))

    def test_assert_local_bench_rejects_malformed_surface_counters(self) -> None:
        report = self.valid_report()
        report["proxy"]["errors"] = "0"
        report["tcp"]["messages"] = "10"

        errors = assert_local_bench.assert_report(report)

        self.assertEqual(len(errors), 2)
        self.assertTrue(any("proxy: errors must be numeric" in error for error in errors))
        self.assertTrue(any("tcp: messages must be numeric" in error for error in errors))


class EdgeNamespaceSmokeTests(unittest.TestCase):
    @staticmethod
    def valid_provenance() -> dict[str, object]:
        return {
            "generated_at_utc": "2026-06-22T18:26:39Z",
            "source_tree": {
                "cwd": "/repo",
                "git_root": "/repo",
                "git_commit": "a" * 40,
                "git_commit_short": "a" * 12,
                "git_branch": "main",
                "git_dirty": True,
            },
        }

    @staticmethod
    def valid_edge_smoke_report() -> dict[str, object]:
        return {
            "skipped": False,
            "nft_loaded": True,
            "listed_edge_table": True,
            "protected_tcp_ports_present": True,
            "tcp4_connlimit_present": True,
            "tcp6_connlimit_present": True,
            "syn_rate_sets_timeout_bounded": True,
            "tcp_invalid_null_drop_present": True,
            "tcp_invalid_xmas_drop_present": True,
            "tcp4_syn_backstop_present": True,
            "ipv6_prefix_syn_backstop_present": True,
            "global_syn_backstop_present": True,
            "ct_invalid_drop_present": True,
            "new_non_syn_drop_present": True,
            "tcp4_connlimit_rule_present": True,
            "ipv6_prefix_connlimit_present": True,
            "tcp6_connlimit_rule_present": True,
            "udp_protected_port_drop_present": True,
            "udp_protected_port_drop_extension_safe_source": True,
            "icmpv4_control_exemption_present": True,
            "icmpv4_flood_drop_present": True,
            "icmpv6_control_exemption_present": True,
            "icmpv6_flood_drop_present": True,
        }

    @staticmethod
    def valid_edge_packet_probe_report() -> dict[str, object]:
        return {
            "skipped": False,
            "tcp_clean_connect_allowed": True,
            "tcp_clean_connect_payload": "ok",
            "tcp_clean_connect_error": None,
            "udp_protected_port_silently_dropped": True,
            "udp_protected_port_result": "timeout",
            "tcp_connlimit_enforced": True,
            "tcp_connlimit_attempts": 140,
            "tcp_connlimit_successes": 128,
            "tcp_connlimit_failures": 12,
            "tcp_connlimit_failure_tail": ["TimeoutError:timed out"],
            "ipv6_tcp_clean_connect_allowed": True,
            "ipv6_tcp_clean_connect_payload": "ok",
            "ipv6_tcp_clean_connect_error": None,
            "ipv6_udp_protected_port_silently_dropped": True,
            "ipv6_udp_protected_port_result": "timeout",
            "ipv6_tcp_connlimit_enforced": True,
            "ipv6_tcp_connlimit_attempts": 140,
            "ipv6_tcp_connlimit_successes": 128,
            "ipv6_tcp_connlimit_failures": 12,
            "ipv6_tcp_connlimit_failure_tail": ["TimeoutError:timed out"],
            "ipv6_hop_by_hop_udp_packet_sent": True,
            "ipv6_hop_by_hop_udp_sent_bytes": 71,
            "ipv6_hop_by_hop_udp_protected_port_silently_dropped": True,
            "ipv6_hop_by_hop_udp_icmpv6_replies": [],
            "ipv6_hop_by_hop_udp_port_unreachable_replies": [],
        }

    def test_assert_edge_namespace_smoke_accepts_loaded_template(self) -> None:
        report = self.valid_edge_smoke_report()

        self.assertEqual(run_edge_namespace_smoke.assert_smoke_result(report), [])

    def test_assert_edge_namespace_smoke_accepts_required_packet_probe(self) -> None:
        report = self.valid_edge_smoke_report()
        report["packet_probe"] = self.valid_edge_packet_probe_report()

        self.assertEqual(
            run_edge_namespace_smoke.assert_smoke_result(
                report,
                require_packet_probe=True,
            ),
            [],
        )

    def test_assert_edge_namespace_smoke_rejects_missing_required_packet_probe(self) -> None:
        report = self.valid_edge_smoke_report()

        errors = run_edge_namespace_smoke.assert_smoke_result(
            report,
            require_packet_probe=True,
        )

        self.assertIn("packet probe required but report missing packet_probe object", errors)

    def test_assert_edge_namespace_smoke_rejects_skipped_required_packet_probe(self) -> None:
        report = self.valid_edge_smoke_report()
        report["packet_probe"] = {"skipped": True, "reason": "ip netns failed"}

        errors = run_edge_namespace_smoke.assert_smoke_result(
            report,
            require_packet_probe=True,
        )

        self.assertIn("packet probe skipped: 'ip netns failed'", errors)

    def test_assert_edge_namespace_smoke_rejects_failed_packet_probe(self) -> None:
        report = self.valid_edge_smoke_report()
        packet_probe = self.valid_edge_packet_probe_report()
        packet_probe["udp_protected_port_silently_dropped"] = False
        packet_probe["udp_protected_port_result"] = "oserror:111:ConnectionRefusedError"
        report["packet_probe"] = packet_probe

        errors = run_edge_namespace_smoke.assert_smoke_result(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("packet_probe.udp_protected_port_silently_dropped", errors[0])

    def test_assert_edge_namespace_smoke_rejects_failed_connlimit_probe(self) -> None:
        report = self.valid_edge_smoke_report()
        packet_probe = self.valid_edge_packet_probe_report()
        packet_probe["tcp_connlimit_enforced"] = False
        packet_probe["tcp_connlimit_successes"] = 140
        packet_probe["tcp_connlimit_failures"] = 0
        report["packet_probe"] = packet_probe

        errors = run_edge_namespace_smoke.assert_smoke_result(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("packet_probe.tcp_connlimit_enforced", errors[0])

    def test_assert_edge_namespace_smoke_rejects_failed_ipv6_connlimit_probe(self) -> None:
        report = self.valid_edge_smoke_report()
        packet_probe = self.valid_edge_packet_probe_report()
        packet_probe["ipv6_tcp_connlimit_enforced"] = False
        packet_probe["ipv6_tcp_connlimit_successes"] = 140
        packet_probe["ipv6_tcp_connlimit_failures"] = 0
        report["packet_probe"] = packet_probe

        errors = run_edge_namespace_smoke.assert_smoke_result(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("packet_probe.ipv6_tcp_connlimit_enforced", errors[0])

    def test_assert_edge_namespace_smoke_rejects_failed_hop_by_hop_udp_probe(self) -> None:
        report = self.valid_edge_smoke_report()
        packet_probe = self.valid_edge_packet_probe_report()
        packet_probe["ipv6_hop_by_hop_udp_protected_port_silently_dropped"] = False
        packet_probe["ipv6_hop_by_hop_udp_port_unreachable_replies"] = [
            {"type": 1, "code": 4, "source": "fd00:230::1", "destination": "fd00:230::2"}
        ]
        report["packet_probe"] = packet_probe

        errors = run_edge_namespace_smoke.assert_smoke_result(report)

        self.assertEqual(len(errors), 1)
        self.assertIn(
            "packet_probe.ipv6_hop_by_hop_udp_protected_port_silently_dropped",
            errors[0],
        )

    def test_packet_probe_ready_line_reader_returns_ready_line(self) -> None:
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "r", encoding="utf-8") as reader:
            with os.fdopen(write_fd, "w", encoding="utf-8") as writer:
                writer.write("ready\n")
                writer.flush()

                self.assertEqual(
                    run_edge_namespace_smoke.read_line_with_timeout(reader, 0.1),
                    "ready\n",
                )

    def test_packet_probe_ready_line_reader_times_out(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(read_fd, "r", encoding="utf-8") as reader:
                self.assertIsNone(
                    run_edge_namespace_smoke.read_line_with_timeout(reader, 0.01)
                )
        finally:
            os.close(write_fd)

    def test_assert_edge_namespace_smoke_accepts_required_provenance(self) -> None:
        report = {**self.valid_edge_smoke_report(), **self.valid_provenance()}

        self.assertEqual(
            run_edge_namespace_smoke.assert_smoke_result(report, require_provenance=True),
            [],
        )

    def test_assert_edge_namespace_smoke_rejects_missing_required_provenance(self) -> None:
        report = self.valid_edge_smoke_report()

        errors = run_edge_namespace_smoke.assert_smoke_result(report, require_provenance=True)

        self.assertIn("report missing generated_at_utc provenance timestamp", errors)
        self.assertIn("report missing source_tree provenance object", errors)

    def test_assert_edge_namespace_smoke_rejects_missing_ipv6_backstop(self) -> None:
        report = self.valid_edge_smoke_report()
        report["ipv6_prefix_connlimit_present"] = False

        errors = run_edge_namespace_smoke.assert_smoke_result(report)

        self.assertEqual(len(errors), 1)
        self.assertIn("ipv6_prefix_connlimit_present", errors[0])

    def test_assert_edge_namespace_smoke_allows_explicit_skip(self) -> None:
        report = run_edge_namespace_smoke.skip_report(["nft"])

        self.assertEqual(run_edge_namespace_smoke.assert_smoke_result(report), [])
        self.assertTrue(report["skipped"])

    def test_assert_edge_namespace_smoke_requires_provenance_on_skip(self) -> None:
        report = run_edge_namespace_smoke.skip_report(["nft"])

        errors = run_edge_namespace_smoke.assert_smoke_result(report, require_provenance=True)

        self.assertIn("report missing generated_at_utc provenance timestamp", errors)
        self.assertIn("report missing source_tree provenance object", errors)

    def test_run_edge_namespace_smoke_reports_timeout(self) -> None:
        original_run = run_edge_namespace_smoke.subprocess.run

        def fake_run(*_args: object, **_kwargs: object) -> object:
            raise run_edge_namespace_smoke.subprocess.TimeoutExpired(
                cmd=["unshare"],
                timeout=1,
                output=b"partial stdout",
                stderr=b"partial stderr",
            )

        run_edge_namespace_smoke.subprocess.run = fake_run  # type: ignore[assignment]
        try:
            report = run_edge_namespace_smoke.run_namespace_smoke(Path("edge.nft"), timeout_seconds=1)
        finally:
            run_edge_namespace_smoke.subprocess.run = original_run  # type: ignore[assignment]

        self.assertFalse(report["skipped"])
        self.assertTrue(report["timed_out"])
        self.assertEqual(report["timeout_seconds"], 1)
        self.assertEqual(report["stdout"], "partial stdout")
        self.assertEqual(report["stderr"], "partial stderr")
        self.assertFalse(report["nft_loaded"])
        self.assertTrue(run_edge_namespace_smoke.assert_smoke_result(report))


class AnalyzerTests(unittest.TestCase):
    def test_read_events_includes_rotated_logs_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "attack_events.jsonl"
            (Path(tmp) / "attack_events.jsonl.2").write_text(
                json.dumps({"signature": "oldest"}) + "\n",
                encoding="utf-8",
            )
            (Path(tmp) / "attack_events.jsonl.1").write_text(
                json.dumps({"signature": "middle"}) + "\n",
                encoding="utf-8",
            )
            (Path(tmp) / "attack_events.jsonl.bad").write_text(
                json.dumps({"signature": "ignored"}) + "\n",
                encoding="utf-8",
            )
            path.write_text(json.dumps({"signature": "newest"}) + "\n", encoding="utf-8")

            events = codex_analyzer.read_events(path, max_events=2)

        self.assertEqual([event["signature"] for event in events], ["middle", "newest"])

    def test_deterministic_filters_are_adaptive_signature_rules(self) -> None:
        events = [
            {"signature": "abc", "path": "/x", "user_agent": "bench", "reason": "per_ip_rate_limited"},
            {"signature": "abc", "path": "/x", "user_agent": "bench", "reason": "per_ip_rate_limited"},
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45)
        self.assertEqual(len(filters), 1)
        clean = codex_analyzer.sanitize_filter(filters[0], ttl_seconds=45)
        self.assertTrue(clean["adaptive"])
        self.assertEqual(clean["ttl_seconds"], 45)
        self.assertEqual(clean["condition"]["signature"], "abc")
        self.assertEqual(clean["action"]["status"], 403)

    def test_sanitize_filter_clamps_ttl_seconds_to_server_ceiling(self) -> None:
        clean = codex_analyzer.sanitize_filter(
            {
                "id": "ttl",
                "ttl_seconds": codex_analyzer.FILTER_TTL_MAX_SECONDS + 1,
                "condition": {"signature": "abc"},
            },
            ttl_seconds=45,
        )

        self.assertEqual(clean["ttl_seconds"], codex_analyzer.FILTER_TTL_MAX_SECONDS)

    def test_sanitize_filter_uses_positive_fallback_for_bad_ttl_seconds(self) -> None:
        clean = codex_analyzer.sanitize_filter(
            {
                "id": "ttl",
                "ttl_seconds": 0,
                "condition": {"signature": "abc"},
            },
            ttl_seconds=45,
        )

        self.assertEqual(clean["ttl_seconds"], 45)

    def test_sanitize_filter_drops_catch_all_path_prefixes(self) -> None:
        for path_prefix in ["", "/"]:
            with self.subTest(path_prefix=path_prefix):
                clean = codex_analyzer.sanitize_filter(
                    {
                        "id": "root-prefix",
                        "condition": {"path_prefix": path_prefix, "signature": "abc"},
                    },
                    ttl_seconds=45,
                )

                self.assertNotIn("path_prefix", clean["condition"])
                self.assertEqual(clean["condition"]["signature"], "abc")

    def test_build_prompt_clamps_ttl_seconds_to_server_ceiling(self) -> None:
        prompt = codex_analyzer.build_prompt(
            [],
            min_count=1,
            ttl_seconds=codex_analyzer.FILTER_TTL_MAX_SECONDS + 1,
        )

        self.assertEqual(prompt["ttl_seconds"], codex_analyzer.FILTER_TTL_MAX_SECONDS)

    def test_observed_only_events_do_not_learn_by_default(self) -> None:
        events = [
            {"signature": "abc", "path": "/x", "user_agent": "bench", "reason": "observed"},
            {"signature": "abc", "path": "/x", "user_agent": "bench", "reason": "observed"},
        ]
        self.assertEqual(codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45), [])
        self.assertEqual(
            len(codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45, learn_observed=True)),
            1,
        )

    def test_merge_strong_coverage_adds_missing_signatures(self) -> None:
        events = [
            {"signature": "covered", "path": "/a", "user_agent": "bench", "reason": "per_ip_rate_limited"},
            {"signature": "missing", "path": "/b", "user_agent": "bench", "reason": "per_ip_rate_limited"},
        ]
        provider_filters = [
            {
                "id": "provider-covered",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "covered"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        merged = codex_analyzer.merge_strong_coverage(provider_filters, events, min_count=1, ttl_seconds=20)
        signatures = {item["condition"]["signature"] for item in merged}
        self.assertEqual(signatures, {"covered", "missing"})

    def test_merge_coverage_adds_observed_filters_when_enabled(self) -> None:
        events = [
            {
                "signature": "sig-a",
                "path": "/api/abcdefghij/1",
                "path_shape": "/api/:token/:num",
                "user_agent": "bench",
                "reason": "observed",
            },
            {
                "signature": "sig-b",
                "path": "/api/klmnopqrst/2",
                "path_shape": "/api/:token/:num",
                "user_agent": "bench",
                "reason": "observed",
            },
        ]
        strict = codex_analyzer.merge_strong_coverage([], events, min_count=2, ttl_seconds=20)
        observed = codex_analyzer.merge_strong_coverage(
            [],
            events,
            min_count=2,
            ttl_seconds=20,
            learn_observed=True,
        )
        self.assertEqual(strict, [])
        self.assertIn(
            "/api/:token/:num",
            {
                item["condition"].get("path_shape")
                for item in observed
                if isinstance(item.get("condition"), dict)
            },
        )

    def test_merge_existing_filters_preserves_dormant_rules(self) -> None:
        existing = [
            {
                "id": "old",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "oldsig"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        new = [
            {
                "id": "new",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "newsig"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        merged = codex_analyzer.merge_existing_filters(existing, new, ttl_seconds=20, max_filters=10)
        self.assertEqual({item["condition"]["signature"] for item in merged}, {"oldsig", "newsig"})

    def test_merge_existing_filters_replaces_same_signature(self) -> None:
        existing = [
            {
                "id": "old",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "same"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        new = [
            {
                "id": "new",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "same"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        merged = codex_analyzer.merge_existing_filters(existing, new, ttl_seconds=20, max_filters=10)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "new")

    def test_merge_existing_filters_cap_prefers_new_rules(self) -> None:
        existing = [
            {
                "id": f"old-{idx}",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": f"old-{idx}"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
            for idx in range(3)
        ]
        new = [
            {
                "id": "new",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "new"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        merged = codex_analyzer.merge_existing_filters(existing, new, ttl_seconds=20, max_filters=3)
        self.assertEqual(len(merged), 3)
        self.assertIn("new", {item["condition"]["signature"] for item in merged})

    def test_provider_config_merges_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providers.json"
            path.write_text(json.dumps({"selected_provider": "openrouter", "providers": {"openrouter": {"model": "x/y"}}}))
            cfg = codex_analyzer.load_provider_config(path)
            provider = codex_analyzer.provider_config(cfg, "openrouter")
            self.assertEqual(cfg["selected_provider"], "openrouter")
            self.assertEqual(provider["model"], "x/y")
            self.assertEqual(provider["base_url"], "https://openrouter.ai/api/v1")

    def test_codex_defaults_are_gpt55_high_fast(self) -> None:
        cfg = codex_analyzer.load_provider_config(Path("/tmp/nonexistent-altura-provider-config.json"))
        provider = codex_analyzer.provider_config(cfg, "codex")
        self.assertEqual(provider["model"], "gpt-5.5")
        self.assertEqual(provider["reasoning_effort"], "high")
        self.assertEqual(provider["service_tier"], "fast")

    def test_deterministic_filters_learn_catalog_shape_when_route_family_is_hot(self) -> None:
        events = [
            {
                "signature": "sig-a",
                "path": "/api/catalog/1",
                "path_shape": "/api/catalog/:num",
                "user_agent": "bench",
                "reason": "observed",
            },
            {
                "signature": "sig-b",
                "path": "/api/catalog/2",
                "path_shape": "/api/catalog/:num",
                "user_agent": "bench",
                "reason": "observed",
            },
        ]
        filters = codex_analyzer.deterministic_filters(
            events, min_count=2, ttl_seconds=45, learn_observed=True
        )
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["condition"]["path_shape"], "/api/catalog/:num")

    def test_deterministic_filters_learn_precise_benign_shape_runtime_signatures(self) -> None:
        events = [
            {
                "signature": "sig-a",
                "path": "/api/catalog/1",
                "path_shape": "/api/catalog/:num",
                "signature_basis": "GET|/api/catalog/:num|page,sort|curl|*/*",
                "user_agent": "bench",
                "reason": "observed",
            },
            {
                "signature": "sig-a",
                "path": "/api/catalog/2",
                "path_shape": "/api/catalog/:num",
                "signature_basis": "GET|/api/catalog/:num|page,sort|curl|*/*",
                "user_agent": "bench",
                "reason": "observed",
            },
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45, learn_observed=True)
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["condition"]["signature"], "sig-a")

    def test_deterministic_filters_learn_dictionary_slug_path_shape(self) -> None:
        events = [
            {
                "signature": "sig-a",
                "path": "/api/subscription/1",
                "path_shape": "/api/subscription/:num",
                "user_agent": "bench",
                "reason": "global_observed",
            },
            {
                "signature": "sig-b",
                "path": "/api/subscription/2",
                "path_shape": "/api/subscription/:num",
                "user_agent": "bench",
                "reason": "global_observed",
            },
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45)
        shapes = {
            item["condition"].get("path_shape")
            for item in filters
            if isinstance(item.get("condition"), dict)
        }
        self.assertIn("/api/subscription/:num", shapes)

    def test_deterministic_filters_learn_path_shape_for_polymorphic_events(self) -> None:
        events = [
            {
                "signature": "sig-a",
                "path": "/api/abcdefghij/1",
                "path_shape": "/api/:token/:num",
                "user_agent": "bench",
                "reason": "global_observed",
            },
            {
                "signature": "sig-b",
                "path": "/api/klmnopqrst/2",
                "path_shape": "/api/:token/:num",
                "user_agent": "bench",
                "reason": "global_observed",
            },
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45)
        self.assertEqual(len(filters), 1)
        clean = codex_analyzer.sanitize_filter(filters[0], ttl_seconds=45)
        self.assertEqual(clean["condition"]["path_shape"], "/api/:token/:num")

    def test_deterministic_filters_learn_short_token_path_shape_for_polymorphic_events(self) -> None:
        events = [
            {
                "signature": "a",
                "path": "/api/ab",
                "path_shape": "/api/:short-token",
                "user_agent": "bench",
                "reason": "global_observed",
            },
            {
                "signature": "b",
                "path": "/api/cd",
                "path_shape": "/api/:short-token",
                "user_agent": "bench",
                "reason": "global_observed",
            },
        ]

        filters = codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45)
        clean = codex_analyzer.sanitize_filter(filters[0], ttl_seconds=45)

        self.assertEqual(clean["condition"]["path_shape"], "/api/:short-token")

    def test_body_too_large_events_are_strong_evidence(self) -> None:
        events = [
            {
                "signature": "sig-body",
                "path": "/upload",
                "user_agent": "bench",
                "reason": "body_too_large",
            }
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=1, ttl_seconds=45)
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["condition"]["signature"], "sig-body")

    def test_signature_rate_limited_events_are_strong_evidence(self) -> None:
        events = [
            {
                "signature": "sig-hot",
                "path": "/hot",
                "user_agent": "bench",
                "reason": "signature_rate_limited",
            }
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=1, ttl_seconds=45)
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["condition"]["signature"], "sig-hot")

    def test_trusted_proxy_rate_limited_events_are_strong_evidence(self) -> None:
        events = [
            {
                "signature": "sig-edge",
                "path": "/api/login",
                "path_shape": "/api/login",
                "user_agent": "bench",
                "reason": "trusted_proxy_rate_limited",
            }
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=1, ttl_seconds=45)
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["condition"]["signature"], "sig-edge")

    def test_path_shape_rate_limited_events_are_strong_evidence(self) -> None:
        events = [
            {
                "signature": "sig-a",
                "path": "/api/abcdefghij/1",
                "path_shape": "/api/:token/:num",
                "user_agent": "bench",
                "reason": "path_shape_rate_limited",
            },
            {
                "signature": "sig-b",
                "path": "/api/klmnopqrst/2",
                "path_shape": "/api/:token/:num",
                "user_agent": "bench",
                "reason": "path_shape_rate_limited",
            },
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45)
        shapes = {
            item["condition"].get("path_shape")
            for item in filters
            if isinstance(item.get("condition"), dict)
        }
        self.assertIn("/api/:token/:num", shapes)

    def test_api_key_prefers_environment(self) -> None:
        old = os.environ.get("ALTURA_TEST_KEY")
        os.environ["ALTURA_TEST_KEY"] = "from-env"
        try:
            self.assertEqual(
                codex_analyzer.provider_api_key("openai", {"api_key_env": "ALTURA_TEST_KEY"}),
                "from-env",
            )
        finally:
            if old is None:
                os.environ.pop("ALTURA_TEST_KEY", None)
            else:
                os.environ["ALTURA_TEST_KEY"] = old


class DefenseBenchTests(unittest.TestCase):
    def valid_provenance(self) -> dict[str, object]:
        return {
            "generated_at_utc": "2026-06-22T18:26:39Z",
            "source_tree": {
                "cwd": "/repo",
                "git_root": "/repo",
                "git_commit": "0123456789abcdef0123456789abcdef01234567",
                "git_commit_short": "0123456789ab",
                "git_branch": "main",
                "git_dirty": True,
            },
        }

    def valid_defense_report(self) -> dict[str, object]:
        return {
            **self.valid_provenance(),
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "bypass_probe": {
                            "requests": 20,
                            "errors": 0,
                            "hung_workers": 0,
                            "allowed_percent": 100.0,
                        },
                        "effective_target_score": {
                            "attacker_block_target_percent": 90.0,
                            "benign_allow_target_percent": 95.0,
                            "attacker_blocked_or_limited_percent": 98.0,
                            "benign_allowed_percent": 100.0,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                        }
                    }
                }
            },
        }

    def test_defense_artifact_audit_accepts_labeled_historical_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            current_path = Path(tmp) / "defense_bench_current.json"
            legacy_path = Path(tmp) / "defense_bench_legacy.json"
            manifest_path = Path(tmp) / "defense_artifacts_manifest.json"
            current_path.write_text(json.dumps(self.valid_defense_report()), encoding="utf-8")
            legacy_path.write_text(
                json.dumps(
                    {
                        "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
                        "scenarios": {
                            "basic": {
                                "rate_limit": {
                                    "target_score": {
                                        "meets_attacker_block_target": True,
                                        "meets_benign_allow_target": True,
                                        "bypass_errors": 0,
                                    }
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            manifest_path.write_text(
                json.dumps(
                    {
                        "historical_artifacts": {
                            "defense_bench_legacy.json": "pre-provenance fixture"
                        }
                    }
                ),
                encoding="utf-8",
            )

            reasons, manifest_errors = (
                assert_defense_bench.load_historical_artifact_reasons(manifest_path)
            )
            errors = assert_defense_bench.artifact_audit_errors(
                [current_path, legacy_path],
                reasons,
            )

        self.assertEqual(manifest_errors, [])
        self.assertEqual(errors, [])

    def test_defense_artifact_audit_rejects_unlabeled_stale_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            legacy_path = Path(tmp) / "defense_bench_legacy.json"
            legacy_path.write_text(
                json.dumps(
                    {
                        "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
                        "scenarios": {
                            "basic": {
                                "rate_limit": {
                                    "target_score": {
                                        "meets_attacker_block_target": True,
                                        "meets_benign_allow_target": True,
                                        "bypass_errors": 0,
                                    }
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            errors = assert_defense_bench.artifact_audit_errors([legacy_path], {})

        self.assertEqual(len(errors), 1)
        self.assertIn("not current-verifiable", errors[0])
        self.assertIn("not labeled historical", errors[0])
        self.assertIn("report missing generated_at_utc provenance timestamp", errors[0])

    def test_defense_artifact_audit_rejects_stale_manifest_entries(self) -> None:
        errors = assert_defense_bench.artifact_audit_errors(
            [],
            {"defense_bench_missing.json": "stale manifest entry"},
        )

        self.assertEqual(
            errors,
            [
                "historical artifact manifest references untracked defense artifact "
                "defense_bench_missing.json"
            ],
        )

    def test_assert_defense_bench_accepts_one_passing_layer_per_scenario(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "collect": {"errors": 0, "hung_workers": 0},
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                            "attacker_blocked_or_limited_percent": 98.0,
                            "benign_allowed_percent": None,
                        },
                    }
                }
            },
        }

        self.assertEqual(assert_defense_bench.assert_report(report, expect_scenarios=1), [])
        self.assertEqual(
            assert_defense_bench.passing_layer_summary(report),
            ["basic: rate_limit attacker=98.0 benign=None"],
        )

    def test_assert_defense_bench_accepts_required_provenance(self) -> None:
        report = {
            **self.valid_provenance(),
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                }
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=1,
                require_provenance=True,
            ),
            [],
        )

    def test_assert_defense_bench_accepts_required_run_strength(self) -> None:
        report = {
            **self.valid_provenance(),
            "provider": "deterministic",
            "preset": "all",
            "duration_seconds": 1.0,
            "workers": 8,
            "analyzer_wait_seconds": 8.0,
            "per_ip_rps": 80,
            "path_shape_rps": 80,
            "signature_threshold_per_second": 60,
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                }
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=1,
                require_provenance=True,
                expect_provider="deterministic",
                expect_preset="all",
                expect_scenario_names={"basic"},
                expect_common_layer_names={"rate_limit"},
                expect_static_only_scenario_names=set(),
                min_duration=1,
                min_workers=8,
                min_analyzer_wait=8,
                expect_per_ip_rps=80,
                expect_path_shape_rps=80,
                expect_signature_threshold=60,
            ),
            [],
        )

    def test_assert_defense_bench_accepts_expected_layer_names(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "direct_upstream": {"allowed_percent": 100.0},
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                    "learned_filter_strict": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
                "xff-rotating": {
                    "direct_upstream": {"allowed_percent": 100.0},
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                    "learned_filter_strict": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                    "learned_filter_observed": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=2,
                expect_common_layer_names={
                    "direct_upstream",
                    "rate_limit",
                    "learned_filter_strict",
                },
                expect_observed_learning_scenario_names={"xff-rotating"},
            ),
            [],
        )

    def test_assert_defense_bench_rejects_missing_or_unexpected_layer_names(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "direct_upstream": {"allowed_percent": 100.0},
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                    "surprise_layer": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
                "xff-rotating": {
                    "direct_upstream": {"allowed_percent": 100.0},
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=2,
            expect_common_layer_names={
                "direct_upstream",
                "rate_limit",
                "learned_filter_strict",
            },
            expect_observed_learning_scenario_names={"xff-rotating"},
        )

        self.assertIn("basic: missing expected layers: learned_filter_strict", errors)
        self.assertIn("basic: unexpected layers: surprise_layer", errors)
        self.assertIn(
            "xff-rotating: missing expected layers: learned_filter_observed, learned_filter_strict",
            errors,
        )
        self.assertIn(
            "missing expected observed-learning scenarios: xff-rotating",
            errors,
        )

    def test_assert_defense_bench_rejects_empty_expected_layer_sets(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
            },
        }

        common_errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            expect_common_layer_names=set(),
        )
        observed_errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            expect_observed_learning_scenario_names=set(),
        )

        self.assertIn("expected common layer set must not be empty", common_errors)
        self.assertIn(
            "expected observed-learning scenario set must not be empty",
            observed_errors,
        )

    def test_assert_defense_bench_rejects_unexpected_observed_learning_scenarios(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                    "learned_filter_observed": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            expect_observed_learning_scenario_names={"xff-rotating"},
        )

        self.assertIn(
            "missing expected observed-learning scenarios: xff-rotating",
            errors,
        )
        self.assertIn("unexpected observed-learning scenarios: basic", errors)

    def test_assert_defense_bench_accepts_expected_static_only_scenarios(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "slow": {
                    "static_filter": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                    "static_filter": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=2,
                expect_static_only_scenario_names={"slow"},
            ),
            [],
        )

    def test_assert_defense_bench_rejects_unexpected_static_only_scenarios(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "slow": {
                    "static_filter": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
                "expected-static": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=2,
            expect_static_only_scenario_names={"expected-static"},
        )

        self.assertIn("missing expected static-only scenarios: expected-static", errors)
        self.assertIn("unexpected static-only scenarios: slow", errors)

    def test_assert_defense_bench_accepts_required_layer_traffic(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "collect": {"requests": 100, "errors": 0, "hung_workers": 0},
                        "bypass_probe": {
                            "requests": 20,
                            "errors": 0,
                            "hung_workers": 0,
                        },
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "benign_allowed_percent": 100.0,
                            "bypass_errors": 0,
                        },
                    },
                    "learned_filter_strict": {
                        "collect": {"requests": 100, "errors": 0, "hung_workers": 0},
                        "replay": {"requests": 90, "errors": 0, "hung_workers": 0},
                        "bypass_probe": {
                            "requests": 20,
                            "errors": 0,
                            "hung_workers": 0,
                        },
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "benign_allowed_percent": 95.0,
                            "bypass_errors": 0,
                        },
                    },
                },
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=1,
                require_layer_traffic=True,
            ),
            [],
        )

    def test_assert_defense_bench_rejects_missing_or_empty_layer_traffic(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "collect": {
                            "requests": 0,
                            "errors": 1,
                            "error_samples": ["RemoteDisconnected: peer closed"],
                            "hung_workers": 1,
                        },
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "benign_allowed_percent": None,
                            "bypass_errors": 0,
                        },
                    },
                    "learned_filter_strict": {
                        "collect": {"requests": 10, "errors": 0, "hung_workers": 0},
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "benign_allowed_percent": 95.0,
                            "bypass_errors": 0,
                        },
                    },
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            require_layer_traffic=True,
        )

        self.assertIn(
            "basic/rate_limit/collect: expected requests>0, found 0",
            errors,
        )
        self.assertIn(
            "basic/rate_limit/collect: expected errors=0, found 1; "
            "samples=['RemoteDisconnected: peer closed']",
            errors,
        )
        self.assertIn(
            "basic/rate_limit/collect: expected hung_workers=0, found 1",
            errors,
        )
        self.assertIn("basic/learned_filter_strict: missing replay phase", errors)
        self.assertIn(
            "basic/learned_filter_strict: missing bypass_probe phase",
            errors,
        )

    def test_assert_defense_bench_accepts_open_proxy_negative_control(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "proxy_open": {
                        "collect": {
                            "requests": 100,
                            "errors": 0,
                            "hung_workers": 0,
                            "allowed_percent": 100.0,
                        },
                        "effective_target_score": {
                            "meets_attacker_block_target": False,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        },
                    },
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=1,
                require_open_proxy_negative_control=True,
            ),
            [],
        )

    def test_assert_defense_bench_rejects_bad_open_proxy_negative_control(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "missing": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
                "weak": {
                    "proxy_open": {
                        "collect": {
                            "requests": 10,
                            "errors": 0,
                            "hung_workers": 0,
                            "allowed_percent": 80.0,
                        },
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        },
                    },
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=2,
            require_open_proxy_negative_control=True,
        )

        self.assertIn("missing: missing proxy_open negative-control layer", errors)
        self.assertIn(
            "weak/proxy_open/collect: expected allowed_percent>=95.0, found 80.0",
            errors,
        )
        self.assertIn(
            "weak/proxy_open: expected meets_attacker_block_target=false, found True",
            errors,
        )

    def test_assert_defense_bench_accepts_consistent_target_scores(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "proxy_open": {
                        "effective_target_score": {
                            "attacker_block_target_percent": 90.0,
                            "benign_allow_target_percent": 95.0,
                            "attacker_blocked_or_limited_percent": 0.0,
                            "benign_allowed_percent": None,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                            "meets_attacker_block_target": False,
                            "meets_benign_allow_target": False,
                        },
                    },
                    "rate_limit": {
                        "effective_target_score": {
                            "attacker_block_target_percent": 90.0,
                            "benign_allow_target_percent": 95.0,
                            "attacker_blocked_or_limited_percent": 98.5,
                            "benign_allowed_percent": 96.0,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                        }
                    },
                },
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=1,
                require_score_consistency=True,
            ),
            [],
        )

    def test_assert_defense_bench_accepts_measured_benign_scores(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "attacker_block_target_percent": 90.0,
                            "benign_allow_target_percent": 95.0,
                            "attacker_blocked_or_limited_percent": 98.0,
                            "benign_allowed_percent": 100.0,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                        }
                    },
                },
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=1,
                require_measured_benign=True,
            ),
            [],
        )

    def test_assert_defense_bench_requires_numeric_benign_measurement(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "unmeasured": {
                        "effective_target_score": {
                            "attacker_block_target_percent": 90.0,
                            "benign_allow_target_percent": 95.0,
                            "attacker_blocked_or_limited_percent": 98.0,
                            "benign_allowed_percent": None,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": False,
                        }
                    },
                    "measured_but_below_target": {
                        "effective_target_score": {
                            "attacker_block_target_percent": 90.0,
                            "benign_allow_target_percent": 95.0,
                            "attacker_blocked_or_limited_percent": 98.0,
                            "benign_allowed_percent": 94.0,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": False,
                        }
                    },
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            require_measured_benign=True,
        )

        self.assertIn(
            "basic/unmeasured/effective_target_score: "
            "benign_allowed_percent must be measured and numeric, found None",
            errors,
        )
        self.assertFalse(
            any(
                "basic/measured_but_below_target/effective_target_score" in error
                for error in errors
            ),
            errors,
        )

    def test_assert_defense_bench_rejects_inconsistent_target_scores(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "attacker_block_target_percent": 90.0,
                            "benign_allow_target_percent": 95.0,
                            "attacker_blocked_or_limited_percent": 80.0,
                            "benign_allowed_percent": 94.0,
                            "replay_errors": 0,
                            "bypass_errors": 1,
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                        }
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            require_score_consistency=True,
        )

        self.assertIn(
            "basic/rate_limit/effective_target_score: "
            "meets_attacker_block_target expected False "
            "from attacker_blocked_or_limited_percent=80.0 "
            "and attacker_block_target_percent=90.0, found True",
            errors,
        )
        self.assertIn(
            "basic/rate_limit/effective_target_score: "
            "meets_benign_allow_target expected False "
            "from benign_allowed_percent=94.0 "
            "benign_allow_target_percent=95.0 and bypass_errors=1, found True",
            errors,
        )

    def test_assert_defense_bench_accepts_expected_scenario_names(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
                "xff-rotating": {
                    "trusted_proxy_rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=2,
                expect_scenario_names={"basic", "xff-rotating"},
            ),
            [],
        )

    def test_assert_defense_bench_rejects_missing_or_unexpected_scenario_names(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
                "replacement": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=2,
            expect_scenario_names={"basic", "xff-rotating"},
        )

        self.assertIn("missing expected scenarios: xff-rotating", errors)
        self.assertIn("unexpected scenarios: replacement", errors)

    def test_assert_defense_bench_rejects_empty_expected_scenario_set(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            expect_scenario_names=set(),
        )

        self.assertIn("expected scenario set must not be empty", errors)

    def test_assert_defense_bench_accepts_direct_upstream_baseline(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "direct_upstream": {
                        "requests": 100,
                        "errors": 0,
                        "hung_workers": 0,
                        "allowed_percent": 100.0,
                    },
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                }
            },
        }

        self.assertEqual(
            assert_defense_bench.assert_report(
                report,
                expect_scenarios=1,
                require_direct_baseline=True,
            ),
            [],
        )

    def test_assert_defense_bench_rejects_bad_direct_upstream_baseline(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "missing": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                },
                "weak": {
                    "direct_upstream": {
                        "requests": 0,
                        "errors": 1,
                        "hung_workers": 1,
                        "allowed_percent": 80.0,
                    },
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                },
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=2,
            require_direct_baseline=True,
        )

        self.assertIn("missing: missing direct_upstream baseline", errors)
        self.assertIn("weak/direct_upstream: expected requests>0, found 0", errors)
        self.assertIn("weak/direct_upstream: expected errors=0, found 1", errors)
        self.assertIn("weak/direct_upstream: expected hung_workers=0, found 1", errors)
        self.assertIn(
            "weak/direct_upstream: expected allowed_percent>=95.0, found 80.0",
            errors,
        )

    def test_assert_defense_bench_rejects_weak_run_strength(self) -> None:
        report = {
            **self.valid_provenance(),
            "provider": "deterministic",
            "preset": "base",
            "duration_seconds": 0.5,
            "workers": 4,
            "analyzer_wait_seconds": 4,
            "per_ip_rps": 100,
            "path_shape_rps": 100,
            "signature_threshold_per_second": 120,
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            require_provenance=True,
            expect_provider="deterministic",
            expect_preset="all",
            min_duration=1,
            min_workers=8,
            min_analyzer_wait=8,
            expect_per_ip_rps=80,
            expect_path_shape_rps=80,
            expect_signature_threshold=60,
        )

        self.assertIn("report preset expected 'all', found 'base'", errors)
        self.assertIn("report duration_seconds must be >= 1, found 0.5", errors)
        self.assertIn("report workers must be >= 8, found 4", errors)
        self.assertIn("report analyzer_wait_seconds must be >= 8, found 4", errors)
        self.assertIn("report per_ip_rps expected 80, found 100", errors)
        self.assertIn("report path_shape_rps expected 80, found 100", errors)
        self.assertIn("report signature_threshold_per_second expected 60, found 120", errors)

    def test_assert_defense_bench_rejects_missing_required_provenance(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            require_provenance=True,
        )

        self.assertIn("report missing generated_at_utc provenance timestamp", errors)
        self.assertIn("report missing source_tree provenance object", errors)

    def test_assert_defense_bench_rejects_copied_tree_when_provenance_required(self) -> None:
        report = {
            "generated_at_utc": "2026-06-22T18:26:39Z",
            "source_tree": {
                "cwd": "/copied-tree",
                "git_root": None,
                "git_commit": None,
                "git_commit_short": None,
                "git_branch": None,
                "git_dirty": None,
            },
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(
            report,
            expect_scenarios=1,
            require_provenance=True,
        )

        self.assertIn("report source_tree.git_root must be a non-empty string", errors)
        self.assertIn("report source_tree.git_commit must be a full Git object id", errors)
        self.assertIn("report source_tree.git_dirty must be a boolean", errors)

    def test_assert_defense_bench_rejects_missing_passing_layer(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "proxy_open": {
                        "effective_target_score": {
                            "meets_attacker_block_target": False,
                            "meets_benign_allow_target": True,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                        }
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(report, expect_scenarios=1)

        self.assertEqual(len(errors), 1)
        self.assertIn("no defense layer met", errors[0])

    def test_assert_defense_bench_rejects_missing_or_fractional_bypass_errors(self) -> None:
        self.assertFalse(
            assert_defense_bench.score_passes(
                {
                    "meets_attacker_block_target": True,
                    "meets_benign_allow_target": True,
                }
            )
        )
        self.assertFalse(
            assert_defense_bench.score_passes(
                {
                    "meets_attacker_block_target": True,
                    "meets_benign_allow_target": True,
                    "bypass_errors": 0.5,
                }
            )
        )
        self.assertTrue(
            assert_defense_bench.score_passes(
                {
                    "meets_attacker_block_target": True,
                    "meets_benign_allow_target": True,
                    "bypass_errors": 0,
                }
            )
        )

    def test_assert_defense_bench_rejects_legacy_target_score_only(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(report, expect_scenarios=1)

        self.assertGreaterEqual(len(errors), 1)
        self.assertIn(
            "basic/rate_limit: missing effective_target_score (legacy target_score is ignored)",
            errors,
        )

    def test_assert_defense_bench_allows_unscored_direct_upstream_baseline(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "direct_upstream": {"allowed_percent": 100.0},
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "bypass_errors": 0,
                        }
                    },
                }
            },
        }

        self.assertEqual(assert_defense_bench.assert_report(report, expect_scenarios=1), [])

    def test_assert_defense_bench_allows_collection_errors_on_unselected_layers(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "proxy_open": {
                        "collect": {"errors": 16, "hung_workers": 0},
                        "effective_target_score": {
                            "meets_attacker_block_target": False,
                            "meets_benign_allow_target": True,
                            "replay_errors": 16,
                            "bypass_errors": 0,
                        },
                    },
                    "rate_limit": {
                        "collect": {"errors": 0, "hung_workers": 0},
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                        },
                    }
                }
            },
        }

        self.assertEqual(assert_defense_bench.assert_report(report, expect_scenarios=1), [])

    def test_assert_defense_bench_rejects_hung_workers(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "collect": {"errors": 0, "hung_workers": 1},
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                        },
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(report, expect_scenarios=1)

        self.assertEqual(len(errors), 1)
        self.assertIn("basic/rate_limit/collect", errors[0])

    def test_assert_defense_bench_rejects_malformed_hung_workers(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "collect": {"errors": 0, "hung_workers": "n/a"},
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                        },
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(report, expect_scenarios=1)

        self.assertEqual(len(errors), 1)
        self.assertIn("basic/rate_limit/collect had hung_workers='n/a'", errors[0])

    def test_assert_defense_bench_rejects_non_string_safety_metadata(self) -> None:
        report = {
            "safety": {"note": "loopback-only X-Forwarded-For"},
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                        },
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(report, expect_scenarios=1)

        self.assertIn("report safety metadata must be a string", errors)

    def test_assert_defense_bench_rejects_malformed_layer_payload(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {"basic": {"rate_limit": "corrupt"}},
        }

        errors = assert_defense_bench.assert_report(report, expect_scenarios=1)

        self.assertIn("basic/rate_limit: layer payload is not an object", errors)
        self.assertIn("basic: no scored defense layers", errors)

    def test_assert_defense_bench_rejects_metrics_errors(self) -> None:
        report = {
            "safety": "loopback-only; spoof cases use X-Forwarded-For headers",
            "scenarios": {
                "basic": {
                    "rate_limit": {
                        "metrics_errors": ["after: metrics fetch failed"],
                        "collect": {"errors": 0, "hung_workers": 0},
                        "effective_target_score": {
                            "meets_attacker_block_target": True,
                            "meets_benign_allow_target": True,
                            "replay_errors": 0,
                            "bypass_errors": 0,
                        },
                    }
                }
            },
        }

        errors = assert_defense_bench.assert_report(report, expect_scenarios=1)

        self.assertEqual(len(errors), 1)
        self.assertIn("basic/rate_limit", errors[0])
        self.assertIn("metrics_errors", errors[0])

    def test_smart_api_mix_observed_learning_does_not_enable_xff_trust(self) -> None:
        self.assertFalse(run_defense_bench.scenario_needs_xff_trust("smart-api-mix"))
        self.assertTrue(run_defense_bench.scenario_runs_observed_learning("smart-api-mix"))

    def test_xff_scenarios_use_observed_learning_with_xff_trust(self) -> None:
        self.assertTrue(run_defense_bench.scenario_needs_xff_trust("xff-polymorphic"))
        self.assertTrue(run_defense_bench.scenario_runs_observed_learning("xff-polymorphic"))

    def test_slow_polymorphic_scenario_uses_distributed_workers(self) -> None:
        self.assertEqual(
            run_defense_bench.scenario_worker_count("slow-xff-polymorphic", 8),
            128,
        )
        self.assertEqual(
            run_defense_bench.scenario_worker_count("slow-xff-polymorphic", 192),
            192,
        )
        self.assertEqual(
            run_defense_bench.scenario_worker_count("slow-xff-polymorphic", 8, bypass=True),
            8,
        )
        self.assertEqual(
            run_defense_bench.scenario_worker_count(
                "slow-xff-polymorphic",
                8,
                direct_baseline=True,
            ),
            8,
        )
        self.assertEqual(run_defense_bench.scenario_worker_count("basic", 8), 8)

    def test_benchmark_generated_at_uses_utc_marker(self) -> None:
        generated_at = bench_provenance.generated_at_utc()

        self.assertIn("T", generated_at)
        self.assertTrue(generated_at.endswith("Z"))

    def test_benchmark_source_metadata_degrades_without_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            metadata = bench_provenance.source_tree_metadata(Path(tmp))

        self.assertEqual(metadata["cwd"], tmp)
        self.assertIsNone(metadata["git_root"])
        self.assertIsNone(metadata["git_commit"])
        self.assertIsNone(metadata["git_commit_short"])
        self.assertIsNone(metadata["git_branch"])
        self.assertIsNone(metadata["git_dirty"])

    def test_benchmark_source_metadata_reports_clean_git_tree(self) -> None:
        real_git_output = bench_provenance.git_output

        def fake_git_output(_cwd: Path, args: list[str]) -> str | None:
            values = {
                ("rev-parse", "--show-toplevel"): "/repo",
                ("rev-parse", "HEAD"): "abcdef1234567890abcdef1234567890abcdef1234",
                ("rev-parse", "--short=12", "HEAD"): "abcdef123456",
                ("rev-parse", "--abbrev-ref", "HEAD"): "main",
                ("status", "--porcelain"): "",
            }
            return values.get(tuple(args))

        bench_provenance.git_output = fake_git_output
        try:
            metadata = bench_provenance.source_tree_metadata(Path("/repo"))
        finally:
            bench_provenance.git_output = real_git_output

        self.assertEqual(metadata["git_root"], "/repo")
        self.assertEqual(metadata["git_commit"], "abcdef1234567890abcdef1234567890abcdef1234")
        self.assertEqual(metadata["git_commit_short"], "abcdef123456")
        self.assertEqual(metadata["git_branch"], "main")
        self.assertIs(metadata["git_dirty"], False)

    def test_path_shape_rate_layer_config_isolates_shape_bucket(self) -> None:
        high_limits = run_defense_bench.high_request_limit_overrides(1_000_000)
        path_shape_overrides = {
            **high_limits,
            "path_shape_rps": 80,
            "path_shape_burst": 80,
        }
        with tempfile.TemporaryDirectory() as tmp:
            config_path, _, _ = run_defense_bench.write_config(
                Path(tmp),
                12345,
                12346,
                per_ip_rps=1_000_000,
                signature_threshold=60,
                adaptive_enabled=True,
                trusted_xff=True,
                limit_overrides=path_shape_overrides,
            )

            cfg = json.loads(config_path.read_text(encoding="utf-8"))

        limits = cfg["http"]["limits"]
        self.assertTrue(cfg["http"]["downstream_keep_alive"])
        self.assertEqual(limits["global_rps"], 1_000_000)
        self.assertEqual(limits["global_burst"], 1_000_000)
        self.assertEqual(limits["per_ip_rps"], 1_000_000)
        self.assertEqual(limits["trusted_proxy_rps"], 1_000_000)
        self.assertEqual(limits["trusted_proxy_burst"], 1_000_000)
        self.assertEqual(limits["signature_rps"], 1_000_000)
        self.assertEqual(limits["signature_burst"], 1_000_000)
        self.assertEqual(limits["path_shape_rps"], 80)
        self.assertEqual(limits["path_shape_burst"], 80)
        self.assertEqual(limits["per_ip_connects_per_second"], 1_000_000)
        self.assertEqual(limits["per_ip_connect_burst"], 1_000_000)
        self.assertEqual(limits["global_connects_per_second"], 1_000_000)
        self.assertEqual(limits["global_connect_burst"], 1_000_000)

    def test_high_request_limit_overrides_lifts_all_request_shape_buckets(self) -> None:
        overrides = run_defense_bench.high_request_limit_overrides(1234)

        self.assertEqual(overrides["global_rps"], 1234)
        self.assertEqual(overrides["trusted_proxy_rps"], 1234)
        self.assertEqual(overrides["signature_rps"], 1234)
        self.assertEqual(overrides["path_shape_rps"], 1234)
        self.assertEqual(overrides["max_tracked_signatures"], 65_536)
        self.assertEqual(overrides["max_tracked_path_shapes"], 65_536)

    def test_defense_bench_reports_selected_metric_deltas(self) -> None:
        delta = run_defense_bench.selected_metrics_delta(
            {
                "altura_http_rate_limited": 5,
                "altura_http_path_shape_rate_limited": 2,
            },
            {
                "altura_http_rate_limited": 9,
                "altura_http_path_shape_rate_limited": 5,
                "unrelated_metric": 100,
            },
        )

        self.assertEqual(delta["altura_http_rate_limited"], 4)
        self.assertEqual(delta["altura_http_path_shape_rate_limited"], 3)
        self.assertNotIn("unrelated_metric", delta)

    def test_fetch_metrics_retries_transient_rate_limit_response(self) -> None:
        class MetricsHandler(socketserver.BaseRequestHandler):
            calls = 0

            def handle(self) -> None:
                _ = self.request.recv(4096)
                type(self).calls += 1
                if type(self).calls == 1:
                    self.request.sendall(
                        b"HTTP/1.1 429 Too Many Requests\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    return
                body = b"altura_http_rate_limited 7\n"
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + body
                )

        class MetricsServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

        MetricsHandler.calls = 0
        with MetricsServer(("127.0.0.1", 0), MetricsHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            metrics = run_defense_bench.fetch_metrics(int(server.server_address[1]))
            server.shutdown()

        self.assertEqual(metrics["altura_http_rate_limited"], 7)
        self.assertEqual(MetricsHandler.calls, 2)

    def test_fetch_metrics_retries_transient_transport_error(self) -> None:
        real_connection = run_defense_bench.http.client.HTTPConnection

        class FakeResponse:
            status = 200

            def read(self) -> bytes:
                return b"altura_http_blocked 3\n"

        class FakeConnection:
            calls = 0

            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def request(self, *_args: object, **_kwargs: object) -> None:
                type(self).calls += 1
                if type(self).calls == 1:
                    raise TimeoutError("timed out")

            def getresponse(self) -> FakeResponse:
                return FakeResponse()

            def close(self) -> None:
                pass

        FakeConnection.calls = 0
        run_defense_bench.http.client.HTTPConnection = FakeConnection
        try:
            metrics = run_defense_bench.fetch_metrics(12345)
        finally:
            run_defense_bench.http.client.HTTPConnection = real_connection

        self.assertEqual(metrics["altura_http_blocked"], 3)
        self.assertEqual(FakeConnection.calls, 2)

    def test_try_fetch_metrics_returns_error_without_raising(self) -> None:
        real_fetch = run_defense_bench.fetch_metrics

        def fail_fetch(_port: int, _token: str = "bench-token") -> dict[str, float]:
            raise RuntimeError("metrics unavailable")

        run_defense_bench.fetch_metrics = fail_fetch
        try:
            metrics, error = run_defense_bench.try_fetch_metrics(12345)
        finally:
            run_defense_bench.fetch_metrics = real_fetch

        self.assertEqual(metrics, {})
        self.assertEqual(error, "metrics unavailable")

    def test_phase_summary_includes_bounded_error_samples(self) -> None:
        phase = run_defense_bench.PhaseResult()
        for idx in range(run_defense_bench.ERROR_SAMPLE_LIMIT + 3):
            phase.record_error(RuntimeError(f"boom-{idx}"))

        summary = run_defense_bench.summarize_phase(phase)

        self.assertEqual(summary["errors"], run_defense_bench.ERROR_SAMPLE_LIMIT + 3)
        self.assertEqual(len(summary["error_samples"]), run_defense_bench.ERROR_SAMPLE_LIMIT)
        self.assertEqual(summary["error_samples"][0], "RuntimeError: boom-0")
        self.assertEqual(
            summary["error_samples"][-1],
            f"RuntimeError: boom-{run_defense_bench.ERROR_SAMPLE_LIMIT - 1}",
        )

    def test_run_phase_retries_one_transient_timeout(self) -> None:
        real_connection = run_defense_bench.http.client.HTTPConnection

        class FakeResponse:
            status = 204
            will_close = True

            def getheader(self, _name: str) -> str | None:
                return "close"

            def read(self) -> bytes:
                return b""

        class FakeConnection:
            calls = 0

            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def request(self, *_args: object, **_kwargs: object) -> None:
                type(self).calls += 1
                if type(self).calls == 1:
                    raise TimeoutError("timed out")

            def getresponse(self) -> FakeResponse:
                return FakeResponse()

            def close(self) -> None:
                pass

        FakeConnection.calls = 0
        run_defense_bench.http.client.HTTPConnection = FakeConnection
        try:
            phase = run_defense_bench.run_phase(12345, "basic", 0.001, 1)
        finally:
            run_defense_bench.http.client.HTTPConnection = real_connection

        self.assertEqual(phase.errors, 0)
        self.assertGreaterEqual(phase.requests, 1)
        self.assertGreaterEqual(FakeConnection.calls, 2)

    def test_target_score_counts_rate_limited_attack_traffic(self) -> None:
        replay = run_defense_bench.PhaseResult(requests=10)
        replay.statuses[204] = 1
        replay.statuses[429] = 9
        bypass = run_defense_bench.PhaseResult(requests=20)
        bypass.statuses[204] = 20

        score = run_defense_bench.target_score(replay, bypass)

        self.assertEqual(score["attacker_blocked_percent"], 0.0)
        self.assertEqual(score["attacker_limited_percent"], 90.0)
        self.assertEqual(score["attacker_blocked_or_limited_percent"], 90.0)
        self.assertTrue(score["meets_attacker_block_target"])
        self.assertTrue(score["meets_benign_allow_target"])

    def test_target_score_counts_attack_connection_errors_as_stopped(self) -> None:
        replay = run_defense_bench.PhaseResult(requests=2, errors=8)
        replay.statuses[403] = 2

        score = run_defense_bench.target_score(replay, None)

        self.assertEqual(score["attacker_blocked_percent"], 100.0)
        self.assertEqual(score["replay_errors"], 8)
        self.assertEqual(score["attacker_blocked_or_limited_percent"], 100.0)
        self.assertTrue(score["meets_attacker_block_target"])
        self.assertFalse(score["meets_benign_allow_target"])

    def test_target_score_requires_measured_benign_allowance(self) -> None:
        replay = run_defense_bench.PhaseResult(requests=10)
        replay.statuses[429] = 10

        score = run_defense_bench.target_score(replay, None)

        self.assertTrue(score["meets_attacker_block_target"])
        self.assertIsNone(score["benign_allowed_percent"])
        self.assertFalse(score["meets_benign_allow_target"])

    def test_target_score_still_requires_benign_allowance(self) -> None:
        replay = run_defense_bench.PhaseResult(requests=10)
        replay.statuses[429] = 10
        bypass = run_defense_bench.PhaseResult(requests=20)
        bypass.statuses[204] = 18
        bypass.statuses[429] = 2

        score = run_defense_bench.target_score(replay, bypass)

        self.assertTrue(score["meets_attacker_block_target"])
        self.assertFalse(score["meets_benign_allow_target"])


class EdgeTemplateTests(unittest.TestCase):
    def test_loopback_listeners_do_not_require_edge_port_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = base / "config.json"
            nft = base / "edge.nft"
            config.write_text(
                json.dumps(
                    {
                        "http": {"listen": "127.0.0.1:8080"},
                        "tcp": [{"listen": "[::1]:7000"}],
                    }
                ),
                encoding="utf-8",
            )
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_edge_port_coverage(config, nft), [])

    def test_public_listener_requires_matching_protected_tcp_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = base / "config.json"
            nft = base / "edge.nft"
            config.write_text(
                json.dumps(
                    {
                        "http": {"listen": "0.0.0.0:8080"},
                        "tcp": [{"listen": "[::]:7000"}],
                    }
                ),
                encoding="utf-8",
            )
            nft.write_text(nft_template("{ 80, 443, 8080 }"), encoding="utf-8")

            errors = validate_edge_templates.validate_edge_port_coverage(config, nft)

            self.assertEqual(
                errors,
                ["protected_tcp_ports is missing public AlturaProt listener ports: 7000"],
            )

            nft.write_text(nft_template("{ 80, 443, 7000, 8080 }"), encoding="utf-8")
            self.assertEqual(validate_edge_templates.validate_edge_port_coverage(config, nft), [])

    def test_protected_tcp_ports_parse_service_names_and_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ http, https, 7000-7002 }"), encoding="utf-8")

            ranges, errors = validate_edge_templates.protected_tcp_port_ranges(nft)

            self.assertEqual(errors, [])
            self.assertTrue(validate_edge_templates.port_in_ranges(80, ranges))
            self.assertTrue(validate_edge_templates.port_in_ranges(443, ranges))
            self.assertTrue(validate_edge_templates.port_in_ranges(7001, ranges))
            self.assertFalse(validate_edge_templates.port_in_ranges(7003, ranges))

    def test_udp_to_protected_tcp_ports_requires_raw_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }", include_preraw=False), encoding="utf-8")

            errors = validate_edge_templates.validate_udp_protected_port_drop(nft)

            self.assertEqual(
                errors,
                [f"missing preraw chain with protected-port UDP drop in {nft}"],
            )

            nft.write_text(
                nft_template(
                    "{ 80, 443 }",
                    preraw="meta l4proto udp udp dport @protected_tcp_ports drop",
                ),
                encoding="utf-8",
            )
            self.assertEqual(validate_edge_templates.validate_udp_protected_port_drop(nft), [])

            nft.write_text(
                nft_template("{ 80, 443 }", preraw="udp dport @protected_tcp_ports drop"),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_udp_protected_port_drop(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("meta l4proto udp", errors[0])

    def test_generic_tcp_backstops_use_extension_safe_l4proto(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(
                validate_edge_templates.validate_generic_tcp_backstop_protocol_matches(nft),
                [],
            )

            nft.write_text(
                nft_template("{ 80, 443 }", generic_tcp_l4proto=False),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_generic_tcp_backstop_protocol_matches(nft)

            self.assertEqual(len(errors), 5)
            self.assertTrue(all("generic TCP extension-safe" in item for item in errors))
            self.assertTrue(any("null TCP flag drop" in item for item in errors))
            self.assertTrue(any("global SYN flood drop" in item for item in errors))
            self.assertTrue(any("new non-SYN drop" in item for item in errors))

    def test_ipv6_prefix_backstops_require_prefix64_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_ipv6_prefix_backstops(nft), [])

            nft.write_text(
                nft_template(
                    "{ 80, 443 }",
                    preraw=(
                        "meta l4proto udp udp dport @protected_tcp_ports drop\n"
                        "    ip6 nexthdr tcp tcp dport @protected_tcp_ports "
                        "tcp flags & (fin|syn|rst|ack) == syn meter tcp6_syn_rate "
                        "{ ip6 saddr . tcp dport timeout 10s limit rate over 200/second "
                        "burst 400 packets } drop"
                    ),
                ),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_ipv6_prefix_backstops(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("IPv6 /64 SYN backstop", errors[0])

            nft.write_text(
                nft_template(
                    "{ 80, 443 }",
                    input_rules=(
                        "ip6 nexthdr tcp tcp dport @protected_tcp_ports ct state new "
                        "add @tcp6_connlimit { ip6 saddr . tcp dport ct count over 128 } drop"
                    ),
                ),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_ipv6_prefix_backstops(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("IPv6 /64 connection-count backstop", errors[0])

    def test_ipv6_protocol_matches_are_extension_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(
                validate_edge_templates.validate_ipv6_extension_safe_protocol_matches(nft),
                [],
            )

            nft.write_text(
                nft_template("{ 80, 443 }", syn_protocol="ip6 nexthdr tcp"),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_ipv6_extension_safe_protocol_matches(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("extension-safe SYN protocol match", errors[0])

            nft.write_text(
                nft_template("{ 80, 443 }", connlimit_protocol="ip6 nexthdr tcp"),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_ipv6_extension_safe_protocol_matches(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("extension-safe connection-count protocol match", errors[0])

            nft.write_text(
                nft_template("{ 80, 443 }", icmp_protocol="ip6 nexthdr ipv6-icmp"),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_ipv6_extension_safe_protocol_matches(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("extension-safe ICMPv6 flood protocol match", errors[0])

    def test_icmpv6_control_exemption_precedes_flood_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_icmpv6_control_exemption(nft), [])

            nft.write_text(
                nft_template("{ 80, 443 }", include_icmpv6_control_exemption=False),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_icmpv6_control_exemption(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("missing ICMPv6 control exemption", errors[0])

            nft.write_text(
                nft_template("{ 80, 443 }", icmpv6_control_after_drop=True),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_icmpv6_control_exemption(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("must appear before", errors[0])

            nft.write_text(
                nft_template(
                    "{ 80, 443 }",
                    icmpv6_control_types=(
                        "destination-unreachable, packet-too-big, time-exceeded"
                    ),
                ),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_icmpv6_control_exemption(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("parameter-problem", errors[0])

    def test_icmpv4_control_exemption_precedes_flood_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_icmpv4_control_exemption(nft), [])

            nft.write_text(
                nft_template("{ 80, 443 }", include_icmpv4_control_exemption=False),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_icmpv4_control_exemption(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("missing ICMPv4 control exemption", errors[0])

            nft.write_text(
                nft_template("{ 80, 443 }", icmpv4_control_after_drop=True),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_icmpv4_control_exemption(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("must appear before", errors[0])

            nft.write_text(
                nft_template(
                    "{ 80, 443 }",
                    icmpv4_control_types="destination-unreachable, time-exceeded",
                ),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_icmpv4_control_exemption(nft)
            self.assertEqual(len(errors), 1)
            self.assertIn("parameter-problem", errors[0])

    def test_connlimit_sets_have_explicit_size_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_connlimit_set_sizes(nft), [])

            nft.write_text(
                nft_template("{ 80, 443 }", connlimit_set_size=None),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_connlimit_set_sizes(nft)
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("explicit positive size" in error for error in errors))

            nft.write_text(
                nft_template("{ 80, 443 }", connlimit_set_size="1048577"),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_connlimit_set_sizes(nft)
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("exceeds 1048576" in error for error in errors))

    def test_syn_rate_sets_have_explicit_size_and_timeout_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_syn_rate_set_bounds(nft), [])

            nft.write_text(
                nft_template("{ 80, 443 }", syn_rate_set_size=None),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_syn_rate_set_bounds(nft)
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("explicit positive size" in error for error in errors))

            nft.write_text(
                nft_template("{ 80, 443 }", syn_rate_set_flags="dynamic"),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_syn_rate_set_bounds(nft)
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("flags timeout" in error for error in errors))

            nft.write_text(
                nft_template("{ 80, 443 }", syn_rate_set_timeout="2m"),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_syn_rate_set_bounds(nft)
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("exceeds 60s" in error for error in errors))

    def test_connlimit_thresholds_align_with_userspace_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nft = Path(tmp) / "edge.nft"
            nft.write_text(nft_template("{ 80, 443 }"), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_connlimit_thresholds(nft), [])

            nft.write_text(
                nft_template("{ 80, 443 }", connlimit_count="512"),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_connlimit_thresholds(nft)
            self.assertEqual(len(errors), 2)
            self.assertTrue(
                all(
                    "exceeds tightest public userspace per-IP connection cap" in error
                    for error in errors
                )
            )

    def test_connlimit_thresholds_follow_public_listener_caps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            nft = base / "edge.nft"
            config = base / "config.json"
            nft.write_text(nft_template("{ 80, 443 }", connlimit_count="128"), encoding="utf-8")
            config.write_text(
                json.dumps(
                    {
                        "http": {
                            "listen": "0.0.0.0:8080",
                            "limits": {"max_connections_per_ip": 1024},
                        },
                        "tcp": [
                            {
                                "listen": "0.0.0.0:7000",
                                "limits": {"max_connections_per_ip": 64},
                            },
                            {
                                "listen": "127.0.0.1:7001",
                                "limits": {"max_connections_per_ip": 8},
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            errors = validate_edge_templates.validate_connlimit_thresholds(nft, config)

            self.assertEqual(len(errors), 2)
            self.assertTrue(all("connection cap 64" in error for error in errors))

            nft.write_text(nft_template("{ 80, 443 }", connlimit_count="64"), encoding="utf-8")
            self.assertEqual(
                validate_edge_templates.validate_connlimit_thresholds(nft, config),
                [],
            )

    def test_fragment_reassembly_sysctls_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sysctl = Path(tmp) / "sysctl.conf"
            sysctl.write_text(sysctl_template(), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_fragment_sysctls(sysctl), [])

            sysctl.write_text("net.core.somaxconn = 65535\n", encoding="utf-8")
            errors = validate_edge_templates.validate_fragment_sysctls(sysctl)
            self.assertEqual(len(errors), 1)
            self.assertIn("missing fragment reassembly sysctl bounds", errors[0])

            sysctl.write_text(
                sysctl_template({"net.ipv6.ip6frag_time": "60"}),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_fragment_sysctls(sysctl)
            self.assertEqual(
                errors,
                ["net.ipv6.ip6frag_time=60 exceeds fragment queue retention cap 30s"],
            )

            sysctl.write_text(
                sysctl_template(
                    {
                        "net.ipv6.ip6frag_low_thresh": "8388608",
                        "net.ipv6.ip6frag_high_thresh": "4194304",
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_fragment_sysctls(sysctl)
            self.assertEqual(
                errors,
                [
                    "net.ipv6.ip6frag_low_thresh must be less than or equal to "
                    "net.ipv6.ip6frag_high_thresh"
                ],
            )

    def test_ddos_sysctls_have_effective_guardrail_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sysctl = Path(tmp) / "sysctl.conf"
            sysctl.write_text(sysctl_template(), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_ddos_sysctls(sysctl), [])

            sysctl.write_text(
                sysctl_template(
                    {
                        "net.ipv4.tcp_syncookies": "0",
                        "net.ipv4.tcp_max_syn_backlog": "128",
                        "net.ipv4.tcp_synack_retries": "9",
                        "net.core.netdev_max_backlog": "1000",
                        "net.ipv4.tcp_fin_timeout": "300",
                        "net.netfilter.nf_conntrack_max": "65536",
                        "net.netfilter.nf_conntrack_tcp_timeout_syn_recv": "120",
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_ddos_sysctls(sysctl)

            self.assertIn("net.ipv4.tcp_syncookies=0 must be exactly 1", errors)
            self.assertIn(
                "net.ipv4.tcp_max_syn_backlog=128 is lower than "
                "DDoS guardrail minimum 8192",
                errors,
            )
            self.assertIn(
                "net.ipv4.tcp_synack_retries=9 exceeds DDoS guardrail maximum 5",
                errors,
            )
            self.assertIn(
                "net.core.netdev_max_backlog=1000 is lower than "
                "DDoS guardrail minimum 10000",
                errors,
            )
            self.assertIn(
                "net.ipv4.tcp_fin_timeout=300 exceeds DDoS guardrail maximum 60",
                errors,
            )
            self.assertIn(
                "net.netfilter.nf_conntrack_max=65536 is lower than "
                "DDoS guardrail minimum 262144",
                errors,
            )
            self.assertIn(
                "net.netfilter.nf_conntrack_tcp_timeout_syn_recv=120 exceeds "
                "DDoS guardrail maximum 60",
                errors,
            )

            sysctl.write_text(
                (
                    "net.ipv4.tcp_syncookies = 1\n"
                    "net.ipv4.tcp_max_syn_backlog = 16384\n"
                ),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_ddos_sysctls(sysctl)
            self.assertEqual(len(errors), 1)
            self.assertIn("missing DDoS host sysctl guardrails", errors[0])

    def test_optional_conntrack_sysctl_key_absence_is_soft_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sysctl = Path(tmp) / "sysctl.conf"
            sysctl.write_text(
                (
                    "net.core.somaxconn = 65535\n"
                    "net.netfilter.nf_conntrack_max = 1048576\n"
                    "net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30\n"
                ),
                encoding="utf-8",
            )

            def fake_run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
                key = cmd[-1]
                return subprocess.CompletedProcess(
                    cmd,
                    1 if key.startswith("net.netfilter.") else 0,
                    "",
                    "",
                )

            with patch.object(
                validate_edge_templates.platform, "system", return_value="Linux"
            ), patch.object(
                validate_edge_templates.shutil, "which", return_value="/sbin/sysctl"
            ), patch.object(
                validate_edge_templates, "run", side_effect=fake_run
            ):
                errors = validate_edge_templates.validate_sysctl(sysctl)

            self.assertEqual(len(errors), 2)
            self.assertTrue(all("skipped key existence check" in item for item in errors))

    def test_parse_systemd_seconds_accepts_common_single_unit_forms(self) -> None:
        cases = {
            "250ms": 0.25,
            "2s": 2.0,
            "2sec": 2.0,
            "2min": 120.0,
            "2m": 120.0,
            "2h": 7200.0,
            "2d": 172800.0,
            "2w": 1209600.0,
            "1y": 31557600.0,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(validate_edge_templates.parse_systemd_seconds(value), expected)

        self.assertEqual(validate_edge_templates.parse_systemd_seconds("infinity"), float("inf"))
        with self.assertRaises(ValueError):
            validate_edge_templates.parse_systemd_seconds("1min 30s")

    def test_parse_systemd_nofile_hard_limit_accepts_systemd_limit_forms(self) -> None:
        cases = {
            "1024": 1024,
            "1024:1048576": 1048576,
            "1024:infinity": None,
            "infinity": None,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(
                    validate_edge_templates.parse_systemd_nofile_hard_limit(value),
                    expected,
                )

        for value in ("", "1024:", ":1048576", "1:2:3", "many"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_edge_templates.parse_systemd_nofile_hard_limit(value)

    def test_systemd_unit_keeps_service_manager_guardrails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            unit = Path(tmp) / "altura-prot.service"
            config = Path(tmp) / "config.json"
            config.write_text(
                json.dumps({"runtime": {"min_nofile": 65536, "shutdown_grace_ms": 2000}}),
                encoding="utf-8",
            )
            unit.write_text(systemd_unit_template(), encoding="utf-8")

            self.assertEqual(validate_edge_templates.validate_systemd_unit(unit, config), [])

            unit.write_text(
                systemd_unit_template({"LimitNOFILE": "1024"}),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_systemd_unit(unit, config)
            self.assertTrue(any("LimitNOFILE=1024 hard limit 1024" in item for item in errors))

            unit.write_text(
                systemd_unit_template({"LimitNOFILE": "1024:1048576"}),
                encoding="utf-8",
            )
            self.assertEqual(validate_edge_templates.validate_systemd_unit(unit, config), [])

            unit.write_text(
                systemd_unit_template({"LimitNOFILE": "1024:infinity"}),
                encoding="utf-8",
            )
            self.assertEqual(validate_edge_templates.validate_systemd_unit(unit, config), [])

            unit.write_text(
                systemd_unit_template({"LimitNOFILE": "1024:2048"}),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_systemd_unit(unit, config)
            self.assertTrue(
                any("LimitNOFILE=1024:2048 hard limit 2048" in item for item in errors)
            )

            config.write_text(
                json.dumps(
                    {
                        "runtime": {"min_nofile": 65536, "shutdown_grace_ms": 2000},
                        "http": {
                            "listen": "127.0.0.1:8080",
                            "limits": {
                                "max_connections": 40000,
                                "max_in_flight_requests": 40000,
                            },
                            "upstream_pool_max_idle_per_host": 1000,
                        },
                        "tcp": [
                            {
                                "listen": "127.0.0.1:7000",
                                "limits": {"max_connections": 20000},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            unit.write_text(
                systemd_unit_template({"LimitNOFILE": "65536"}),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_systemd_unit(unit, config)
            self.assertTrue(
                any("required descriptor budget" in item for item in errors)
            )

            unit.write_text(
                systemd_unit_template({"LimitNOFILE": "200000"}),
                encoding="utf-8",
            )
            self.assertEqual(validate_edge_templates.validate_systemd_unit(unit, config), [])

            config.write_text(
                json.dumps({"runtime": {"min_nofile": 65536, "shutdown_grace_ms": 2000}}),
                encoding="utf-8",
            )

            unit.write_text(
                systemd_unit_template({"ProtectSystem": "false"}),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_systemd_unit(unit, config)
            self.assertTrue(any("ProtectSystem=false" in item for item in errors))

            unit.write_text(
                systemd_unit_template({"TimeoutStopSec": "1s"}),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_systemd_unit(unit, config)
            self.assertTrue(any("TimeoutStopSec=1s" in item for item in errors))

            unit.write_text(
                systemd_unit_template({"AmbientCapabilities": "CAP_NET_BIND_SERVICE CAP_NET_RAW"}),
                encoding="utf-8",
            )
            errors = validate_edge_templates.validate_systemd_unit(unit, config)
            self.assertTrue(any("AmbientCapabilities" in item for item in errors))


def nft_template(
    elements: str,
    preraw: str | None = None,
    input_rules: str | None = None,
    include_preraw: bool = True,
    syn_protocol: str = "meta nfproto ipv6 meta l4proto tcp",
    connlimit_protocol: str = "meta nfproto ipv6 meta l4proto tcp",
    icmp_protocol: str = "meta nfproto ipv6 meta l4proto ipv6-icmp",
    generic_tcp_l4proto: bool = True,
    include_icmpv4_control_exemption: bool = True,
    icmpv4_control_after_drop: bool = False,
    icmpv4_control_types: str = (
        "destination-unreachable, time-exceeded, parameter-problem"
    ),
    include_icmpv6_control_exemption: bool = True,
    icmpv6_control_after_drop: bool = False,
    icmpv6_control_types: str = (
        "destination-unreachable, packet-too-big, time-exceeded, parameter-problem, "
        "nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert"
    ),
    connlimit_set_size: str | None = "65535",
    connlimit_count: str = "128",
    syn_rate_set_size: str | None = "65535",
    syn_rate_set_flags: str = "dynamic,timeout",
    syn_rate_set_timeout: str | None = "10s",
) -> str:
    generic_tcp_prefix = "meta l4proto tcp " if generic_tcp_l4proto else ""
    if preraw is None:
        preraw = (
            f"{generic_tcp_prefix}tcp dport @protected_tcp_ports "
            "tcp flags & (fin|syn|rst|ack) == 0 drop\n"
            f"    {generic_tcp_prefix}tcp dport @protected_tcp_ports "
            "tcp flags & (fin|syn|rst|psh|ack|urg) == fin|psh|urg drop\n"
            "    meta l4proto udp udp dport @protected_tcp_ports drop\n"
            f"    {syn_protocol} tcp dport @protected_tcp_ports "
            "tcp flags & (fin|syn|rst|ack) == syn update @tcp6_syn_rate "
            "{ ip6 saddr and ffff:ffff:ffff:ffff:: . tcp dport "
            "limit rate over 200/second burst 400 packets } drop\n"
            f"    {generic_tcp_prefix}tcp dport @protected_tcp_ports "
            "tcp flags & (fin|syn|rst|ack) == syn "
            "limit rate over 5000/second burst 10000 packets drop"
        )
    if input_rules is None:
        icmpv6_control_rule = (
            "    meta nfproto ipv6 meta l4proto ipv6-icmp icmpv6 type { "
            + icmpv6_control_types
            + " } accept\n"
            if include_icmpv6_control_exemption
            else ""
        )
        icmpv4_control_rule = (
            "    ip protocol icmp icmp type { "
            + icmpv4_control_types
            + " } accept\n"
            if include_icmpv4_control_exemption
            else ""
        )
        icmpv4_drop_rule = (
            "    ip protocol icmp limit rate over 100/second burst 200 packets drop"
        )
        icmpv4_rules = (
            icmpv4_drop_rule + "\n" + icmpv4_control_rule.rstrip()
            if icmpv4_control_after_drop
            else icmpv4_control_rule + icmpv4_drop_rule
        )
        icmpv6_drop_rule = (
            f"    {icmp_protocol} limit rate over 100/second burst 200 packets drop"
        )
        icmpv6_rules = (
            icmpv6_drop_rule + "\n" + icmpv6_control_rule.rstrip()
            if icmpv6_control_after_drop
            else icmpv6_control_rule + icmpv6_drop_rule
        )
        input_rules = (
            f"{generic_tcp_prefix}tcp dport @protected_tcp_ports ct state new "
            "tcp flags & (fin|syn|rst|ack) != syn drop\n"
            f"{generic_tcp_prefix}tcp dport @protected_tcp_ports ct state new "
            f"add @tcp4_connlimit {{ ip saddr . tcp dport ct count over {connlimit_count} }} drop\n"
            f"{connlimit_protocol} tcp dport @protected_tcp_ports ct state new "
            "add @tcp6_connlimit { ip6 saddr and ffff:ffff:ffff:ffff:: . tcp dport "
            f"ct count over {connlimit_count} }} drop\n"
            f"{generic_tcp_prefix}tcp dport @protected_tcp_ports ct state new "
            "limit rate over 5000/second burst 10000 packets drop\n"
            f"{icmpv4_rules}\n"
            f"{icmpv6_rules}"
        )
    connlimit_size = (
        ""
        if connlimit_set_size is None
        else f"    size {connlimit_set_size}\n"
    )
    syn_rate_size = (
        ""
        if syn_rate_set_size is None
        else f"    size {syn_rate_set_size}\n"
    )
    syn_rate_timeout = (
        ""
        if syn_rate_set_timeout is None
        else f"    timeout {syn_rate_set_timeout}\n"
    )
    preraw_chain = (
        ""
        if not include_preraw
        else f"""
  chain preraw {{
    type filter hook prerouting priority raw; policy accept;
    {preraw}
  }}
"""
    )
    return f"""
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
{syn_rate_size}    flags {syn_rate_set_flags}
{syn_rate_timeout}  }}

  set tcp6_syn_rate {{
    type ipv6_addr . inet_service
{syn_rate_size}    flags {syn_rate_set_flags}
{syn_rate_timeout}  }}
{preraw_chain}

  chain input {{
    type filter hook input priority filter; policy accept;
    {input_rules}
  }}
}}
"""


def sysctl_template(overrides: dict[str, str] | None = None) -> str:
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


def systemd_unit_template(overrides: dict[str, str] | None = None) -> str:
    unit_values = {
        "StartLimitIntervalSec": "60",
        "StartLimitBurst": "5",
    }
    service_values = {
        "Type": "simple",
        "User": "altura-prot",
        "Group": "altura-prot",
        "ExecStart": "/usr/local/bin/altura-prot --config /etc/altura-prot/config.json",
        "Restart": "on-failure",
        "TimeoutStopSec": "15s",
        "LimitNOFILE": "1048576",
        "TasksMax": "32768",
        "MemoryHigh": "2G",
        "MemoryMax": "3G",
        "ConfigurationDirectory": "altura-prot",
        "StateDirectory": "altura-prot",
        "LogsDirectory": "altura-prot",
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
        for key, value in overrides.items():
            if key in unit_values:
                unit_values[key] = value
            else:
                service_values[key] = value
    unit_lines = "\n".join(f"{key}={value}" for key, value in unit_values.items())
    service_lines = "\n".join(f"{key}={value}" for key, value in service_values.items())
    return f"""[Unit]
Description=AlturaProt
{unit_lines}

[Service]
{service_lines}

[Install]
WantedBy=multi-user.target
"""


class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class CliAgentProviderTests(unittest.TestCase):
    def test_cli_agent_argv_claude_uses_stdin_and_json(self) -> None:
        argv, use_stdin = codex_analyzer.cli_agent_argv("claude", "claude", "claude-opus-4-8", "PROMPT")
        self.assertTrue(use_stdin)
        self.assertEqual(argv, ["claude", "-p", "--output-format", "json", "--model", "claude-opus-4-8"])
        # No model -> no --model flag, prompt still via stdin (not argv).
        argv, use_stdin = codex_analyzer.cli_agent_argv("claude", "claude", "", "PROMPT")
        self.assertEqual(argv, ["claude", "-p", "--output-format", "json"])
        self.assertNotIn("PROMPT", argv)

    def test_cli_agent_argv_others_pass_prompt_as_argv(self) -> None:
        for provider, command, expect_head in (
            ("opencode", "opencode", ["opencode", "run", "--model", "m"]),
            ("cursor", "cursor-agent", ["cursor-agent", "-p", "--output-format", "text", "--model", "m"]),
        ):
            argv, use_stdin = codex_analyzer.cli_agent_argv(provider, command, "m", "PROMPT")
            self.assertFalse(use_stdin)
            self.assertEqual(argv[: len(expect_head)], expect_head)
            self.assertEqual(argv[-1], "PROMPT")
        argv, use_stdin = codex_analyzer.cli_agent_argv("grok", "grok", "grok-4", "PROMPT")
        self.assertFalse(use_stdin)
        self.assertEqual(argv, ["grok", "-p", "PROMPT", "--model", "grok-4"])

    def test_cli_agent_response_text_unwraps_claude_envelope(self) -> None:
        self.assertEqual(
            codex_analyzer.cli_agent_response_text("claude", '{"type":"result","result":"{\\"filters\\":[]}"}'),
            '{"filters":[]}',
        )
        # Non-JSON stdout is returned verbatim for downstream extract_json.
        self.assertEqual(codex_analyzer.cli_agent_response_text("claude", "raw text"), "raw text")
        self.assertEqual(codex_analyzer.cli_agent_response_text("grok", "  hi  "), "hi")

    def test_response_text_from_gemini_joins_parts_and_raises_on_garbage(self) -> None:
        data = {"candidates": [{"content": {"parts": [{"text": '{"filters":'}, {"text": "[]}"}]}}]}
        self.assertEqual(codex_analyzer.response_text_from_gemini(data), '{"filters":[]}')
        with self.assertRaises(RuntimeError):
            codex_analyzer.response_text_from_gemini({"candidates": []})

    def test_provider_config_exposes_new_providers(self) -> None:
        cfg = codex_analyzer.load_provider_config(Path("/tmp/nonexistent-altura-provider-config.json"))
        claude = codex_analyzer.provider_config(cfg, "claude")
        self.assertEqual(claude["kind"], "cli_agent")
        self.assertEqual(claude["command"], "claude")
        self.assertEqual(claude["login_cmd"], "claude auth login")
        gemini = codex_analyzer.provider_config(cfg, "gemini")
        self.assertEqual(gemini["api_key_env"], "GEMINI_API_KEY")
        self.assertIn("generativelanguage", gemini["base_url"])

    def test_run_provider_dispatches_cli_agent_and_sanitizes(self) -> None:
        prompt = codex_analyzer.build_prompt([], min_count=1, ttl_seconds=30)
        cfg = codex_analyzer.provider_config(
            codex_analyzer.load_provider_config(Path("/tmp/nonexistent.json")), "claude"
        )
        out = '{"type":"result","result":"{\\"filters\\":[{\\"condition\\":{\\"signature\\":\\"sig-x\\"},\\"action\\":{\\"kind\\":\\"block\\",\\"status\\":403,\\"body\\":\\"x\\"}}]}"}'
        with patch("subprocess.run", return_value=_FakeProc(0, out)) as run:
            filters = codex_analyzer.run_provider("claude", prompt, cfg, ttl_seconds=30)
        # claude is fed on stdin, not argv.
        self.assertIsNotNone(run.call_args.kwargs.get("input"))
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["condition"]["signature"], "sig-x")
        self.assertEqual(filters[0]["action"]["status"], 403)

    def test_cli_agent_nonzero_exit_raises(self) -> None:
        prompt = codex_analyzer.build_prompt([], min_count=1, ttl_seconds=30)
        cfg = codex_analyzer.provider_config(
            codex_analyzer.load_provider_config(Path("/tmp/nonexistent.json")), "grok"
        )
        with patch("subprocess.run", return_value=_FakeProc(1, "", "not logged in")):
            with self.assertRaises(RuntimeError):
                codex_analyzer.run_provider("grok", prompt, cfg, ttl_seconds=30)

    def test_run_provider_dispatches_gemini(self) -> None:
        prompt = codex_analyzer.build_prompt([], min_count=1, ttl_seconds=30)
        cfg = codex_analyzer.provider_config(
            codex_analyzer.load_provider_config(Path("/tmp/nonexistent.json")), "gemini"
        )
        gemini_data = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": '{"filters":[{"condition":{"signature":"g"},"action":{"kind":"block","status":403,"body":"x"}}]}'
                            }
                        ]
                    }
                }
            ]
        }
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
            with patch.object(codex_analyzer, "post_json", return_value=gemini_data) as post:
                filters = codex_analyzer.run_provider("gemini", prompt, cfg, ttl_seconds=30)
        url = post.call_args.args[0]
        self.assertIn(":generateContent", url)
        self.assertEqual(post.call_args.args[1]["x-goog-api-key"], "test-key")
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["condition"]["signature"], "g")

    def test_detect_cli_agent_reports_missing_binary(self) -> None:
        info = codex_analyzer.detect_cli_agent(
            "claude", {"command": "altura-no-such-binary-xyz", "login_cmd": "x login"}
        )
        self.assertFalse(info["installed"])
        self.assertEqual(info["version"], "")
        self.assertEqual(info["login_cmd"], "x login")


class AiProviderCliTests(unittest.TestCase):
    def _ns(self, **overrides: object) -> object:
        import argparse

        base = {
            "provider": "gemini",
            "model": None,
            "cli_command": None,
            "base_url": None,
            "api_key_env": None,
            "api_key": None,
            "select": True,
        }
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_set_api_provider_writes_config_secret_and_selects(self) -> None:
        import ai_provider_cli

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "providers.json"
            sec_path = Path(tmp) / "secrets.json"
            env = {
                "ALTURA_PROT_PROVIDER_CONFIG": str(cfg_path),
                "ALTURA_PROT_PROVIDER_SECRETS": str(sec_path),
            }
            with patch.dict(os.environ, env, clear=False):
                ai_provider_cli.set_provider(
                    self._ns(provider="gemini", model="gemini-2.5-pro", api_key="sk-secret")
                )
            config = json.loads(cfg_path.read_text())
            self.assertEqual(config["selected_provider"], "gemini")
            self.assertEqual(config["providers"]["gemini"]["model"], "gemini-2.5-pro")
            secrets = json.loads(sec_path.read_text())
            self.assertEqual(secrets["gemini"]["api_key"], "sk-secret")
            self.assertEqual(sec_path.stat().st_mode & 0o777, 0o600)

    def test_set_cli_agent_records_model_without_secret(self) -> None:
        import ai_provider_cli

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "providers.json"
            sec_path = Path(tmp) / "secrets.json"
            env = {
                "ALTURA_PROT_PROVIDER_CONFIG": str(cfg_path),
                "ALTURA_PROT_PROVIDER_SECRETS": str(sec_path),
            }
            with patch.dict(os.environ, env, clear=False):
                ai_provider_cli.set_provider(
                    self._ns(provider="claude", model="claude-opus-4-8", api_key=None)
                )
            config = json.loads(cfg_path.read_text())
            self.assertEqual(config["selected_provider"], "claude")
            self.assertEqual(config["providers"]["claude"]["model"], "claude-opus-4-8")
            self.assertFalse(sec_path.exists())

    def test_set_no_select_keeps_previous_selection(self) -> None:
        import ai_provider_cli

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "providers.json"
            sec_path = Path(tmp) / "secrets.json"
            env = {
                "ALTURA_PROT_PROVIDER_CONFIG": str(cfg_path),
                "ALTURA_PROT_PROVIDER_SECRETS": str(sec_path),
            }
            with patch.dict(os.environ, env, clear=False):
                ai_provider_cli.set_provider(self._ns(provider="openai", model="m1", select=True))
                ai_provider_cli.set_provider(self._ns(provider="anthropic", model="m2", select=False))
            config = json.loads(cfg_path.read_text())
            self.assertEqual(config["selected_provider"], "openai")
            self.assertEqual(config["providers"]["anthropic"]["model"], "m2")

    def test_provider_families_are_disjoint_and_complete(self) -> None:
        import ai_provider_cli

        self.assertEqual(set(ai_provider_cli.CLI_AGENTS) & set(ai_provider_cli.API_PROVIDERS), set())
        for provider in ai_provider_cli.PROVIDERS:
            self.assertIn(provider, codex_analyzer.DEFAULT_PROVIDER_CONFIG["providers"])


class AttackThresholdGateTests(unittest.TestCase):
    """The AI provider must only be called once attack volume crosses the
    user-set --min-attack-events threshold; below it, the free deterministic
    generator runs and no provider call is made."""

    def test_count_attack_evidence_counts_only_strong_denials(self) -> None:
        events = [
            {"reason": "per_ip_rate_limited"},
            {"reason": "observed"},
            {"reason": "filter_block"},
            {"reason": "observed"},
        ]
        # Only deterministic-denial events count; observed volume never does.
        self.assertEqual(codex_analyzer.count_attack_evidence(events), 2)

    def _args(self, events: Path, out: Path, **flags: object) -> object:
        import sys

        argv = ["codexsdgate", "--once", "--events", str(events), "--filters", str(out)]
        for key, value in flags.items():
            flag = f"--{key.replace('_', '-')}"
            if isinstance(value, bool):
                if value:
                    argv.append(flag)
            else:
                argv += [flag, str(value)]
        with patch.object(sys, "argv", argv):
            return codex_analyzer.parse_args()

    def _write_events(self, path: Path, count: int, reason: str = "per_ip_rate_limited") -> None:
        line = json.dumps(
            {
                "signature": "GET|/api/x|curl|*/*",
                "path": "/api/x",
                "path_shape": "/api/x",
                "method": "GET",
                "user_agent": "curl",
                "reason": reason,
            }
        )
        path.write_text("\n".join([line] * count) + "\n", encoding="utf-8")

    def test_below_threshold_skips_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ev, out = Path(tmp) / "ev.jsonl", Path(tmp) / "out.json"
            self._write_events(ev, 3)
            args = self._args(ev, out, min_attack_events=10, min_count=1)
            with patch.object(codex_analyzer, "run_provider") as run_provider:
                codex_analyzer.analyze_once(args)
            run_provider.assert_not_called()
            self.assertTrue(out.exists())

    def test_at_threshold_calls_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ev, out = Path(tmp) / "ev.jsonl", Path(tmp) / "out.json"
            self._write_events(ev, 12)
            args = self._args(ev, out, min_attack_events=10, min_count=1)
            with patch.object(codex_analyzer, "run_provider", return_value=[]) as run_provider:
                codex_analyzer.analyze_once(args)
            run_provider.assert_called_once()

    def test_threshold_zero_always_calls_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ev, out = Path(tmp) / "ev.jsonl", Path(tmp) / "out.json"
            self._write_events(ev, 1)
            args = self._args(ev, out, min_attack_events=0, min_count=1)
            with patch.object(codex_analyzer, "run_provider", return_value=[]) as run_provider:
                codex_analyzer.analyze_once(args)
            run_provider.assert_called_once()

    def test_observed_only_traffic_stays_below_strong_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ev, out = Path(tmp) / "ev.jsonl", Path(tmp) / "out.json"
            self._write_events(ev, 50, reason="observed")  # weak evidence only
            args = self._args(ev, out, min_attack_events=10, min_count=1)
            with patch.object(codex_analyzer, "run_provider") as run_provider:
                codex_analyzer.analyze_once(args)
            run_provider.assert_not_called()

    def test_learn_observed_does_not_let_observed_volume_fire_ai(self) -> None:
        # Even with --learn-observed, a flood of observed-only traffic is not a
        # real attack and must not wake the AI provider.
        with tempfile.TemporaryDirectory() as tmp:
            ev, out = Path(tmp) / "ev.jsonl", Path(tmp) / "out.json"
            self._write_events(ev, 50, reason="observed")
            args = self._args(ev, out, min_attack_events=10, min_count=1, learn_observed=True)
            with patch.object(codex_analyzer, "run_provider") as run_provider:
                codex_analyzer.analyze_once(args)
            run_provider.assert_not_called()


class AnalyzerTimerUnitTests(unittest.TestCase):
    def test_analyzer_service_runs_threshold_gated_oneshot(self) -> None:
        text = Path("ops/systemd/altura-prot-analyzer.service").read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", text)
        self.assertIn("User=altura-prot", text)
        self.assertIn("@PYTHON@", text)
        self.assertIn("--min-attack-events @MIN_ATTACK_EVENTS@", text)
        self.assertIn("codexsdgate.py", text)
        self.assertIn("--provider auto", text)
        self.assertIn("ReadWritePaths=/var/lib/altura-prot", text)
        self.assertIn("NoNewPrivileges=true", text)
        # AI providers need network egress.
        self.assertIn("AF_INET", text)
        # Must NOT lock W^X: Node/V8-based agent CLIs need writable+exec JIT pages.
        self.assertNotIn("MemoryDenyWriteExecute=", text)

    def test_analyzer_timer_is_periodic_and_persistent(self) -> None:
        text = Path("ops/systemd/altura-prot-analyzer.timer").read_text(encoding="utf-8")
        self.assertIn("OnUnitActiveSec=@INTERVAL@", text)
        self.assertIn("Persistent=true", text)
        self.assertIn("WantedBy=timers.target", text)

    def test_installer_wires_the_analyzer_timer(self) -> None:
        install = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn("install_ai_timer", install)
        self.assertIn("--ai-timer", install)
        self.assertIn("--ai-interval", install)
        self.assertIn("--ai-threshold", install)
        self.assertIn("altura-prot-analyzer.timer", install)
        # Substitutes the template placeholders.
        self.assertIn("@MIN_ATTACK_EVENTS@", install)
        self.assertIn("@INTERVAL@", install)


class InstallerAiAutodetectTests(unittest.TestCase):
    """Exercise install.sh's agent-friendly `--ai auto` resolver in isolation by
    sourcing its shell functions under a controlled PATH/env."""

    def _run_autodetect(self, bin_files: dict[str, str], env_overrides: dict[str, str]) -> str:
        import shutil
        import stat

        dirname_bin = shutil.which("dirname")
        bash_bin = shutil.which("bash") or "/bin/bash"
        self.assertIsNotNone(dirname_bin, "dirname required for the test harness")
        install = Path("install.sh").read_text(encoding="utf-8")
        body = "\n".join(line for line in install.splitlines() if line.strip() != 'main "$@"')
        harness = body + '\nprintf "RESULT=%s\\n" "$(ai_autodetect)"\n'
        with tempfile.TemporaryDirectory() as tmp:
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            os.symlink(dirname_bin, bindir / "dirname")  # only external cmd the script sources
            for name, content in bin_files.items():
                fake = bindir / name
                fake.write_text(content, encoding="utf-8")
                fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            script = Path(tmp) / "harness.sh"
            script.write_text(harness, encoding="utf-8")
            env = {"PATH": str(bindir), "HOME": tmp}
            env.update(env_overrides)
            proc = subprocess.run([bash_bin, str(script)], env=env, capture_output=True, text=True, timeout=30)
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT="):
                return line.split("=", 1)[1]
        self.fail(f"no RESULT line; stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_auto_prefers_installed_agent_cli(self) -> None:
        # codex is highest preference, so a present codex wins regardless of env.
        result = self._run_autodetect(
            {"codex": "#!/bin/sh\necho fake\n"},
            {"GEMINI_API_KEY": "should-be-ignored"},
        )
        self.assertEqual(result, "codex")

    def test_auto_falls_back_to_env_api_key(self) -> None:
        result = self._run_autodetect({}, {"GEMINI_API_KEY": "x"})
        self.assertEqual(result, "gemini")

    def test_auto_returns_none_without_cli_or_key(self) -> None:
        result = self._run_autodetect({}, {})
        self.assertEqual(result, "none")


if __name__ == "__main__":
    unittest.main()
