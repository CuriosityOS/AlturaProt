#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

from bench_provenance import provenance_errors


MISSING = object()


REQUIRED_TRUE_CHECKS: tuple[tuple[str, str], ...] = (
    (
        "guardrails.path_shape_rate.hot_path_shape_limited",
        "long-token path-shape rate bucket must shed repeated route-family bursts",
    ),
    (
        "guardrails.path_shape_rate.short_token_sibling_churn_limited",
        "short-token sibling churn must be limited under the parent route family",
    ),
    (
        "guardrails.path_shape_rate.short_token_path_shape_limited",
        "short-token path-shape limiter must shed the rotating short-token burst",
    ),
    (
        "guardrails.path_shape_rate.short_token_sibling_event_shape_recorded",
        "short-token sibling churn must emit the parent path-shape event evidence",
    ),
    (
        "guardrails.path_shape_rate.version_shape_allowed",
        "normal versioned API routes must remain allowed",
    ),
    (
        "guardrails.path_shape_rate.rate_limited_metric_includes_path_shape_limit",
        "aggregate rate-limit metrics must include path-shape limiting",
    ),
    (
        "guardrails.signature_rate.hot_signature_limited",
        "normalized request-signature rate bucket must shed repeated request shapes",
    ),
    (
        "guardrails.signature_rate.other_signature_allowed",
        "signature limiting must not block unrelated request signatures",
    ),
    (
        "guardrails.signature_rate.signature_metric_matches",
        "signature-rate probe must increment the dedicated signature metric",
    ),
    (
        "guardrails.tcp_min_rate.tcp_min_rate_rejected",
        "explicit TCP minimum-rate guard must reject a slow drip",
    ),
    (
        "guardrails.tcp_min_rate.default_tcp_min_rate_rejected",
        "default TCP minimum-rate guard must reject a slow drip",
    ),
    (
        "guardrails.body_min_rate.request_min_rate_rejected",
        "HTTP request-body minimum-rate guard must reject a slow drip",
    ),
    (
        "guardrails.body_min_rate.request_banked_min_rate_rejected",
        "HTTP request-body minimum-rate guard must reject banked pre-grace bytes followed by a slow drip",
    ),
    (
        "guardrails.body_min_rate.upstream_min_rate_rejected",
        "HTTP upstream-body minimum-rate guard must reject a slow drip",
    ),
    (
        "guardrails.connection_duration_runtime.http_max_connection_duration_enforced",
        "HTTP maximum connection duration must be enforced",
    ),
    (
        "guardrails.connection_duration_runtime.tcp_max_connection_duration_enforced",
        "TCP maximum connection duration must be enforced",
    ),
    (
        "guardrails.filter_activation_nonblocking.activation_nonblocking",
        "adaptive filter activation must not block concurrent control requests",
    ),
    (
        "guardrails.filter_activation_nonblocking.activation_reload_nonblocking",
        "adaptive activation plus runtime reload must not block control requests",
    ),
    (
        "guardrails.filter_activation_nonblocking.runtime_reload_loaded",
        "runtime filter reload must successfully load the generated rule set",
    ),
    (
        "guardrails.runtime_sigterm.sigterm_graceful",
        "runtime shutdown must handle SIGTERM gracefully within the probe timeout",
    ),
    (
        "guardrails.rate_limit_before_filter.rate_limit_precedes_filter",
        "rate limiting must run before blocking filter activation on the hot path",
    ),
    (
        "guardrails.tracked_ip_cap.new_client_denied_when_active_shard_full",
        "tracked-IP capacity exhaustion must fail closed for new clients",
    ),
    (
        "guardrails.adaptive_catalog_shape.catalog_shape_requires_strong_evidence",
        "adaptive catalog path-shape activation must require strong evidence",
    ),
    (
        "guardrails.adaptive_catalog_shape.observed_only_not_activated",
        "observed-only catalog traffic must not activate an adaptive filter",
    ),
    (
        "guardrails.adaptive_window_cap.all_requests_ok",
        "adaptive detector window-cap pressure must not shed ordinary requests",
    ),
    (
        "guardrails.adaptive_window_cap.signature_windows_bounded",
        "adaptive detector signature windows must stay within the configured cap",
    ),
    (
        "guardrails.adaptive_window_cap.path_shape_windows_bounded",
        "adaptive detector path-shape windows must stay within the configured cap",
    ),
    (
        "guardrails.http_connection_rate.connection_rate_limited",
        "per-IP HTTP connection-rate guard must reject excess new connections",
    ),
    (
        "guardrails.slow_body.connection_close",
        "request-body idle timeout responses must close the downstream connection",
    ),
    (
        "guardrails.request_content_encoding.compressed_request_rejected",
        "compressed request bodies must be rejected by default",
    ),
    (
        "guardrails.request_content_encoding.compressed_request_closes_connection",
        "compressed request rejection must close the downstream connection",
    ),
    (
        "guardrails.request_content_encoding.compressed_request_not_stored",
        "compressed request rejection must be marked no-store",
    ),
    (
        "guardrails.expect_guard.expect_continue_rejected",
        "Expect: 100-continue must be rejected by default",
    ),
    (
        "guardrails.expect_guard.unsupported_expectation_rejected",
        "unsupported Expect headers must be rejected",
    ),
    (
        "guardrails.expect_guard.expect_rejections_not_stored",
        "Expect header rejections must be marked no-store",
    ),
    (
        "guardrails.range_guard.multi_range_rejected",
        "multi-range requests must be rejected by default",
    ),
    (
        "guardrails.range_guard.unsupported_range_rejected",
        "unsupported Range units must be rejected",
    ),
    (
        "guardrails.range_guard.malformed_range_rejected",
        "malformed Range headers must be rejected",
    ),
    (
        "guardrails.range_guard.range_rejections_not_stored",
        "Range rejections must be marked no-store",
    ),
    (
        "guardrails.accept_encoding.origin_accept_encoding_stripped",
        "origin requests must strip Accept-Encoding by default",
    ),
    (
        "guardrails.framing_guard.generated_framing_rejection_closes_connection",
        "generated framing rejections must close the downstream connection",
    ),
    (
        "guardrails.framing_guard.generated_framing_rejection_not_stored",
        "generated framing rejections must be marked no-store",
    ),
    (
        "guardrails.framing_guard.transfer_encoding_comma_spray_rejected",
        "comma-sprayed Transfer-Encoding must be rejected",
    ),
    (
        "guardrails.framing_guard.transfer_encoding_empty_comma_spray_rejected",
        "empty comma-sprayed Transfer-Encoding must be rejected",
    ),
    (
        "guardrails.header_timeout.slow_initial_header_timeout_observed",
        "slow initial headers must hit the header-read timeout",
    ),
    (
        "guardrails.header_timeout.raw_initial_408_closes_connection",
        "raw initial header timeout must close the downstream connection",
    ),
    (
        "guardrails.header_timeout.raw_initial_408_not_stored",
        "raw initial header timeout must be marked no-store",
    ),
    (
        "guardrails.header_timeout.idle_keepalive.closed_before_reuse",
        "idle keep-alive connections must be closed before reuse",
    ),
    (
        "guardrails.header_count.header_count_guard_observed",
        "downstream header-count limits must be observed",
    ),
    (
        "guardrails.header_count.raw_initial_431_closes_connection",
        "raw initial too-many-headers rejection must close the connection",
    ),
    (
        "guardrails.header_count.raw_initial_431_not_stored",
        "raw initial too-many-headers rejection must be marked no-store",
    ),
    (
        "guardrails.header_line_cap.header_line_cap_observed",
        "downstream header-line byte cap must be observed",
    ),
    (
        "guardrails.header_line_cap.keepalive_second_431",
        "keep-alive follow-up header-line overflow must return 431",
    ),
    (
        "guardrails.initial_framing_precheck_response.initial_framing_precheck_response_observed",
        "initial HTTP framing precheck must generate a bounded rejection",
    ),
    (
        "guardrails.initial_framing_precheck_response.initial_header_too_large_response_observed",
        "initial header byte overflow must generate a bounded rejection",
    ),
    (
        "guardrails.initial_framing_precheck_response.raw_initial_400_closes_connection",
        "raw initial framing rejection must close the downstream connection",
    ),
    (
        "guardrails.initial_framing_precheck_response.raw_initial_431_closes_connection",
        "raw initial header overflow must close the downstream connection",
    ),
    (
        "guardrails.host_guard.absolute_form_unsupported_scheme_rejected",
        "absolute-form request targets must reject non-http schemes before origin work",
    ),
    (
        "guardrails.allowed_methods_startup.unsupported_connect_rejected",
        "allowed HTTP methods must reject CONNECT at startup",
    ),
    (
        "guardrails.allowed_methods_startup.unsupported_trace_rejected",
        "allowed HTTP methods must reject TRACE at startup",
    ),
    (
        "guardrails.allowed_methods_startup.unsupported_track_rejected",
        "allowed HTTP methods must reject TRACK at startup",
    ),
    (
        "guardrails.http_endpoint_startup.invalid_listen_rejected",
        "invalid HTTP listen addresses must fail startup before binding",
    ),
    (
        "guardrails.http_endpoint_startup.missing_upstream_scheme_rejected",
        "HTTP upstream config must include an http:// scheme",
    ),
    (
        "guardrails.http_endpoint_startup.https_upstream_scheme_rejected",
        "plain HTTP connector deployments must reject https:// upstreams at startup",
    ),
    (
        "guardrails.http_endpoint_startup.upstream_userinfo_rejected",
        "HTTP upstream config must reject URI userinfo",
    ),
    (
        "guardrails.http_endpoint_startup.upstream_query_rejected",
        "HTTP upstream config must reject query strings",
    ),
    (
        "guardrails.tcp_endpoint_startup.invalid_listen_rejected",
        "invalid TCP listen addresses must fail startup before binding",
    ),
    (
        "guardrails.tcp_endpoint_startup.missing_upstream_port_rejected",
        "TCP upstream config must include a numeric port",
    ),
    (
        "guardrails.tcp_endpoint_startup.upstream_scheme_rejected",
        "TCP upstream config must be host:port without a URL scheme",
    ),
    (
        "guardrails.tcp_endpoint_startup.upstream_userinfo_rejected",
        "TCP upstream config must reject URI userinfo",
    ),
    (
        "guardrails.tcp_endpoint_startup.upstream_path_rejected",
        "TCP upstream config must reject path-like upstream values",
    ),
    (
        "guardrails.tcp_endpoint_startup.upstream_zero_port_rejected",
        "TCP upstream config must reject port zero",
    ),
    (
        "guardrails.method_override_headers.override_headers_rejected",
        "method override headers must be rejected by default before origin work",
    ),
    (
        "guardrails.method_override_headers.method_rejected_metric_matches",
        "method override header rejections must increment the method rejection metric",
    ),
    (
        "guardrails.trusted_proxy_aggregate_rate.rotating_xff_aggregate_limited",
        "trusted-proxy aggregate rate limit must catch rotating X-Forwarded-For floods",
    ),
    (
        "guardrails.forwarded_headers.trusted_proxy.duplicate_xff_chain_preserved",
        "trusted-proxy forwarding must canonicalize every duplicate X-Forwarded-For value used for client identity",
    ),
    (
        "guardrails.forwarded_headers.custom_identity_header.custom_identity_xff_synthesized",
        "trusted custom identity headers must synthesize a clean X-Forwarded-For chain instead of preserving spoofed XFF",
    ),
    (
        "guardrails.forwarded_headers.custom_identity_header.duplicate_custom_identity_rejected",
        "trusted custom identity headers must reject duplicate singleton identity fields",
    ),
    (
        "guardrails.forwarded_headers.custom_identity_header.comma_custom_identity_rejected",
        "trusted custom identity headers must reject comma-list singleton identity fields",
    ),
    (
        "guardrails.forwarded_headers.custom_identity_header.custom_identity_rejected_metric_matches",
        "trusted custom identity header rejections must increment the forwarded-rejected metric",
    ),
    (
        "guardrails.upstream_failure_circuit.circuit_scoped_to_path_shape",
        "upstream failure circuit breaker must be scoped by path shape",
    ),
    (
        "guardrails.upstream_connect_timeout.upstream_connect_timeout_observed",
        "upstream connect attempts must honor the connect timeout",
    ),
    (
        "guardrails.upstream_connect_timeout.generated_502_closes_connection",
        "upstream connect-timeout rejection must close the downstream connection",
    ),
    (
        "guardrails.upstream_connect_timeout.generated_502_not_stored",
        "upstream connect-timeout rejection must be marked no-store",
    ),
    (
        "guardrails.upstream_timeout_response.upstream_timeout_response_observed",
        "upstream response timeout must produce a bounded generated response",
    ),
    (
        "guardrails.upstream_timeout_response.generated_504_closes_connection",
        "upstream timeout response must close the downstream connection",
    ),
    (
        "guardrails.upstream_timeout_response.generated_504_not_stored",
        "upstream timeout response must be marked no-store",
    ),
    (
        "guardrails.upstream_header_guard.upstream_header_guard_observed",
        "upstream response-header guard must reject oversized upstream headers",
    ),
    (
        "guardrails.upstream_header_guard.generated_502_closes_connection",
        "upstream header rejection must close the downstream connection",
    ),
    (
        "guardrails.upstream_header_guard.generated_502_not_stored",
        "upstream header rejection must be marked no-store",
    ),
    (
        "guardrails.upstream_in_flight.cache_control_header_matches",
        "upstream in-flight overload responses must be marked no-store",
    ),
    (
        "guardrails.upstream_in_flight.retry_after_header_matches",
        "upstream in-flight overload responses must carry Retry-After",
    ),
    (
        "guardrails.upstream_response_guard.hop_by_hop_headers_stripped",
        "upstream hop-by-hop response headers must be stripped",
    ),
    (
        "guardrails.upstream_response_guard.oversized_response.closed",
        "oversized upstream response bodies must be closed",
    ),
    (
        "guardrails.upstream_response_guard.stalled_response.closed",
        "stalled upstream response bodies must be closed",
    ),
    (
        "guardrails.downstream_keep_alive.closed_before_second_response",
        "downstream keep-alive must be disabled by default",
    ),
    (
        "guardrails.tcp_global_connection_cap.rejected_closed",
        "TCP global connection cap must reject excess active connections",
    ),
    (
        "guardrails.tcp_global_connection_rate.global_connection_rate_limited",
        "TCP global connection-rate bucket must reject excess connection churn",
    ),
    (
        "guardrails.tcp_idle_timeout.closed",
        "TCP idle timeout must close idle raw TCP sessions",
    ),
    (
        "guardrails.tcp_relay_head_of_line.upstream_response_delivered_while_downstream_write_blocked",
        "TCP relay must keep the opposite direction flowing while one direction is write-backpressured",
    ),
    (
        "guardrails.event_log_async_queue.all_requests_completed",
        "event-log queue pressure must not stall request completion",
    ),
    (
        "guardrails.event_log_async_queue.event_log_queue_dropped",
        "event-log async queue must drop when full instead of blocking the request thread",
    ),
    (
        "guardrails.event_log_flush.all_requests_ok",
        "event-log flush probe traffic must complete successfully",
    ),
    (
        "guardrails.event_log_flush.first_event_flushed_immediately",
        "event logging must flush the first event immediately for early attack evidence",
    ),
    (
        "guardrails.event_log_flush.burst_flush_batched",
        "event logging must batch burst flushes instead of forcing per-event sync I/O",
    ),
    (
        "guardrails.event_log_flush.interval_flush_observed",
        "event logging must flush batched events on the configured interval",
    ),
    (
        "guardrails.event_log_field_bounds.all_event_fields_bounded",
        "event-log fields must remain bounded before serialization",
    ),
    (
        "guardrails.event_log_rotation.all_requests_ok",
        "event-log rotation probe traffic must complete successfully",
    ),
    (
        "guardrails.event_log_rotation.backup_present",
        "event-log rotation must create a bounded backup file after the byte cap is reached",
    ),
    (
        "guardrails.event_log_rotation.active_log_present",
        "event-log rotation must leave an active log file available for new events",
    ),
    (
        "guardrails.event_log_rotation.jsonl_valid",
        "event-log rotation must preserve valid JSONL records",
    ),
    (
        "guardrails.event_log_rotation.total_bytes_bounded",
        "event-log rotation must keep retained log bytes bounded",
    ),
    (
        "guardrails.runtime_filter_bounds.oversized_file_rejected_and_last_good_preserved",
        "oversized runtime filter files must be rejected while preserving last-good rules",
    ),
    (
        "guardrails.runtime_filter_bounds.too_many_rules_rejected_and_last_good_preserved",
        "runtime filter over-capacity files must be rejected while preserving last-good rules",
    ),
    (
        "guardrails.config_file_startup.oversized_config_rejected",
        "oversized config files must fail startup before loading",
    ),
    (
        "guardrails.config_file_startup.non_regular_config_rejected",
        "non-regular config paths must fail startup before loading",
    ),
    (
        "guardrails.negative_rate_startup.negative_http_rate_rejected",
        "negative HTTP rate limits must fail startup",
    ),
    (
        "guardrails.negative_rate_startup.negative_tcp_rate_rejected",
        "negative TCP rate limits must fail startup",
    ),
    (
        "guardrails.zero_capacity_startup.http_connection_cap_rejected",
        "zero HTTP connection capacity must fail startup",
    ),
    (
        "guardrails.zero_capacity_startup.tcp_connection_cap_rejected",
        "zero TCP connection capacity must fail startup",
    ),
    (
        "guardrails.zero_capacity_startup.http_metadata_cap_rejected",
        "zero HTTP metadata capacity must fail startup",
    ),
    (
        "guardrails.zero_capacity_startup.http_forwarded_cap_rejected",
        "zero forwarded-header capacity must fail startup",
    ),
    (
        "guardrails.zero_capacity_startup.http_upstream_connect_timeout_rejected",
        "zero HTTP upstream connect timeout must fail startup",
    ),
    (
        "guardrails.dynamic_state_ceiling_startup.all_dynamic_state_ceilings_rejected",
        "dynamic state ceilings above supported bounds must fail startup",
    ),
    (
        "guardrails.control_capacity_startup.filter_file_cap_rejected",
        "filter file capacity above supported bounds must fail startup",
    ),
    (
        "guardrails.control_capacity_startup.filter_rule_cap_rejected",
        "filter rule capacity above supported bounds must fail startup",
    ),
    (
        "guardrails.control_capacity_startup.adaptive_queue_cap_rejected",
        "adaptive queue capacity above supported bounds must fail startup",
    ),
    (
        "guardrails.control_capacity_startup.adaptive_window_cap_rejected",
        "adaptive window capacity above supported bounds must fail startup",
    ),
    (
        "guardrails.control_capacity_startup.adaptive_log_cap_rejected",
        "adaptive log capacity above supported bounds must fail startup",
    ),
    (
        "guardrails.control_capacity_startup.adaptive_flush_interval_rejected",
        "adaptive flush interval above supported bounds must fail startup",
    ),
    (
        "guardrails.http_metadata_ceiling_startup.all_http_metadata_ceilings_rejected",
        "HTTP metadata ceilings above supported bounds must fail startup",
    ),
    (
        "guardrails.http_stream_timeout_ceiling_startup.request_body_idle_timeout_rejected",
        "request-body idle timeout above supported bounds must fail startup",
    ),
    (
        "guardrails.http_stream_timeout_ceiling_startup.upstream_body_idle_timeout_rejected",
        "upstream-body idle timeout above supported bounds must fail startup",
    ),
    (
        "guardrails.http_stream_timeout_ceiling_startup.downstream_write_timeout_rejected",
        "downstream write timeout above supported bounds must fail startup",
    ),
    (
        "guardrails.http_stream_timeout_ceiling_startup.request_body_min_rate_grace_rejected",
        "request-body minimum-rate grace above supported bounds must fail startup",
    ),
    (
        "guardrails.http_stream_timeout_ceiling_startup.upstream_body_min_rate_grace_rejected",
        "upstream-body minimum-rate grace above supported bounds must fail startup",
    ),
    (
        "guardrails.body_size_ceiling_startup.max_body_bytes_rejected",
        "request body size above supported bounds must fail startup",
    ),
    (
        "guardrails.body_size_ceiling_startup.max_upstream_body_bytes_rejected",
        "upstream body size above supported bounds must fail startup",
    ),
    (
        "guardrails.min_rate_ceiling_startup.all_min_rate_ceilings_rejected",
        "minimum-rate ceilings above supported bounds must fail startup",
    ),
    (
        "guardrails.connect_timeout_ceiling_startup.http_upstream_connect_timeout_rejected",
        "HTTP upstream connect timeout above supported bounds must fail startup",
    ),
    (
        "guardrails.connect_timeout_ceiling_startup.tcp_connect_timeout_rejected",
        "TCP connect timeout above supported bounds must fail startup",
    ),
    (
        "guardrails.upstream_timeout_ceiling_startup.upstream_timeout_rejected",
        "upstream response timeout above supported bounds must fail startup",
    ),
    (
        "guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_threshold_rejected",
        "upstream failure threshold above supported bounds must fail startup",
    ),
    (
        "guardrails.upstream_failure_circuit_ceiling_startup.upstream_failure_open_ms_rejected",
        "upstream failure open interval above supported bounds must fail startup",
    ),
    (
        "guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_max_idle_per_host_rejected",
        "upstream idle pool size above supported bounds must fail startup",
    ),
    (
        "guardrails.upstream_idle_pool_ceiling_startup.upstream_pool_idle_timeout_rejected",
        "upstream idle pool timeout above supported bounds must fail startup",
    ),
    (
        "guardrails.connection_duration_ceiling_startup.http_max_connection_duration_rejected",
        "HTTP maximum connection duration above supported bounds must fail startup",
    ),
    (
        "guardrails.connection_duration_ceiling_startup.tcp_max_connection_duration_rejected",
        "TCP maximum connection duration above supported bounds must fail startup",
    ),
    (
        "guardrails.connection_request_count_ceiling_startup.max_requests_per_connection_rejected",
        "maximum requests per connection above supported bounds must fail startup",
    ),
    (
        "guardrails.event_log_queue_capacity_ceiling_startup.event_log_queue_capacity_rejected",
        "event-log queue capacity above supported bounds must fail startup",
    ),
    (
        "guardrails.event_log_backup_count_ceiling_startup.event_log_backup_count_rejected",
        "event-log backup count above supported bounds must fail startup",
    ),
    (
        "guardrails.runtime_nofile.runtime_nofile_observed",
        "runtime NOFILE limit must be observed in the benchmarked process",
    ),
    (
        "guardrails.runtime_nofile_capacity.capacity_rejected",
        "startup must reject configured socket capacity above runtime NOFILE capacity",
    ),
    (
        "guardrails.edge_template_port_coverage.systemd_unit_allowed",
        "shipped systemd unit must satisfy runtime guardrails",
    ),
    (
        "guardrails.edge_template_port_coverage.connlimit_set_sizes_allowed",
        "edge connlimit sets must have explicit bounded sizes",
    ),
    (
        "guardrails.edge_template_port_coverage.covered_public_ports_allowed",
        "edge template must cover configured public listener ports",
    ),
    (
        "guardrails.edge_template_port_coverage.aligned_systemd_capacity_allowed",
        "systemd LimitNOFILE must allow a value that covers the configured socket budget",
    ),
    (
        "guardrails.edge_template_port_coverage.insufficient_systemd_capacity_rejected",
        "systemd validation must reject LimitNOFILE values below configured socket budget",
    ),
    (
        "guardrails.edge_template_port_coverage.aligned_low_cap_connlimit_threshold_allowed",
        "edge connlimit threshold must allow values aligned to a tighter public userspace cap",
    ),
    (
        "guardrails.edge_template_port_coverage.excessive_connlimit_threshold_rejected",
        "edge connlimit threshold must not exceed the tightest public userspace cap",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_public_port_rejected",
        "edge template validation must reject missing public listener ports",
    ),
    (
        "guardrails.edge_template_port_coverage.weak_systemd_sandbox_rejected",
        "systemd validation must reject weak sandboxing",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_udp_drop_rejected",
        "edge template validation must reject missing UDP drop backstops",
    ),
    (
        "guardrails.edge_template_port_coverage.generic_tcp_backstops_allowed",
        "edge template validation must allow generic TCP backstops with explicit transport matching",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_generic_tcp_l4proto_rejected",
        "edge template validation must reject generic TCP backstops missing meta l4proto",
    ),
    (
        "guardrails.edge_template_port_coverage.ipv6_prefix_backstops_allowed",
        "edge template validation must allow IPv6 prefix SYN and connlimit backstops",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_ipv6_prefix_syn_backstop_rejected",
        "edge template validation must reject missing IPv6 prefix SYN backstops",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_ipv6_prefix_connlimit_rejected",
        "edge template validation must reject missing IPv6 prefix connlimit backstops",
    ),
    (
        "guardrails.edge_template_port_coverage.ipv6_extension_safe_protocols_allowed",
        "edge template validation must allow IPv6 extension-header-safe protocol matches",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_ipv6_syn_l4proto_rejected",
        "edge template validation must reject IPv6 SYN rules missing meta l4proto",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_ipv6_connlimit_l4proto_rejected",
        "edge template validation must reject IPv6 connlimit rules missing meta l4proto",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_ipv6_icmp_l4proto_rejected",
        "edge template validation must reject IPv6 ICMP rules missing transport-safe matching",
    ),
    (
        "guardrails.edge_template_port_coverage.icmpv4_control_exemption_allowed",
        "edge template validation must allow required ICMPv4 control traffic before drops",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_icmpv4_control_exemption_rejected",
        "edge template validation must reject missing ICMPv4 control exemptions",
    ),
    (
        "guardrails.edge_template_port_coverage.late_icmpv4_control_exemption_rejected",
        "edge template validation must reject ICMPv4 control exemptions placed after drops",
    ),
    (
        "guardrails.edge_template_port_coverage.icmpv6_control_exemption_allowed",
        "edge template validation must allow required ICMPv6 control traffic before drops",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_icmpv6_control_exemption_rejected",
        "edge template validation must reject missing ICMPv6 control exemptions",
    ),
    (
        "guardrails.edge_template_port_coverage.late_icmpv6_control_exemption_rejected",
        "edge template validation must reject ICMPv6 control exemptions placed after drops",
    ),
    (
        "guardrails.edge_template_port_coverage.syn_rate_set_bounds_allowed",
        "edge template validation must allow bounded SYN-rate sets",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_syn_rate_set_size_rejected",
        "edge template validation must reject SYN-rate sets without explicit size bounds",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_syn_rate_set_timeout_rejected",
        "edge template validation must reject SYN-rate sets without explicit timeout bounds",
    ),
    (
        "guardrails.edge_template_port_coverage.fragment_sysctls_allowed",
        "host sysctl validation must allow bounded fragment reassembly settings",
    ),
    (
        "guardrails.edge_template_port_coverage.missing_fragment_sysctls_rejected",
        "host sysctl validation must reject missing fragment reassembly guardrails",
    ),
    (
        "guardrails.edge_template_port_coverage.excessive_fragment_time_rejected",
        "host sysctl validation must reject excessive fragment retention time",
    ),
    (
        "guardrails.edge_template_port_coverage.invalid_fragment_thresholds_rejected",
        "host sysctl validation must reject invalid fragment memory thresholds",
    ),
    (
        "guardrails.edge_template_port_coverage.insufficient_systemd_nofile_rejected",
        "systemd validation must reject LimitNOFILE values below shipped guardrail minimums",
    ),
    (
        "guardrails.edge_template_port_coverage.excessive_systemd_capabilities_rejected",
        "systemd validation must reject excessive service capabilities",
    ),
    (
        "guardrails.admin_token_startup.long_token_rejected",
        "admin metrics tokens above the bounded comparison budget must fail startup",
    ),
    (
        "guardrails.admin_control_plane.duplicate_metrics_token_rejected",
        "metrics auth must fail closed when duplicate admin token headers are present",
    ),
    (
        "guardrails.admin_control_plane.admin_responses_not_stored",
        "admin control-plane responses must be marked no-store",
    ),
    (
        "guardrails.admin_control_plane.admin_responses_close_connection",
        "admin control-plane responses must close connections by default",
    ),
    (
        "guardrails.admin_control_plane.body_bearing_admin_responses_not_stored",
        "body-bearing admin control-plane responses must be marked no-store",
    ),
    (
        "guardrails.admin_control_plane.body_bearing_health_closes_connection",
        "body-bearing health checks must close before keep-alive reuse",
    ),
    (
        "guardrails.admin_control_plane.body_bearing_metrics_without_token_closes_connection",
        "body-bearing unauthenticated metrics checks must close before keep-alive reuse",
    ),
    (
        "guardrails.admin_control_plane.body_bearing_metrics_with_token_closes_connection",
        "body-bearing authenticated metrics checks must close before keep-alive reuse",
    ),
    (
        "guardrails.admin_rate_limit.retry_after_header_matches",
        "admin endpoint per-IP rate-limit responses must carry Retry-After",
    ),
    (
        "guardrails.admin_rate_limit.cache_control_header_matches",
        "admin endpoint per-IP rate-limit responses must be marked no-store",
    ),
    (
        "guardrails.admin_signature_rate.admin_health_signature_limited",
        "admin health requests must be covered by request-signature limiting",
    ),
    (
        "guardrails.admin_signature_rate.retry_after_header_matches",
        "admin signature-rate responses must carry Retry-After",
    ),
    (
        "guardrails.admin_signature_rate.cache_control_header_matches",
        "admin signature-rate responses must be marked no-store",
    ),
    (
        "guardrails.admin_signature_rate.signature_metric_matches",
        "admin signature-rate probe must increment the dedicated signature metric",
    ),
    (
        "guardrails.admin_signature_rate.rate_limited_metric_includes_signature_limit",
        "aggregate rate-limit metrics must include admin signature limiting",
    ),
)


REQUIRED_VALUE_CHECKS: tuple[tuple[str, Any, str], ...] = (
    (
        "guardrails.tcp_min_rate.slow_drip.second_echo_bytes",
        0,
        "explicit TCP minimum-rate guard must close before the second slow-drip byte is echoed",
    ),
    (
        "guardrails.tcp_min_rate.slow_drip.third_echo_bytes",
        0,
        "explicit TCP minimum-rate guard must keep the third slow-drip byte from echoing",
    ),
    (
        "guardrails.tcp_min_rate.default_slow_drip.second_echo_bytes",
        0,
        "default TCP minimum-rate guard must close before the second slow-drip byte is echoed",
    ),
    (
        "guardrails.tcp_min_rate.default_slow_drip.third_echo_bytes",
        0,
        "default TCP minimum-rate guard must keep the third slow-drip byte from echoing",
    ),
    (
        "guardrails.admin_rate_limit.statuses",
        [200, 429],
        "admin health per-IP rate-limit probe must allow the first request and limit the second",
    ),
    (
        "guardrails.admin_signature_rate.statuses",
        [200, 200, 429, 429],
        "admin health signature-rate probe must allow the burst then limit repeated signatures",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assert local benchmark guardrails.")
    parser.add_argument("report", type=Path, help="JSON report from run_local_bench.py")
    parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="Require generated_at_utc and source_tree Git metadata for fresh CI reports.",
    )
    parser.add_argument("--min-duration", type=float, default=None)
    parser.add_argument("--min-workers", type=int, default=None)
    parser.add_argument("--min-tcp-workers", type=int, default=None)
    parser.add_argument("--expect-binary", default=None)
    return parser.parse_args()


def path_value(report: dict[str, Any], dotted_path: str) -> Any:
    value: Any = report
    for part in dotted_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return MISSING
        value = value[part]
    return value


def format_value(value: Any) -> str:
    if value is MISSING:
        return "<missing>"
    return repr(value)


def append_surface_errors(errors: list[str], report: dict[str, Any]) -> None:
    for surface, count_key in (
        ("proxy", "requests"),
        ("health", "requests"),
        ("tcp", "messages"),
    ):
        payload = report.get(surface)
        if not isinstance(payload, dict):
            errors.append(f"{surface}: missing benchmark surface")
            continue
        surface_errors = payload.get("errors", 0)
        if isinstance(surface_errors, bool) or not isinstance(surface_errors, (int, float)):
            errors.append(
                f"{surface}: errors must be numeric, found {format_value(surface_errors)}"
            )
        elif not math.isfinite(float(surface_errors)) or float(surface_errors) != 0.0:
            errors.append(f"{surface}: expected errors=0, found {surface_errors!r}")
        surface_count = payload.get(count_key, 0)
        if isinstance(surface_count, bool) or not isinstance(surface_count, (int, float)):
            errors.append(
                f"{surface}: {count_key} must be numeric, found {format_value(surface_count)}"
            )
        elif not math.isfinite(float(surface_count)) or float(surface_count) <= 0.0:
            errors.append(f"{surface}: expected {count_key}>0, found {surface_count!r}")


def number_at_least_errors(
    report: dict[str, Any],
    key: str,
    minimum: float | int | None,
) -> list[str]:
    if minimum is None:
        return []
    value = report.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return [f"report {key} must be numeric and >= {minimum}, found {format_value(value)}"]
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < float(minimum):
        return [f"report {key} must be >= {minimum}, found {value!r}"]
    return []


def expected_value_errors(report: dict[str, Any], key: str, expected: Any | None) -> list[str]:
    if expected is None:
        return []
    value = report.get(key, MISSING)
    if value != expected:
        return [f"report {key} expected {expected!r}, found {format_value(value)}"]
    return []


def assert_report(
    report: dict[str, Any],
    require_provenance: bool = False,
    min_duration: float | None = None,
    min_workers: int | None = None,
    min_tcp_workers: int | None = None,
    expect_binary: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if require_provenance:
        errors.extend(provenance_errors(report))
    errors.extend(number_at_least_errors(report, "duration_seconds", min_duration))
    errors.extend(number_at_least_errors(report, "workers", min_workers))
    errors.extend(number_at_least_errors(report, "tcp_workers", min_tcp_workers))
    errors.extend(expected_value_errors(report, "binary", expect_binary))
    append_surface_errors(errors, report)

    guardrails = report.get("guardrails")
    if not isinstance(guardrails, dict):
        return errors + ["report has no guardrails object"]

    for dotted_path, description in REQUIRED_TRUE_CHECKS:
        value = path_value(report, dotted_path)
        if value is not True:
            errors.append(
                f"{dotted_path}: expected true ({description}), found {format_value(value)}"
            )
    for dotted_path, expected, description in REQUIRED_VALUE_CHECKS:
        value = path_value(report, dotted_path)
        if value != expected:
            errors.append(
                f"{dotted_path}: expected {expected!r} ({description}), "
                f"found {format_value(value)}"
            )
    return errors


def passing_guardrail_summary(report: dict[str, Any]) -> list[str]:
    lines = []
    for dotted_path, description in REQUIRED_TRUE_CHECKS:
        if path_value(report, dotted_path) is True:
            lines.append(f"{dotted_path}: {description}")
    for dotted_path, expected, description in REQUIRED_VALUE_CHECKS:
        if path_value(report, dotted_path) == expected:
            lines.append(f"{dotted_path}: {description}")
    return lines


def main() -> None:
    args = parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    errors = assert_report(
        report,
        args.require_provenance,
        args.min_duration,
        args.min_workers,
        args.min_tcp_workers,
        args.expect_binary,
    )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        raise SystemExit(1)
    for line in passing_guardrail_summary(report):
        print(line)


if __name__ == "__main__":
    main()
