#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

from bench_provenance import git_output, provenance_errors


UNSCORED_LAYERS = {"direct_upstream"}
STATIC_ONLY_LAYERS = {"static_filter"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assert deterministic defense-benchmark coverage."
    )
    parser.add_argument(
        "report",
        type=Path,
        nargs="?",
        help="JSON report from run_defense_bench.py",
    )
    parser.add_argument("--expect-scenarios", type=int, default=None)
    parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="Require generated_at_utc and source_tree Git metadata for fresh CI reports.",
    )
    parser.add_argument("--expect-provider", default=None)
    parser.add_argument("--expect-preset", default=None)
    parser.add_argument(
        "--expect-scenario-set",
        default=None,
        help="Comma-separated exact scenario names required in the report.",
    )
    parser.add_argument(
        "--expect-common-layer-set",
        default=None,
        help="Comma-separated exact layer names required in every scenario.",
    )
    parser.add_argument(
        "--expect-observed-learning-scenarios",
        default=None,
        help=(
            "Comma-separated exact scenario names that must include "
            "learned_filter_observed and no others may include it."
        ),
    )
    parser.add_argument(
        "--expect-static-only-scenarios",
        default=None,
        help=(
            "Comma-separated exact scenario names that may rely only on "
            "static/manual filter coverage."
        ),
    )
    parser.add_argument("--min-duration", type=float, default=None)
    parser.add_argument("--min-workers", type=int, default=None)
    parser.add_argument("--min-analyzer-wait", type=float, default=None)
    parser.add_argument("--expect-per-ip-rps", type=int, default=None)
    parser.add_argument("--expect-path-shape-rps", type=int, default=None)
    parser.add_argument("--expect-signature-threshold", type=int, default=None)
    parser.add_argument(
        "--require-direct-baseline",
        action="store_true",
        help="Require every scenario's direct upstream baseline to be healthy.",
    )
    parser.add_argument(
        "--require-layer-traffic",
        action="store_true",
        help="Require every scored defense layer to show real benchmark phase traffic.",
    )
    parser.add_argument(
        "--require-open-proxy-negative-control",
        action="store_true",
        help="Require proxy_open to prove the attack workload is not self-blocking.",
    )
    parser.add_argument(
        "--require-score-consistency",
        action="store_true",
        help="Require effective_target_score booleans to match their numeric thresholds.",
    )
    parser.add_argument(
        "--require-measured-benign",
        action="store_true",
        help="Require every scored defense layer to report measured benign allowance.",
    )
    parser.add_argument(
        "--audit-tracked-artifacts",
        type=Path,
        default=None,
        help=(
            "Audit tracked defense_bench*.json files in this directory. "
            "Current-verifiable artifacts must pass the base assertion with "
            "required provenance; non-current artifacts must be listed in the "
            "historical artifact manifest."
        ),
    )
    parser.add_argument(
        "--artifact-manifest",
        type=Path,
        default=None,
        help="JSON manifest that labels historical defense benchmark artifacts.",
    )
    args = parser.parse_args()
    if args.report is None and args.audit_tracked_artifacts is None:
        parser.error("either report or --audit-tracked-artifacts is required")
    if args.audit_tracked_artifacts is not None and args.artifact_manifest is None:
        parser.error("--artifact-manifest is required with --audit-tracked-artifacts")
    return args


def layer_score(layer: dict[str, Any]) -> dict[str, Any] | None:
    score = layer.get("effective_target_score")
    return score if isinstance(score, dict) else None


def score_passes(score: dict[str, Any]) -> bool:
    return (
        score.get("meets_attacker_block_target") is True
        and score.get("meets_benign_allow_target") is True
        and score_non_negative_int(score, "bypass_errors") == 0
    )


def phase_has_hung_workers(phase: dict[str, Any]) -> bool:
    hung_workers = phase_number(phase, "hung_workers")
    return hung_workers is None or hung_workers != 0


def phase_hung_messages(scenario: str, layer: str, payload: dict[str, Any]) -> list[str]:
    messages = []
    for phase_name in ["direct_upstream", "collect", "replay", "bypass_probe"]:
        phase = payload.get(phase_name)
        if isinstance(phase, dict) and phase_has_hung_workers(phase):
            messages.append(
                f"{scenario}/{layer}/{phase_name} had "
                f"hung_workers={format_value(phase.get('hung_workers', MISSING))}"
            )
    return messages


def layer_error_messages(scenario: str, layer: str, payload: dict[str, Any]) -> list[str]:
    messages = []
    metrics_errors = payload.get("metrics_errors")
    if isinstance(metrics_errors, list) and metrics_errors:
        messages.append(f"{scenario}/{layer} had metrics_errors={metrics_errors!r}")
    elif metrics_errors:
        messages.append(f"{scenario}/{layer} had metrics_errors={metrics_errors!r}")
    return messages


def format_value(value: Any) -> str:
    return "<missing>" if value is MISSING else repr(value)


MISSING = object()


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


def parse_name_set(raw: str | None) -> set[str] | None:
    if raw is None:
        return None
    return {item.strip() for item in raw.split(",") if item.strip()}


def scenario_name_errors(
    scenarios: dict[Any, Any],
    expected_names: set[str] | None,
) -> list[str]:
    if expected_names is None:
        return []
    if not expected_names:
        return ["expected scenario set must not be empty"]
    actual_names = {str(name) for name in scenarios}
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    errors = []
    if missing:
        errors.append(f"missing expected scenarios: {', '.join(missing)}")
    if unexpected:
        errors.append(f"unexpected scenarios: {', '.join(unexpected)}")
    return errors


def layer_name_errors(
    scenario: str,
    scenario_data: dict[str, Any],
    expected_common_layers: set[str] | None,
    observed_learning_scenarios: set[str] | None,
) -> list[str]:
    expected_layers: set[str] | None = None
    if expected_common_layers is not None:
        if not expected_common_layers:
            return ["expected common layer set must not be empty"]
        expected_layers = set(expected_common_layers)

    if observed_learning_scenarios is not None:
        if expected_layers is None:
            expected_layers = set(scenario_data)
        if scenario in observed_learning_scenarios:
            expected_layers.add("learned_filter_observed")
        else:
            expected_layers.discard("learned_filter_observed")

    if expected_layers is None:
        return []
    actual_layers = {str(layer) for layer in scenario_data}
    missing = sorted(expected_layers - actual_layers)
    unexpected = sorted(actual_layers - expected_layers)
    errors = []
    if missing:
        errors.append(f"{scenario}: missing expected layers: {', '.join(missing)}")
    if unexpected:
        errors.append(f"{scenario}: unexpected layers: {', '.join(unexpected)}")
    return errors


def observed_learning_scenario_errors(
    scenarios: dict[Any, Any],
    expected_names: set[str] | None,
) -> list[str]:
    if expected_names is None:
        return []
    if not expected_names:
        return ["expected observed-learning scenario set must not be empty"]
    actual_names = {
        str(name)
        for name, scenario_data in scenarios.items()
        if isinstance(scenario_data, dict) and "learned_filter_observed" in scenario_data
    }
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    errors = []
    if missing:
        errors.append(
            f"missing expected observed-learning scenarios: {', '.join(missing)}"
        )
    if unexpected:
        errors.append(f"unexpected observed-learning scenarios: {', '.join(unexpected)}")
    return errors


def static_only_scenario_errors(
    actual_names: set[str],
    expected_names: set[str] | None,
) -> list[str]:
    if expected_names is None:
        return []
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    errors = []
    if missing:
        errors.append(f"missing expected static-only scenarios: {', '.join(missing)}")
    if unexpected:
        errors.append(f"unexpected static-only scenarios: {', '.join(unexpected)}")
    return errors


def phase_number(phase: dict[str, Any], key: str) -> float | None:
    value = phase.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) else None


def score_number(score: dict[str, Any], key: str) -> float | None:
    value = score.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) else None


def score_non_negative_int(score: dict[str, Any], key: str) -> int | None:
    value = score.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def direct_baseline_errors(scenario: str, scenario_data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    baseline = scenario_data.get("direct_upstream")
    if not isinstance(baseline, dict):
        return [f"{scenario}: missing direct_upstream baseline"]

    requests = phase_number(baseline, "requests")
    if requests is None or requests <= 0:
        errors.append(
            f"{scenario}/direct_upstream: expected requests>0, "
            f"found {format_value(baseline.get('requests', MISSING))}"
        )

    baseline_errors = phase_number(baseline, "errors")
    if baseline_errors is None or baseline_errors != 0:
        errors.append(
            f"{scenario}/direct_upstream: expected errors=0, "
            f"found {format_value(baseline.get('errors', MISSING))}"
        )

    hung_workers = phase_number(baseline, "hung_workers")
    if hung_workers is None or hung_workers != 0:
        errors.append(
            f"{scenario}/direct_upstream: expected hung_workers=0, "
            f"found {format_value(baseline.get('hung_workers', MISSING))}"
        )

    allowed_percent = phase_number(baseline, "allowed_percent")
    if allowed_percent is None or allowed_percent < 95.0:
        errors.append(
            f"{scenario}/direct_upstream: expected allowed_percent>=95.0, "
            f"found {format_value(baseline.get('allowed_percent', MISSING))}"
        )
    return errors


def phase_traffic_errors(
    scenario: str,
    layer: str,
    phase_name: str,
    phase: Any,
    required: bool,
) -> list[str]:
    if phase is None:
        return [f"{scenario}/{layer}: missing {phase_name} phase"] if required else []
    if not isinstance(phase, dict):
        return [f"{scenario}/{layer}/{phase_name}: phase payload is not an object"]
    errors = []
    requests = phase_number(phase, "requests")
    if requests is None or requests <= 0:
        errors.append(
            f"{scenario}/{layer}/{phase_name}: expected requests>0, "
            f"found {format_value(phase.get('requests', MISSING))}"
        )
    phase_errors = phase_number(phase, "errors")
    if phase_errors is None or phase_errors != 0:
        sample_suffix = ""
        samples = phase.get("error_samples")
        if isinstance(samples, list) and samples:
            sample_suffix = f"; samples={samples[:3]!r}"
        errors.append(
            f"{scenario}/{layer}/{phase_name}: expected errors=0, "
            f"found {format_value(phase.get('errors', MISSING))}{sample_suffix}"
        )
    hung_workers = phase_number(phase, "hung_workers")
    if hung_workers is None or hung_workers != 0:
        errors.append(
            f"{scenario}/{layer}/{phase_name}: expected hung_workers=0, "
            f"found {format_value(phase.get('hung_workers', MISSING))}"
        )
    return errors


def layer_traffic_errors(scenario: str, layer: str, payload: dict[str, Any]) -> list[str]:
    if layer in UNSCORED_LAYERS:
        return []
    errors = phase_traffic_errors(
        scenario,
        layer,
        "collect",
        payload.get("collect"),
        required=True,
    )
    errors.extend(
        phase_traffic_errors(
            scenario,
            layer,
            "replay",
            payload.get("replay"),
            required=layer.startswith("learned_filter_"),
        )
    )
    score = layer_score(payload)
    errors.extend(
        phase_traffic_errors(
            scenario,
            layer,
            "bypass_probe",
            payload.get("bypass_probe"),
            required=isinstance(score, dict),
        )
    )
    return errors


def open_proxy_negative_control_errors(
    scenario: str,
    scenario_data: dict[str, Any],
) -> list[str]:
    layer = scenario_data.get("proxy_open")
    if not isinstance(layer, dict):
        return [f"{scenario}: missing proxy_open negative-control layer"]
    errors = phase_traffic_errors(
        scenario,
        "proxy_open",
        "collect",
        layer.get("collect"),
        required=True,
    )
    collect = layer.get("collect")
    if isinstance(collect, dict):
        allowed_percent = phase_number(collect, "allowed_percent")
        if allowed_percent is None or allowed_percent < 95.0:
            errors.append(
                f"{scenario}/proxy_open/collect: expected allowed_percent>=95.0, "
                f"found {format_value(collect.get('allowed_percent', MISSING))}"
            )
    score = layer_score(layer)
    if not isinstance(score, dict):
        errors.append(f"{scenario}/proxy_open: missing effective_target_score")
    elif score.get("meets_attacker_block_target") is not False:
        errors.append(
            f"{scenario}/proxy_open: expected meets_attacker_block_target=false, "
            f"found {format_value(score.get('meets_attacker_block_target', MISSING))}"
        )
    return errors


def score_consistency_errors(
    scenario: str,
    layer: str,
    score: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    prefix = f"{scenario}/{layer}/effective_target_score"

    attacker_target = score_number(score, "attacker_block_target_percent")
    attacker_actual = score_number(score, "attacker_blocked_or_limited_percent")
    attacker_flag = score.get("meets_attacker_block_target", MISSING)
    if attacker_target is None:
        errors.append(
            f"{prefix}: attacker_block_target_percent must be numeric, "
            f"found {format_value(score.get('attacker_block_target_percent', MISSING))}"
        )
    if attacker_actual is None:
        errors.append(
            f"{prefix}: attacker_blocked_or_limited_percent must be numeric, "
            f"found {format_value(score.get('attacker_blocked_or_limited_percent', MISSING))}"
        )
    if attacker_flag is not True and attacker_flag is not False:
        errors.append(
            f"{prefix}: meets_attacker_block_target must be boolean, "
            f"found {format_value(attacker_flag)}"
        )
    if (
        attacker_target is not None
        and attacker_actual is not None
        and (attacker_flag is True or attacker_flag is False)
    ):
        expected_attacker = attacker_actual >= attacker_target
        if attacker_flag is not expected_attacker:
            errors.append(
                f"{prefix}: meets_attacker_block_target expected {expected_attacker} "
                f"from attacker_blocked_or_limited_percent={attacker_actual!r} "
                f"and attacker_block_target_percent={attacker_target!r}, "
                f"found {format_value(attacker_flag)}"
            )

    benign_target = score_number(score, "benign_allow_target_percent")
    benign_raw = score.get("benign_allowed_percent", MISSING)
    benign_actual: float | None = None
    benign_numeric_or_none = False
    if benign_target is None:
        errors.append(
            f"{prefix}: benign_allow_target_percent must be numeric, "
            f"found {format_value(score.get('benign_allow_target_percent', MISSING))}"
        )
    if benign_raw is None:
        benign_numeric_or_none = True
    elif isinstance(benign_raw, bool) or not isinstance(benign_raw, (int, float)):
        errors.append(
            f"{prefix}: benign_allowed_percent must be numeric or None, "
            f"found {format_value(benign_raw)}"
        )
    else:
        benign_actual = float(benign_raw)
        if math.isfinite(benign_actual):
            benign_numeric_or_none = True
        else:
            errors.append(
                f"{prefix}: benign_allowed_percent must be numeric or None, "
                f"found {format_value(benign_raw)}"
            )

    replay_errors = score_non_negative_int(score, "replay_errors")
    bypass_errors = score_non_negative_int(score, "bypass_errors")
    if replay_errors is None:
        errors.append(
            f"{prefix}: replay_errors must be a non-negative integer, "
            f"found {format_value(score.get('replay_errors', MISSING))}"
        )
    if bypass_errors is None:
        errors.append(
            f"{prefix}: bypass_errors must be a non-negative integer, "
            f"found {format_value(score.get('bypass_errors', MISSING))}"
        )

    benign_flag = score.get("meets_benign_allow_target", MISSING)
    if benign_flag is not True and benign_flag is not False:
        errors.append(
            f"{prefix}: meets_benign_allow_target must be boolean, "
            f"found {format_value(benign_flag)}"
        )
    if (
        benign_target is not None
        and benign_numeric_or_none
        and bypass_errors is not None
        and (benign_flag is True or benign_flag is False)
    ):
        expected_benign = (
            bypass_errors == 0
            and benign_actual is not None
            and benign_actual >= benign_target
        )
        if benign_flag is not expected_benign:
            errors.append(
                f"{prefix}: meets_benign_allow_target expected {expected_benign} "
                f"from benign_allowed_percent={format_value(benign_raw)} "
                f"benign_allow_target_percent={benign_target!r} "
                f"and bypass_errors={bypass_errors!r}, found {format_value(benign_flag)}"
            )
    return errors


def measured_benign_errors(
    scenario: str,
    layer: str,
    score: dict[str, Any],
) -> list[str]:
    prefix = f"{scenario}/{layer}/effective_target_score"
    benign_target = score_number(score, "benign_allow_target_percent")
    benign_allowed = score_number(score, "benign_allowed_percent")
    bypass_errors = score_non_negative_int(score, "bypass_errors")
    errors: list[str] = []
    if benign_target is None:
        errors.append(
            f"{prefix}: benign_allow_target_percent must be numeric for measured benign proof, "
            f"found {format_value(score.get('benign_allow_target_percent', MISSING))}"
        )
    if benign_allowed is None:
        errors.append(
            f"{prefix}: benign_allowed_percent must be measured and numeric, "
            f"found {format_value(score.get('benign_allowed_percent', MISSING))}"
        )
    if bypass_errors is None:
        errors.append(
            f"{prefix}: bypass_errors must be a non-negative integer for measured benign proof, "
            f"found {format_value(score.get('bypass_errors', MISSING))}"
        )
    return errors


def assert_report(
    report: dict[str, Any],
    expect_scenarios: int | None = None,
    require_provenance: bool = False,
    expect_provider: str | None = None,
    expect_preset: str | None = None,
    expect_scenario_names: set[str] | None = None,
    expect_common_layer_names: set[str] | None = None,
    expect_observed_learning_scenario_names: set[str] | None = None,
    expect_static_only_scenario_names: set[str] | None = None,
    min_duration: float | None = None,
    min_workers: int | None = None,
    min_analyzer_wait: float | None = None,
    expect_per_ip_rps: int | None = None,
    expect_path_shape_rps: int | None = None,
    expect_signature_threshold: int | None = None,
    require_direct_baseline: bool = False,
    require_layer_traffic: bool = False,
    require_open_proxy_negative_control: bool = False,
    require_score_consistency: bool = False,
    require_measured_benign: bool = False,
) -> list[str]:
    errors: list[str] = []
    if require_provenance:
        errors.extend(provenance_errors(report))
    errors.extend(expected_value_errors(report, "provider", expect_provider))
    errors.extend(expected_value_errors(report, "preset", expect_preset))
    errors.extend(number_at_least_errors(report, "duration_seconds", min_duration))
    errors.extend(number_at_least_errors(report, "workers", min_workers))
    errors.extend(number_at_least_errors(report, "analyzer_wait_seconds", min_analyzer_wait))
    errors.extend(expected_value_errors(report, "per_ip_rps", expect_per_ip_rps))
    errors.extend(expected_value_errors(report, "path_shape_rps", expect_path_shape_rps))
    errors.extend(
        expected_value_errors(
            report,
            "signature_threshold_per_second",
            expect_signature_threshold,
        )
    )

    safety = report.get("safety")
    if not isinstance(safety, str):
        errors.append("report safety metadata must be a string")
    elif "loopback-only" not in safety or "X-Forwarded-For" not in safety:
        errors.append("report safety metadata must state loopback-only X-Forwarded-For simulation")

    scenarios = report.get("scenarios")
    if not isinstance(scenarios, dict) or not scenarios:
        return errors + ["report has no scenarios"]
    if expect_scenarios is not None and len(scenarios) != expect_scenarios:
        errors.append(f"expected {expect_scenarios} scenarios, found {len(scenarios)}")
    errors.extend(scenario_name_errors(scenarios, expect_scenario_names))
    errors.extend(
        observed_learning_scenario_errors(
            scenarios,
            expect_observed_learning_scenario_names,
        )
    )

    static_only_scenarios: set[str] = set()
    for scenario, scenario_data in sorted(scenarios.items()):
        if not isinstance(scenario_data, dict):
            errors.append(f"{scenario}: scenario payload is not an object")
            continue
        errors.extend(
            layer_name_errors(
                str(scenario),
                scenario_data,
                expect_common_layer_names,
                expect_observed_learning_scenario_names,
            )
        )
        if require_direct_baseline:
            errors.extend(direct_baseline_errors(str(scenario), scenario_data))
        if require_open_proxy_negative_control:
            errors.extend(open_proxy_negative_control_errors(str(scenario), scenario_data))
        passing_layers = []
        scored_layers = []
        for layer, payload in sorted(scenario_data.items()):
            if not isinstance(payload, dict):
                errors.append(f"{scenario}/{layer}: layer payload is not an object")
                continue
            errors.extend(phase_hung_messages(str(scenario), str(layer), payload))
            errors.extend(layer_error_messages(str(scenario), str(layer), payload))
            if require_layer_traffic:
                errors.extend(layer_traffic_errors(str(scenario), str(layer), payload))
            if str(layer) in UNSCORED_LAYERS:
                continue
            score = layer_score(payload)
            if score is None:
                legacy_note = (
                    " (legacy target_score is ignored)"
                    if isinstance(payload.get("target_score"), dict)
                    else ""
                )
                errors.append(
                    f"{scenario}/{layer}: missing effective_target_score{legacy_note}"
                )
                continue
            if require_score_consistency:
                errors.extend(score_consistency_errors(str(scenario), str(layer), score))
            if require_measured_benign:
                errors.extend(measured_benign_errors(str(scenario), str(layer), score))
            scored_layers.append(str(layer))
            if score_passes(score):
                passing_layers.append(str(layer))
        if not scored_layers:
            errors.append(f"{scenario}: no scored defense layers")
        elif not passing_layers:
            errors.append(
                f"{scenario}: no defense layer met attacker block and benign allow targets; "
                f"scored={','.join(scored_layers)}"
            )
        elif all(layer in STATIC_ONLY_LAYERS for layer in passing_layers):
            static_only_scenarios.add(str(scenario))
    errors.extend(
        static_only_scenario_errors(
            static_only_scenarios,
            expect_static_only_scenario_names,
        )
    )
    return errors


def passing_layer_summary(report: dict[str, Any]) -> list[str]:
    scenarios = report.get("scenarios")
    if not isinstance(scenarios, dict):
        return []
    lines = []
    for scenario, scenario_data in sorted(scenarios.items()):
        if not isinstance(scenario_data, dict):
            continue
        for layer, payload in sorted(scenario_data.items()):
            if not isinstance(payload, dict):
                continue
            score = layer_score(payload)
            if score is not None and score_passes(score):
                lines.append(
                    f"{scenario}: {layer} "
                    f"attacker={score.get('attacker_blocked_or_limited_percent')} "
                    f"benign={score.get('benign_allowed_percent')}"
                )
                break
    return lines


def load_json_object(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, [f"{path}: failed to read JSON: {exc}"]
    except json.JSONDecodeError as exc:
        return None, [f"{path}: invalid JSON: {exc}"]
    if not isinstance(payload, dict):
        return None, [f"{path}: JSON top level must be an object"]
    return payload, []


def load_historical_artifact_reasons(path: Path) -> tuple[dict[str, str], list[str]]:
    payload, errors = load_json_object(path)
    if payload is None:
        return {}, errors
    raw_historical = payload.get("historical_artifacts")
    if not isinstance(raw_historical, dict):
        return {}, [f"{path}: missing historical_artifacts object"]

    reasons: dict[str, str] = {}
    for name, reason in sorted(raw_historical.items()):
        if not isinstance(name, str) or not name:
            errors.append(f"{path}: historical artifact names must be non-empty strings")
            continue
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"{path}: historical artifact {name} needs a non-empty reason")
            continue
        reasons[name] = reason.strip()
    return reasons, errors


def tracked_defense_artifact_paths(artifact_dir: Path) -> tuple[list[Path], list[str]]:
    if not artifact_dir.exists():
        return [], [f"{artifact_dir}: artifact directory does not exist"]
    if not artifact_dir.is_dir():
        return [], [f"{artifact_dir}: artifact path is not a directory"]

    git_root = git_output(artifact_dir, ["rev-parse", "--show-toplevel"])
    if not git_root:
        return sorted(artifact_dir.glob("defense_bench*.json")), []

    root = Path(git_root)
    try:
        rel_dir = artifact_dir.resolve().relative_to(root.resolve())
    except ValueError:
        return sorted(artifact_dir.glob("defense_bench*.json")), []

    tracked = git_output(root, ["ls-files", "--", str(rel_dir)])
    if tracked is None:
        return [], [f"{artifact_dir}: git ls-files failed"]
    paths = []
    for raw_line in tracked.splitlines():
        path = root / raw_line
        if path.name.startswith("defense_bench") and path.suffix == ".json":
            paths.append(path)
    return sorted(paths), []


def artifact_audit_errors(
    artifact_paths: list[Path],
    historical_reasons: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    seen_names: set[str] = set()
    for path in sorted(artifact_paths):
        seen_names.add(path.name)
        report, load_errors = load_json_object(path)
        if report is None:
            errors.extend(load_errors)
            continue

        current_errors = assert_report(
            report,
            require_provenance=True,
            require_score_consistency=True,
            require_measured_benign=True,
        )
        if not current_errors:
            continue
        if path.name in historical_reasons:
            continue
        sample = "; ".join(current_errors[:3])
        errors.append(
            f"{path}: tracked defense artifact is not current-verifiable and is not "
            f"labeled historical in manifest ({sample})"
        )

    for name in sorted(set(historical_reasons) - seen_names):
        errors.append(
            f"historical artifact manifest references untracked defense artifact {name}"
        )
    return errors


def tracked_artifact_audit_errors(
    artifact_dir: Path,
    manifest_path: Path,
) -> list[str]:
    historical_reasons, errors = load_historical_artifact_reasons(manifest_path)
    artifact_paths, path_errors = tracked_defense_artifact_paths(artifact_dir)
    errors.extend(path_errors)
    if errors:
        return errors
    return artifact_audit_errors(artifact_paths, historical_reasons)


def main() -> None:
    args = parse_args()
    errors: list[str] = []
    report: dict[str, Any] | None = None
    if args.report is not None:
        loaded_report, load_errors = load_json_object(args.report)
        if loaded_report is None:
            errors.extend(load_errors)
        else:
            report = loaded_report
            errors.extend(
                assert_report(
                    report,
                    args.expect_scenarios,
                    args.require_provenance,
                    args.expect_provider,
                    args.expect_preset,
                    parse_name_set(args.expect_scenario_set),
                    parse_name_set(args.expect_common_layer_set),
                    parse_name_set(args.expect_observed_learning_scenarios),
                    parse_name_set(args.expect_static_only_scenarios),
                    args.min_duration,
                    args.min_workers,
                    args.min_analyzer_wait,
                    args.expect_per_ip_rps,
                    args.expect_path_shape_rps,
                    args.expect_signature_threshold,
                    args.require_direct_baseline,
                    args.require_layer_traffic,
                    args.require_open_proxy_negative_control,
                    args.require_score_consistency,
                    args.require_measured_benign,
                )
            )
    if args.audit_tracked_artifacts is not None:
        errors.extend(
            tracked_artifact_audit_errors(
                args.audit_tracked_artifacts,
                args.artifact_manifest,
            )
        )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        raise SystemExit(1)
    if report is not None:
        for line in passing_layer_summary(report):
            print(line)


if __name__ == "__main__":
    main()
