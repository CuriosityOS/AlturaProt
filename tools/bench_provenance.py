from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def generated_at_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def git_output(cwd: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def source_tree_metadata(cwd: Path) -> dict[str, Any]:
    git_root = git_output(cwd, ["rev-parse", "--show-toplevel"])
    git_commit = git_output(cwd, ["rev-parse", "HEAD"]) if git_root else None
    git_status = git_output(cwd, ["status", "--porcelain"]) if git_root else None
    git_dirty = None if git_status is None else bool(git_status)
    return {
        "cwd": str(cwd),
        "git_root": git_root,
        "git_commit": git_commit,
        "git_commit_short": git_output(cwd, ["rev-parse", "--short=12", "HEAD"])
        if git_commit
        else None,
        "git_branch": git_output(cwd, ["rev-parse", "--abbrev-ref", "HEAD"])
        if git_commit
        else None,
        "git_dirty": git_dirty,
    }


def provenance_errors(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    generated_at = report.get("generated_at_utc")
    if not isinstance(generated_at, str) or not generated_at:
        errors.append("report missing generated_at_utc provenance timestamp")
    elif not generated_at.endswith("Z"):
        errors.append("report generated_at_utc must be a UTC timestamp ending in Z")
    else:
        try:
            parsed = datetime.fromisoformat(generated_at[:-1] + "+00:00")
        except ValueError:
            errors.append("report generated_at_utc is not ISO-8601 parseable")
        else:
            if parsed.utcoffset() != timedelta(0):
                errors.append("report generated_at_utc must parse as UTC")

    source_tree = report.get("source_tree")
    if not isinstance(source_tree, dict):
        errors.append("report missing source_tree provenance object")
        return errors

    for key in ["cwd", "git_root", "git_branch"]:
        if not isinstance(source_tree.get(key), str) or not source_tree.get(key):
            errors.append(f"report source_tree.{key} must be a non-empty string")

    commit = source_tree.get("git_commit")
    if not isinstance(commit, str) or len(commit) not in {40, 64} or not commit.isalnum():
        errors.append("report source_tree.git_commit must be a full Git object id")
    elif not all(ch in "0123456789abcdefABCDEF" for ch in commit):
        errors.append("report source_tree.git_commit must be hexadecimal")

    short = source_tree.get("git_commit_short")
    if not isinstance(short, str) or not (7 <= len(short) <= 64) or not short.isalnum():
        errors.append("report source_tree.git_commit_short must be a Git object id prefix")
    elif not all(ch in "0123456789abcdefABCDEF" for ch in short):
        errors.append("report source_tree.git_commit_short must be hexadecimal")

    if not isinstance(source_tree.get("git_dirty"), bool):
        errors.append("report source_tree.git_dirty must be a boolean")
    return errors
