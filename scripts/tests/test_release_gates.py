"""Security checks cannot be bypassed by manual or CI-only deployment."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "release_gates", Path(__file__).resolve().parents[1] / "check-release-gates.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SHA = "a" * 40


def good_runs() -> list[dict[str, Any]]:
    return [
        {"head_sha": SHA, "event": "push", "head_branch": "main", "path": path,
         "name": name, "status": "completed", "conclusion": "success", "run_number": 1}
        for path, name in MODULE.REQUIRED.items()
    ]


def test_all_exact_revision_checks_allow_release() -> None:
    MODULE.check_runs({"workflow_runs": good_runs()}, SHA)


@pytest.mark.parametrize("field,value", [
    ("head_sha", "b" * 40), ("event", "pull_request"), ("head_branch", "work"),
    ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "skipped"),
    ("path", ".github/workflows/other.yml"),
])
def test_invalid_security_run_blocks_release(field: str, value: str) -> None:
    runs = good_runs()
    runs[1][field] = value
    with pytest.raises(ValueError, match="Security"):
        MODULE.check_runs({"workflow_runs": runs}, SHA)


def test_old_success_cannot_mask_failed_rerun() -> None:
    runs = good_runs()
    runs.append({**runs[1], "run_number": 2, "conclusion": "failure"})
    with pytest.raises(ValueError, match="Security"):
        MODULE.check_runs({"workflow_runs": runs}, SHA)


def test_missing_runs_block_release() -> None:
    with pytest.raises(ValueError, match="no main-push run"):
        MODULE.check_runs({}, SHA)
