#!/usr/bin/env python3
"""Require successful main-push validation on the exact release commit."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from typing import Any

REQUIRED = {
    ".github/workflows/ci.yml": "CI",
    ".github/workflows/security.yml": "Security",
    ".github/workflows/codeql.yml": "CodeQL",
}


def check_runs(payload: dict[str, Any], sha: str) -> None:
    failures = []
    for path, name in REQUIRED.items():
        candidates = [
            run for run in payload.get("workflow_runs", [])
            if run.get("head_sha") == sha and run.get("event") == "push"
            and run.get("head_branch") == "main" and run.get("path") == path
            and run.get("name") == name
        ]
        latest = max(candidates, key=lambda run: (
            run.get("run_number", 0), run.get("run_attempt", 0), run.get("id", 0)
        ), default=None)
        if latest is None:
            failures.append(f"{name}: no main-push run for this commit")
        elif latest.get("status") != "completed" or latest.get("conclusion") != "success":
            failures.append(f"{name}: {latest.get('status')} / {latest.get('conclusion')}")
    if failures:
        raise ValueError("Release blocked: " + "; ".join(failures))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        parser.error("sha must be a full commit SHA")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("repository must be owner/name")
    response = subprocess.run(
        ["gh", "api", f"repos/{args.repository}/actions/runs?head_sha={args.sha}&event=push&per_page=100"],
        capture_output=True, text=True, check=True, timeout=60,
    )
    check_runs(json.loads(response.stdout), args.sha)
    print(f"All required release checks passed for {args.sha}")


if __name__ == "__main__":
    main()
