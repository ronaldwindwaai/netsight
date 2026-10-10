"""Shared builders for the diagnostic session tests (valid sessions without any I/O)."""

from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from netsight_api.schemas_diagnostic_session import DiagnosticSession

_VECTORS = Path(__file__).resolve().parents[3] / "contracts" / "test-vectors"
_BASE: dict[str, Any] = json.loads(
    (_VECTORS / "diagnostic-session.vectors.json").read_text("utf-8")
)["diagnostic_session"]["base"]


def session_id(number: int) -> str:
    return f"diagnostic-{uuid.UUID(int=number)}"


def session_document(
    number: int = 1,
    *,
    target: str = "SERVER01",
    completed_at: datetime | None = None,
) -> dict[str, Any]:
    document = copy.deepcopy(_BASE)
    run = document["run"]
    run["id"] = session_id(number)
    run["target"] = target
    if completed_at is not None:
        run["completed_at"] = completed_at.isoformat().replace("+00:00", "Z")
        run["started_at"] = (completed_at - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    return document


def make_session(
    number: int = 1,
    *,
    target: str = "SERVER01",
    completed_at: datetime | None = None,
) -> DiagnosticSession:
    document = session_document(number, target=target, completed_at=completed_at)
    return DiagnosticSession.model_validate_json(json.dumps(document))


# RBAC-MATRIX "Diagnostics": Management and Auditor have no access; Technician is "Basic".
DIAGNOSTIC_ROLES = ["administrator", "network_engineer", "security_analyst", "technician"]
NO_DIAGNOSTIC_ROLES = ["management", "auditor"]
