import json
from typing import Any

import pytest

from netsight_api.contracts import SCHEMA_DIR, ContractViolation, validate

DEVICE = {
    "id": "device-dc425b99-786e-50f0-82dc-ebe2d0aa0e38",
    "name": "core-sw-01",
    "status": "healthy",
    "source_aliases": [{"source": "librenms", "native_id": "1"}],
    "freshness": {"state": "fresh", "observed_at": "2026-10-02T12:00:00Z", "source": "librenms"},
}

ALERT = {
    "id": "alert-1",
    "severity": "high",
    "state": "open",
    "title": "Interface down",
    "observed_at": "2026-10-02T12:00:00Z",
}

# S6-1 tightened the incident contract (canonical IDs, required-nullable fields,
# resolution invariant); exhaustive cases live in test_incident_alert_contracts.py.
INCIDENT = {
    "id": "incident-3f2b8a40-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
    "title": "Perimeter outage",
    "severity": "critical",
    "state": "open",
    "created_at": "2026-10-02T12:00:00Z",
    "updated_at": "2026-10-02T12:00:00Z",
    "assignee_id": None,
    "evidence_ids": [],
    "resolution": None,
}

EVIDENCE = {
    "id": "ev-1",
    "source": "blackbox",
    "observed_at": "2026-10-02T12:00:00Z",
    "kind": "tcp:443",
    "payload": {"ok": False},
    "freshness_state": "fresh",
}

# Step 12 replaced the placeholder action-request schema; the canonical instance is the shared vector.
ACTION_REQUEST = json.loads(
    (SCHEMA_DIR.parents[1] / "contracts" / "test-vectors" / "actions.vectors.json").read_text(
        "utf-8"
    )
)["action_request"]["base"]


@pytest.mark.parametrize(
    "name,instance",
    [
        ("device", DEVICE),
        ("alert", ALERT),
        ("incident", INCIDENT),
        ("evidence", EVIDENCE),
        ("action_request", ACTION_REQUEST),
    ],
)
def test_valid_instances_pass(name: str, instance: dict[str, Any]) -> None:
    validate(name, instance)


@pytest.mark.parametrize(
    "name,instance",
    [
        ("device", {**DEVICE, "status": "broken"}),
        ("device", {**DEVICE, "id": "librenms:1"}),
        ("device", {k: v for k, v in DEVICE.items() if k != "freshness"}),
        ("device", {k: v for k, v in DEVICE.items() if k != "source_aliases"}),
        ("alert", {**ALERT, "severity": "catastrophic"}),
        ("incident", {**INCIDENT, "state": "deleted"}),
        ("evidence", {**EVIDENCE, "payload": "not-an-object"}),
        ("action_request", {**ACTION_REQUEST, "risk": "E"}),
        ("action_request", {**ACTION_REQUEST, "reason": "ab"}),
    ],
)
def test_invalid_instances_fail(name: str, instance: dict[str, Any]) -> None:
    with pytest.raises(ContractViolation):
        validate(name, instance)


def test_unknown_schema_name() -> None:
    with pytest.raises(KeyError):
        validate("does-not-exist", {})
