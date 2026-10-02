import pytest

from netsight_api.contracts import ContractViolation, validate

DEVICE = {
    "id": "dev-1",
    "name": "core-sw-01",
    "status": "healthy",
    "freshness": {"state": "fresh", "observed_at": "2026-10-02T12:00:00Z", "source": "librenms"},
}

ALERT = {
    "id": "alert-1",
    "severity": "high",
    "state": "open",
    "title": "Interface down",
    "observed_at": "2026-10-02T12:00:00Z",
}

INCIDENT = {
    "id": "inc-1",
    "title": "Perimeter outage",
    "severity": "critical",
    "state": "open",
    "created_at": "2026-10-02T12:00:00Z",
}

EVIDENCE = {
    "id": "ev-1",
    "source": "blackbox",
    "observed_at": "2026-10-02T12:00:00Z",
    "kind": "tcp:443",
    "payload": {"ok": False},
    "freshness_state": "fresh",
}

ACTION_REQUEST = {
    "id": "act-1",
    "action_type": "firewall.rule_add",
    "target_id": "fw-1",
    "risk": "C",
    "state": "proposed",
    "requester_id": "user-1",
    "reason": "Restore HTTPS path",
}


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
def test_valid_instances_pass(name: str, instance: dict) -> None:
    validate(name, instance)


@pytest.mark.parametrize(
    "name,instance",
    [
        ("device", {**DEVICE, "status": "broken"}),
        ("device", {k: v for k, v in DEVICE.items() if k != "freshness"}),
        ("alert", {**ALERT, "severity": "catastrophic"}),
        ("incident", {**INCIDENT, "state": "deleted"}),
        ("evidence", {**EVIDENCE, "payload": "not-an-object"}),
        ("action_request", {**ACTION_REQUEST, "risk": "E"}),
        ("action_request", {**ACTION_REQUEST, "reason": "ab"}),
    ],
)
def test_invalid_instances_fail(name: str, instance: dict) -> None:
    with pytest.raises(ContractViolation):
        validate(name, instance)


def test_unknown_schema_name() -> None:
    with pytest.raises(KeyError):
        validate("does-not-exist", {})
