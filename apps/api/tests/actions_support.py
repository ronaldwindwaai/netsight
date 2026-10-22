"""Builders for the controlled-action tests (Step 12): requests, a clock and an in-memory store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.model import NewAction
from netsight_api.actions.store import InMemoryActionStore
from netsight_api.schemas_actions import ActionActor
from netsight_api.schemas_unknown_devices import UnknownDeviceFinding

NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)
FINDING = "unknown-device-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ALICE = ActionActor(id="alice", kind="human")  # requester
BOB = ActionActor(id="bob", kind="human")  # approver
CAROL = ActionActor(id="carol", kind="human")  # second approver
ROBOT = ActionActor(id="robot", kind="ai")
_counter = 0


def action_id() -> str:
    global _counter
    _counter += 1
    return f"action-{_counter:08x}-0000-4000-8000-000000000000"


def new_action(**overrides: Any) -> NewAction:
    values: dict[str, Any] = {
        "id": action_id(),
        "action_type": "endpoint.isolate",
        "target_id": f"endpoint:laptop-{_counter}",
        "params": {"duration_minutes": 60},
        "risk": "C",
        "requester": ALICE,
        "reason": "Unknown device on the finance VLAN",
        "source": None,
        "approvals_required": 1,
        "policy_checks": (),
        "created_at": NOW,
        "approve_by": NOW + timedelta(hours=24),
        "execute_within_seconds": 3600,
        "timeout_seconds": 30,
    }
    values.update(overrides)
    return NewAction(**values)


def two_person(**overrides: Any) -> NewAction:
    return new_action(
        action_type="switch.port.disable",
        target_id=f"interface:sw1-gi0-{_counter + 1}",
        params={},
        risk="D",
        approvals_required=2,
        **overrides,
    )


def new_store(*, kill_switch: KillSwitch | None = None, **limits: int) -> InMemoryActionStore:
    return InMemoryActionStore(kill_switch=kill_switch or KillSwitch(), **limits)


def make_finding(**changes: Any) -> UnknownDeviceFinding:
    from unknown_support import detection

    detected = detection(with_action=True, severity="high", basis="policy-rule")
    base = {
        "id": FINDING,
        "state": "new",
        "severity": detected.severity,
        "severity_basis": detected.severity_basis,
        "evidence_version": 3,
        "assignee_id": None,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "seen_count": 1,
        "recurrence_of": None,
        "endpoint": detected.endpoint,
        "chain": list(detected.chain),
        "comparison": detected.comparison,
        "proposed_action": detected.proposed_action,
    }
    return UnknownDeviceFinding(**{**base, **changes})
