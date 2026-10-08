"""Behavioural conformance suite for the incident / alert-rule repositories.

The same tests run against the in-memory fake and (when
``NETSIGHT_TEST_PG_DSN`` is set) the PostgreSQL implementation, so the fake
cannot drift from the real store.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from pg_support import app_role, isolated_schema, requires_pg
from pydantic import ValidationError

from netsight_api import schemas
from netsight_api.contracts import validate
from netsight_api.storage import (
    AlertRuleRepository,
    IllegalTransitionError,
    IncidentRepository,
    InMemoryAlertRuleRepository,
    InMemoryIncidentRepository,
    InvalidOperationError,
    NotFoundError,
    ScopeViolationError,
    StorageConflictError,
)

START = datetime(2026, 10, 8, 8, 0, tzinfo=UTC)
ORDER = ["open", "acknowledged", "investigating", "mitigated", "resolved", "closed"]
ALLOWED = {
    ("open", "acknowledged"),
    ("acknowledged", "investigating"),
    ("investigating", "mitigated"),
    ("mitigated", "resolved"),
    ("resolved", "closed"),
    ("resolved", "open"),
    ("closed", "open"),
}


class FakeClock:
    """Strictly increasing deterministic clock (1s per call)."""

    def __init__(self) -> None:
        self.current = START

    def __call__(self) -> datetime:
        self.current += timedelta(seconds=1)
        return self.current


@dataclass
class Stores:
    incidents: IncidentRepository
    rules: AlertRuleRepository
    clock: FakeClock


@pytest.fixture(
    params=[
        "memory",
        pytest.param("postgres", marks=requires_pg),
        pytest.param("postgres-app-role", marks=requires_pg),
    ]
)
def stores(request: pytest.FixtureRequest) -> Iterator[Stores]:
    clock = FakeClock()
    if request.param == "memory":
        yield Stores(
            InMemoryIncidentRepository(clock=clock),
            InMemoryAlertRuleRepository(clock=clock),
            clock,
        )
        return
    from pg_support import PG_DSN

    from netsight_api.storage.migrate import apply_grants, apply_up
    from netsight_api.storage.postgres import (
        PostgresAlertRuleRepository,
        PostgresIncidentRepository,
        PostgresSettings,
    )

    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        runtime = owner
        if request.param == "postgres-app-role":
            role, role_dsn = stack.enter_context(app_role())
            runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        with owner.connect() as conn:
            apply_up(conn)
            if request.param == "postgres-app-role":
                apply_grants(conn, role)
        yield Stores(
            PostgresIncidentRepository(runtime, clock=clock),
            PostgresAlertRuleRepository(runtime, clock=clock),
            clock,
        )


def resolution_input(**overrides: Any) -> schemas.IncidentResolutionInput:
    payload: dict[str, Any] = {
        "summary": "Replaced failed uplink optic",
        "root_cause_status": "determined",
        "root_cause": "Failed SFP",
        "impact": "Guest Wi-Fi down 40 minutes",
        "restored_at": "2026-10-08T07:30:00Z",
        "follow_up_actions": ["Order spare SFPs"],
        **overrides,
    }
    return schemas.IncidentResolutionInput.model_validate_json(json.dumps(payload))


def new_incident(repo: IncidentRepository, **overrides: Any) -> schemas.Incident:
    args: dict[str, Any] = {"title": "Perimeter outage", "severity": "critical", "actor_id": "u-1"}
    args.update(overrides)
    return repo.create_incident(**args)


def drive_to(repo: IncidentRepository, target: str) -> schemas.Incident:
    incident = new_incident(repo)
    for state in ORDER[1 : ORDER.index(target) + 1]:
        state = cast(schemas.IncidentState, state)
        incident = repo.transition_state(
            incident.id,
            to_state=state,
            actor_id="u-1",
            resolution=resolution_input() if state == "resolved" else None,
        )
    assert incident.state == target
    return incident


def kinds(repo: IncidentRepository, incident_id: str) -> list[str]:
    return [event.kind for event in repo.list_timeline(incident_id)]


# --- incidents: create / read / list ------------------------------------------


def test_create_incident_starts_open_and_validates_against_contract(stores: Stores) -> None:
    incident = new_incident(stores.incidents, evidence_ids=["ev-1"])
    assert incident.state == "open"
    assert incident.resolution is None
    assert incident.assignee_id is None
    assert incident.evidence_ids == ["ev-1"]
    assert incident.created_at == incident.updated_at
    validate("incident", json.loads(incident.model_dump_json()))
    assert stores.incidents.get_incident(incident.id) == incident


def test_get_unknown_or_malformed_id_returns_none(stores: Stores) -> None:
    assert stores.incidents.get_incident("incident-00000000-0000-4000-8000-000000000000") is None
    assert stores.incidents.get_incident("inc-1") is None
    assert stores.incidents.get_incident("'; DROP TABLE incidents;--") is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"title": ""},
        {"title": "x" * 256},
        {"severity": "info"},
        {"actor_id": ""},
        {"evidence_ids": ["a", "a"]},
        {"evidence_ids": [f"e{i}" for i in range(257)]},
    ],
)
def test_create_incident_rejects_invalid_input(stores: Stores, overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        new_incident(stores.incidents, **overrides)
    assert stores.incidents.list_incidents() == []


def test_hostile_and_unicode_text_is_stored_verbatim(stores: Stores) -> None:
    title = "'; DROP TABLE incidents;-- \u202e <script>alert(1)</script> \U0001f525 ü"
    created = new_incident(stores.incidents, title=title)
    assert stores.incidents.get_incident(created.id) == created
    assert created.title == title
    assert len(stores.incidents.list_incidents()) == 1


def test_list_incidents_filters_orders_and_pages(stores: Stores) -> None:
    first = new_incident(stores.incidents, title="first")
    second = new_incident(stores.incidents, title="second")
    third = new_incident(stores.incidents, title="third")
    stores.incidents.transition_state(second.id, to_state="acknowledged", actor_id="u-1")

    assert [i.id for i in stores.incidents.list_incidents()] == [third.id, second.id, first.id]
    assert [i.id for i in stores.incidents.list_incidents(state="open")] == [third.id, first.id]
    assert [i.id for i in stores.incidents.list_incidents(limit=1, offset=1)] == [second.id]
    assert stores.incidents.list_incidents(offset=10) == []


def test_list_incidents_filters_by_severity_and_assignee(stores: Stores) -> None:
    low = new_incident(stores.incidents, severity="low")
    high = new_incident(stores.incidents, severity="high")
    crit = new_incident(stores.incidents, severity="critical")
    stores.incidents.set_assignee(high.id, assignee_id="u-9", actor_id="u-1")
    stores.incidents.set_assignee(crit.id, assignee_id="u-9", actor_id="u-1")
    listed = stores.incidents.list_incidents
    assert [i.id for i in listed(severity="low")] == [low.id]
    assert [i.id for i in listed(assignee_id="u-9")] == [crit.id, high.id]
    assert [i.id for i in listed(assignee_id="u-9", severity="high")] == [high.id]
    assert [i.id for i in listed(state="acknowledged")] == []
    assert listed(assignee_id="someone-else") == []
    # Filter values are data: SQL metacharacters match nothing and break nothing.
    assert listed(assignee_id="x' OR '1'='1") == []


@pytest.mark.parametrize("limit", [0, -1, 101])
def test_list_incidents_enforces_server_side_bounds(stores: Stores, limit: int) -> None:
    with pytest.raises(ValueError):
        stores.incidents.list_incidents(limit=limit)
    with pytest.raises(ValueError):
        stores.incidents.list_incidents(offset=-1)


def test_returned_incident_is_a_detached_immutable_copy(stores: Stores) -> None:
    incident = new_incident(stores.incidents, evidence_ids=["ev-1"])
    with pytest.raises(ValidationError):
        incident.title = "tampered"
    incident.evidence_ids.append("tampered")
    reread = stores.incidents.get_incident(incident.id)
    assert reread is not None
    assert reread.evidence_ids == ["ev-1"]


# --- incidents: state machine -------------------------------------------------


def test_full_lifecycle_records_every_step_on_the_timeline(stores: Stores) -> None:
    incident = drive_to(stores.incidents, "resolved")
    assert incident.resolution is not None
    assert incident.resolution.resolved_by == "u-1"
    assert incident.resolution.resolved_at == incident.updated_at
    closed = stores.incidents.transition_state(incident.id, to_state="closed", actor_id="u-2")

    assert closed.state == "closed"
    assert closed.resolution == incident.resolution
    validate("incident", json.loads(closed.model_dump_json()))
    events = stores.incidents.list_timeline(incident.id)
    assert [e.seq for e in events] == list(range(1, len(events) + 1))
    assert kinds(stores.incidents, incident.id) == [
        "state-changed",
        "state-changed",
        "state-changed",
        "state-changed",
        "resolution",
        "state-changed",
    ]
    assert [(e.state_from, e.state_to) for e in events if e.kind == "state-changed"] == [
        ("open", "acknowledged"),
        ("acknowledged", "investigating"),
        ("investigating", "mitigated"),
        ("mitigated", "resolved"),
        ("resolved", "closed"),
    ]
    for event in events:
        validate("incident_timeline_event", json.loads(event.model_dump_json()))


def test_resolution_is_recorded_as_one_atomic_state_change_plus_resolution_event(
    stores: Stores,
) -> None:
    incident = drive_to(stores.incidents, "mitigated")
    before = len(stores.incidents.list_timeline(incident.id))
    resolved = stores.incidents.transition_state(
        incident.id, to_state="resolved", actor_id="u-9", resolution=resolution_input()
    )
    events = stores.incidents.list_timeline(incident.id)
    assert len(events) == before + 2
    state_event, resolution_event = events[-2], events[-1]
    assert (state_event.kind, state_event.state_from, state_event.state_to) == (
        "state-changed",
        "mitigated",
        "resolved",
    )
    assert resolution_event.kind == "resolution"
    assert resolution_event.message == "Replaced failed uplink optic"
    assert resolved.resolution is not None
    assert resolved.resolution.summary == "Replaced failed uplink optic"


@pytest.mark.parametrize(
    ("current", "target"),
    [(a, b) for a in ORDER for b in ORDER if (a, b) not in ALLOWED],
)
def test_illegal_transitions_are_rejected_and_change_nothing(
    stores: Stores, current: str, target: str
) -> None:
    incident = drive_to(stores.incidents, current)
    events_before = stores.incidents.list_timeline(incident.id)
    with pytest.raises(IllegalTransitionError):
        stores.incidents.transition_state(
            incident.id,
            to_state=target,  # type: ignore[arg-type]
            actor_id="u-1",
            reason="because",
            resolution=resolution_input() if target == "resolved" else None,
        )
    assert stores.incidents.get_incident(incident.id) == incident
    assert stores.incidents.list_timeline(incident.id) == events_before


def test_resolving_requires_a_complete_resolution(stores: Stores) -> None:
    incident = drive_to(stores.incidents, "mitigated")
    with pytest.raises(InvalidOperationError):
        stores.incidents.transition_state(incident.id, to_state="resolved", actor_id="u-1")
    assert stores.incidents.get_incident(incident.id) == incident


def test_resolution_is_rejected_on_any_other_transition(stores: Stores) -> None:
    incident = new_incident(stores.incidents)
    with pytest.raises(InvalidOperationError):
        stores.incidents.transition_state(
            incident.id,
            to_state="acknowledged",
            actor_id="u-1",
            resolution=resolution_input(),
        )


def test_not_determined_root_cause_is_accepted_without_a_root_cause(stores: Stores) -> None:
    incident = drive_to(stores.incidents, "mitigated")
    resolved = stores.incidents.transition_state(
        incident.id,
        to_state="resolved",
        actor_id="u-1",
        resolution=resolution_input(root_cause_status="not-determined", root_cause=None),
    )
    assert resolved.resolution is not None
    assert resolved.resolution.root_cause_status == "not-determined"
    assert resolved.resolution.root_cause is None


def test_resolution_input_without_root_cause_decision_is_invalid() -> None:
    with pytest.raises(ValidationError):
        resolution_input(root_cause=None)
    with pytest.raises(ValidationError):
        resolution_input(impact="")


def test_restoration_time_after_resolution_time_is_rejected(stores: Stores) -> None:
    incident = drive_to(stores.incidents, "mitigated")
    future = (stores.clock.current + timedelta(days=1)).isoformat()
    with pytest.raises(ValueError):
        stores.incidents.transition_state(
            incident.id,
            to_state="resolved",
            actor_id="u-1",
            resolution=resolution_input(restored_at=future),
        )
    assert stores.incidents.get_incident(incident.id) == incident


@pytest.mark.parametrize("start", ["resolved", "closed"])
def test_reopen_requires_an_audit_reason(stores: Stores, start: str) -> None:
    incident = drive_to(stores.incidents, start)
    events_before = stores.incidents.list_timeline(incident.id)
    for reason in (None, "", "   ", "r" * 1001):
        with pytest.raises(InvalidOperationError):
            stores.incidents.transition_state(
                incident.id, to_state="open", actor_id="u-1", reason=reason
            )
    assert stores.incidents.get_incident(incident.id) == incident
    assert stores.incidents.list_timeline(incident.id) == events_before


@pytest.mark.parametrize("start", ["resolved", "closed"])
def test_reopen_clears_the_resolution_but_keeps_history(stores: Stores, start: str) -> None:
    incident = drive_to(stores.incidents, start)
    reopened = stores.incidents.transition_state(
        incident.id, to_state="open", actor_id="u-3", reason="Fault recurred"
    )
    assert reopened.state == "open"
    assert reopened.resolution is None
    validate("incident", json.loads(reopened.model_dump_json()))
    last = stores.incidents.list_timeline(incident.id)[-1]
    assert (last.kind, last.state_from, last.state_to) == ("state-changed", start, "open")
    assert last.reason == "Fault recurred"
    assert last.actor_id == "u-3"
    assert "resolution" in kinds(stores.incidents, incident.id)
    # The incident can run the whole lifecycle again.
    again = stores.incidents.transition_state(incident.id, to_state="acknowledged", actor_id="u-3")
    assert again.state == "acknowledged"


def test_transition_on_unknown_incident_is_not_found(stores: Stores) -> None:
    with pytest.raises(NotFoundError):
        stores.incidents.transition_state(
            "incident-00000000-0000-4000-8000-000000000000",
            to_state="acknowledged",
            actor_id="u-1",
        )


# --- incidents: assignee / evidence / events ----------------------------------


def test_set_assignee_updates_record_and_timeline(stores: Stores) -> None:
    incident = new_incident(stores.incidents)
    assigned = stores.incidents.set_assignee(incident.id, assignee_id="u-7", actor_id="u-1")
    assert assigned.assignee_id == "u-7"
    assert assigned.updated_at > incident.updated_at
    unassigned = stores.incidents.set_assignee(incident.id, assignee_id=None, actor_id="u-1")
    assert unassigned.assignee_id is None
    events = stores.incidents.list_timeline(incident.id)
    assert [(e.kind, e.subject_id) for e in events] == [
        ("assignee-changed", "u-7"),
        ("assignee-changed", None),
    ]


def test_add_evidence_is_idempotent_and_bounded(stores: Stores) -> None:
    incident = new_incident(stores.incidents)
    once = stores.incidents.add_evidence(incident.id, evidence_id="ev-1", actor_id="u-1")
    twice = stores.incidents.add_evidence(incident.id, evidence_id="ev-1", actor_id="u-1")
    assert once.evidence_ids == twice.evidence_ids == ["ev-1"]
    assert kinds(stores.incidents, incident.id) == ["evidence-added"]
    with pytest.raises(ValueError):
        stores.incidents.add_evidence(incident.id, evidence_id="", actor_id="u-1")

    full = new_incident(stores.incidents, evidence_ids=[f"e{i}" for i in range(256)])
    with pytest.raises(InvalidOperationError):
        stores.incidents.add_evidence(full.id, evidence_id="one-too-many", actor_id="u-1")


def test_append_event_adds_comment_with_monotonic_sequence(stores: Stores) -> None:
    incident = new_incident(stores.incidents)
    first = stores.incidents.append_event(
        incident.id, kind="comment", actor_id="u-1", message="Looking at it"
    )
    second = stores.incidents.append_event(
        incident.id, kind="alert-linked", actor_id="system", subject_id="alert-42"
    )
    assert (first.seq, second.seq) == (1, 2)
    assert first.incident_id == incident.id
    assert second.subject_id == "alert-42"
    validate("incident_timeline_event", json.loads(first.model_dump_json()))


@pytest.mark.parametrize(
    "kind",
    ["state-changed", "resolution", "assignee-changed", "evidence-added"],
)
def test_append_event_cannot_forge_record_changing_events(stores: Stores, kind: str) -> None:
    incident = new_incident(stores.incidents)
    with pytest.raises(InvalidOperationError):
        stores.incidents.append_event(
            incident.id,
            kind=kind,  # type: ignore[arg-type]
            actor_id="u-1",
            message="forged",
            subject_id="x",
        )
    assert stores.incidents.list_timeline(incident.id) == []


@pytest.mark.parametrize(
    "args",
    [
        {"kind": "comment"},
        {"kind": "comment", "message": ""},
        {"kind": "comment", "message": "m" * 4001},
        {"kind": "alert-linked"},
        {"kind": "diagnostic", "subject_id": ""},
        {"kind": "comment", "message": "ok", "actor_id": ""},
    ],
)
def test_append_event_validates_payload(stores: Stores, args: dict[str, Any]) -> None:
    incident = new_incident(stores.incidents)
    call: dict[str, Any] = {"actor_id": "u-1", **args}
    with pytest.raises(ValueError):
        stores.incidents.append_event(incident.id, **call)
    assert stores.incidents.list_timeline(incident.id) == []


def test_append_event_on_unknown_incident_is_not_found(stores: Stores) -> None:
    with pytest.raises(NotFoundError):
        stores.incidents.append_event(
            "incident-00000000-0000-4000-8000-000000000000",
            kind="comment",
            actor_id="u-1",
            message="hi",
        )
    with pytest.raises(NotFoundError):
        stores.incidents.list_timeline("incident-00000000-0000-4000-8000-000000000000")


# --- incidents: assigned-only scope (enforced under the row lock) ---------------

TECH = "microsoft:tech-1"
SCOPED_WRITES: dict[str, Any] = {
    "transition": lambda repo, iid, **kw: repo.transition_state(
        iid, to_state="acknowledged", actor_id=TECH, **kw
    ),
    "comment": lambda repo, iid, **kw: repo.append_event(
        iid, kind="comment", actor_id=TECH, message="on site", **kw
    ),
    "evidence": lambda repo, iid, **kw: repo.add_evidence(
        iid, evidence_id="ev-1", actor_id=TECH, **kw
    ),
}


@pytest.mark.parametrize("write", sorted(SCOPED_WRITES))
def test_scoped_write_succeeds_for_the_required_assignee(stores: Stores, write: str) -> None:
    incident = new_incident(stores.incidents)
    stores.incidents.set_assignee(incident.id, assignee_id=TECH, actor_id="u-1")
    SCOPED_WRITES[write](stores.incidents, incident.id, required_assignee=TECH)
    assert len(stores.incidents.list_timeline(incident.id)) == 2


@pytest.mark.parametrize("write", sorted(SCOPED_WRITES))
@pytest.mark.parametrize("assignee", ["microsoft:tech-2", None, "microsoft:tech-1 "])
def test_scoped_write_is_refused_and_changes_nothing_for_any_other_assignee(
    stores: Stores, write: str, assignee: str | None
) -> None:
    incident = new_incident(stores.incidents)
    if assignee is not None:
        stores.incidents.set_assignee(incident.id, assignee_id=assignee, actor_id="u-1")
    before = stores.incidents.get_incident(incident.id)
    history = stores.incidents.list_timeline(incident.id)
    with pytest.raises(ScopeViolationError):
        SCOPED_WRITES[write](stores.incidents, incident.id, required_assignee=TECH)
    assert stores.incidents.get_incident(incident.id) == before
    assert stores.incidents.list_timeline(incident.id) == history


@pytest.mark.parametrize("write", sorted(SCOPED_WRITES))
def test_scoped_write_is_refused_after_the_incident_is_reassigned(
    stores: Stores, write: str
) -> None:
    incident = new_incident(stores.incidents)
    stores.incidents.set_assignee(incident.id, assignee_id=TECH, actor_id="u-1")
    stores.incidents.set_assignee(incident.id, assignee_id="microsoft:tech-2", actor_id="u-1")
    with pytest.raises(ScopeViolationError):
        SCOPED_WRITES[write](stores.incidents, incident.id, required_assignee=TECH)


@pytest.mark.parametrize("write", sorted(SCOPED_WRITES))
def test_scope_is_judged_before_the_state_machine_so_state_is_not_disclosed(
    stores: Stores, write: str
) -> None:
    incident = drive_to(stores.incidents, "closed")  # closed: any write is an illegal transition
    with pytest.raises(ScopeViolationError):
        SCOPED_WRITES[write](stores.incidents, incident.id, required_assignee=TECH)


@pytest.mark.parametrize("write", sorted(SCOPED_WRITES))
def test_scoped_write_on_an_unknown_incident_is_not_found(stores: Stores, write: str) -> None:
    with pytest.raises(NotFoundError):
        SCOPED_WRITES[write](
            stores.incidents,
            "incident-00000000-0000-4000-8000-000000000000",
            required_assignee=TECH,
        )


@pytest.mark.parametrize("write", sorted(SCOPED_WRITES))
@pytest.mark.parametrize("scope", [{}, {"required_assignee": None}])
def test_unscoped_write_ignores_the_assignee(
    stores: Stores, write: str, scope: dict[str, Any]
) -> None:
    incident = new_incident(stores.incidents)
    stores.incidents.set_assignee(incident.id, assignee_id="microsoft:tech-2", actor_id="u-1")
    SCOPED_WRITES[write](stores.incidents, incident.id, **scope)
    assert len(stores.incidents.list_timeline(incident.id)) == 2


def test_closed_incidents_accept_nothing_but_a_reopen(stores: Stores) -> None:
    incident = drive_to(stores.incidents, "closed")
    events_before = stores.incidents.list_timeline(incident.id)
    with pytest.raises(IllegalTransitionError):
        stores.incidents.append_event(incident.id, kind="comment", actor_id="u", message="late")
    with pytest.raises(IllegalTransitionError):
        stores.incidents.set_assignee(incident.id, assignee_id="u-2", actor_id="u")
    with pytest.raises(IllegalTransitionError):
        stores.incidents.add_evidence(incident.id, evidence_id="ev-9", actor_id="u")
    assert stores.incidents.list_timeline(incident.id) == events_before
    stores.incidents.transition_state(incident.id, to_state="open", actor_id="u", reason="again")
    stores.incidents.append_event(incident.id, kind="comment", actor_id="u", message="back")


def test_list_timeline_pages_in_sequence_order(stores: Stores) -> None:
    incident = new_incident(stores.incidents)
    for index in range(5):
        stores.incidents.append_event(
            incident.id, kind="comment", actor_id="u", message=f"note {index}"
        )
    page = stores.incidents.list_timeline(incident.id, after_seq=2, limit=2)
    assert [e.seq for e in page] == [3, 4]
    assert stores.incidents.list_timeline(incident.id, after_seq=5) == []
    with pytest.raises(ValueError):
        stores.incidents.list_timeline(incident.id, limit=0)
    with pytest.raises(ValueError):
        stores.incidents.list_timeline(incident.id, limit=501)
    with pytest.raises(ValueError):
        stores.incidents.list_timeline(incident.id, after_seq=-1)


def test_timeline_is_append_only_by_interface(stores: Stores) -> None:
    public = {
        name
        for name in dir(stores.incidents)
        if not name.startswith("_") and callable(getattr(stores.incidents, name))
    }
    assert public == {
        "create_incident",
        "get_incident",
        "list_incidents",
        "transition_state",
        "set_assignee",
        "add_evidence",
        "append_event",
        "list_timeline",
    }
    incident = new_incident(stores.incidents)
    event = stores.incidents.append_event(
        incident.id, kind="comment", actor_id="u", message="original"
    )
    with pytest.raises(ValidationError):
        event.message = "edited"
    returned = stores.incidents.list_timeline(incident.id)
    returned.clear()
    assert len(stores.incidents.list_timeline(incident.id)) == 1


# --- alert rules ----------------------------------------------------------------


def rule_definition(**overrides: Any) -> schemas.AlertRuleDefinition:
    payload: dict[str, Any] = {
        "name": "After-hours large upload",
        "scope": {"kind": "device_group", "ref": "staff-workstations"},
        "condition": {
            "metric": "traffic.upload_bytes",
            "operator": "gt",
            "threshold": 1000000000,
            "pattern": None,
        },
        "baseline_mode": "none",
        "window_seconds": 900,
        "for_seconds": 0,
        "cooldown_seconds": 3600,
        "schedule": {
            "timezone": "Africa/Windhoek",
            "active": [{"weekdays": ["mon", "fri"], "from": "20:00", "to": "06:00"}],
        },
        "exceptions": {"destinations": ["approved-backup"], "device_groups": ["cctv"]},
        "severity": "high",
        "labels": {"team": "network"},
        "actions": ["create_alert", "email"],
        "incident_policy": "create",
        **overrides,
    }
    return schemas.AlertRuleDefinition.model_validate_json(json.dumps(payload))


def test_new_rules_are_always_drafts_and_never_active(stores: Stores) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    assert rule.status == "draft"
    assert rule.version == 1
    assert rule.created_by == "u-1"
    assert rule.approved_by is None and rule.approved_at is None
    validate("alert_rule", json.loads(rule.model_dump_json(by_alias=True)))
    assert stores.rules.get_rule(rule.id) == rule
    assert stores.rules.get_rule("alert-rule-00000000-0000-4000-8000-000000000000") is None
    assert stores.rules.get_rule("nope") is None


def test_rule_round_trips_nested_fields_exactly(stores: Stores) -> None:
    definition = rule_definition(
        condition={
            "metric": "dns.query",
            "operator": "matches",
            "threshold": None,
            "pattern": "^a",
        },
        schedule=None,
        labels={"team": "net", "site": "hq"},
    )
    rule = stores.rules.create_rule(definition, actor_id="u-1")
    reread = stores.rules.get_rule(rule.id)
    assert reread == rule
    assert reread is not None
    assert reread.condition.pattern == "^a" and reread.schedule is None
    assert reread.labels == {"team": "net", "site": "hq"}


def test_approval_activates_a_rule_exactly_once(stores: Stores) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    active = stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=1)
    assert active.status == "active"
    assert active.approved_by == "u-2"
    assert active.approved_at is not None
    assert active.version == 2
    validate("alert_rule", json.loads(active.model_dump_json(by_alias=True)))
    with pytest.raises(IllegalTransitionError):
        stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=2)
    with pytest.raises(ValueError):
        stores.rules.approve_rule(rule.id, approver_id="", expected_version=2)
    with pytest.raises(NotFoundError):
        stores.rules.approve_rule(
            "alert-rule-00000000-0000-4000-8000-000000000000",
            approver_id="u",
            expected_version=1,
        )


def test_approval_is_bound_to_the_reviewed_version(stores: Stores) -> None:
    """A reviewer who approved version 1 must not activate an edit made afterwards."""
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    edited = stores.rules.update_rule(
        rule.id, rule_definition(name="changed after review"), expected_version=1, actor_id="u-1"
    )
    assert edited.version == 2
    with pytest.raises(StorageConflictError):
        stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=1)
    with pytest.raises(StorageConflictError):
        stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=3)
    unchanged = stores.rules.get_rule(rule.id)
    assert unchanged is not None
    assert (unchanged.status, unchanged.version, unchanged.approved_by) == ("draft", 2, None)
    approved = stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=2)
    assert (approved.status, approved.version) == ("active", 3)


def test_concurrent_approvals_of_the_same_version_only_one_wins(stores: Stores) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")

    def approve(index: int) -> str:
        try:
            stores.rules.approve_rule(rule.id, approver_id=f"u-{index}", expected_version=1)
        except (StorageConflictError, IllegalTransitionError):
            return "rejected"
        return "ok"

    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(approve, range(2, 8)))
    assert sorted(outcomes) == ["ok"] + ["rejected"] * 5


def test_active_rules_cannot_be_edited_until_disabled(stores: Stores) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=1)
    with pytest.raises(IllegalTransitionError):
        stores.rules.update_rule(
            rule.id, rule_definition(name="renamed"), expected_version=2, actor_id="u-1"
        )
    disabled = stores.rules.disable_rule(rule.id, actor_id="u-3")
    assert disabled.status == "disabled"
    assert disabled.approved_by == "u-2"
    validate("alert_rule", json.loads(disabled.model_dump_json(by_alias=True)))


def test_rule_edit_and_disable_require_a_valid_actor(stores: Stores) -> None:
    """Every rule mutation names its actor so the route layer can audit it (PRD 32)."""
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    with pytest.raises(ValueError):
        stores.rules.update_rule(
            rule.id, rule_definition(name="x"), expected_version=1, actor_id=""
        )
    stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=1)
    with pytest.raises(ValueError):
        stores.rules.disable_rule(rule.id, actor_id="")
    unchanged = stores.rules.get_rule(rule.id)
    assert unchanged is not None and unchanged.status == "active"


def test_editing_a_disabled_rule_resets_it_to_an_unapproved_draft(stores: Stores) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=1)
    stores.rules.disable_rule(rule.id, actor_id="u-1")
    edited = stores.rules.update_rule(
        rule.id,
        rule_definition(name="renamed", severity="low"),
        expected_version=3,
        actor_id="u-1",
    )
    assert (edited.name, edited.severity, edited.status) == ("renamed", "low", "draft")
    assert edited.approved_by is None and edited.approved_at is None
    assert edited.version == 4
    assert edited.created_by == "u-1" and edited.created_at == rule.created_at
    assert edited.updated_at > rule.updated_at
    with pytest.raises(IllegalTransitionError):
        stores.rules.disable_rule(rule.id, actor_id="u-1")


def test_draft_edit_bumps_version(stores: Stores) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    edited = stores.rules.update_rule(
        rule.id, rule_definition(cooldown_seconds=60), expected_version=1, actor_id="u-1"
    )
    assert (edited.status, edited.version, edited.cooldown_seconds) == ("draft", 2, 60)
    with pytest.raises(NotFoundError):
        stores.rules.update_rule(
            "alert-rule-00000000-0000-4000-8000-000000000000",
            rule_definition(),
            expected_version=1,
            actor_id="u-1",
        )


def test_update_rule_with_a_stale_version_conflicts_and_changes_nothing(stores: Stores) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    first = stores.rules.update_rule(
        rule.id, rule_definition(name="first"), expected_version=1, actor_id="u-1"
    )
    assert first.version == 2
    with pytest.raises(StorageConflictError):
        stores.rules.update_rule(
            rule.id, rule_definition(name="second"), expected_version=1, actor_id="u-1"
        )
    with pytest.raises(StorageConflictError):
        stores.rules.update_rule(
            rule.id, rule_definition(name="future"), expected_version=3, actor_id="u-1"
        )
    unchanged = stores.rules.get_rule(rule.id)
    assert unchanged is not None
    assert (unchanged.name, unchanged.version) == ("first", 2)
    assert (
        stores.rules.update_rule(
            rule.id, rule_definition(name="second"), expected_version=2, actor_id="u-1"
        ).version
        == 3
    )


def test_concurrent_edits_from_the_same_version_only_one_wins(stores: Stores) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")

    def edit(index: int) -> str:
        try:
            stores.rules.update_rule(
                rule.id,
                rule_definition(name=f"editor {index}"),
                expected_version=1,
                actor_id="u-1",
            )
        except StorageConflictError:
            return "conflict"
        return "ok"

    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(edit, range(6)))
    assert sorted(outcomes) == ["conflict"] * 5 + ["ok"]
    final = stores.rules.get_rule(rule.id)
    assert final is not None and final.version == 2


def test_list_rules_filters_by_status_and_pages(stores: Stores) -> None:
    a = stores.rules.create_rule(rule_definition(name="a"), actor_id="u")
    b = stores.rules.create_rule(rule_definition(name="b"), actor_id="u")
    stores.rules.approve_rule(b.id, approver_id="u2", expected_version=1)
    assert [r.id for r in stores.rules.list_rules()] == [b.id, a.id]
    assert [r.id for r in stores.rules.list_rules(status="active")] == [b.id]
    assert [r.id for r in stores.rules.list_rules(limit=1, offset=1)] == [a.id]
    with pytest.raises(ValueError):
        stores.rules.list_rules(limit=101)


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"window_seconds": 59},
        {"actions": []},
        {"condition": {"metric": "x.y", "operator": "gt", "threshold": None, "pattern": None}},
        {"schedule": {"timezone": "Windhoek", "active": []}},
    ],
)
def test_rule_definitions_are_validated_at_the_boundary(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        rule_definition(**overrides)


# --- maintenance windows ---------------------------------------------------------


def window_definition(**overrides: Any) -> schemas.MaintenanceWindowDefinition:
    payload: dict[str, Any] = {
        "name": "Core switch upgrade",
        "scope": {"kind": "site", "ref": "windhoek-hq"},
        "starts_at": "2026-10-10T22:00:00Z",
        "ends_at": "2026-10-11T02:00:00Z",
        "evaluation": "retain",
        "reason": "Planned firmware upgrade",
        **overrides,
    }
    return schemas.MaintenanceWindowDefinition.model_validate_json(json.dumps(payload))


def test_create_and_get_window(stores: Stores) -> None:
    window = stores.rules.create_window(window_definition(), actor_id="u-1")
    assert window.status == "scheduled"
    assert window.created_by == "u-1"
    assert window.cancelled_by is None and window.cancelled_at is None
    validate("maintenance_window", json.loads(window.model_dump_json()))
    assert stores.rules.get_window(window.id) == window
    assert stores.rules.get_window("nope") is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"ends_at": "2026-10-10T22:00:00Z"},
        {"ends_at": "2026-10-10T21:00:00Z"},
        {"ends_at": "2026-11-20T22:00:00Z"},
        {"reason": ""},
        {"evaluation": "pause"},
    ],
)
def test_window_definitions_are_validated_at_the_boundary(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        window_definition(**overrides)


def test_list_windows_active_at_is_start_inclusive_end_exclusive(stores: Stores) -> None:
    window = stores.rules.create_window(window_definition(), actor_id="u-1")
    start = datetime(2026, 10, 10, 22, 0, tzinfo=UTC)
    end = datetime(2026, 10, 11, 2, 0, tzinfo=UTC)
    assert [w.id for w in stores.rules.list_windows(active_at=start)] == [window.id]
    assert [w.id for w in stores.rules.list_windows(active_at=end - timedelta(seconds=1))] == [
        window.id
    ]
    assert stores.rules.list_windows(active_at=end) == []
    assert stores.rules.list_windows(active_at=start - timedelta(seconds=1)) == []
    assert [w.id for w in stores.rules.list_windows()] == [window.id]
    with pytest.raises(ValueError):
        stores.rules.list_windows(active_at=datetime(2026, 10, 10, 22, 0))  # noqa: DTZ001 - naive on purpose


def test_cancelled_windows_are_hidden_unless_requested(stores: Stores) -> None:
    window = stores.rules.create_window(window_definition(), actor_id="u-1")
    cancelled = stores.rules.cancel_window(window.id, actor_id="u-2")
    assert cancelled.status == "cancelled"
    assert cancelled.cancelled_by == "u-2" and cancelled.cancelled_at is not None
    validate("maintenance_window", json.loads(cancelled.model_dump_json()))
    in_window = datetime(2026, 10, 10, 23, 0, tzinfo=UTC)
    assert stores.rules.list_windows(active_at=in_window) == []
    assert stores.rules.list_windows() == []
    assert [w.id for w in stores.rules.list_windows(include_cancelled=True)] == [window.id]
    with pytest.raises(IllegalTransitionError):
        stores.rules.cancel_window(window.id, actor_id="u-2")
    with pytest.raises(NotFoundError):
        stores.rules.cancel_window("maintenance-00000000-0000-4000-8000-000000000000", actor_id="u")


def test_window_paging_is_bounded(stores: Stores) -> None:
    with pytest.raises(ValueError):
        stores.rules.list_windows(limit=0)
    with pytest.raises(ValueError):
        stores.rules.list_windows(offset=-1)
