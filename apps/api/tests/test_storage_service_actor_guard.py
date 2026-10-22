"""The storage layer refuses a service principal for every operation that records a human
judgement or edits configuration (resolve, reopen, acknowledge, assign, evidence, rule edits).

Defence in depth behind the evaluator's narrow adapter: even a caller that reaches the repository
directly cannot make the alert evaluator resolve an incident. Runs on the in-memory store and, with
``NETSIGHT_TEST_PG_DSN``, PostgreSQL (the shared conformance fixture).
"""

from __future__ import annotations

import pytest
import test_storage_conformance as conformance
from test_storage_conformance import (
    Stores,
    drive_to,
    new_incident,
    resolution_input,
    rule_definition,
    window_definition,
)

from netsight_api.evaluation.incidents import SERVICE_ACTOR_ID
from netsight_api.storage import ScopeViolationError
from netsight_api.storage.lifecycle import is_service_actor

stores = conformance.stores  # the shared fixture: in-memory and, with a DSN, PostgreSQL
SERVICE_ACTORS = [SERVICE_ACTOR_ID, "service:other", "SERVICE:Shouting"]


@pytest.mark.parametrize(
    ("actor", "expected"),
    [
        (SERVICE_ACTOR_ID, True),
        ("service:anything", True),
        ("Service:Anything", True),
        ("human:oidc:alice", False),
        ("seed:admin", False),
        ("u-1", False),
        ("my-service:thing", False),
        ("", False),
    ],
)
def test_service_actors_are_recognised_by_their_reserved_prefix(actor: str, expected: bool) -> None:
    assert is_service_actor(actor) is expected


@pytest.mark.parametrize("actor", SERVICE_ACTORS)
def test_a_service_actor_cannot_advance_resolve_or_reopen_an_incident(
    stores: Stores, actor: str
) -> None:
    incident = new_incident(stores.incidents)
    with pytest.raises(ScopeViolationError):
        stores.incidents.transition_state(incident.id, to_state="acknowledged", actor_id=actor)
    resolved = drive_to(stores.incidents, "resolved")
    with pytest.raises(ScopeViolationError):
        stores.incidents.transition_state(
            resolved.id, to_state="open", actor_id=actor, reason="try again"
        )
    mitigated = drive_to(stores.incidents, "mitigated")
    with pytest.raises(ScopeViolationError):
        stores.incidents.transition_state(
            mitigated.id, to_state="resolved", actor_id=actor, resolution=resolution_input()
        )
    for before, after in ((incident, "open"), (resolved, "resolved"), (mitigated, "mitigated")):
        current = stores.incidents.get_incident(before.id)
        assert current is not None and current.state == after
        assert current.resolution == before.resolution


@pytest.mark.parametrize("actor", SERVICE_ACTORS)
def test_a_service_actor_cannot_assign_or_attach_evidence(stores: Stores, actor: str) -> None:
    incident = new_incident(stores.incidents)
    with pytest.raises(ScopeViolationError):
        stores.incidents.set_assignee(incident.id, assignee_id="u-2", actor_id=actor)
    with pytest.raises(ScopeViolationError):
        stores.incidents.add_evidence(incident.id, evidence_id="ev-1", actor_id=actor)
    current = stores.incidents.get_incident(incident.id)
    assert current is not None
    assert current.assignee_id is None and current.evidence_ids == []
    assert len(stores.incidents.list_timeline(incident.id)) == 0


@pytest.mark.parametrize("actor", SERVICE_ACTORS)
def test_a_service_actor_cannot_edit_approve_or_disable_a_rule(stores: Stores, actor: str) -> None:
    rule = stores.rules.create_rule(rule_definition(), actor_id="u-1")
    with pytest.raises(ScopeViolationError):
        stores.rules.update_rule(
            rule.id, rule_definition(name="hijacked"), expected_version=1, actor_id=actor
        )
    with pytest.raises(ScopeViolationError):
        stores.rules.approve_rule(rule.id, approver_id=actor, expected_version=1)
    approved = stores.rules.approve_rule(rule.id, approver_id="u-2", expected_version=1)
    with pytest.raises(ScopeViolationError):
        stores.rules.disable_rule(approved.id, actor_id=actor)
    current = stores.rules.get_rule(rule.id)
    assert current is not None and current.status == "active" and current.name != "hijacked"


@pytest.mark.parametrize("actor", SERVICE_ACTORS)
def test_a_service_actor_cannot_create_a_rule_or_a_maintenance_window(
    stores: Stores, actor: str
) -> None:
    with pytest.raises(ScopeViolationError):
        stores.rules.create_rule(rule_definition(), actor_id=actor)
    with pytest.raises(ScopeViolationError):
        stores.rules.create_window(window_definition(), actor_id=actor)
    assert stores.rules.list_rules() == [] and stores.rules.list_windows() == []


@pytest.mark.parametrize("actor", SERVICE_ACTORS)
def test_a_service_actor_cannot_cancel_a_maintenance_window(stores: Stores, actor: str) -> None:
    window = stores.rules.create_window(window_definition(), actor_id="u-1")
    with pytest.raises(ScopeViolationError):
        stores.rules.cancel_window(window.id, actor_id=actor)
    current = stores.rules.get_window(window.id)
    assert current is not None and current.status == "scheduled"


def test_a_service_actor_may_still_open_an_incident_and_leave_a_note(stores: Stores) -> None:
    incident = stores.incidents.create_incident(
        title="Device down", severity="high", actor_id=SERVICE_ACTOR_ID
    )
    event = stores.incidents.append_event(
        incident.id,
        kind="alert-linked",
        actor_id=SERVICE_ACTOR_ID,
        message="fired",
        subject_id="a" * 32,
    )
    assert event.actor_id == SERVICE_ACTOR_ID


def test_humans_are_unaffected(stores: Stores) -> None:
    incident = new_incident(stores.incidents)
    moved = stores.incidents.transition_state(
        incident.id, to_state="acknowledged", actor_id="human:oidc:alice"
    )
    assert moved.state == "acknowledged"
