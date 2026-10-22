"""Engine output -> incident store (S6 step 2): exactly one deduplicated incident per grouping
key, a service principal (never a human), a timeline entry, and no automatic resolution."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from evaluation_support import (
    DEVICE_A,
    DEVICE_B,
    T0,
    Stack,
    decision_for,
)

from netsight_api.evaluation.incidents import (
    SERVICE_ACTOR_ID,
    SERVICE_IDENTITY,
    AlertIncidentService,
)
from netsight_api.rbac import PrincipalKind, is_allowed
from netsight_api.schemas import Incident, IncidentResolutionInput
from netsight_api.storage import InMemoryAlertIncidentLinkRepository

BIDI = chr(0x202E)


def service(stack: Stack) -> AlertIncidentService:
    return AlertIncidentService(stack.incidents, stack.links)


def all_incidents(stack: Stack) -> list[Incident]:
    return stack.incidents.list_incidents(limit=100)


def human_resolve(stack: Stack, incident_id: str) -> None:
    resolution = IncidentResolutionInput.model_validate_json(
        json.dumps(
            {
                "summary": "fixed",
                "root_cause_status": "not-determined",
                "root_cause": None,
                "impact": "none",
                "restored_at": "2026-10-10T08:30:00Z",
                "follow_up_actions": [],
            }
        )
    )
    for state in ("acknowledged", "investigating", "mitigated", "resolved"):
        stack.incidents.transition_state(
            incident_id,
            to_state=state,  # type: ignore[arg-type]
            actor_id="human:oidc:alice",
            resolution=resolution if state == "resolved" else None,
        )


def ensure(stack: Stack, rule: Any, entity: str, **decision_overrides: Any) -> Any:
    return service(stack).ensure(
        rule=rule,
        decision=decision_for(rule, entity, **decision_overrides),
        entity=entity,
        correlation_id="cycle-1",
    )


# --- the principal --------------------------------------------------------------------------------


def test_the_evaluator_is_a_service_principal_with_no_roles_and_no_human_permissions() -> None:
    assert SERVICE_IDENTITY.principal is PrincipalKind.SERVICE
    assert SERVICE_IDENTITY.id == SERVICE_ACTOR_ID and not SERVICE_IDENTITY.roles
    for permission in (
        "incidents:resolve",
        "incidents:reopen",
        "incidents:transition",
        "alert-rules:write",
        "alert-rules:approve",
        "maintenance:write",
    ):
        assert not is_allowed(SERVICE_IDENTITY, permission)


def test_the_service_offers_no_way_to_resolve_close_or_edit_anything() -> None:
    names = {name for name in dir(AlertIncidentService) if not name.startswith("_")}
    assert names == {"ensure", "note_recovery"}  # open + record recovery; never resolve


# --- policy create -------------------------------------------------------------------------------


def test_policy_none_never_touches_the_store() -> None:
    stack = Stack.build()
    rule = stack.active_rule(incident_policy="none", actions=["email"])
    effect = ensure(stack, rule, DEVICE_A)
    assert (effect.action, effect.incident_id) == ("none", None)
    assert all_incidents(stack) == []


def test_a_firing_alert_creates_one_open_incident_by_the_service_principal() -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    effect = ensure(stack, rule, DEVICE_A)
    assert effect.action == "created" and effect.incident_id is not None
    (incident,) = all_incidents(stack)
    assert incident.id == effect.incident_id
    assert (incident.state, incident.severity, incident.assignee_id) == ("open", "high", None)
    assert "Device down" in incident.title and DEVICE_A in incident.title
    (event,) = stack.incidents.list_timeline(incident.id)
    assert (event.kind, event.actor_id) == ("alert-linked", SERVICE_ACTOR_ID)
    assert event.subject_id == decision_for(rule, DEVICE_A).fingerprint
    assert event.message is not None and "Device down" in event.message


def test_repeated_firing_decisions_never_create_a_second_incident() -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    first = ensure(stack, rule, DEVICE_A)
    for _ in range(5):
        again = ensure(stack, rule, DEVICE_A)
        assert (again.action, again.incident_id) == ("none", first.incident_id)
    assert len(all_incidents(stack)) == 1
    assert len(stack.incidents.list_timeline(first.incident_id)) == 1


def test_policy_create_opens_one_incident_per_alert() -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    first, second = ensure(stack, rule, DEVICE_A), ensure(stack, rule, DEVICE_B)
    assert first.incident_id != second.incident_id
    assert len(all_incidents(stack)) == 2


@pytest.mark.parametrize(
    ("alert_severity", "incident_severity"),
    [
        ("info", "low"),
        ("low", "low"),
        ("medium", "medium"),
        ("high", "high"),
        ("critical", "critical"),
    ],
)
def test_alert_severity_maps_onto_the_incident_scale(
    alert_severity: str, incident_severity: str
) -> None:
    stack = Stack.build()
    ensure(stack, stack.active_rule(severity=alert_severity), DEVICE_A)
    assert all_incidents(stack)[0].severity == incident_severity


def test_a_still_firing_alert_gets_no_new_incident_when_a_human_resolves_the_old_one() -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    first = ensure(stack, rule, DEVICE_A)
    assert ensure(stack, rule, DEVICE_A).action == "none"
    human_resolve(stack, first.incident_id)
    again = ensure(stack, rule, DEVICE_A)  # same outage: the alert has not recovered
    assert again.action == "none" and again.incident_id == first.incident_id
    assert len(all_incidents(stack)) == 1


def test_a_new_incident_is_created_once_the_alert_recovered_after_a_human_resolution() -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    first = ensure(stack, rule, DEVICE_A)
    human_resolve(stack, first.incident_id)
    service(stack).note_recovery(rule=rule, decision=decision_for(rule, DEVICE_A))
    second = ensure(stack, rule, DEVICE_A)
    assert second.action == "created" and second.incident_id != first.incident_id
    assert stack.links.get("alert", decision_for(rule, DEVICE_A).fingerprint) == second.incident_id
    assert len(all_incidents(stack)) == 2


def test_the_evaluator_never_resolves_so_a_recovered_alert_leaves_the_incident_open() -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    created = ensure(stack, rule, DEVICE_A)
    ensure(
        stack,
        rule,
        DEVICE_A,
        outcome="not-met",
        phase="inactive",
        transition="resolved",
        notify=False,
    )
    incident = stack.incidents.get_incident(created.incident_id)
    assert incident is not None and incident.state == "open" and incident.resolution is None


# --- policy group ---------------------------------------------------------------------------------


def test_group_policy_attaches_further_alerts_to_the_one_group_incident() -> None:
    stack = Stack.build()
    rule = stack.active_rule(incident_policy="group")
    first = ensure(stack, rule, DEVICE_A)
    second = ensure(stack, rule, DEVICE_B)
    third = ensure(stack, rule, DEVICE_B)
    assert (first.action, second.action, third.action) == ("created", "attached", "none")
    assert second.incident_id == first.incident_id == third.incident_id
    assert len(all_incidents(stack)) == 1
    events = stack.incidents.list_timeline(first.incident_id)
    assert [e.kind for e in events] == ["alert-linked", "alert-linked"]
    assert {e.subject_id for e in events} == {
        decision_for(rule, DEVICE_A).fingerprint,
        decision_for(rule, DEVICE_B).fingerprint,
    }
    assert all(e.actor_id == SERVICE_ACTOR_ID for e in events)


def test_group_policy_separates_groups_with_different_labels() -> None:
    stack = Stack.build()
    network = stack.active_rule(incident_policy="group", labels={"team": "network"})
    security = stack.active_rule(incident_policy="group", labels={"team": "security"})
    assert (
        ensure(stack, network, DEVICE_A).incident_id
        != ensure(stack, security, DEVICE_A).incident_id
    )


def test_group_policy_opens_a_fresh_group_incident_after_a_human_resolves_the_old_one() -> None:
    stack = Stack.build()
    rule = stack.active_rule(incident_policy="group")
    first = ensure(stack, rule, DEVICE_A)
    human_resolve(stack, first.incident_id)
    second = ensure(stack, rule, DEVICE_B)
    assert second.action == "created" and second.incident_id != first.incident_id
    assert stack.links.get("group", decision_for(rule, DEVICE_B).group_key) == second.incident_id


# --- races and concurrency -----------------------------------------------------------------------


def test_concurrent_firing_in_one_process_creates_exactly_one_incident() -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    svc = service(stack)
    decision = decision_for(rule, DEVICE_A)

    def fire(_: int) -> str | None:
        return svc.ensure(
            rule=rule, decision=decision, entity=DEVICE_A, correlation_id="c"
        ).incident_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(fire, range(16)))
    assert len(set(ids)) == 1 and len(all_incidents(stack)) == 1


class RacingLinks(InMemoryAlertIncidentLinkRepository):
    """Another evaluator claims the key between our read and our claim."""

    def __init__(self, stack: Stack, rival_incident_id: str) -> None:
        super().__init__(incident_exists=lambda _id: True)
        self._rival = rival_incident_id
        self._raced = False

    def claim(self, kind: Any, key: str, *, incident_id: str, replacing: str | None) -> bool:
        if not self._raced and kind in ("alert", "group"):
            self._raced = True
            super().claim(kind, key, incident_id=self._rival, replacing=None)
        return super().claim(kind, key, incident_id=incident_id, replacing=replacing)


def test_losing_a_claim_race_attaches_to_the_winner_and_marks_the_orphan() -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    winner = stack.incidents.create_incident(title="rival", severity="high", actor_id="x:rival")
    racing = RacingLinks(stack, winner.id)
    svc = AlertIncidentService(stack.incidents, racing)
    effect = svc.ensure(
        rule=rule, decision=decision_for(rule, DEVICE_A), entity=DEVICE_A, correlation_id="c"
    )
    assert effect.action == "attached" and effect.incident_id == winner.id
    assert racing.get("alert", decision_for(rule, DEVICE_A).fingerprint) == winner.id
    orphans = [i for i in all_incidents(stack) if i.id != winner.id]
    assert len(orphans) == 1
    (note,) = stack.incidents.list_timeline(orphans[0].id)
    assert note.kind == "comment" and winner.id in (note.message or "")


# --- hostile text, audit, failures ----------------------------------------------------------------


def test_untrusted_text_is_bounded_and_single_line_in_title_and_message() -> None:
    stack = Stack.build()
    hostile = "Down\r\nBcc: x@y.z\x00" + BIDI + "<script>alert(1)</script>" + "A" * 400
    rule = stack.active_rule(name=hostile[:255])
    ensure(stack, rule, DEVICE_A)
    (incident,) = all_incidents(stack)
    assert 1 <= len(incident.title) <= 255
    assert not any(ch in incident.title for ch in "\r\n\x00" + BIDI)
    (event,) = stack.incidents.list_timeline(incident.id)
    assert event.message is not None and len(event.message) <= 4000
    assert not any(ch in event.message for ch in "\r\n\x00" + BIDI)
    assert "<script>" in incident.title  # kept as inert text, never interpreted


def test_creation_and_attachment_are_audited_without_free_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stack = Stack.build()
    rule = stack.active_rule(incident_policy="group", name="Secret-ish name 123")
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        first = ensure(stack, rule, DEVICE_A)
        ensure(stack, rule, DEVICE_B)
        ensure(stack, rule, DEVICE_B)
    records = [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]
    assert [r["action"] for r in records] == ["incident.auto_create", "incident.auto_attach"]
    created = records[0]
    assert created["outcome"] == "success" and created["actor_id"] == SERVICE_ACTOR_ID
    assert created["target"] == first.incident_id and created["correlation_id"] == "cycle-1"
    assert created["rule_id"] == rule.id and created["policy"] == "group"
    assert "Secret-ish" not in caplog.text and DEVICE_A not in caplog.text


class BrokenIncidents:
    def __getattr__(self, name: str) -> Any:
        def fail(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("postgresql://user:pw@db/x is down")

        return fail


def test_store_failures_propagate_and_are_audited_as_failures(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    svc = AlertIncidentService(BrokenIncidents(), stack.links)  # type: ignore[arg-type]
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"), pytest.raises(RuntimeError):
        svc.ensure(
            rule=rule, decision=decision_for(rule, DEVICE_A), entity=DEVICE_A, correlation_id="c"
        )
    (record,) = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"
    ]
    assert (record["action"], record["outcome"]) == ("incident.auto_create", "failure")
    assert record["reason"] == "RuntimeError" and "pw@db" not in caplog.text
    assert stack.links.get("alert", decision_for(rule, DEVICE_A).fingerprint) is None


def test_a_failed_timeline_note_does_not_lose_the_created_incident() -> None:
    stack = Stack.build()
    rule = stack.active_rule()

    class NoteFails:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

        def append_event(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("note failed")

    svc = AlertIncidentService(NoteFails(stack.incidents), stack.links)  # type: ignore[arg-type]
    effect = svc.ensure(
        rule=rule, decision=decision_for(rule, DEVICE_A), entity=DEVICE_A, correlation_id="c"
    )
    assert effect.action == "created"
    assert stack.links.get("alert", decision_for(rule, DEVICE_A).fingerprint) == effect.incident_id
    # and the next decision does not create a duplicate
    assert (
        service(stack)
        .ensure(
            rule=rule, decision=decision_for(rule, DEVICE_A), entity=DEVICE_A, correlation_id="c"
        )
        .action
        == "none"
    )
    assert T0  # (clock fixture sanity: nothing here reads the wall clock)
