"""Shared builders for the evaluation tests (S6 step 2): rules, windows, observations, a
scriptable source and a stack of in-memory stores wired like production."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from netsight_api.alerting.engine import Decision, Observation
from netsight_api.alerting.grouping import alert_fingerprint, group_key
from netsight_api.evaluation.adapter import EvaluatorIncidentAdapter
from netsight_api.evaluation.source import ObservationBatch
from netsight_api.schemas import (
    AlertRule,
    AlertRuleDefinition,
    MaintenanceWindow,
    MaintenanceWindowDefinition,
)
from netsight_api.storage import (
    AlertIncidentLinkRepository,
    InMemoryAlertIncidentLinkRepository,
    InMemoryAlertIncidentStore,
    InMemoryAlertRuleRepository,
    InMemoryIncidentRepository,
)

T0 = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)
DEVICE_A = "device-00000000-0000-4000-8000-00000000000a"
DEVICE_B = "device-00000000-0000-4000-8000-00000000000b"
ORGANISATION = ("organisation", "default")


class MutableClock:
    """An injected clock the test advances explicitly."""

    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> datetime:
        self.now += timedelta(**delta)
        return self.now


def definition(**overrides: Any) -> AlertRuleDefinition:
    """A device-down rule: fires as soon as ``device.status`` drops below 1."""
    payload: dict[str, Any] = {
        "name": "Device down",
        "scope": {"kind": "organisation", "ref": "default"},
        "condition": {"metric": "device.status", "operator": "lt", "threshold": 1, "pattern": None},
        "baseline_mode": "none",
        "window_seconds": 900,
        "for_seconds": 0,
        "cooldown_seconds": 0,
        "schedule": None,
        "exceptions": {"destinations": [], "device_groups": []},
        "severity": "high",
        "labels": {"team": "network"},
        "actions": ["create_alert", "email"],
        "incident_policy": "create",
        **overrides,
    }
    return AlertRuleDefinition.model_validate_json(json.dumps(payload))


@dataclass
class Stack:
    rules: InMemoryAlertRuleRepository
    incidents: InMemoryIncidentRepository
    links: InMemoryAlertIncidentLinkRepository
    opener: InMemoryAlertIncidentStore
    clock: MutableClock = field(default_factory=MutableClock)

    @classmethod
    def build(cls) -> Stack:
        clock = MutableClock()
        incidents = InMemoryIncidentRepository(clock=clock)
        links = InMemoryAlertIncidentLinkRepository(
            incident_exists=lambda incident_id: incidents.get_incident(incident_id) is not None
        )
        return cls(
            rules=InMemoryAlertRuleRepository(clock=clock),
            incidents=incidents,
            links=links,
            opener=InMemoryAlertIncidentStore(incidents, links),
            clock=clock,
        )

    @property
    def evaluator(self) -> EvaluatorIncidentAdapter:
        """What the evaluator is given: create-and-link, append a note, read; nothing else."""
        return EvaluatorIncidentAdapter(self.incidents, self.opener)

    def evaluator_with(self, links: AlertIncidentLinkRepository) -> EvaluatorIncidentAdapter:
        """The same stores, but the incident-and-link transaction claims through ``links``."""
        return EvaluatorIncidentAdapter(
            self.incidents, InMemoryAlertIncidentStore(self.incidents, links)
        )

    def active_rule(self, **overrides: Any) -> AlertRule:
        draft = self.rules.create_rule(definition(**overrides), actor_id="seed:admin")
        return self.rules.approve_rule(draft.id, approver_id="seed:admin", expected_version=1)

    def draft_rule(self, **overrides: Any) -> AlertRule:
        return self.rules.create_rule(definition(**overrides), actor_id="seed:admin")

    def window(
        self, *, scope: tuple[str, str] = ORGANISATION, evaluation: str = "retain", **overrides: Any
    ) -> MaintenanceWindow:
        starts = overrides.pop("starts_at", self.clock.now - timedelta(minutes=5))
        window_definition = MaintenanceWindowDefinition.model_validate_json(
            json.dumps(
                {
                    "name": "Planned work",
                    "scope": {"kind": scope[0], "ref": scope[1]},
                    "starts_at": starts.isoformat(),
                    "ends_at": (starts + timedelta(hours=2)).isoformat(),
                    "evaluation": evaluation,
                    "reason": "scheduled maintenance",
                    **overrides,
                }
            )
        )
        return self.rules.create_window(
            window_definition, actor_id="seed:admin", organisation_allowed=True
        )


def decision_for(rule: AlertRule, entity: str, **overrides: Any) -> Decision:
    from netsight_api.alerting.engine import definition_of

    fields: dict[str, Any] = {
        "at": T0,
        "outcome": "firing",
        "phase": "firing",
        "notify": True,
        "transition": "fired",
        "blocked_by": None,
        "maintenance_windows": (),
        "fingerprint": alert_fingerprint(rule.id, entity),
        "group_key": group_key(definition_of(rule)),
    }
    fields.update(overrides)
    return Decision(**fields)


def observation(
    entity: str,
    value: float | None,
    *,
    at: datetime = T0,
    scopes: frozenset[tuple[str, str]] | None = None,
) -> Observation:
    return Observation(
        at=at,
        entity=entity,
        scopes=scopes if scopes is not None else frozenset({("device", entity), ORGANISATION}),
        value=value,
    )


class ScriptedSource:
    """An ObservationSource whose answers are set by the test; records every call."""

    def __init__(self, metrics: tuple[str, ...] = ("device.status",)) -> None:
        self.metrics = metrics
        self.batches: dict[str, ObservationBatch | Exception] = {}
        self.calls: list[tuple[str, datetime]] = []
        self.in_flight = 0
        self.peak_in_flight = 0

    def set(self, metric: str, *readings: tuple[str, float | None], at: datetime = T0) -> None:
        self.batches[metric] = ObservationBatch(
            "ok", tuple(observation(entity, value, at=at) for entity, value in readings)
        )

    def supports(self, metric: str) -> bool:
        return metric in self.metrics

    async def observe(self, metric: str, *, now: datetime) -> ObservationBatch:
        import asyncio

        self.calls.append((metric, now))
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0)
            outcome = self.batches.get(metric, ObservationBatch("not-connected"))
            if isinstance(outcome, Exception):
                raise outcome
            if outcome.state == "ok":  # restamp: the runner's clock is the observation time
                return ObservationBatch(
                    "ok",
                    tuple(
                        Observation(
                            at=now,
                            entity=o.entity,
                            scopes=o.scopes,
                            value=o.value,
                            text=o.text,
                        )
                        for o in outcome.observations
                    ),
                )
            return outcome
        finally:
            self.in_flight -= 1
