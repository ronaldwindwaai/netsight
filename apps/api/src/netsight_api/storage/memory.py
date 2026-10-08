"""In-memory repositories for unit tests (not for production use).

They apply exactly the same domain rules as the PostgreSQL store by sharing
``lifecycle`` and are validated by the same conformance suite. All returned
models are deep copies, so callers cannot corrupt stored state.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Sequence
from datetime import datetime

from netsight_api.schemas import (
    AlertRule,
    AlertRuleDefinition,
    AlertRuleStatus,
    Incident,
    IncidentResolutionInput,
    IncidentSeverity,
    IncidentState,
    IncidentTimelineEvent,
    MaintenanceWindow,
    MaintenanceWindowDefinition,
)
from netsight_api.storage import lifecycle
from netsight_api.storage.lifecycle import Clock, UuidFactory
from netsight_api.storage.repository import NoteKind


class InMemoryIncidentRepository:
    def __init__(self, *, clock: Clock = lifecycle.utc_now, new_uuid: UuidFactory = uuid.uuid4):
        self._clock = clock
        self._new_uuid = new_uuid
        self._lock = threading.RLock()
        self._incidents: dict[str, Incident] = {}
        self._events: dict[str, list[IncidentTimelineEvent]] = {}

    def create_incident(
        self,
        *,
        title: str,
        severity: IncidentSeverity,
        actor_id: str,
        evidence_ids: Sequence[str] = (),
    ) -> Incident:
        with self._lock:
            incident = lifecycle.new_incident(
                incident_uuid=self._new_uuid(),
                title=title,
                severity=severity,
                actor_id=actor_id,
                evidence_ids=evidence_ids,
                now=self._clock(),
            )
            self._incidents[incident.id] = incident
            self._events[incident.id] = []
            return incident.model_copy(deep=True)

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            found = self._incidents.get(incident_id)
            return found.model_copy(deep=True) if found else None

    def list_incidents(
        self,
        *,
        state: IncidentState | None = None,
        severity: IncidentSeverity | None = None,
        assignee_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Incident]:
        lifecycle.check_page(limit, offset)
        with self._lock:
            rows = [
                i
                for i in self._incidents.values()
                if (state is None or i.state == state)
                and (severity is None or i.severity == severity)
                and (assignee_id is None or i.assignee_id == assignee_id)
            ]
            rows.sort(key=lambda i: (i.created_at, i.id), reverse=True)
            return [i.model_copy(deep=True) for i in rows[offset : offset + limit]]

    def transition_state(
        self,
        incident_id: str,
        *,
        to_state: IncidentState,
        actor_id: str,
        reason: str | None = None,
        resolution: IncidentResolutionInput | None = None,
        required_assignee: str | None = None,
    ) -> Incident:
        with self._lock:
            current = self._existing(incident_id)
            lifecycle.require_assignee(current, required_assignee)
            now = self._clock()
            plan = lifecycle.plan_transition(
                current,
                to_state=to_state,
                actor_id=actor_id,
                reason=reason,
                resolution=resolution,
                now=now,
            )
            return self._commit(plan, actor_id, now)

    def set_assignee(self, incident_id: str, *, assignee_id: str | None, actor_id: str) -> Incident:
        with self._lock:
            current = self._existing(incident_id)
            now = self._clock()
            plan = lifecycle.plan_assignee(
                current, assignee_id=assignee_id, actor_id=actor_id, now=now
            )
            return self._commit(plan, actor_id, now)

    def add_evidence(
        self,
        incident_id: str,
        *,
        evidence_id: str,
        actor_id: str,
        required_assignee: str | None = None,
    ) -> Incident:
        with self._lock:
            current = self._existing(incident_id)
            lifecycle.require_assignee(current, required_assignee)
            now = self._clock()
            plan = lifecycle.plan_evidence(
                current, evidence_id=evidence_id, actor_id=actor_id, now=now
            )
            return self._commit(plan, actor_id, now)

    def append_event(
        self,
        incident_id: str,
        *,
        kind: NoteKind,
        actor_id: str,
        message: str | None = None,
        subject_id: str | None = None,
        required_assignee: str | None = None,
    ) -> IncidentTimelineEvent:
        with self._lock:
            current = self._existing(incident_id)
            lifecycle.require_assignee(current, required_assignee)
            draft = lifecycle.plan_note(
                current, kind=kind, actor_id=actor_id, message=message, subject_id=subject_id
            )
            event = self._materialise(draft, current.id, actor_id, self._clock())
            self._events[current.id].append(event)
            return event.model_copy(deep=True)

    def list_timeline(
        self, incident_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[IncidentTimelineEvent]:
        lifecycle.check_timeline_page(after_seq, limit)
        with self._lock:
            self._existing(incident_id)
            events = [e for e in self._events[incident_id] if e.seq > after_seq]
            return [e.model_copy(deep=True) for e in events[:limit]]

    # -- internals ---------------------------------------------------------------

    def _existing(self, incident_id: str) -> Incident:
        found = self._incidents.get(incident_id)
        return lifecycle.require_found(found, "incident")

    def _materialise(
        self, draft: lifecycle.EventDraft, incident_id: str, actor_id: str, now: datetime
    ) -> IncidentTimelineEvent:
        return lifecycle.materialise_event(
            draft,
            event_uuid=self._new_uuid(),
            incident_id=incident_id,
            seq=len(self._events[incident_id]) + 1,
            actor_id=actor_id,
            now=now,
        )

    def _commit(self, plan: lifecycle.TransitionPlan, actor_id: str, now: datetime) -> Incident:
        """Build every event first so a failure leaves the store untouched."""
        base = len(self._events[plan.incident.id])
        events = [
            lifecycle.materialise_event(
                draft,
                event_uuid=self._new_uuid(),
                incident_id=plan.incident.id,
                seq=base + offset,
                actor_id=actor_id,
                now=now,
            )
            for offset, draft in enumerate(plan.events, start=1)
        ]
        self._incidents[plan.incident.id] = plan.incident
        self._events[plan.incident.id].extend(events)
        return plan.incident.model_copy(deep=True)


class InMemoryAlertRuleRepository:
    def __init__(self, *, clock: Clock = lifecycle.utc_now, new_uuid: UuidFactory = uuid.uuid4):
        self._clock = clock
        self._new_uuid = new_uuid
        self._lock = threading.RLock()
        self._rules: dict[str, AlertRule] = {}
        self._windows: dict[str, MaintenanceWindow] = {}

    def create_rule(self, definition: AlertRuleDefinition, *, actor_id: str) -> AlertRule:
        with self._lock:
            rule = lifecycle.new_rule(
                definition, rule_uuid=self._new_uuid(), actor_id=actor_id, now=self._clock()
            )
            self._rules[rule.id] = rule
            return rule.model_copy(deep=True)

    def get_rule(self, rule_id: str) -> AlertRule | None:
        with self._lock:
            found = self._rules.get(rule_id)
            return found.model_copy(deep=True) if found else None

    def list_rules(
        self, *, status: AlertRuleStatus | None = None, limit: int = 50, offset: int = 0
    ) -> list[AlertRule]:
        lifecycle.check_page(limit, offset)
        with self._lock:
            rows = [r for r in self._rules.values() if status is None or r.status == status]
            rows.sort(key=lambda r: (r.created_at, r.id), reverse=True)
            return [r.model_copy(deep=True) for r in rows[offset : offset + limit]]

    def update_rule(
        self,
        rule_id: str,
        definition: AlertRuleDefinition,
        *,
        expected_version: int,
        actor_id: str,
    ) -> AlertRule:
        with self._lock:
            current = lifecycle.require_found(self._rules.get(rule_id), "alert rule")
            lifecycle.require_version(current, expected_version)
            updated = lifecycle.edited_rule(
                current, definition, actor_id=actor_id, now=self._clock()
            )
            self._rules[rule_id] = updated
            return updated.model_copy(deep=True)

    def approve_rule(self, rule_id: str, *, approver_id: str, expected_version: int) -> AlertRule:
        with self._lock:
            current = lifecycle.require_found(self._rules.get(rule_id), "alert rule")
            updated = lifecycle.approved_rule(
                current,
                approver_id=approver_id,
                expected_version=expected_version,
                now=self._clock(),
            )
            self._rules[rule_id] = updated
            return updated.model_copy(deep=True)

    def disable_rule(self, rule_id: str, *, actor_id: str) -> AlertRule:
        with self._lock:
            current = lifecycle.require_found(self._rules.get(rule_id), "alert rule")
            updated = lifecycle.disabled_rule(current, actor_id=actor_id, now=self._clock())
            self._rules[rule_id] = updated
            return updated.model_copy(deep=True)

    def create_window(
        self, definition: MaintenanceWindowDefinition, *, actor_id: str
    ) -> MaintenanceWindow:
        with self._lock:
            window = lifecycle.new_window(
                definition, window_uuid=self._new_uuid(), actor_id=actor_id, now=self._clock()
            )
            self._windows[window.id] = window
            return window.model_copy(deep=True)

    def get_window(self, window_id: str) -> MaintenanceWindow | None:
        with self._lock:
            found = self._windows.get(window_id)
            return found.model_copy(deep=True) if found else None

    def list_windows(
        self,
        *,
        active_at: datetime | None = None,
        include_cancelled: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MaintenanceWindow]:
        lifecycle.check_page(limit, offset)
        lifecycle.check_active_at(active_at)
        with self._lock:
            rows = [
                w
                for w in self._windows.values()
                if lifecycle.window_matches(
                    w, active_at=active_at, include_cancelled=include_cancelled
                )
            ]
            rows.sort(key=lambda w: (w.starts_at, w.id))
            return [w.model_copy(deep=True) for w in rows[offset : offset + limit]]

    def cancel_window(self, window_id: str, *, actor_id: str) -> MaintenanceWindow:
        with self._lock:
            current = lifecycle.require_found(self._windows.get(window_id), "maintenance window")
            updated = lifecycle.cancelled_window(current, actor_id=actor_id, now=self._clock())
            self._windows[window_id] = updated
            return updated.model_copy(deep=True)
