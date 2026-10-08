"""Repository interfaces for the PostgreSQL-owned incident and alert-rule entities.

Two implementations exist: an in-memory fake for unit tests and a PostgreSQL
store; both must pass the same conformance suite
(``tests/test_storage_conformance.py``).

Design rules encoded in the interface:

* The incident timeline is append-only: there is no method that updates or
  deletes an event, and the database rejects both.
* Nothing is hard-deleted. Rules are disabled, windows cancelled, incidents
  closed.
* Every mutating method takes the acting identity explicitly; callers (the
  S6-2 routes) are responsible for authorisation and auditing.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Literal, Protocol

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

MAX_PAGE_SIZE = 100
MAX_TIMELINE_PAGE_SIZE = 500

# Timeline kinds a caller may append directly. Kinds that change the incident
# record (state-changed, resolution, assignee-changed, evidence-added) are only
# written by the dedicated methods so the record and its history cannot diverge.
NoteKind = Literal[
    "alert-linked",
    "alert-unlinked",
    "comment",
    "diagnostic",
    "action-proposed",
    "action-approved",
    "action-executed",
]


class IncidentRepository(Protocol):
    def create_incident(
        self,
        *,
        title: str,
        severity: IncidentSeverity,
        actor_id: str,
        evidence_ids: Sequence[str] = (),
    ) -> Incident: ...

    def get_incident(self, incident_id: str) -> Incident | None: ...

    def list_incidents(
        self, *, state: IncidentState | None = None, limit: int = 50, offset: int = 0
    ) -> list[Incident]: ...

    def transition_state(
        self,
        incident_id: str,
        *,
        to_state: IncidentState,
        actor_id: str,
        reason: str | None = None,
        resolution: IncidentResolutionInput | None = None,
    ) -> Incident: ...

    def set_assignee(
        self, incident_id: str, *, assignee_id: str | None, actor_id: str
    ) -> Incident: ...

    def add_evidence(self, incident_id: str, *, evidence_id: str, actor_id: str) -> Incident: ...

    def append_event(
        self,
        incident_id: str,
        *,
        kind: NoteKind,
        actor_id: str,
        message: str | None = None,
        subject_id: str | None = None,
    ) -> IncidentTimelineEvent: ...

    def list_timeline(
        self, incident_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[IncidentTimelineEvent]: ...


class AlertRuleRepository(Protocol):
    def create_rule(self, definition: AlertRuleDefinition, *, actor_id: str) -> AlertRule: ...

    def get_rule(self, rule_id: str) -> AlertRule | None: ...

    def list_rules(
        self, *, status: AlertRuleStatus | None = None, limit: int = 50, offset: int = 0
    ) -> list[AlertRule]: ...

    def update_rule(
        self, rule_id: str, definition: AlertRuleDefinition, *, expected_version: int
    ) -> AlertRule:
        """Optimistic edit: raises ``StorageConflictError`` unless the stored version matches."""
        ...

    def approve_rule(self, rule_id: str, *, approver_id: str) -> AlertRule: ...

    def disable_rule(self, rule_id: str) -> AlertRule: ...

    def create_window(
        self, definition: MaintenanceWindowDefinition, *, actor_id: str
    ) -> MaintenanceWindow: ...

    def get_window(self, window_id: str) -> MaintenanceWindow | None: ...

    def list_windows(
        self,
        *,
        active_at: datetime | None = None,
        include_cancelled: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MaintenanceWindow]: ...

    def cancel_window(self, window_id: str, *, actor_id: str) -> MaintenanceWindow: ...
