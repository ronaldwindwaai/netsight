"""PostgreSQL implementation of the incident / alert-rule repositories.

* psycopg 3, synchronous, one short transaction per repository call (a pool can
  be added later behind ``PostgresSettings.connect`` without touching callers).
* Every statement is a static string with bound parameters; nothing is built
  from caller data. Identifiers are fixed in the SQL text.
* Row locks (``SELECT ... FOR UPDATE``) serialise concurrent writers on an
  incident / rule / window, so state transitions and timeline sequence numbers
  are race-free. ``UNIQUE (incident_id, seq)`` is the backstop.
* Connection settings, timeouts and error translation live in ``connection.py``.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from psycopg.types.json import Jsonb
from pydantic import BaseModel

from netsight_api.schemas import (
    AlertCondition,
    AlertExceptions,
    AlertRule,
    AlertRuleDefinition,
    AlertRuleStatus,
    AlertSchedule,
    AlertScope,
    Incident,
    IncidentResolution,
    IncidentResolutionInput,
    IncidentSeverity,
    IncidentState,
    IncidentTimelineEvent,
    MaintenanceWindow,
    MaintenanceWindowDefinition,
)
from netsight_api.storage import lifecycle
from netsight_api.storage.connection import Connection, PostgresSettings
from netsight_api.storage.errors import NotFoundError
from netsight_api.storage.lifecycle import Clock, UuidFactory
from netsight_api.storage.repository import NoteKind

Row = dict[str, Any]


# --- row mapping ------------------------------------------------------------------


def _load[M: BaseModel](model: type[M], value: object) -> M:
    """Validate JSON-native database content strictly against the contract model."""
    return model.model_validate_json(json.dumps(value))


def _dump(model: BaseModel) -> Jsonb:
    return Jsonb(model.model_dump(mode="json"))


def _incident_from_row(row: Row) -> Incident:
    return Incident(
        id=lifecycle.format_id("incident", row["id"]),
        title=row["title"],
        severity=row["severity"],
        state=row["state"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        assignee_id=row["assignee_id"],
        evidence_ids=list(row["evidence_ids"]),
        resolution=None
        if row["resolution"] is None
        else _load(IncidentResolution, row["resolution"]),
    )


def _event_from_row(row: Row) -> IncidentTimelineEvent:
    return IncidentTimelineEvent(
        id=lifecycle.format_id("incident-event", row["id"]),
        incident_id=lifecycle.format_id("incident", row["incident_id"]),
        seq=row["seq"],
        occurred_at=row["occurred_at"],
        actor_id=row["actor_id"],
        kind=row["kind"],
        state_from=row["state_from"],
        state_to=row["state_to"],
        reason=row["reason"],
        message=row["message"],
        subject_id=row["subject_id"],
    )


def _rule_from_row(row: Row) -> AlertRule:
    return AlertRule(
        id=lifecycle.format_id("alert-rule", row["id"]),
        name=row["name"],
        status=row["status"],
        scope=_load(AlertScope, row["scope"]),
        condition=_load(AlertCondition, row["condition"]),
        baseline_mode=row["baseline_mode"],
        window_seconds=row["window_seconds"],
        for_seconds=row["for_seconds"],
        cooldown_seconds=row["cooldown_seconds"],
        schedule=None if row["schedule"] is None else _load(AlertSchedule, row["schedule"]),
        exceptions=_load(AlertExceptions, row["exceptions"]),
        severity=row["severity"],
        labels=dict(row["labels"]),
        actions=list(row["actions"]),
        incident_policy=row["incident_policy"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        approved_by=row["approved_by"],
        approved_at=row["approved_at"],
        version=row["version"],
    )


def _rule_params(rule: AlertRule, rule_uuid: uuid.UUID) -> Row:
    return {
        "id": rule_uuid,
        "name": rule.name,
        "status": rule.status,
        "scope": _dump(rule.scope),
        "condition": _dump(rule.condition),
        "baseline_mode": rule.baseline_mode,
        "window_seconds": rule.window_seconds,
        "for_seconds": rule.for_seconds,
        "cooldown_seconds": rule.cooldown_seconds,
        "schedule": None if rule.schedule is None else _dump(rule.schedule),
        "exceptions": _dump(rule.exceptions),
        "severity": rule.severity,
        "labels": Jsonb(rule.labels),
        "actions": list(rule.actions),
        "incident_policy": rule.incident_policy,
        "created_by": rule.created_by,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
        "approved_by": rule.approved_by,
        "approved_at": rule.approved_at,
        "version": rule.version,
    }


def _window_from_row(row: Row) -> MaintenanceWindow:
    return MaintenanceWindow(
        id=lifecycle.format_id("maintenance", row["id"]),
        name=row["name"],
        scope=_load(AlertScope, row["scope"]),
        starts_at=row["starts_at"],
        ends_at=row["ends_at"],
        evaluation=row["evaluation"],
        status=row["status"],
        reason=row["reason"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        cancelled_by=row["cancelled_by"],
        cancelled_at=row["cancelled_at"],
    )


# --- SQL (static; parameters are always bound) ---------------------------------------

_SELECT_INCIDENT_LOCKED = (
    "SELECT id, title, severity, state, assignee_id, evidence_ids, resolution, "
    "created_at, updated_at FROM incidents WHERE id = %s FOR UPDATE"
)
_SELECT_INCIDENT = (
    "SELECT id, title, severity, state, assignee_id, evidence_ids, resolution, "
    "created_at, updated_at FROM incidents WHERE id = %s"
)
_SELECT_INCIDENTS_HEAD = (
    "SELECT id, title, severity, state, assignee_id, evidence_ids, resolution, "
    "created_at, updated_at FROM incidents"
)
_SELECT_INCIDENTS_TAIL = " ORDER BY created_at DESC, id DESC LIMIT %(limit)s OFFSET %(offset)s"
# One predicate per optional filter; values are always bound parameters. The statements
# are assembled once at import from these constants only (never from request data), one
# per filter combination, so each keeps an index-friendly plan (no optional-filter predicates).
_INCIDENT_FILTERS: tuple[tuple[str, str], ...] = (
    ("state", "state = %(state)s"),
    ("severity", "severity = %(severity)s"),
    ("assignee_id", "assignee_id = %(assignee_id)s"),
)


def _incident_list_statements() -> dict[frozenset[str], str]:
    statements: dict[frozenset[str], str] = {}
    for mask in range(1 << len(_INCIDENT_FILTERS)):
        chosen = [item for bit, item in enumerate(_INCIDENT_FILTERS) if mask >> bit & 1]
        where = " AND ".join(predicate for _, predicate in chosen)
        middle = " WHERE " + where if where else ""
        statements[frozenset(name for name, _ in chosen)] = (
            _SELECT_INCIDENTS_HEAD + middle + _SELECT_INCIDENTS_TAIL
        )
    return statements


_SELECT_INCIDENTS_BY_FILTER = _incident_list_statements()
_INSERT_INCIDENT = (
    "INSERT INTO incidents (id, title, severity, state, assignee_id, evidence_ids, resolution, "
    "created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s::text[], %s, %s, %s)"
)
_UPDATE_INCIDENT = (
    "UPDATE incidents SET state = %s, assignee_id = %s, evidence_ids = %s::text[], "
    "resolution = %s, updated_at = %s WHERE id = %s"
)
_SELECT_LAST_SEQ = (
    "SELECT COALESCE(MAX(seq), 0) AS last_seq FROM incident_timeline_events WHERE incident_id = %s"
)
_INSERT_EVENT = (
    "INSERT INTO incident_timeline_events (id, incident_id, seq, occurred_at, actor_id, kind, "
    "state_from, state_to, reason, message, subject_id) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
_SELECT_EVENTS = (
    "SELECT id, incident_id, seq, occurred_at, actor_id, kind, state_from, state_to, reason, "
    "message, subject_id FROM incident_timeline_events "
    "WHERE incident_id = %s AND seq > %s ORDER BY seq LIMIT %s"
)

_SELECT_RULE = (
    "SELECT id, name, status, scope, condition, baseline_mode, window_seconds, for_seconds, "
    "cooldown_seconds, schedule, exceptions, severity, labels, actions, incident_policy, "
    "created_by, created_at, updated_at, approved_by, approved_at, version "
    "FROM alert_rules WHERE id = %s"
)
_SELECT_RULE_LOCKED = (
    "SELECT id, name, status, scope, condition, baseline_mode, window_seconds, for_seconds, "
    "cooldown_seconds, schedule, exceptions, severity, labels, actions, incident_policy, "
    "created_by, created_at, updated_at, approved_by, approved_at, version "
    "FROM alert_rules WHERE id = %s FOR UPDATE"
)
_SELECT_RULES = (
    "SELECT id, name, status, scope, condition, baseline_mode, window_seconds, for_seconds, "
    "cooldown_seconds, schedule, exceptions, severity, labels, actions, incident_policy, "
    "created_by, created_at, updated_at, approved_by, approved_at, version FROM alert_rules "
    "ORDER BY created_at DESC, id DESC LIMIT %(limit)s OFFSET %(offset)s"
)
_SELECT_RULES_BY_STATUS = (
    "SELECT id, name, status, scope, condition, baseline_mode, window_seconds, for_seconds, "
    "cooldown_seconds, schedule, exceptions, severity, labels, actions, incident_policy, "
    "created_by, created_at, updated_at, approved_by, approved_at, version FROM alert_rules "
    "WHERE status = %(status)s "
    "ORDER BY created_at DESC, id DESC LIMIT %(limit)s OFFSET %(offset)s"
)
_INSERT_RULE = (
    "INSERT INTO alert_rules (id, name, status, scope, condition, baseline_mode, window_seconds, "
    "for_seconds, cooldown_seconds, schedule, exceptions, severity, labels, actions, "
    "incident_policy, created_by, created_at, updated_at, approved_by, approved_at, version) "
    "VALUES (%(id)s, %(name)s, %(status)s, %(scope)s, %(condition)s, %(baseline_mode)s, "
    "%(window_seconds)s, %(for_seconds)s, %(cooldown_seconds)s, %(schedule)s, %(exceptions)s, "
    "%(severity)s, %(labels)s, %(actions)s::text[], %(incident_policy)s, %(created_by)s, "
    "%(created_at)s, %(updated_at)s, %(approved_by)s, %(approved_at)s, %(version)s)"
)
_UPDATE_RULE = (
    "UPDATE alert_rules SET name = %(name)s, status = %(status)s, scope = %(scope)s, "
    "condition = %(condition)s, baseline_mode = %(baseline_mode)s, "
    "window_seconds = %(window_seconds)s, for_seconds = %(for_seconds)s, "
    "cooldown_seconds = %(cooldown_seconds)s, schedule = %(schedule)s, "
    "exceptions = %(exceptions)s, severity = %(severity)s, labels = %(labels)s, "
    "actions = %(actions)s::text[], incident_policy = %(incident_policy)s, "
    "updated_at = %(updated_at)s, approved_by = %(approved_by)s, approved_at = %(approved_at)s, "
    "version = %(version)s WHERE id = %(id)s"
)

_SELECT_WINDOW = (
    "SELECT id, name, scope, starts_at, ends_at, evaluation, status, reason, created_by, "
    "created_at, cancelled_by, cancelled_at FROM maintenance_windows WHERE id = %s"
)
_SELECT_WINDOW_LOCKED = (
    "SELECT id, name, scope, starts_at, ends_at, evaluation, status, reason, created_by, "
    "created_at, cancelled_by, cancelled_at FROM maintenance_windows WHERE id = %s FOR UPDATE"
)
_SELECT_WINDOWS_ALL = (
    "SELECT id, name, scope, starts_at, ends_at, evaluation, status, reason, created_by, "
    "created_at, cancelled_by, cancelled_at FROM maintenance_windows "
    "ORDER BY starts_at, id LIMIT %(limit)s OFFSET %(offset)s"
)
_SELECT_WINDOWS_SCHEDULED = (
    "SELECT id, name, scope, starts_at, ends_at, evaluation, status, reason, created_by, "
    "created_at, cancelled_by, cancelled_at FROM maintenance_windows "
    "WHERE status = 'scheduled' "
    "ORDER BY starts_at, id LIMIT %(limit)s OFFSET %(offset)s"
)
_SELECT_WINDOWS_ACTIVE = (
    "SELECT id, name, scope, starts_at, ends_at, evaluation, status, reason, created_by, "
    "created_at, cancelled_by, cancelled_at FROM maintenance_windows "
    "WHERE status = 'scheduled' AND starts_at <= %(active_at)s AND ends_at > %(active_at)s "
    "ORDER BY starts_at, id LIMIT %(limit)s OFFSET %(offset)s"
)
_INSERT_WINDOW = (
    "INSERT INTO maintenance_windows (id, name, scope, starts_at, ends_at, evaluation, status, "
    "reason, created_by, created_at, cancelled_by, cancelled_at) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
# Serialises the count-then-insert of the capacity caps; any role may take an advisory lock.
_LOCK_RULE_CREATION = "SELECT pg_advisory_xact_lock(hashtextextended('netsight.alert_rules', 0))"
_LOCK_WINDOW_CREATION = (
    "SELECT pg_advisory_xact_lock(hashtextextended('netsight.maintenance_windows', 0))"
)
_COUNT_RULES = "SELECT count(*) AS n FROM alert_rules"
_COUNT_LIVE_WINDOWS = (
    "SELECT count(*) AS n, "
    "count(*) FILTER (WHERE scope = %(scope)s) AS in_scope FROM maintenance_windows "
    "WHERE status = 'scheduled' AND ends_at > %(now)s"
)
_UPDATE_WINDOW_CANCELLED = (
    "UPDATE maintenance_windows SET status = %s, cancelled_by = %s, cancelled_at = %s WHERE id = %s"
)


def _one(conn: Connection, statement: Any, params: Sequence[object]) -> Row | None:
    return conn.execute(statement, params).fetchone()


def insert_incident_row(conn: Connection, incident_uuid: uuid.UUID, incident: Incident) -> None:
    """Insert a new incident in the caller's transaction (also used by ``open_linked``)."""
    conn.execute(
        _INSERT_INCIDENT,
        (
            incident_uuid,
            incident.title,
            incident.severity,
            incident.state,
            incident.assignee_id,
            incident.evidence_ids,
            None,
            incident.created_at,
            incident.updated_at,
        ),
    )


def insert_event_row(
    conn: Connection,
    event_uuid: uuid.UUID,
    incident_uuid: uuid.UUID,
    event: IncidentTimelineEvent,
) -> None:
    conn.execute(
        _INSERT_EVENT,
        (
            event_uuid,
            incident_uuid,
            event.seq,
            event.occurred_at,
            event.actor_id,
            event.kind,
            event.state_from,
            event.state_to,
            event.reason,
            event.message,
            event.subject_id,
        ),
    )


class PostgresIncidentRepository:
    def __init__(
        self,
        settings: PostgresSettings,
        *,
        clock: Clock = lifecycle.utc_now,
        new_uuid: UuidFactory = uuid.uuid4,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._new_uuid = new_uuid

    def create_incident(
        self,
        *,
        title: str,
        severity: IncidentSeverity,
        actor_id: str,
        evidence_ids: Sequence[str] = (),
    ) -> Incident:
        incident_uuid = self._new_uuid()
        incident = lifecycle.new_incident(
            incident_uuid=incident_uuid,
            title=title,
            severity=severity,
            actor_id=actor_id,
            evidence_ids=evidence_ids,
            now=self._clock(),
        )
        with self._settings.session() as conn:
            insert_incident_row(conn, incident_uuid, incident)
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        incident_uuid = lifecycle.parse_id("incident", incident_id)
        if incident_uuid is None:
            return None
        with self._settings.session() as conn:
            row = _one(conn, _SELECT_INCIDENT, (incident_uuid,))
        return None if row is None else _incident_from_row(row)

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
        filters: dict[str, Any] = {
            name: value
            for name, value in (
                ("state", state),
                ("severity", severity),
                ("assignee_id", assignee_id),
            )
            if value is not None
        }
        statement = _SELECT_INCIDENTS_BY_FILTER[frozenset(filters)]
        with self._settings.session() as conn:
            rows = conn.execute(statement, {**filters, "limit": limit, "offset": offset}).fetchall()
        return [_incident_from_row(row) for row in rows]

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
        with self._settings.session() as conn:
            incident_uuid, current = self._lock(conn, incident_id)
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
            return self._apply(conn, incident_uuid, plan, actor_id, now)

    def set_assignee(self, incident_id: str, *, assignee_id: str | None, actor_id: str) -> Incident:
        with self._settings.session() as conn:
            incident_uuid, current = self._lock(conn, incident_id)
            now = self._clock()
            plan = lifecycle.plan_assignee(
                current, assignee_id=assignee_id, actor_id=actor_id, now=now
            )
            return self._apply(conn, incident_uuid, plan, actor_id, now)

    def add_evidence(
        self,
        incident_id: str,
        *,
        evidence_id: str,
        actor_id: str,
        required_assignee: str | None = None,
    ) -> Incident:
        with self._settings.session() as conn:
            incident_uuid, current = self._lock(conn, incident_id)
            lifecycle.require_assignee(current, required_assignee)
            now = self._clock()
            plan = lifecycle.plan_evidence(
                current, evidence_id=evidence_id, actor_id=actor_id, now=now
            )
            return self._apply(conn, incident_uuid, plan, actor_id, now)

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
        with self._settings.session() as conn:
            incident_uuid, current = self._lock(conn, incident_id)
            lifecycle.require_assignee(current, required_assignee)
            draft = lifecycle.plan_note(
                current, kind=kind, actor_id=actor_id, message=message, subject_id=subject_id
            )
            last = self._last_seq(conn, incident_uuid)
            event_uuid = self._new_uuid()
            event = lifecycle.materialise_event(
                draft,
                event_uuid=event_uuid,
                incident_id=current.id,
                seq=last + 1,
                actor_id=actor_id,
                now=self._clock(),
            )
            self._insert_event(conn, event_uuid, incident_uuid, event)
            return event

    def list_timeline(
        self, incident_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[IncidentTimelineEvent]:
        lifecycle.check_timeline_page(after_seq, limit)
        incident_uuid = lifecycle.parse_id("incident", incident_id)
        with self._settings.session() as conn:
            if incident_uuid is None or _one(conn, _SELECT_INCIDENT, (incident_uuid,)) is None:
                raise NotFoundError("incident not found")
            rows = conn.execute(_SELECT_EVENTS, (incident_uuid, after_seq, limit)).fetchall()
        return [_event_from_row(row) for row in rows]

    # -- internals ---------------------------------------------------------------

    def _lock(self, conn: Connection, incident_id: str) -> tuple[uuid.UUID, Incident]:
        incident_uuid = lifecycle.parse_id("incident", incident_id)
        if incident_uuid is None:
            raise NotFoundError("incident not found")
        row = _one(conn, _SELECT_INCIDENT_LOCKED, (incident_uuid,))
        if row is None:
            raise NotFoundError("incident not found")
        return incident_uuid, _incident_from_row(row)

    def _last_seq(self, conn: Connection, incident_uuid: uuid.UUID) -> int:
        row = _one(conn, _SELECT_LAST_SEQ, (incident_uuid,))
        return 0 if row is None else int(row["last_seq"])

    def _insert_event(
        self,
        conn: Connection,
        event_uuid: uuid.UUID,
        incident_uuid: uuid.UUID,
        event: IncidentTimelineEvent,
    ) -> None:
        insert_event_row(conn, event_uuid, incident_uuid, event)

    def _apply(
        self,
        conn: Connection,
        incident_uuid: uuid.UUID,
        plan: lifecycle.TransitionPlan,
        actor_id: str,
        now: datetime,
    ) -> Incident:
        """Validate every event first, then write the record and its history together."""
        if not plan.events:
            return plan.incident
        last = self._last_seq(conn, incident_uuid)
        staged = []
        for offset, draft in enumerate(plan.events, start=1):
            event_uuid = self._new_uuid()
            staged.append(
                (
                    event_uuid,
                    lifecycle.materialise_event(
                        draft,
                        event_uuid=event_uuid,
                        incident_id=plan.incident.id,
                        seq=last + offset,
                        actor_id=actor_id,
                        now=now,
                    ),
                )
            )
        incident = plan.incident
        conn.execute(
            _UPDATE_INCIDENT,
            (
                incident.state,
                incident.assignee_id,
                incident.evidence_ids,
                None if incident.resolution is None else _dump(incident.resolution),
                incident.updated_at,
                incident_uuid,
            ),
        )
        for event_uuid, event in staged:
            self._insert_event(conn, event_uuid, incident_uuid, event)
        return incident


class PostgresAlertRuleRepository:
    def __init__(
        self,
        settings: PostgresSettings,
        *,
        clock: Clock = lifecycle.utc_now,
        new_uuid: UuidFactory = uuid.uuid4,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._new_uuid = new_uuid

    def create_rule(self, definition: AlertRuleDefinition, *, actor_id: str) -> AlertRule:
        rule_uuid = self._new_uuid()
        rule = lifecycle.new_rule(
            definition, rule_uuid=rule_uuid, actor_id=actor_id, now=self._clock()
        )
        with self._settings.session() as conn:
            conn.execute(_LOCK_RULE_CREATION)
            lifecycle.check_rule_capacity(self._count(conn, _COUNT_RULES, {}))
            conn.execute(_INSERT_RULE, _rule_params(rule, rule_uuid))
        return rule

    def get_rule(self, rule_id: str) -> AlertRule | None:
        rule_uuid = lifecycle.parse_id("alert-rule", rule_id)
        if rule_uuid is None:
            return None
        with self._settings.session() as conn:
            row = _one(conn, _SELECT_RULE, (rule_uuid,))
        return None if row is None else _rule_from_row(row)

    def list_rules(
        self, *, status: AlertRuleStatus | None = None, limit: int = 50, offset: int = 0
    ) -> list[AlertRule]:
        lifecycle.check_page(limit, offset)
        page: dict[str, Any] = {"limit": limit, "offset": offset}
        with self._settings.session() as conn:
            if status is None:
                rows = conn.execute(_SELECT_RULES, page).fetchall()
            else:
                rows = conn.execute(_SELECT_RULES_BY_STATUS, {**page, "status": status}).fetchall()
        return [_rule_from_row(row) for row in rows]

    def update_rule(
        self,
        rule_id: str,
        definition: AlertRuleDefinition,
        *,
        expected_version: int,
        actor_id: str,
    ) -> AlertRule:
        with self._settings.session() as conn:
            rule_uuid, current = self._lock_rule(conn, rule_id)
            lifecycle.require_version(current, expected_version)
            updated = lifecycle.edited_rule(
                current, definition, actor_id=actor_id, now=self._clock()
            )
            conn.execute(_UPDATE_RULE, _rule_params(updated, rule_uuid))
            return updated

    def approve_rule(self, rule_id: str, *, approver_id: str, expected_version: int) -> AlertRule:
        with self._settings.session() as conn:
            rule_uuid, current = self._lock_rule(conn, rule_id)
            updated = lifecycle.approved_rule(
                current,
                approver_id=approver_id,
                expected_version=expected_version,
                now=self._clock(),
            )
            conn.execute(_UPDATE_RULE, _rule_params(updated, rule_uuid))
            return updated

    def disable_rule(self, rule_id: str, *, actor_id: str) -> AlertRule:
        with self._settings.session() as conn:
            rule_uuid, current = self._lock_rule(conn, rule_id)
            updated = lifecycle.disabled_rule(current, actor_id=actor_id, now=self._clock())
            conn.execute(_UPDATE_RULE, _rule_params(updated, rule_uuid))
            return updated

    def create_window(
        self,
        definition: MaintenanceWindowDefinition,
        *,
        actor_id: str,
        organisation_allowed: bool = False,
    ) -> MaintenanceWindow:
        lifecycle.require_window_creation_scope(
            definition, organisation_allowed=organisation_allowed
        )
        window_uuid = self._new_uuid()
        now = self._clock()
        window = lifecycle.new_window(
            definition, window_uuid=window_uuid, actor_id=actor_id, now=now
        )
        with self._settings.session() as conn:
            conn.execute(_LOCK_WINDOW_CREATION)
            counts = conn.execute(
                _COUNT_LIVE_WINDOWS, {"scope": _dump(window.scope), "now": now}
            ).fetchone()
            lifecycle.check_window_capacity(
                live_total=0 if counts is None else int(counts["n"]),
                live_in_scope=0 if counts is None else int(counts["in_scope"]),
            )
            conn.execute(
                _INSERT_WINDOW,
                (
                    window_uuid,
                    window.name,
                    _dump(window.scope),
                    window.starts_at,
                    window.ends_at,
                    window.evaluation,
                    window.status,
                    window.reason,
                    window.created_by,
                    window.created_at,
                    None,
                    None,
                ),
            )
        return window

    def get_window(self, window_id: str) -> MaintenanceWindow | None:
        window_uuid = lifecycle.parse_id("maintenance", window_id)
        if window_uuid is None:
            return None
        with self._settings.session() as conn:
            row = _one(conn, _SELECT_WINDOW, (window_uuid,))
        return None if row is None else _window_from_row(row)

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
        page: dict[str, Any] = {"limit": limit, "offset": offset}
        if active_at is not None:
            statement, params = _SELECT_WINDOWS_ACTIVE, {**page, "active_at": active_at}
        elif include_cancelled:
            statement, params = _SELECT_WINDOWS_ALL, page
        else:
            statement, params = _SELECT_WINDOWS_SCHEDULED, page
        with self._settings.session() as conn:
            rows = conn.execute(statement, params).fetchall()
        return [_window_from_row(row) for row in rows]

    def cancel_window(
        self, window_id: str, *, actor_id: str, organisation_allowed: bool = False
    ) -> MaintenanceWindow:
        window_uuid = lifecycle.parse_id("maintenance", window_id)
        if window_uuid is None:
            raise NotFoundError("maintenance window not found")
        with self._settings.session() as conn:
            row = _one(conn, _SELECT_WINDOW_LOCKED, (window_uuid,))
            if row is None:
                raise NotFoundError("maintenance window not found")
            current = _window_from_row(row)
            lifecycle.require_window_scope(current, organisation_allowed=organisation_allowed)
            updated = lifecycle.cancelled_window(current, actor_id=actor_id, now=self._clock())
            conn.execute(
                _UPDATE_WINDOW_CANCELLED,
                (updated.status, updated.cancelled_by, updated.cancelled_at, window_uuid),
            )
            return updated

    @staticmethod
    def _count(conn: Connection, statement: str, params: Mapping[str, object]) -> int:
        row = conn.execute(statement, params).fetchone()
        return 0 if row is None else int(row["n"])

    def _lock_rule(self, conn: Connection, rule_id: str) -> tuple[uuid.UUID, AlertRule]:
        rule_uuid = lifecycle.parse_id("alert-rule", rule_id)
        if rule_uuid is None:
            raise NotFoundError("alert rule not found")
        row = _one(conn, _SELECT_RULE_LOCKED, (rule_uuid,))
        if row is None:
            raise NotFoundError("alert rule not found")
        return rule_uuid, _rule_from_row(row)
