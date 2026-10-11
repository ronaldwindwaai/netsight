"""PostgreSQL implementation of the unknown-device finding store (see ``unknown_devices``).

One short transaction per call, static SQL fragments from a closed set, bound parameters. The rules
that decide what is legal live in ``unknown_devices`` (shared with the in-memory fake); the database
repeats them as CHECKs and triggers (migration 0006) so a bug here still cannot break the lifecycle.

* ``observe`` takes a transaction-level advisory lock keyed by the endpoint, so two scanners seeing
  one new endpoint at the same moment make one finding (the partial unique index is the backstop);
* every other write locks the finding row (``FOR UPDATE``) before it reads the state it decides on,
  so the loser of a race sees the new state and gets a conflict instead of overwriting;
* the timeline is appended inside the same transaction as the change it records, with the next
  sequence number taken under that row lock.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any, Final

from psycopg.types.json import Jsonb
from pydantic import ValidationError

from netsight_api.schemas_unknown_devices import (
    FINAL_STATES,
    OPEN_STATES,
    SYSTEM_ACTOR,
    FindingState,
    Severity,
    UnknownDeviceCounts,
    UnknownDeviceEvent,
    UnknownDeviceFinding,
)
from netsight_api.storage import lifecycle
from netsight_api.storage.connection import Connection, PostgresSettings
from netsight_api.storage.errors import IllegalTransitionError, NotFoundError, StorageError
from netsight_api.storage.unknown_devices import (
    EVENT_PREFIX,
    FINDING_PREFIX,
    Observation,
    build_counts,
    check_actor,
    check_list_args,
    check_timeline_args,
    clean_assignee,
    clean_comment,
    plan_transition,
)
from netsight_api.unknown_devices.model import Detection, finding_fingerprint

_LOGGER: Final = logging.getLogger("netsight_api")
Row = dict[str, Any]

_COLUMNS: Final = (
    "id, state, severity, severity_basis, assignee_id, first_seen_at, last_seen_at, seen_count, "
    "recurrence_of, endpoint, chain, comparison, proposed_action"
)
_OPEN: Final = tuple(OPEN_STATES)
_LOCK_SUBJECT: Final = "SELECT pg_advisory_xact_lock(hashtextextended(%s, 8))"
_SELECT_OPEN: Final = (
    f"SELECT {_COLUMNS} FROM unknown_device_findings "
    "WHERE subject_key = %s AND state = ANY(%s) FOR UPDATE"
)
_SELECT_LATEST: Final = (
    "SELECT id, state FROM unknown_device_findings WHERE subject_key = %s "
    "ORDER BY created_at DESC, id DESC LIMIT 1"
)
_INSERT_FINDING: Final = (
    "INSERT INTO unknown_device_findings (id, subject_key, state, severity, severity_basis, "
    "assignee_id, first_seen_at, last_seen_at, seen_count, recurrence_of, endpoint, chain, "
    "comparison, proposed_action, created_at, updated_at) "
    "VALUES (%s, %s, 'new', %s, %s, NULL, %s, %s, 1, %s, %s, %s, %s, %s, %s, %s)"
)
_REFRESH: Final = (
    "UPDATE unknown_device_findings SET last_seen_at = %s, seen_count = seen_count + 1, "
    "comparison = %s, updated_at = %s WHERE id = %s"
)
_REFRESH_EVIDENCE: Final = (
    "UPDATE unknown_device_findings SET last_seen_at = %s, seen_count = seen_count + 1, "
    "comparison = %s, severity = %s, severity_basis = %s, endpoint = %s, chain = %s, "
    "proposed_action = %s, updated_at = %s WHERE id = %s"
)
_SELECT_ONE: Final = f"SELECT {_COLUMNS} FROM unknown_device_findings WHERE id = %s"
_LOCK_ONE: Final = f"SELECT {_COLUMNS} FROM unknown_device_findings WHERE id = %s FOR UPDATE"
_NEXT_SEQ: Final = (
    "SELECT coalesce(max(seq), 0) + 1 AS seq FROM unknown_device_events WHERE finding_id = %s"
)
_INSERT_EVENT: Final = (
    "INSERT INTO unknown_device_events (id, finding_id, seq, occurred_at, actor_id, kind, "
    "state_from, state_to, reason, message, subject_id, snapshot) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
_SELECT_EVENTS: Final = (
    "SELECT id, finding_id, seq, occurred_at, actor_id, kind, state_from, state_to, reason, "
    "message, subject_id FROM unknown_device_events WHERE finding_id = %s AND seq > %s "
    "ORDER BY seq LIMIT %s"
)
_SET_STATE: Final = "UPDATE unknown_device_findings SET state = %s, updated_at = %s WHERE id = %s"
_SET_ASSIGNEE: Final = (
    "UPDATE unknown_device_findings SET assignee_id = %s, updated_at = %s WHERE id = %s"
)
_ORDER: Final = " ORDER BY last_seen_at DESC, id DESC LIMIT %s OFFSET %s"
_COUNTS: Final = (
    "SELECT state, severity, count(*) AS n FROM unknown_device_findings GROUP BY state, severity"
)


def _finding(row: Row) -> UnknownDeviceFinding:
    try:
        return UnknownDeviceFinding.model_validate(
            {
                **row,
                "id": lifecycle.format_id(FINDING_PREFIX, row["id"]),
                "recurrence_of": (
                    None
                    if row["recurrence_of"] is None
                    else lifecycle.format_id(FINDING_PREFIX, row["recurrence_of"])
                ),
            }
        )
    except ValidationError as error:
        _LOGGER.warning("a stored unknown-device finding failed validation")
        raise StorageError("a stored finding could not be read") from error


def _event(row: Row) -> UnknownDeviceEvent:
    try:
        return UnknownDeviceEvent.model_validate(
            {
                **row,
                "id": lifecycle.format_id(EVENT_PREFIX, row["id"]),
                "finding_id": lifecycle.format_id(FINDING_PREFIX, row["finding_id"]),
            }
        )
    except ValidationError as error:
        _LOGGER.warning("a stored unknown-device event failed validation")
        raise StorageError("a stored event could not be read") from error


def _snapshot(detection: Detection) -> Jsonb:
    return Jsonb(
        {
            "endpoint": detection.endpoint.model_dump(mode="json"),
            "chain": [s.model_dump(mode="json") for s in detection.chain],
            "comparison": detection.comparison.model_dump(mode="json"),
            "severity": detection.severity,
            "severity_basis": detection.severity_basis,
            "proposed_action": (
                detection.proposed_action.model_dump(mode="json")
                if detection.proposed_action
                else None
            ),
        }
    )


def _json(model: Any) -> Jsonb:
    return Jsonb(model.model_dump(mode="json"))


class PostgresUnknownDeviceRepository:
    def __init__(
        self,
        settings: PostgresSettings,
        *,
        clock: Callable[[], datetime] = lifecycle.utc_now,
        new_uuid: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._new_uuid = new_uuid

    # -- helpers --

    def _append(
        self,
        conn: Connection,
        finding_key: uuid.UUID,
        kind: str,
        actor_id: str,
        now: datetime,
        *,
        state_from: str | None = None,
        state_to: str | None = None,
        reason: str | None = None,
        message: str | None = None,
        subject_id: str | None = None,
        snapshot: Jsonb | None = None,
    ) -> uuid.UUID:
        """Append one event; the caller holds the finding's row lock, so ``seq`` cannot collide."""
        row = conn.execute(_NEXT_SEQ, (finding_key,)).fetchone()
        assert row is not None  # an aggregate always returns a row
        event_key = self._new_uuid()
        conn.execute(
            _INSERT_EVENT,
            (
                event_key,
                finding_key,
                row["seq"],
                now,
                actor_id,
                kind,
                state_from,
                state_to,
                reason,
                message,
                subject_id,
                snapshot,
            ),
        )
        return event_key

    @staticmethod
    def _key(finding_id: str) -> uuid.UUID:
        key = lifecycle.parse_id(FINDING_PREFIX, finding_id)
        if key is None:
            raise NotFoundError("finding not found")
        return key

    def _lock(self, conn: Connection, finding_id: str) -> tuple[uuid.UUID, UnknownDeviceFinding]:
        key = self._key(finding_id)
        row = conn.execute(_LOCK_ONE, (key,)).fetchone()
        if row is None:
            raise NotFoundError("finding not found")
        return key, _finding(row)

    # -- scanner write --

    def observe(self, detection: Detection) -> Observation:
        with self._settings.session() as conn:
            now = self._clock()
            conn.execute(_LOCK_SUBJECT, (detection.subject_key,))
            open_row = conn.execute(_SELECT_OPEN, (detection.subject_key, list(_OPEN))).fetchone()
            if open_row is not None:
                return self._refresh(conn, open_row, detection, now)
            latest = conn.execute(_SELECT_LATEST, (detection.subject_key,)).fetchone()
            if latest is not None and latest["state"] == "false-positive":
                return Observation("suppressed", lifecycle.format_id(FINDING_PREFIX, latest["id"]))
            recurrence = (
                latest["id"] if latest is not None and latest["state"] == "resolved" else None
            )
            key = self._new_uuid()
            conn.execute(
                _INSERT_FINDING,
                (
                    key,
                    detection.subject_key,
                    detection.severity,
                    detection.severity_basis,
                    now,
                    now,
                    recurrence,
                    _json(detection.endpoint),
                    Jsonb([s.model_dump(mode="json") for s in detection.chain]),
                    _json(detection.comparison),
                    _json(detection.proposed_action) if detection.proposed_action else None,
                    now,
                    now,
                ),
            )
            self._append(conn, key, "detected", SYSTEM_ACTOR, now, snapshot=_snapshot(detection))
            if detection.proposed_action is not None:
                self._append(conn, key, "action-proposed", SYSTEM_ACTOR, now)
            return Observation("created", lifecycle.format_id(FINDING_PREFIX, key))

    def _refresh(
        self, conn: Connection, row: Row, detection: Detection, now: datetime
    ) -> Observation:
        current = _finding(row)
        key = row["id"]
        if finding_fingerprint(current) == detection.fingerprint():
            conn.execute(_REFRESH, (now, _json(detection.comparison), now, key))
        else:
            conn.execute(
                _REFRESH_EVIDENCE,
                (
                    now,
                    _json(detection.comparison),
                    detection.severity,
                    detection.severity_basis,
                    _json(detection.endpoint),
                    Jsonb([s.model_dump(mode="json") for s in detection.chain]),
                    _json(detection.proposed_action) if detection.proposed_action else None,
                    now,
                    key,
                ),
            )
            self._append(
                conn, key, "evidence-updated", SYSTEM_ACTOR, now, snapshot=_snapshot(detection)
            )
            if current.proposed_action is None and detection.proposed_action is not None:
                self._append(conn, key, "action-proposed", SYSTEM_ACTOR, now)
        return Observation("refreshed", current.id)

    # -- reads --

    def get_finding(self, finding_id: str) -> UnknownDeviceFinding | None:
        key = lifecycle.parse_id(FINDING_PREFIX, finding_id)
        if key is None:
            return None
        with self._settings.session() as conn:
            row = conn.execute(_SELECT_ONE, (key,)).fetchone()
        return None if row is None else _finding(row)

    def list_findings(
        self,
        *,
        states: Sequence[FindingState] | None = None,
        severity: Severity | None = None,
        assigned: bool | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[UnknownDeviceFinding], int]:
        check_list_args(limit, offset)
        conditions: list[str] = []
        params: list[object] = []
        if states is not None:
            conditions.append("state = ANY(%s)")
            params.append(list(states))
        if severity is not None:
            conditions.append("severity = %s")
            params.append(severity)
        if assigned is not None:
            conditions.append("assignee_id IS NOT NULL" if assigned else "assignee_id IS NULL")
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        with self._settings.session() as conn:
            total = conn.execute(
                "SELECT count(*) AS n FROM unknown_device_findings" + where, params
            ).fetchone()
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM unknown_device_findings" + where + _ORDER,
                [*params, limit, offset],
            ).fetchall()
        return [_finding(r) for r in rows], 0 if total is None else int(total["n"])

    def counts(self) -> UnknownDeviceCounts:
        with self._settings.session() as conn:
            rows = conn.execute(_COUNTS).fetchall()
        states: list[FindingState] = []
        severities: list[Severity] = []
        for row in rows:
            states.extend([row["state"]] * int(row["n"]))
            severities.extend([row["severity"]] * int(row["n"]))
        return build_counts(states, severities)

    def list_timeline(
        self, finding_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[UnknownDeviceEvent]:
        check_timeline_args(after_seq, limit)
        key = self._key(finding_id)
        with self._settings.session() as conn:
            if conn.execute(_SELECT_ONE, (key,)).fetchone() is None:
                raise NotFoundError("finding not found")
            rows = conn.execute(_SELECT_EVENTS, (key, after_seq, limit)).fetchall()
        return [_event(r) for r in rows]

    # -- people's writes --

    def transition_state(
        self,
        finding_id: str,
        *,
        to_state: FindingState,
        actor_id: str,
        reason: str | None = None,
    ) -> UnknownDeviceFinding:
        check_actor(actor_id)
        with self._settings.session() as conn:
            key, current = self._lock(conn, finding_id)
            cleaned = plan_transition(current.state, to_state, reason)
            now = self._clock()
            conn.execute(_SET_STATE, (to_state, now, key))
            self._append(
                conn,
                key,
                "state-changed",
                actor_id,
                now,
                state_from=current.state,
                state_to=to_state,
                reason=cleaned,
            )
            row = conn.execute(_SELECT_ONE, (key,)).fetchone()
        assert row is not None  # the row was locked in this transaction
        return _finding(row)

    def set_assignee(
        self, finding_id: str, *, assignee_id: str | None, actor_id: str
    ) -> UnknownDeviceFinding:
        check_actor(actor_id)
        assignee = clean_assignee(assignee_id)
        with self._settings.session() as conn:
            key, current = self._lock(conn, finding_id)
            if current.state in FINAL_STATES:
                raise IllegalTransitionError("a finished finding cannot be reassigned")
            if current.assignee_id != assignee:
                now = self._clock()
                conn.execute(_SET_ASSIGNEE, (assignee, now, key))
                self._append(conn, key, "assignee-changed", actor_id, now, subject_id=assignee)
            row = conn.execute(_SELECT_ONE, (key,)).fetchone()
        assert row is not None
        return _finding(row)

    def add_comment(self, finding_id: str, *, actor_id: str, message: str) -> UnknownDeviceEvent:
        check_actor(actor_id)
        text = clean_comment(message)
        with self._settings.session() as conn:
            key, _ = self._lock(conn, finding_id)
            event_key = self._append(conn, key, "comment", actor_id, self._clock(), message=text)
            row = conn.execute(
                "SELECT id, finding_id, seq, occurred_at, actor_id, kind, state_from, state_to, "
                "reason, message, subject_id FROM unknown_device_events WHERE id = %s",
                (event_key,),
            ).fetchone()
        assert row is not None
        return _event(row)
