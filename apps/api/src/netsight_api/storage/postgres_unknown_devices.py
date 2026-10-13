"""PostgreSQL implementation of the unknown-device finding store (see ``unknown_devices``).

One short transaction per call, static SQL fragments from a closed set, bound parameters. The rules
that decide what is legal live in ``unknown_devices`` (shared with the in-memory fake); the database
repeats them as CHECKs and triggers (migration 0006) so a bug here still cannot break the lifecycle.

* ``observe`` takes a transaction-level advisory lock for every key of the endpoint (MAC and
  address, in a fixed order), so two scanners seeing one new endpoint at the same moment make one
  finding (the partial unique index is the backstop), and reads the clock only after it holds them;
* every other write locks the finding row (``FOR UPDATE``) before it reads the state it decides on,
  so the loser of a race sees the new state and gets a conflict instead of overwriting;
* the timeline is appended inside the same transaction as the change it records, with the next
  sequence number taken under that row lock; the database refuses to commit a finding whose state,
  assignee or evidence its timeline does not account for;
* times only move forward (``greatest``) and counters stop at the contract's cap (``LEAST``).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import Any, Final

from psycopg.types.json import Jsonb
from pydantic import ValidationError

from netsight_api.schemas_unknown_devices import (
    FINAL_STATES,
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
    DEFAULT_FP_TTL,
    EVENT_PREFIX,
    FINDING_PREFIX,
    Known,
    Observation,
    check_actor,
    check_evidence_version,
    check_list_args,
    check_states,
    check_timeline_args,
    clean_assignee,
    clean_comment,
    counts_from_groups,
    decide,
    plan_transition,
    refresh_applies,
    sighting_due,
)
from netsight_api.unknown_devices.model import Detection

_LOGGER: Final = logging.getLogger("netsight_api")
Row = dict[str, Any]

_CAP: Final = 1_000_000
_COLUMNS: Final = (
    "id, state, severity, severity_basis, evidence_version, assignee_id, first_seen_at, "
    "last_seen_at, seen_count, recurrence_of, endpoint, chain, comparison, proposed_action"
)
_LOCK_SUBJECT: Final = "SELECT pg_advisory_xact_lock(hashtextextended(%s, 8))"
_INSERT_FINDING: Final = (
    "INSERT INTO unknown_device_findings (id, subject_key, state, severity, severity_basis, "
    "assignee_id, first_seen_at, last_seen_at, seen_count, recurrence_of, endpoint, chain, "
    "comparison, proposed_action, created_at, updated_at) "
    "VALUES (%s, %s, 'new', %s, %s, NULL, %s, %s, 1, %s, %s, %s, %s, %s, %s, %s)"
)
_REFRESH: Final = (
    "UPDATE unknown_device_findings SET last_seen_at = greatest(last_seen_at, %s), "
    f"seen_count = LEAST(seen_count + 1, {_CAP}), comparison = %s, "
    "updated_at = greatest(updated_at, %s) WHERE id = %s"
)
_REFRESH_EVIDENCE: Final = (
    "UPDATE unknown_device_findings SET last_seen_at = greatest(last_seen_at, %s), "
    f"seen_count = LEAST(seen_count + 1, {_CAP}), comparison = %s, severity = %s, "
    "severity_basis = %s, endpoint = %s, chain = %s, proposed_action = %s, "
    "updated_at = greatest(updated_at, %s) WHERE id = %s"
)
_SELECT_ONE: Final = f"SELECT {_COLUMNS} FROM unknown_device_findings WHERE id = %s"
_EXISTS: Final = "SELECT 1 AS present FROM unknown_device_findings WHERE id = %s"
_LOCK_ONE: Final = f"SELECT {_COLUMNS} FROM unknown_device_findings WHERE id = %s FOR UPDATE"
_NEXT_SEQ: Final = (
    f"SELECT LEAST(coalesce(max(seq), 0) + 1, {_CAP}) AS seq "
    "FROM unknown_device_events WHERE finding_id = %s"
)
_LAST_EVENT: Final = (
    "SELECT max(occurred_at) AS at FROM unknown_device_events WHERE finding_id = %s AND kind = %s"
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
_SELECT_EVENT: Final = (
    "SELECT id, finding_id, seq, occurred_at, actor_id, kind, state_from, state_to, reason, "
    "message, subject_id FROM unknown_device_events WHERE id = %s"
)
_SET_STATE: Final = (
    "UPDATE unknown_device_findings SET state = %s, updated_at = greatest(updated_at, %s) "
    "WHERE id = %s"
)
_SET_ASSIGNEE: Final = (
    "UPDATE unknown_device_findings SET assignee_id = %s, updated_at = greatest(updated_at, %s) "
    "WHERE id = %s"
)
_ORDER: Final = " ORDER BY last_seen_at DESC, id DESC LIMIT %s OFFSET %s"
_COUNTS: Final = (
    "SELECT state, severity, count(*) AS n FROM unknown_device_findings GROUP BY state, severity"
)


def _finding(row: Row) -> UnknownDeviceFinding:
    try:
        return UnknownDeviceFinding.model_validate(
            {
                **{k: v for k, v in row.items() if k != "updated_at"},
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


def _chain(detection: Detection) -> Jsonb:
    return Jsonb([s.model_dump(mode="json") for s in detection.chain])


def _history_query(detection: Detection) -> tuple[str, list[object]]:
    """Every finding that may be of this endpoint: by any of its keys or by what it has since gained.

    The fragments are a closed set; every value is bound.
    """
    keys = list(detection.lookup_keys)
    clauses = [f"subject_key IN ({', '.join(['%s'] * len(keys))})"]
    params: list[object] = list(keys)
    if detection.endpoint.mac is not None:
        clauses.append("endpoint ->> 'mac' = %s")
        params.append(detection.endpoint.mac)
    if detection.endpoint.ip is not None:
        clauses.append("endpoint ->> 'ip' = %s")
        params.append(detection.endpoint.ip)
    sql = (
        f"SELECT {_COLUMNS}, updated_at FROM unknown_device_findings WHERE "
        + " OR ".join(clauses)
        + " ORDER BY created_at DESC, id DESC FOR UPDATE"
    )
    return sql, params


class PostgresUnknownDeviceRepository:
    def __init__(
        self,
        settings: PostgresSettings,
        *,
        clock: Callable[[], datetime] = lifecycle.utc_now,
        new_uuid: Callable[[], uuid.UUID] = uuid.uuid4,
        fp_ttl: timedelta = DEFAULT_FP_TTL,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._new_uuid = new_uuid
        self._fp_ttl = fp_ttl

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

    @staticmethod
    def _last_event_at(conn: Connection, key: uuid.UUID, kind: str) -> datetime | None:
        row = conn.execute(_LAST_EVENT, (key, kind)).fetchone()
        return None if row is None else row["at"]

    # -- scanner write --

    def known_subject_keys(self, keys: Sequence[str]) -> set[str]:
        if not keys:
            return set()
        sql = (
            "SELECT DISTINCT subject_key FROM unknown_device_findings WHERE subject_key IN ("
            + ", ".join(["%s"] * len(keys))
            + ")"
        )
        with self._settings.session() as conn:
            rows = conn.execute(sql, list(keys)).fetchall()
        return {r["subject_key"] for r in rows}

    def observe(self, detection: Detection) -> Observation:
        with self._settings.session() as conn:
            for key in sorted(detection.lookup_keys):
                conn.execute(_LOCK_SUBJECT, (key,))
            now = self._clock()  # after the locks: a waiter must not stamp a time from before them
            sql, params = _history_query(detection)
            history = [
                Known(_finding(r), r["updated_at"]) for r in conn.execute(sql, params).fetchall()
            ]
            decision = decide(history, detection, now, self._fp_ttl)
            if decision.action == "refresh" and decision.known is not None:
                return self._refresh(conn, decision.known.finding, detection, now)
            if decision.action == "suppress" and decision.known is not None:
                return self._suppress(conn, decision.known.finding, detection, now)
            recurrence = decision.known.finding.id if decision.known is not None else None
            return self._create(conn, detection, now, recurrence)

    def _create(
        self, conn: Connection, detection: Detection, now: datetime, recurrence: str | None
    ) -> Observation:
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
                None if recurrence is None else self._key(recurrence),
                _json(detection.endpoint),
                _chain(detection),
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
        self, conn: Connection, current: UnknownDeviceFinding, detection: Detection, now: datetime
    ) -> Observation:
        key = self._key(current.id)
        last = self._last_event_at(conn, key, "evidence-updated")
        if not refresh_applies(current, detection, now, last):
            conn.execute(_REFRESH, (now, _json(detection.comparison), now, key))
            return Observation("refreshed", current.id)
        conn.execute(
            _REFRESH_EVIDENCE,
            (
                now,
                _json(detection.comparison),
                detection.severity,
                detection.severity_basis,
                _json(detection.endpoint),
                _chain(detection),
                _json(detection.proposed_action) if detection.proposed_action else None,
                now,
                key,
            ),
        )
        self._append(conn, key, "evidence-updated", SYSTEM_ACTOR, now, snapshot=_snapshot(detection))
        if current.proposed_action is None and detection.proposed_action is not None:
            self._append(conn, key, "action-proposed", SYSTEM_ACTOR, now)
        return Observation("refreshed", current.id)

    def _suppress(
        self, conn: Connection, dismissed: UnknownDeviceFinding, detection: Detection, now: datetime
    ) -> Observation:
        key = self._key(dismissed.id)
        last = self._last_event_at(conn, key, "suppressed-sighting")
        if sighting_due(dismissed, detection, now, last):
            self._append(
                conn, key, "suppressed-sighting", SYSTEM_ACTOR, now, snapshot=_snapshot(detection)
            )
        return Observation("suppressed", dismissed.id)

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
        wanted = check_states(states)
        conditions: list[str] = []
        params: list[object] = []
        if wanted is not None:
            # literals from the closed set (checked above), so the planner can use the partial index
            conditions.append(
                "state IN (" + ", ".join(f"'{s}'" for s in wanted) + ")" if wanted else "FALSE"
            )
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
        return counts_from_groups((r["state"], r["severity"], int(r["n"])) for r in rows)

    def list_timeline(
        self, finding_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[UnknownDeviceEvent]:
        check_timeline_args(after_seq, limit)
        key = self._key(finding_id)
        with self._settings.session() as conn:
            if conn.execute(_EXISTS, (key,)).fetchone() is None:
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
        expected_evidence_version: int,
        reason: str | None = None,
    ) -> UnknownDeviceFinding:
        check_actor(actor_id)
        with self._settings.session() as conn:
            key, current = self._lock(conn, finding_id)
            check_evidence_version(current, expected_evidence_version)
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
        self,
        finding_id: str,
        *,
        assignee_id: str | None,
        actor_id: str,
        expected_evidence_version: int,
    ) -> UnknownDeviceFinding:
        check_actor(actor_id)
        assignee = clean_assignee(assignee_id)
        with self._settings.session() as conn:
            key, current = self._lock(conn, finding_id)
            check_evidence_version(current, expected_evidence_version)
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
            row = conn.execute(_SELECT_EVENT, (event_key,)).fetchone()
        assert row is not None
        return _event(row)
