"""Rows of the PostgreSQL action store: the SQL, and the mapping between rows and contract models.

Every statement is a constant from a closed set with bound parameters (migration 0007 describes the
tables). A row that no longer parses as the contract model (an edit with the triggers disabled, a
bug elsewhere) raises ``StoredRecordError``: the request is never served half-trusted, and the
message carries no stored content.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, NoReturn

from psycopg.types.json import Jsonb
from pydantic import ValidationError

from netsight_api.actions.lifecycle import request_digest, run_deadline
from netsight_api.actions.model import NewAction
from netsight_api.schemas_actions import ActionHistoryEvent, ActionRequest
from netsight_api.storage.errors import StorageError

Row = Mapping[str, Any]
LOGGER: Final = logging.getLogger("netsight_api")

OPEN: Final = "('proposed', 'pending-approval', 'approved', 'executing')"
FINISHED: Final = "('rejected', 'expired', 'cancelled', 'succeeded', 'failed', 'rolled-back')"
_FIELDS: Final = (
    "id, action_type, target_id, params, risk, state, requester_id, requester_kind, reason, "
    "source, approvals_required, approvals, created_at, approve_by, execute_by, version, digest, "
    "policy_checks, pre_checks, execution, execute_within_seconds, timeout_seconds, exec_key, "
    "exec_actor_id"
)
_EVENT_FIELDS: Final = "seq, at, type, actor_id, from_state, to_state, code, note, prev_hash, hash"

SELECT_REQUEST: Final = (
    f"SELECT {_FIELDS} FROM action_requests WHERE id = %s AND evicted_at IS NULL"
)
LOCK_REQUEST: Final = SELECT_REQUEST + " FOR UPDATE"
FIND_BY_KEY: Final = (
    "SELECT id, create_fingerprint FROM action_requests "
    "WHERE requester_id = %s AND create_key = %s AND evicted_at IS NULL"
)
COUNT_STORED: Final = "SELECT count(*) AS n FROM action_requests WHERE evicted_at IS NULL"
# Only a request older than the minimum age (a parameter) may make room: see store.EVICT_MIN_AGE_SECONDS.
EVICTABLE: Final = (
    "SELECT id FROM action_requests WHERE evicted_at IS NULL "
    f"AND state IN {FINISHED} AND created_at <= %s ORDER BY created_at, id "
    "LIMIT 1 FOR UPDATE SKIP LOCKED"
)
EVICT: Final = "UPDATE action_requests SET evicted_at = %s WHERE id = %s"
OPEN_ON_TARGET: Final = (
    f"SELECT 1 AS found FROM action_requests WHERE state IN {OPEN} "
    "AND action_type = %s AND target_id = %s LIMIT 1"
)
COUNT_OPEN_OF: Final = (
    f"SELECT count(*) AS n FROM action_requests WHERE state IN {OPEN} AND requester_id = %s"
)
RUNNING_ON_TARGET: Final = (
    "SELECT 1 AS found FROM action_requests "
    "WHERE target_id = %s AND state = 'executing' AND id <> %s LIMIT 1"
)
SWEEP_BATCH: Final = 200
DUE: Final = (
    f"SELECT {_FIELDS} FROM action_requests WHERE evicted_at IS NULL AND state IN {OPEN} "
    "AND id IS DISTINCT FROM %s AND ("
    "(state = 'pending-approval' AND approve_by < %s) "  # 'proposed' is transient: never stored
    "OR (state = 'approved' AND execute_by < %s) "
    "OR (state = 'executing' AND run_by < %s)) "
    f"ORDER BY created_at, id LIMIT {SWEEP_BATCH} FOR UPDATE SKIP LOCKED"
)
INSERT_REQUEST: Final = (
    "INSERT INTO action_requests (id, action_type, target_id, params, risk, state, requester_id, "
    "requester_kind, reason, source, approvals_required, approvals, created_at, approve_by, "
    "execute_by, execute_within_seconds, timeout_seconds, version, digest, policy_checks, "
    "pre_checks, execution, create_key, create_fingerprint) "
    "VALUES (%s, %s, %s, %s, %s, 'proposed', %s, %s, %s, %s, %s, '[]'::jsonb, %s, %s, NULL, %s, %s, "
    "1, %s, %s, '[]'::jsonb, NULL, %s, %s)"
)
UPDATE_REQUEST: Final = (
    "UPDATE action_requests SET state = %s, version = %s, approvals = %s, execute_by = %s, "
    "run_by = %s, pre_checks = %s, execution = %s, exec_key = %s, exec_actor_id = %s WHERE id = %s"
)
INSERT_EVENT: Final = (
    "INSERT INTO action_history (action_id, seq, at, type, actor_id, from_state, to_state, code, "
    "note, prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
LAST_EVENT: Final = (
    f"SELECT {_EVENT_FIELDS} FROM action_history WHERE action_id = %s ORDER BY seq DESC LIMIT 1"
)
EVENTS: Final = f"SELECT {_EVENT_FIELDS} FROM action_history WHERE action_id = %s ORDER BY seq"
LISTING: Final = (
    f"SELECT {_FIELDS} FROM action_requests WHERE evicted_at IS NULL "
    "AND (%(state)s::text IS NULL OR state = %(state)s) "
    "ORDER BY created_at DESC, id DESC LIMIT %(limit)s OFFSET %(offset)s"
)
LISTING_TOTAL: Final = (
    "SELECT count(*) AS n FROM action_requests WHERE evicted_at IS NULL "
    "AND (%(state)s::text IS NULL OR state = %(state)s)"
)
PROBE: Final = "SELECT 1 AS found FROM action_requests LIMIT 1"


class StoredRecordError(StorageError):
    """A stored row does not parse as the contract model; nothing of it is served."""


@dataclass
class Held:
    """A request as read, with what the store needs beside the contract fields."""

    request: ActionRequest
    execute_within: int
    timeout: int
    exec_key: tuple[str, str] | None
    last: ActionHistoryEvent | None = None


def utc(value: datetime) -> datetime:
    """The same instant in UTC. A datetime without a time zone is a bug upstream, not a guess to make."""
    if value.tzinfo is None:
        raise ValueError("a datetime needs a time zone")
    return value.astimezone(UTC)


def _utc_or_none(value: datetime | None) -> datetime | None:
    return None if value is None else utc(value)


def _unreadable(what: str, key: object, error: Exception | None) -> NoReturn:
    """Log what is wrong without what is stored (the id and field names only), then refuse the row."""
    detail = ""
    if isinstance(error, ValidationError):
        detail = " fields: " + ",".join(
            sorted({".".join(map(str, d["loc"])) for d in error.errors()})
        )
    elif error is not None:
        detail = f" ({type(error).__name__})"
    LOGGER.warning("%s: %s%s", what, key, detail)
    raise StoredRecordError(f"{what}") from None


def request_from_row(row: Row) -> ActionRequest:
    key = row.get("id")
    try:
        request = ActionRequest.model_validate(
            {
                **{k: row[k] for k in _PLAIN},
                "requester": {"id": row["requester_id"], "kind": row["requester_kind"]},
                "created_at": utc(row["created_at"]),
                "approve_by": utc(row["approve_by"]),
                "execute_by": _utc_or_none(row["execute_by"]),
            }
        )
    except (ValidationError, KeyError, AttributeError, TypeError, ValueError) as error:
        _unreadable("a stored action request could not be read", key, error)
    if (
        request_digest(request) != request.digest
    ):  # the content moved behind the digest an approver saw
        _unreadable("a stored action request does not match its digest", key, None)
    return request


def held_from_row(row: Row) -> Held:
    exec_key = None if row["exec_key"] is None else (row["exec_key"], row["exec_actor_id"])
    return Held(
        request_from_row(row), row["execute_within_seconds"], row["timeout_seconds"], exec_key
    )


def event_from_row(row: Row) -> ActionHistoryEvent:
    try:
        return ActionHistoryEvent.model_validate({**row, "at": utc(row["at"])})
    except (ValidationError, KeyError, AttributeError, TypeError, ValueError) as error:
        _unreadable(
            "a stored action history event could not be read", f"seq {row.get('seq')}", error
        )


_PLAIN: Final = (
    "id",
    "action_type",
    "target_id",
    "params",
    "risk",
    "state",
    "reason",
    "source",
    "approvals_required",
    "approvals",
    "version",
    "digest",
    "policy_checks",
    "pre_checks",
    "execution",
)


def _jsons(models: list[Any]) -> Jsonb:
    return Jsonb([m.model_dump(mode="json") for m in models])


def insert_params(request: ActionRequest, new: NewAction, key: str) -> tuple[object, ...]:
    return (
        request.id,
        request.action_type,
        request.target_id,
        Jsonb(request.params),
        request.risk,
        request.requester.id,
        request.requester.kind,
        request.reason,
        None if request.source is None else Jsonb(request.source.model_dump(mode="json")),
        request.approvals_required,
        request.created_at,
        request.approve_by,
        new.execute_within_seconds,
        new.timeout_seconds,
        request.digest,
        _jsons(request.policy_checks),
        key,
        new.fingerprint,
    )


def update_params(held: Held) -> tuple[object, ...]:
    request = held.request
    execution = request.execution
    return (
        request.state,
        request.version,
        _jsons(request.approvals),
        request.execute_by,
        None if execution is None else run_deadline(execution, held.timeout),
        _jsons(request.pre_checks),
        None if execution is None else Jsonb(execution.model_dump(mode="json")),
        None if held.exec_key is None else held.exec_key[0],
        None if held.exec_key is None else held.exec_key[1],
        request.id,
    )


def event_params(action_id: str, event: ActionHistoryEvent) -> tuple[object, ...]:
    return (
        action_id,
        event.seq,
        event.at,
        event.type,
        event.actor_id,
        event.from_state,
        event.to_state,
        event.code,
        event.note,
        event.prev_hash,
        event.hash,
    )
