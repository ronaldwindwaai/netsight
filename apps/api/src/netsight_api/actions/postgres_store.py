"""The durable PostgreSQL action store (Step 12 follow-up, D-53; migration 0007).

It implements the ``ActionStore`` Protocol with the rules of ``InMemoryActionStore``: both decide with
``lifecycle.py``; this module only makes each decision atomic and shared between workers.

* every change is ONE transaction that first locks the request row (``SELECT ... FOR UPDATE``) and
  reads the state it decides on, so the loser of a race sees the winner's state and is refused
  (stale or illegal), never overwriting it; a request and its events are written together;
* creation takes one advisory lock, so the caps (25 open per requester, 5000 stored), the one-open
  request per action and target and the idempotency key are exact across workers (the cheap refusals,
  an idempotent replay, a duplicate and the per-requester cap, are answered before the lock is
  taken and again under it); a run takes a lock
  on its target, so only one execution runs there (a unique index is the backstop);
* deadlines are swept with ``FOR UPDATE SKIP LOCKED``: workers sharing a clock divide the work and
  each overdue request is moved once, and reported to ``on_system_transition`` at most once, after commit
  (a crash between the commit and the callback loses that audit record; the move itself is kept). One
  sweep handles one bounded batch, outside the creation lock, and skips (logging the id) a row that no
  longer parses so one corrupt row cannot block anyone else;
* a refusal that must not undo the clock's move (a decision on a request that expired) commits the move
  first and raises afterwards; any other refusal rolls the whole transaction back;
* "evicting" the oldest finished request (only one older than ``EVICT_MIN_AGE_SECONDS``) hides it and
  frees its idempotency key (``evicted_at``) and is logged; the row and its history stay, because the
  history is append-only and retention is a pending decision;
* an unreachable or failing database raises ``StoreUnavailable`` (503) and logs the exception class and
  SQLSTATE (never the DSN, a parameter or a row), never a fall back to memory and never an empty answer;
  a stored row that does not parse, or whose content no longer matches its digest, raises
  ``StoredRecordError`` (a ``StorageError``);
* worker clocks: windows and the sweep use the ``now`` the caller passes (the API's clock), so skew
  between workers moves a deadline by the skew; keep the hosts on NTP.

The kill switch is the process-local flag every store consults (see ``killswitch.py``).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final, Literal

import psycopg

from netsight_api.actions import errors as e
from netsight_api.actions import lifecycle
from netsight_api.actions import postgres_rows as q
from netsight_api.actions.history import history_matches
from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.lifecycle import Move
from netsight_api.actions.model import ExecutionFinish, NewAction
from netsight_api.actions.postgres_rows import Held, StoredRecordError
from netsight_api.actions.store import (
    EVICT_MIN_AGE_SECONDS,
    MAX_OPEN_PER_REQUESTER,
    MAX_STORED,
    BeginResult,
    CreateResult,
)
from netsight_api.schemas_actions import (
    MAX_PAGE_SIZE,
    ActionActor,
    ActionHistoryEvent,
    ActionRequest,
    ExecutionMode,
    RequestState,
    is_action_id,
)
from netsight_api.storage.connection import Connection, PostgresSettings
from netsight_api.storage.errors import StorageConflictError, StorageError

_LOGGER: Final = logging.getLogger("netsight_api")
# Advisory locks are per database: a namespace (the first int) per purpose, so two uses can never collide.
LOCK_NAMESPACE_CREATE: Final = 0x4E53_4143  # "NSAC": creating an action request
LOCK_NAMESPACE_TARGET: Final = 0x4E53_4154  # "NSAT": running an action on a target
CREATE_LOCK_KEY: Final = 1
_CREATE_LOCK: Final = "SELECT pg_advisory_xact_lock(%s, %s)"
_TARGET_LOCK: Final = "SELECT pg_advisory_xact_lock(%s, hashtext(%s))"
# SQLSTATEs that mean "the database answers but the store is not set up" (missing table, schema or grant).
_NOT_SET_UP: Final = frozenset({"42P01", "42501", "3F000"})
_REQUEST_TRIGGERS: Final = 5
_HISTORY_TRIGGERS: Final = 4
_READY: Final = (
    "SELECT (has_table_privilege('action_requests', 'SELECT') "
    "AND has_table_privilege('action_requests', 'INSERT') "
    "AND has_column_privilege('action_requests', 'state', 'UPDATE') "
    "AND has_table_privilege('action_history', 'SELECT') "
    "AND has_table_privilege('action_history', 'INSERT')) AS granted, "
    "(SELECT count(*) FROM pg_trigger WHERE tgrelid = 'action_requests'::regclass "
    "AND tgenabled = 'A' AND NOT tgisinternal) AS request_triggers, "
    "(SELECT count(*) FROM pg_trigger WHERE tgrelid = 'action_history'::regclass "
    "AND tgenabled = 'A' AND NOT tgisinternal) AS history_triggers"
)
_SNAPSHOT: Final = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"


class _KeepThenRefuse(Exception):
    """Commit what the transaction wrote so far, then raise ``error`` to the caller."""

    def __init__(self, error: e.ActionError) -> None:
        super().__init__(error.code)
        self.error = error


@dataclass
class _Tx:
    conn: Connection
    reports: list[tuple[str, str, str]] = field(default_factory=list)


class PostgresActionStore:
    kind: Literal["memory", "postgres"] = "postgres"
    durable = True

    def __init__(
        self,
        settings: PostgresSettings,
        *,
        kill_switch: KillSwitch,
        max_open_per_requester: int = MAX_OPEN_PER_REQUESTER,
        max_stored: int = MAX_STORED,
        on_system_transition: Callable[[str, str, str], None] | None = None,
        allow_self_execute: bool = False,
    ) -> None:
        self._settings = settings
        self._kill = kill_switch
        self.allow_self_execute = allow_self_execute
        self._on_system = on_system_transition
        self._max_open = max_open_per_requester
        self._max_stored = max_stored

    # --- plumbing ------------------------------------------------------------------------------------

    @staticmethod
    def _unavailable(error: StorageError) -> e.StoreUnavailable:
        """The 503 for a database failure, after logging what an operator needs: class and SQLSTATE only."""
        cause = error.__cause__ or error
        _LOGGER.error(
            "action store database failure: %s sqlstate=%s",
            type(cause).__name__,
            getattr(cause, "sqlstate", None) or "-",
        )
        return e.StoreUnavailable()

    @contextmanager
    def _guarded(self) -> Iterator[None]:
        """Database failures become ``StoreUnavailable``; an unreadable stored row stays a StorageError."""
        try:
            yield
        except StoredRecordError:
            raise
        except StorageError as error:
            raise self._unavailable(error) from None

    def _run[T](
        self, body: Callable[[_Tx], T], *, on_conflict: type[e.ActionError] | None = None
    ) -> T:
        """One write transaction: commit, then report the clock's moves, then raise any kept refusal."""
        refusal: e.ActionError | None = None
        result: T | None = None
        reports: list[tuple[str, str, str]] = []
        try:
            with self._settings.session() as conn:
                tx = _Tx(conn, reports)
                try:
                    result = body(tx)
                except _KeepThenRefuse as stop:
                    refusal = stop.error
        except StorageConflictError as error:
            unavailable = self._unavailable(error)
            raise (on_conflict() if on_conflict else unavailable) from None
        except StoredRecordError:
            raise
        except StorageError as error:
            raise self._unavailable(error) from None
        self._report(reports)
        if refusal is not None:
            raise refusal
        return result  # type: ignore[return-value]

    def _read[T](self, body: Callable[[Connection], T]) -> T:
        """One consistent read-only snapshot (a request and its history are read at the same moment)."""
        with self._guarded(), self._settings.session() as conn:
            conn.execute(_SNAPSHOT)
            return body(conn)

    def _report(self, reports: list[tuple[str, str, str]]) -> None:
        if self._on_system is None:
            return
        for report in reports:
            try:
                self._on_system(*report)
            except Exception:
                _LOGGER.exception("reporting a system transition of an action request failed")

    def check(self) -> None:
        """Raise unless the store is ready for this credential.

        ``StoreMisconfigured`` when the database answers but a table, a grant or a trigger of migration
        0007 is missing (a deployment error); ``StoreUnavailable`` when it cannot be reached or queried
        (possibly transient). Both are logged with the exception class and SQLSTATE only.
        """
        try:
            with self._settings.connect() as conn:
                row = conn.execute(_READY).fetchone()
        except psycopg.Error as error:
            _LOGGER.error(
                "action store probe failed: %s sqlstate=%s",
                type(error).__name__,
                error.sqlstate or "-",
            )
            raise (
                e.StoreMisconfigured if error.sqlstate in _NOT_SET_UP else e.StoreUnavailable
            )() from None
        ready = (
            row is not None
            and row["granted"]
            and row["request_triggers"] == _REQUEST_TRIGGERS
            and row["history_triggers"] == _HISTORY_TRIGGERS
        )
        if not ready:
            _LOGGER.error("action store is missing grants or enabled triggers of migration 0007")
            raise e.StoreMisconfigured

    # --- reads ---------------------------------------------------------------------------------------

    def get(self, action_id: str) -> ActionRequest | None:
        if not is_action_id(action_id):
            return None

        def read(conn: Connection) -> ActionRequest | None:
            row = conn.execute(q.SELECT_REQUEST, (action_id,)).fetchone()
            return None if row is None else q.request_from_row(row)

        return self._read(read)

    def history(self, action_id: str) -> list[ActionHistoryEvent]:
        return self._read(lambda conn: self._snapshot(conn, action_id)[1])

    def verify_chain(self, action_id: str) -> bool:
        def verify(conn: Connection) -> bool:
            request, events = self._snapshot(conn, action_id)
            return history_matches(request, events)

        return self._read(verify)

    @staticmethod
    def _snapshot(
        conn: Connection, action_id: str
    ) -> tuple[ActionRequest, list[ActionHistoryEvent]]:
        row = (
            conn.execute(q.SELECT_REQUEST, (action_id,)).fetchone()
            if is_action_id(action_id)
            else None
        )
        if row is None:
            raise e.ActionNotFound
        events = [q.event_from_row(r) for r in conn.execute(q.EVENTS, (action_id,)).fetchall()]
        return q.request_from_row(row), events

    def list_requests(
        self, *, state: RequestState | None = None, limit: int, offset: int, now: datetime
    ) -> tuple[list[ActionRequest], int]:
        now = q.utc(now)
        arguments = {
            "state": state,
            "limit": max(0, min(limit, MAX_PAGE_SIZE)),
            "offset": max(0, offset),
        }

        def read(conn: Connection) -> tuple[list[ActionRequest], int]:
            rows = conn.execute(q.LISTING, arguments).fetchall()
            total = conn.execute(q.LISTING_TOTAL, {"state": state}).fetchone()
            return [q.request_from_row(r) for r in rows], 0 if total is None else int(total["n"])

        self.expire_due(
            now
        )  # its own write transaction; the page and its total are then one read snapshot
        return self._read(read)

    # --- creation ------------------------------------------------------------------------------------

    def create(self, new: NewAction, *, idempotency_key: str, now: datetime) -> CreateResult:
        now = q.utc(now)
        self.expire_due(
            now
        )  # a finished-by-the-clock request must not block new work; outside the lock

        def body(tx: _Tx) -> CreateResult:
            replay = self._replay(tx, new, idempotency_key)
            if replay is not None:
                return replay
            self._admit(tx, new, now, locked=False)  # the cheap refusals need no global lock
            tx.conn.execute(_CREATE_LOCK, (LOCK_NAMESPACE_CREATE, CREATE_LOCK_KEY))
            replay = self._replay(tx, new, idempotency_key)  # a worker may have made it meanwhile
            if replay is not None:
                return replay
            self._admit(tx, new, now, locked=True)
            return CreateResult(self._insert(tx, new, idempotency_key, now), False)

        return self._run(body)

    def _replay(self, tx: _Tx, new: NewAction, key: str) -> CreateResult | None:
        seen = tx.conn.execute(q.FIND_BY_KEY, (new.requester.id, key)).fetchone()
        if seen is None:
            return None
        if seen["create_fingerprint"] != new.fingerprint:
            raise e.IdempotencyConflict
        return CreateResult(self._lock(tx, seen["id"]).request, True)

    def _insert(self, tx: _Tx, new: NewAction, key: str, now: datetime) -> ActionRequest:
        request = lifecycle.new_request(new)
        if lifecycle.request_digest(request) != new.digest:  # the digest must be of what is stored
            raise ValueError("the digest does not match the content of the proposal")
        tx.conn.execute(q.INSERT_REQUEST, q.insert_params(request, new, key))
        genesis = lifecycle.genesis_event(request, now)
        tx.conn.execute(q.INSERT_EVENT, q.event_params(request.id, genesis))
        held = Held(request, new.execute_within_seconds, new.timeout_seconds, None, genesis)
        for move in lifecycle.creation_moves(request):
            self._persist(tx, held, now, move)
        return held.request

    def _admit(self, tx: _Tx, new: NewAction, now: datetime, *, locked: bool) -> None:
        """The refusals before a request is stored. Making room (a write) happens only under the lock."""
        if self._kill.engaged:
            raise e.KillSwitchEngaged
        stored = tx.conn.execute(q.COUNT_STORED).fetchone()
        if (
            locked
            and stored is not None
            and stored["n"] >= self._max_stored
            and not self._evict_oldest(tx, now)
        ):
            raise e.StoreFull
        if tx.conn.execute(q.OPEN_ON_TARGET, (new.action_type, new.target_id)).fetchone():
            raise e.DuplicateOpenRequest
        mine = tx.conn.execute(q.COUNT_OPEN_OF, (new.requester.id,)).fetchone()
        if mine is not None and mine["n"] >= self._max_open:
            raise e.TooManyOpenRequests

    @staticmethod
    def _evict_oldest(tx: _Tx, now: datetime) -> bool:
        """Hide the oldest finished request (and free its idempotency key). Open requests stay."""
        cutoff = now - timedelta(seconds=EVICT_MIN_AGE_SECONDS)
        oldest = tx.conn.execute(q.EVICTABLE, (cutoff,)).fetchone()
        if oldest is None:
            return False
        tx.conn.execute(q.EVICT, (now, oldest["id"]))
        _LOGGER.warning("action request %s evicted to make room", oldest["id"])
        return True

    # --- decisions -----------------------------------------------------------------------------------

    def approve(
        self,
        action_id: str,
        *,
        approver: ActionActor,
        expected_digest: str,
        expected_version: int,
        now: datetime,
    ) -> ActionRequest:
        now = q.utc(now)
        quote = (expected_digest, expected_version)

        def body(tx: _Tx) -> ActionRequest:
            held = self._lock(tx, action_id)
            self._raise_if_expired(tx, held, now)
            if self._kill.engaged:
                raise e.KillSwitchEngaged
            move = lifecycle.approval_move(held.request, approver, quote, now, held.execute_within)
            return self._persist(tx, held, now, move)

        return self._run(body)

    def reject(
        self,
        action_id: str,
        *,
        actor: ActionActor,
        expected_digest: str,
        expected_version: int,
        reason: str,
        now: datetime,
    ) -> ActionRequest:
        now = q.utc(now)
        quote = (expected_digest, expected_version)

        def body(tx: _Tx) -> ActionRequest:
            held = self._lock(tx, action_id)
            self._raise_if_expired(tx, held, now)
            return self._persist(
                tx, held, now, lifecycle.rejection_move(held.request, actor, quote, reason)
            )

        return self._run(body)

    def cancel(
        self,
        action_id: str,
        *,
        actor: ActionActor,
        expected_digest: str,
        expected_version: int,
        reason: str,
        now: datetime,
    ) -> ActionRequest:
        now = q.utc(now)
        quote = (expected_digest, expected_version)

        def body(tx: _Tx) -> ActionRequest:
            held = self._lock(tx, action_id)
            self._raise_if_expired(tx, held, now)
            move = lifecycle.cancellation_move(held.request, actor, quote, reason)
            return self._persist(tx, held, now, move)

        return self._run(body)

    # --- execution -----------------------------------------------------------------------------------

    def begin_execution(
        self,
        action_id: str,
        *,
        actor: ActionActor,
        expected_digest: str,
        expected_version: int,
        idempotency_key: str,
        executor_id: str,
        mode: ExecutionMode,
        steps: list[str],
        now: datetime,
    ) -> BeginResult:
        now = q.utc(now)
        quote = (expected_digest, expected_version)

        def body(tx: _Tx) -> BeginResult:
            held = self._lock(tx, action_id)
            self._sweep(tx, now, skip=action_id)  # a timed-out run must stop locking its target
            if held.exec_key is not None and held.exec_key[0] == idempotency_key:
                # A retry reports the recorded result and never runs again, but only for the person
                # who started the run: the key is not a bearer token for someone else's request.
                if held.exec_key[1] != actor.id or held.request.digest != expected_digest:
                    raise e.IdempotencyConflict
                return BeginResult(held.request, True)
            self._raise_if_expired(tx, held, now)
            if self._kill.engaged:
                raise e.KillSwitchEngaged
            lifecycle.check_start(
                held.request, actor, quote, allow_self_execute=self.allow_self_execute
            )
            self._lock_target(tx, held.request)
            held.exec_key = (idempotency_key, actor.id)
            move = lifecycle.start_move(
                actor, executor_id=executor_id, mode=mode, steps=steps, now=now
            )
            return BeginResult(self._persist(tx, held, now, move), False)

        return self._run(body, on_conflict=e.TargetLocked)

    @staticmethod
    def _lock_target(tx: _Tx, request: ActionRequest) -> None:
        """Only one execution runs on a target: serialise the check (the unique index is the backstop)."""
        tx.conn.execute(_TARGET_LOCK, (LOCK_NAMESPACE_TARGET, request.target_id))
        if tx.conn.execute(q.RUNNING_ON_TARGET, (request.target_id, request.id)).fetchone():
            raise e.TargetLocked

    def finish_execution(
        self, action_id: str, finish: ExecutionFinish, *, now: datetime
    ) -> ActionRequest:
        now = q.utc(now)

        def body(tx: _Tx) -> ActionRequest:
            held = self._lock(tx, action_id)
            for move in lifecycle.finish_moves(held.request, finish):
                self._persist(tx, held, now, move)
            return held.request

        return self._run(body)

    # --- deadlines -----------------------------------------------------------------------------------

    def expire_due(self, now: datetime) -> int:
        now = q.utc(now)
        return self._run(lambda tx: self._sweep(tx, now, skip=None))

    def _sweep(self, tx: _Tx, now: datetime, *, skip: str | None) -> int:
        """Move one batch of overdue requests except ``skip``; rows another worker holds are that worker's.

        A row that no longer parses is logged (by id) and skipped, so it cannot block the others.
        """
        moved = 0
        for row in tx.conn.execute(q.DUE, (skip, now, now, now)).fetchall():
            try:
                held = self._with_last(tx, q.held_from_row(row))
            except StoredRecordError:
                continue
            if self._expire(tx, held, now) is not None:
                moved += 1
        return moved

    def _expire(self, tx: _Tx, held: Held, now: datetime) -> Move | None:
        move = lifecycle.expiry_move(held.request, held.timeout, now)
        if move is not None:
            self._persist(tx, held, now, move)
            tx.reports.append((held.request.id, move.to_state, move.code))
        return move

    def _raise_if_expired(self, tx: _Tx, held: Held, now: datetime) -> None:
        move = self._expire(tx, held, now)
        if move is not None and held.request.state == "expired":
            raise _KeepThenRefuse(e.ApprovalExpired())

    # --- helpers -------------------------------------------------------------------------------------

    def _lock(self, tx: _Tx, action_id: str) -> Held:
        """The request under its row lock, with the end of its chain. The row is current, not a snapshot."""
        row = (
            tx.conn.execute(q.LOCK_REQUEST, (action_id,)).fetchone()
            if is_action_id(action_id)
            else None
        )
        if row is None:
            raise e.ActionNotFound
        return self._with_last(tx, q.held_from_row(row))

    @staticmethod
    def _with_last(tx: _Tx, held: Held) -> Held:
        last = tx.conn.execute(q.LAST_EVENT, (held.request.id,)).fetchone()
        held.last = None if last is None else q.event_from_row(last)
        return held

    @staticmethod
    def _persist(tx: _Tx, held: Held, now: datetime, move: Move) -> ActionRequest:
        """Append the next chained event and write the re-validated request, in this transaction."""
        held.request, event = lifecycle.advance(held.request, held.last, now, move)
        held.last = event
        tx.conn.execute(q.INSERT_EVENT, q.event_params(held.request.id, event))
        tx.conn.execute(q.UPDATE_REQUEST, q.update_params(held))
        return held.request


__all__ = ["PostgresActionStore", "StoredRecordError"]
