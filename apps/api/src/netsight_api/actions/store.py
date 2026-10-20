"""The action request store: the Protocol and the in-memory implementation (Step 12).

Every rule that must hold under concurrency lives *here*, inside one lock, not in the routes:

* the lifecycle is the fixed table ``schemas_actions.ALLOWED_TRANSITIONS``;
* an approval, rejection, cancellation or execution quotes the request's ``digest`` (its content) and
  ``version`` (its position in the history) and loses with ``StaleRequest`` if either moved, so a
  decision is always about what the person saw and a replayed approval changes nothing;
* a requester never approves their own request, one person approves once, and only a human approves;
* a requester does not execute their own request either, unless the operator sets the policy flag
  ``allow_self_execute`` (default off); both rules compare the stable ``ActionActor.id``;
* two-person requests need ``approvals_required`` distinct approvers;
* an idempotency key is scoped to its requester: the same key and body returns the first request, the
  same key with another body is refused; an execution key starts a run once;
* one open request per action type and target, a cap per requester and in total;
* at most one execution runs on a target at a time;
* approval and execution have deadlines, checked on every touch and by ``expire_due``; a run that never
  reports back is failed after its timeout;
* the kill switch is read inside the lock, so a request cannot slip through while it is being engaged.

``InMemoryActionStore`` keeps requests in memory: ``durable`` is false and a restart loses them. That is
stated in the status contract, not hidden. ``postgres_store.PostgresActionStore`` implements the same
Protocol with the same rules (``lifecycle.py``) in transactions under row locks. Returned objects are
copies; the history is append-only and hash-chained (``history.py``).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal, Protocol

from netsight_api.actions import errors as e
from netsight_api.actions import lifecycle
from netsight_api.actions.history import history_matches
from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.lifecycle import EXECUTION_GRACE_SECONDS, Move
from netsight_api.actions.model import ExecutionFinish, NewAction
from netsight_api.schemas_actions import (
    OPEN_STATES,
    TERMINAL_STATES,
    ActionActor,
    ActionHistoryEvent,
    ActionRequest,
    ExecutionMode,
    RequestState,
)

__all__ = [
    "EVICT_MIN_AGE_SECONDS",
    "EXECUTION_GRACE_SECONDS",
    "MAX_OPEN_PER_REQUESTER",
    "MAX_STORED",
    "ActionStore",
    "BeginResult",
    "CreateResult",
    "InMemoryActionStore",
]

_LOGGER: Final = logging.getLogger("netsight_api")
MAX_OPEN_PER_REQUESTER: Final = 25
MAX_STORED: Final = 5_000
# A finished request may be evicted to make room only once it is this old, so a propose-and-cancel
# loop (whose requests are all young) cannot push other people's finished records out of the store.
EVICT_MIN_AGE_SECONDS: Final = 3_600


@dataclass(frozen=True)
class CreateResult:
    request: ActionRequest
    replayed: bool


@dataclass(frozen=True)
class BeginResult:
    request: ActionRequest
    replayed: bool


class ActionStore(Protocol):
    allow_self_execute: bool
    kind: Literal["memory", "postgres"]
    durable: bool

    def create(self, new: NewAction, *, idempotency_key: str, now: datetime) -> CreateResult: ...
    def get(self, action_id: str) -> ActionRequest | None: ...
    def history(self, action_id: str) -> list[ActionHistoryEvent]: ...
    def verify_chain(self, action_id: str) -> bool: ...
    def list_requests(
        self, *, state: RequestState | None = None, limit: int, offset: int, now: datetime
    ) -> tuple[list[ActionRequest], int]: ...
    def approve(
        self,
        action_id: str,
        *,
        approver: ActionActor,
        expected_digest: str,
        expected_version: int,
        now: datetime,
    ) -> ActionRequest: ...
    def reject(
        self,
        action_id: str,
        *,
        actor: ActionActor,
        expected_digest: str,
        expected_version: int,
        reason: str,
        now: datetime,
    ) -> ActionRequest: ...
    def cancel(
        self,
        action_id: str,
        *,
        actor: ActionActor,
        expected_digest: str,
        expected_version: int,
        reason: str,
        now: datetime,
    ) -> ActionRequest: ...
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
    ) -> BeginResult: ...
    def finish_execution(
        self, action_id: str, finish: ExecutionFinish, *, now: datetime
    ) -> ActionRequest: ...
    def expire_due(self, now: datetime) -> int: ...
    def check(self) -> None: ...


@dataclass
class _Record:
    request: ActionRequest
    history: list[ActionHistoryEvent]
    execute_within: int
    timeout: int
    # (idempotency key, id of the person who started the run): a retry replays only for that person.
    exec_key: tuple[str, str] | None = None
    create_scope: tuple[str, str] | None = None


class InMemoryActionStore:
    kind: Literal["memory", "postgres"] = "memory"
    durable = False

    def __init__(
        self,
        *,
        kill_switch: KillSwitch,
        max_open_per_requester: int = MAX_OPEN_PER_REQUESTER,
        max_stored: int = MAX_STORED,
        on_system_transition: Callable[[str, str, str], None] | None = None,
        allow_self_execute: bool = False,
    ) -> None:
        self._kill = kill_switch
        self.allow_self_execute = allow_self_execute
        # Called with (request id, new state, code) when the clock, not a person, moves a request.
        self._on_system = on_system_transition
        self._max_open = max_open_per_requester
        self._max_stored = max_stored
        self._lock = threading.RLock()
        self._records: dict[str, _Record] = {}
        self._create_keys: dict[tuple[str, str], tuple[str, str]] = {}

    def check(self) -> None:
        """Memory is always reachable."""

    # --- reads ---------------------------------------------------------------------------------------

    def get(self, action_id: str) -> ActionRequest | None:
        with self._lock:
            rec = self._records.get(action_id)
            return rec.request.model_copy(deep=True) if rec else None

    def history(self, action_id: str) -> list[ActionHistoryEvent]:
        with self._lock:
            return [x.model_copy(deep=True) for x in self._record(action_id).history]

    def verify_chain(self, action_id: str) -> bool:
        """The hash chain verifies *and* the history agrees with the request it belongs to."""
        with self._lock:
            rec = self._record(action_id)
            return history_matches(rec.request, rec.history)

    def list_requests(
        self, *, state: RequestState | None = None, limit: int, offset: int, now: datetime
    ) -> tuple[list[ActionRequest], int]:
        with self._lock:
            self.expire_due(now)
            rows = [r.request for r in self._records.values() if state in (None, r.request.state)]
            rows.sort(key=lambda r: (r.created_at, r.id), reverse=True)
            page = rows[offset : offset + limit]
            return [r.model_copy(deep=True) for r in page], len(rows)

    # --- creation ------------------------------------------------------------------------------------

    def create(self, new: NewAction, *, idempotency_key: str, now: datetime) -> CreateResult:
        with self._lock:
            self.expire_due(now)  # a finished-by-the-clock request must not block new work
            scope = (new.requester.id, idempotency_key)
            seen = self._create_keys.get(scope)
            if seen is not None:
                if seen[1] != new.fingerprint:
                    raise e.IdempotencyConflict
                return CreateResult(self._record(seen[0]).request.model_copy(deep=True), True)
            self._admit(new, now)
            request = lifecycle.new_request(new)
            rec = _Record(
                request,
                [lifecycle.genesis_event(request, now)],
                new.execute_within_seconds,
                new.timeout_seconds,
            )
            rec.create_scope = scope
            self._records[new.id] = rec
            self._create_keys[scope] = (new.id, new.fingerprint)
            for move in lifecycle.creation_moves(request):
                self._apply(rec, now, move)
            return CreateResult(rec.request.model_copy(deep=True), False)

    def _admit(self, new: NewAction, now: datetime) -> None:
        if self._kill.engaged:
            raise e.KillSwitchEngaged
        if len(self._records) >= self._max_stored and not self._evict_oldest_finished(now):
            raise e.StoreFull
        mine = 0
        for rec in self._records.values():
            if rec.request.state not in OPEN_STATES:
                continue
            if rec.request.requester.id == new.requester.id:
                mine += 1
            if (rec.request.action_type, rec.request.target_id) == (new.action_type, new.target_id):
                raise e.DuplicateOpenRequest
        if mine >= self._max_open:
            raise e.TooManyOpenRequests

    def _evict_oldest_finished(self, now: datetime) -> bool:
        """Make room by dropping the oldest finished request (and its idempotency key). Open requests stay.

        Only a request older than ``EVICT_MIN_AGE_SECONDS`` is a candidate. The audit log keeps the record
        of what happened; the volatile store only needs to stay bounded.
        """
        cutoff = now - timedelta(seconds=EVICT_MIN_AGE_SECONDS)
        finished = [
            r
            for r in self._records.values()
            if r.request.state in TERMINAL_STATES and r.request.created_at <= cutoff
        ]
        if not finished:
            return False
        oldest = min(finished, key=lambda r: (r.request.created_at, r.request.id))
        _LOGGER.warning("action request %s evicted to make room", oldest.request.id)
        del self._records[oldest.request.id]
        if oldest.create_scope is not None:
            self._create_keys.pop(oldest.create_scope, None)
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
        with self._lock:
            rec = self._record(action_id)
            self._raise_if_expired(rec, now)
            if self._kill.engaged:
                raise e.KillSwitchEngaged
            quote = (expected_digest, expected_version)
            move = lifecycle.approval_move(rec.request, approver, quote, now, rec.execute_within)
            self._apply(rec, now, move)
            return rec.request.model_copy(deep=True)

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
        with self._lock:
            rec = self._record(action_id)
            self._raise_if_expired(rec, now)
            quote = (expected_digest, expected_version)
            self._apply(rec, now, lifecycle.rejection_move(rec.request, actor, quote, reason))
            return rec.request.model_copy(deep=True)

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
        with self._lock:
            rec = self._record(action_id)
            self._raise_if_expired(rec, now)
            quote = (expected_digest, expected_version)
            self._apply(rec, now, lifecycle.cancellation_move(rec.request, actor, quote, reason))
            return rec.request.model_copy(deep=True)

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
        with self._lock:
            rec = self._record(action_id)
            # A run that timed out must stop locking its target. This request is judged below, so that
            # an expired request answers EXPIRED rather than a stale-version error.
            self._sweep(now, skip=action_id)
            if rec.exec_key is not None and rec.exec_key[0] == idempotency_key:
                # A retry reports the recorded result and never runs again, but only for the person who
                # started the run: the key is not a bearer token for someone else's request.
                if rec.exec_key[1] != actor.id or rec.request.digest != expected_digest:
                    raise e.IdempotencyConflict
                return BeginResult(rec.request.model_copy(deep=True), True)
            self._raise_if_expired(rec, now)
            if self._kill.engaged:
                raise e.KillSwitchEngaged
            quote = (expected_digest, expected_version)
            lifecycle.check_start(
                rec.request, actor, quote, allow_self_execute=self.allow_self_execute
            )
            if any(
                other.request.target_id == rec.request.target_id
                and other.request.state == "executing"
                and other.request.id != rec.request.id
                for other in self._records.values()
            ):
                raise e.TargetLocked
            rec.exec_key = (idempotency_key, actor.id)
            move = lifecycle.start_move(
                actor, executor_id=executor_id, mode=mode, steps=steps, now=now
            )
            self._apply(rec, now, move)
            return BeginResult(rec.request.model_copy(deep=True), False)

    def finish_execution(
        self, action_id: str, finish: ExecutionFinish, *, now: datetime
    ) -> ActionRequest:
        with self._lock:
            rec = self._record(action_id)
            for move in lifecycle.finish_moves(rec.request, finish):
                self._apply(rec, now, move)
            return rec.request.model_copy(deep=True)

    # --- deadlines -----------------------------------------------------------------------------------

    def expire_due(self, now: datetime) -> int:
        return self._sweep(now, skip=None)

    def _sweep(self, now: datetime, *, skip: str | None) -> int:
        with self._lock:
            return sum(
                1
                for rec in list(self._records.values())
                if rec.request.id != skip and self._expire_one(rec, now)
            )

    def _expire_one(self, rec: _Record, now: datetime) -> bool:
        move = lifecycle.expiry_move(rec.request, rec.timeout, now)
        if move is None:
            return False
        self._apply(rec, now, move)
        if self._on_system is not None:
            self._on_system(rec.request.id, move.to_state, move.code)
        return True

    def _raise_if_expired(self, rec: _Record, now: datetime) -> None:
        if self._expire_one(rec, now) and rec.request.state == "expired":
            raise e.ApprovalExpired

    # --- helpers -------------------------------------------------------------------------------------

    def _record(self, action_id: str) -> _Record:
        rec = self._records.get(action_id)
        if rec is None:
            raise e.ActionNotFound
        return rec

    @staticmethod
    def _apply(rec: _Record, now: datetime, move: Move) -> None:
        """Append the event, then re-validate the whole request against the contract's invariants."""
        previous = rec.history[-1] if rec.history else None
        rec.request, event = lifecycle.advance(rec.request, previous, now, move)
        rec.history.append(event)
