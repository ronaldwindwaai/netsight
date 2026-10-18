"""The action request store: the Protocol and the in-memory implementation (Step 12).

Every rule that must hold under concurrency lives *here*, inside one lock, not in the routes:

* the lifecycle is the fixed table ``schemas_actions.ALLOWED_TRANSITIONS``;
* an approval, rejection, cancellation or execution quotes the request's ``digest`` (its content) and
  ``version`` (its position in the history) and loses with ``StaleRequest`` if either moved, so a
  decision is always about what the person saw and a replayed approval changes nothing;
* a requester never approves their own request, one person approves once, and only a human approves;
* two-person requests need ``approvals_required`` distinct approvers;
* an idempotency key is scoped to its requester: the same key and body returns the first request, the
  same key with another body is refused; an execution key starts a run once;
* one open request per action type and target, a cap per requester and in total;
* at most one execution runs on a target at a time;
* approval and execution have deadlines, checked on every touch and by ``expire_due``; a run that never
  reports back is failed after its timeout;
* the kill switch is read inside the lock, so a request cannot slip through while it is being engaged.

The store keeps requests in memory: ``durable`` is false and a restart loses them. That is stated in
the status contract, not hidden. Returned objects are copies; the history is append-only and
hash-chained (``history.py``).
"""

from __future__ import annotations

import itertools
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol

from netsight_api.actions import errors as e
from netsight_api.actions.history import next_event, verify_chain
from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.model import ExecutionFinish, NewAction
from netsight_api.schemas_actions import (
    ALLOWED_TRANSITIONS,
    OPEN_STATES,
    TERMINAL_STATES,
    ActionActor,
    ActionExecution,
    ActionHistoryEvent,
    ActionRequest,
    ActionVerification,
    EventType,
    ExecutionMode,
    RequestState,
)

MAX_OPEN_PER_REQUESTER: Final = 25
MAX_STORED: Final = 5_000
# A run is failed this long after its own timeout, so a slow executor is not cut off mid-step.
EXECUTION_GRACE_SECONDS: Final = 60


@dataclass(frozen=True)
class CreateResult:
    request: ActionRequest
    replayed: bool


@dataclass(frozen=True)
class BeginResult:
    request: ActionRequest
    replayed: bool


class ActionStore(Protocol):
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
    def __init__(
        self,
        *,
        kill_switch: KillSwitch,
        max_open_per_requester: int = MAX_OPEN_PER_REQUESTER,
        max_stored: int = MAX_STORED,
        on_system_transition: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self._kill = kill_switch
        # Called with (request id, new state, code) when the clock, not a person, moves a request.
        self._on_system = on_system_transition
        self._max_open = max_open_per_requester
        self._max_stored = max_stored
        self._lock = threading.RLock()
        self._records: dict[str, _Record] = {}
        self._create_keys: dict[tuple[str, str], tuple[str, str]] = {}

    # --- reads ---------------------------------------------------------------------------------------

    def get(self, action_id: str) -> ActionRequest | None:
        with self._lock:
            rec = self._records.get(action_id)
            return rec.request.model_copy(deep=True) if rec else None

    def history(self, action_id: str) -> list[ActionHistoryEvent]:
        with self._lock:
            return [x.model_copy(deep=True) for x in self._record(action_id).history]

    def verify_chain(self, action_id: str) -> bool:
        """The hash chain verifies *and* the history agrees with the request it belongs to.

        A chain alone cannot see its own tail being cut off; the last event must also be the request's
        current version and state, and every step must start where the previous one ended.
        """
        with self._lock:
            rec = self._record(action_id)
            events = rec.history
            if not verify_chain(action_id, events):
                return False
            last = events[-1]
            if last.seq != rec.request.version or last.to_state != rec.request.state:
                return False
            return all(
                later.from_state in (None, earlier.to_state)
                for earlier, later in itertools.pairwise(events)
            )

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
            self._admit(new)
            request = ActionRequest(
                id=new.id,
                action_type=new.action_type,
                target_id=new.target_id,
                params=dict(new.params),
                risk=new.risk,
                state="proposed",
                requester=new.requester,
                reason=new.reason,
                source=new.source,
                approvals_required=new.approvals_required,
                approvals=[],
                created_at=new.created_at,
                approve_by=new.approve_by,
                execute_by=None,
                version=1,
                digest=new.digest,
                policy_checks=list(new.policy_checks),
                pre_checks=[],
                execution=None,
            )
            rec = _Record(request, [], new.execute_within_seconds, new.timeout_seconds)
            rec.create_scope = scope
            self._records[new.id] = rec
            self._create_keys[scope] = (new.id, new.fingerprint)
            self._emit(rec, now, "proposed", new.requester.id, None, "proposed", "proposed")
            self._apply(rec, now, "policy-checked", None, "proposed", "policy-passed")
            self._apply(
                rec, now, "submitted", new.requester.id, "pending-approval", "awaiting-approval"
            )
            return CreateResult(rec.request.model_copy(deep=True), False)

    def _admit(self, new: NewAction) -> None:
        if self._kill.engaged:
            raise e.KillSwitchEngaged
        if len(self._records) >= self._max_stored and not self._evict_oldest_finished():
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

    def _evict_oldest_finished(self) -> bool:
        """Make room by dropping the oldest finished request (and its idempotency key). Open requests stay.

        The audit log keeps the record of what happened; the volatile store only needs to stay bounded, and
        a propose-and-cancel loop must not be able to fill it for everyone.
        """
        finished = [r for r in self._records.values() if r.request.state in TERMINAL_STATES]
        if not finished:
            return False
        oldest = min(finished, key=lambda r: (r.request.created_at, r.request.id))
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
            if approver.kind != "human":
                raise e.ApproverNotHuman
            request = self._quoted(rec, expected_digest, expected_version)
            self._require(request, "pending-approval")
            if approver.id == request.requester.id:
                raise e.SelfApproval
            if any(a.approver_id == approver.id for a in request.approvals):
                raise e.AlreadyApproved
            approvals = [*request.approvals, {"approver_id": approver.id, "approved_at": now}]
            complete = len(approvals) >= request.approvals_required
            self._apply(
                rec,
                now,
                "approved",
                approver.id,
                "approved" if complete else "pending-approval",
                "approval-complete" if complete else "approval-recorded",
                update={
                    "approvals": approvals,
                    "execute_by": now + timedelta(seconds=rec.execute_within) if complete else None,
                },
            )
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
            if actor.kind != "human":
                raise e.ApproverNotHuman
            request = self._quoted(rec, expected_digest, expected_version)
            self._require(request, "proposed", "pending-approval")
            self._apply(rec, now, "rejected", actor.id, "rejected", "rejected", note=reason)
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
            request = self._quoted(rec, expected_digest, expected_version)
            self._require(request, "proposed", "pending-approval", "approved")
            self._apply(rec, now, "cancelled", actor.id, "cancelled", "cancelled", note=reason)
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
            if actor.kind != "human":
                raise e.ApproverNotHuman
            request = self._quoted(rec, expected_digest, expected_version)
            self._require(request, "approved")
            if any(
                other.request.target_id == request.target_id
                and other.request.state == "executing"
                and other.request.id != request.id
                for other in self._records.values()
            ):
                raise e.TargetLocked
            rec.exec_key = (idempotency_key, actor.id)
            execution = ActionExecution(
                executor=executor_id,
                mode=mode,
                effect="none" if mode == "dry-run" else "unknown",
                started_at=now,
                finished_at=None,
                planned_steps=steps,
                verification=ActionVerification(state="unknown", detail="not-run"),
                rollback=None,
                failure=None,
            )
            self._apply(
                rec,
                now,
                "execution-started",
                actor.id,
                "executing",
                "execution-started",
                update={"execution": execution},
            )
            return BeginResult(rec.request.model_copy(deep=True), False)

    def finish_execution(
        self, action_id: str, finish: ExecutionFinish, *, now: datetime
    ) -> ActionRequest:
        with self._lock:
            rec = self._record(action_id)
            self._require(rec.request, "executing")
            execution = rec.request.execution
            if execution is None or not finish.events:
                raise e.InvalidOutcome
            if execution.mode == "dry-run" and finish.effect != "none":
                raise e.InvalidOutcome  # a dry run never changes anything, whatever an executor says
            update_request: dict[str, object] = {}
            if finish.pre_checks:
                update_request["pre_checks"] = list(finish.pre_checks)
            done = execution.model_copy(
                update={
                    "effect": finish.effect,
                    "finished_at": finish.finished_at,
                    "verification": finish.verification,
                    "rollback": finish.rollback,
                    "failure": finish.failure,
                }
            )
            last = len(finish.events) - 1
            for index, (kind, code) in enumerate(finish.events):
                if index == last:
                    self._apply(
                        rec,
                        now,
                        kind,
                        None,
                        finish.final_state,
                        code,
                        update={"execution": done, **update_request},
                    )
                else:
                    self._apply(rec, now, kind, None, "executing", code)
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
        request = rec.request
        if request.state in ("proposed", "pending-approval") and now > request.approve_by:
            self._apply(rec, now, "expired", None, "expired", "approval-window-closed")
            self._report(rec, "expired", "approval-window-closed")
            return True
        if (
            request.state == "approved"
            and request.execute_by is not None
            and now > request.execute_by
        ):
            self._apply(rec, now, "expired", None, "expired", "execution-window-closed")
            self._report(rec, "expired", "execution-window-closed")
            return True
        execution = request.execution
        deadline = (
            execution.started_at + timedelta(seconds=rec.timeout + EXECUTION_GRACE_SECONDS)
            if execution is not None
            else None
        )
        if (
            request.state == "executing"
            and execution is not None
            and deadline is not None
            and now > deadline
        ):
            failed = execution.model_copy(
                update={"finished_at": now, "failure": "executor-timeout"}
            )
            self._apply(
                rec, now, "failed", None, "failed", "executor-timeout", update={"execution": failed}
            )
            self._report(rec, "failed", "executor-timeout")
            return True
        return False

    def _report(self, rec: _Record, state: str, code: str) -> None:
        if self._on_system is not None:
            self._on_system(rec.request.id, state, code)

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
    def _quoted(rec: _Record, digest: str, version: int) -> ActionRequest:
        if rec.request.digest != digest or rec.request.version != version:
            raise e.StaleRequest
        return rec.request

    @staticmethod
    def _require(request: ActionRequest, *states: str) -> None:
        if request.state not in states:
            raise e.IllegalTransition

    def _emit(
        self,
        rec: _Record,
        now: datetime,
        kind: EventType,
        actor_id: str | None,
        from_state: RequestState | None,
        to_state: RequestState,
        code: str,
        note: str | None = None,
    ) -> ActionHistoryEvent:
        moves = from_state is not None and from_state != to_state
        if moves and to_state not in ALLOWED_TRANSITIONS[from_state]:  # type: ignore[index]
            raise RuntimeError("illegal lifecycle move")  # a bug, never reachable from a request
        event = next_event(
            rec.request.id,
            rec.history[-1] if rec.history else None,
            at=now,
            type=kind,
            actor_id=actor_id,
            from_state=from_state,
            to_state=to_state,
            code=code,
            note=note,
        )
        rec.history.append(event)
        return event

    def _apply(
        self,
        rec: _Record,
        now: datetime,
        kind: EventType,
        actor_id: str | None,
        to_state: RequestState,
        code: str,
        *,
        note: str | None = None,
        update: Mapping[str, object] | None = None,
    ) -> None:
        """Append the event, then re-validate the whole request against the contract's invariants."""
        event = self._emit(rec, now, kind, actor_id, rec.request.state, to_state, code, note)
        merged = {
            **rec.request.model_dump(),
            **(update or {}),
            "state": to_state,
            "version": event.seq,
        }
        rec.request = ActionRequest.model_validate(merged)
