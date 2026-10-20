"""The lifecycle rules of an action request as pure functions (Step 12).

Both stores (in memory and PostgreSQL) decide and describe a change with the functions here, so the
rules cannot drift apart: the stores differ only in *how* they hold the request and make a change
atomic (a lock, or a row lock in a transaction). A function either raises the refusal from
``errors`` or returns a :class:`Move`: the event to append and the fields of the request that change.
``advance`` applies one move to a request and re-validates the whole result against the contract.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from netsight_api.actions import errors as e
from netsight_api.actions.history import next_event
from netsight_api.actions.model import ExecutionFinish, NewAction, content_digest
from netsight_api.schemas_actions import (
    ALLOWED_TRANSITIONS,
    ActionActor,
    ActionExecution,
    ActionHistoryEvent,
    ActionRequest,
    ActionVerification,
    EventType,
    ExecutionMode,
    RequestState,
)

# A run is failed this long after its own timeout, so a slow executor is not cut off mid-step.
EXECUTION_GRACE_SECONDS: Final = 60


@dataclass(frozen=True)
class Move:
    """One lifecycle event and the request fields it changes."""

    kind: EventType
    actor_id: str | None
    to_state: RequestState
    code: str
    note: str | None = None
    update: Mapping[str, object] = field(default_factory=dict)


def new_request(new: NewAction) -> ActionRequest:
    """The request as first stored: proposed, version 1, nothing decided."""
    return ActionRequest(
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


def request_digest(request: ActionRequest) -> str:
    """The digest recomputed from the fields a request holds (equal to its ``NewAction.digest``)."""
    return content_digest(
        action_id=request.id,
        action_type=request.action_type,
        target_id=request.target_id,
        params=request.params,
        risk=request.risk,
        requester_id=request.requester.id,
        reason=request.reason,
        source=request.source.model_dump(mode="json") if request.source else None,
        approvals_required=request.approvals_required,
        created_at=request.created_at,
        approve_by=request.approve_by,
    )


def genesis_event(request: ActionRequest, now: datetime) -> ActionHistoryEvent:
    """Event 1: the proposal, made by the requester."""
    return next_event(
        request.id,
        request.digest,
        None,
        at=now,
        type="proposed",
        actor_id=request.requester.id,
        from_state=None,
        to_state="proposed",
        code="proposed",
    )


def creation_moves(request: ActionRequest) -> list[Move]:
    """After the proposal: the policy checks passed, then the requester submitted it for approval."""
    return [
        Move("policy-checked", None, "proposed", "policy-passed"),
        Move("submitted", request.requester.id, "pending-approval", "awaiting-approval"),
    ]


def advance(
    request: ActionRequest, previous: ActionHistoryEvent | None, now: datetime, move: Move
) -> tuple[ActionRequest, ActionHistoryEvent]:
    """Apply one move: the next chained event and the re-validated request."""
    if move.to_state != request.state and move.to_state not in ALLOWED_TRANSITIONS[request.state]:
        raise RuntimeError("illegal lifecycle move")  # a bug, never reachable from a request
    event = next_event(
        request.id,
        request.digest,
        previous,
        at=now,
        type=move.kind,
        actor_id=move.actor_id,
        from_state=request.state,
        to_state=move.to_state,
        code=move.code,
        note=move.note,
    )
    merged = {
        **request.model_dump(),
        **move.update,
        "state": move.to_state,
        "version": event.seq,
    }
    return ActionRequest.model_validate(merged), event


# --- checks every decision makes ----------------------------------------------------------------------------------


def check_quote(request: ActionRequest, digest: str, version: int) -> None:
    """A decision is about what the person saw: content (digest) and position (version)."""
    if request.digest != digest or request.version != version:
        raise e.StaleRequest


def require_state(request: ActionRequest, *states: str) -> None:
    if request.state not in states:
        raise e.IllegalTransition


# --- decisions ----------------------------------------------------------------------------------------------------


def approval_move(
    request: ActionRequest,
    approver: ActionActor,
    quote: tuple[str, int],
    now: datetime,
    execute_within: int,
) -> Move:
    """Record one approval; complete when every required distinct person has approved."""
    if approver.kind != "human":
        raise e.ApproverNotHuman
    check_quote(request, *quote)
    require_state(request, "pending-approval")
    if approver.id == request.requester.id:
        raise e.SelfApproval
    if any(a.approver_id == approver.id for a in request.approvals):
        raise e.AlreadyApproved
    approvals = [*request.approvals, {"approver_id": approver.id, "approved_at": now}]
    complete = len(approvals) >= request.approvals_required
    return Move(
        "approved",
        approver.id,
        "approved" if complete else "pending-approval",
        "approval-complete" if complete else "approval-recorded",
        update={
            "approvals": approvals,
            "execute_by": now + timedelta(seconds=execute_within) if complete else None,
        },
    )


def rejection_move(
    request: ActionRequest, actor: ActionActor, quote: tuple[str, int], reason: str
) -> Move:
    if actor.kind != "human":
        raise e.ApproverNotHuman
    check_quote(request, *quote)
    require_state(request, "proposed", "pending-approval")
    return Move("rejected", actor.id, "rejected", "rejected", note=reason)


def cancellation_move(
    request: ActionRequest, actor: ActionActor, quote: tuple[str, int], reason: str
) -> Move:
    check_quote(request, *quote)
    require_state(request, "proposed", "pending-approval", "approved")
    return Move("cancelled", actor.id, "cancelled", "cancelled", note=reason)


# --- execution ----------------------------------------------------------------------------------------------------


def check_start(
    request: ActionRequest,
    actor: ActionActor,
    quote: tuple[str, int],
    *,
    allow_self_execute: bool,
) -> None:
    """Who may start a run, and on what: a person, not the requester (unless policy says so), the
    content and position they saw, an approved request. The kill switch and the target lock are the
    store's own checks."""
    if actor.kind != "human":
        raise e.ApproverNotHuman
    if not allow_self_execute and actor.id == request.requester.id:
        raise e.SelfExecution
    check_quote(request, *quote)
    require_state(request, "approved")


def start_move(
    actor: ActionActor, *, executor_id: str, mode: ExecutionMode, steps: list[str], now: datetime
) -> Move:
    return Move(
        "execution-started",
        actor.id,
        "executing",
        "execution-started",
        update={
            "execution": ActionExecution(
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
        },
    )


def finish_moves(request: ActionRequest, finish: ExecutionFinish) -> list[Move]:
    """The events an executor's outcome adds; the last one moves the request to its final state."""
    require_state(request, "executing")
    execution = request.execution
    if execution is None or not finish.events:
        raise e.InvalidOutcome
    if execution.mode == "dry-run" and finish.effect != "none":
        raise e.InvalidOutcome  # a dry run never changes anything, whatever an executor says
    final: dict[str, object] = {
        "execution": execution.model_copy(
            update={
                "effect": finish.effect,
                "finished_at": finish.finished_at,
                "verification": finish.verification,
                "rollback": finish.rollback,
                "failure": finish.failure,
            }
        )
    }
    if finish.pre_checks:
        final["pre_checks"] = list(finish.pre_checks)
    last = len(finish.events) - 1
    return [
        Move(kind, None, finish.final_state, code, update=final)
        if index == last
        else Move(kind, None, "executing", code)
        for index, (kind, code) in enumerate(finish.events)
    ]


# --- deadlines ----------------------------------------------------------------------------------------------------


def run_deadline(execution: ActionExecution, timeout_seconds: int) -> datetime:
    return execution.started_at + timedelta(seconds=timeout_seconds + EXECUTION_GRACE_SECONDS)


def expiry_move(request: ActionRequest, timeout_seconds: int, now: datetime) -> Move | None:
    """The clock's move for a request whose window has closed, or ``None`` while it is still in time.

    ``proposed`` is transient: a request leaves it inside the transaction (or lock) that creates it, so a
    stored request is never swept in that state; the branch only keeps the rule complete.
    """
    if request.state in ("proposed", "pending-approval") and now > request.approve_by:
        return Move("expired", None, "expired", "approval-window-closed")
    if request.state == "approved" and request.execute_by is not None and now > request.execute_by:
        return Move("expired", None, "expired", "execution-window-closed")
    execution = request.execution
    if (
        request.state == "executing"
        and execution is not None
        and now > run_deadline(execution, timeout_seconds)
    ):
        failed = execution.model_copy(update={"finished_at": now, "failure": "executor-timeout"})
        return Move("failed", None, "failed", "executor-timeout", update={"execution": failed})
    return None
