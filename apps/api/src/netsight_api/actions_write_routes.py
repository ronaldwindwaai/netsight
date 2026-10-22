"""Controlled-action writes (Step 12): propose, approve, reject, cancel, execute, the kill switch.

There is no route that runs a command: ``execute`` hands an *approved, unexpired, un-stale* request
to the engine, which asks the dry-run executor to record what would happen. Nothing here contacts a
device or a network system, and nothing here can create an action type the catalogue does not list.

The body of an approval, rejection, cancellation or execution quotes the request's ``digest`` and
``version`` (what the person saw) and loses with 409 ``STALE_REQUEST`` otherwise; the store enforces
that, the self-approval ban and the replay rules under one lock. See ``actions_route_support`` for the
order of the guards and for what the audit records.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from netsight_api import actions_route_support as support
from netsight_api.actions.catalog import get_definition
from netsight_api.actions.errors import ActionNotFound, FindingsUnavailable, NotOwner
from netsight_api.actions.model import NewAction
from netsight_api.actions.proposals import ProposalError, propose, propose_from_finding
from netsight_api.actions.wiring import ActionRuntime
from netsight_api.actions_read_routes import status_body
from netsight_api.auth.step_up import step_up_refusal
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_support import no_store
from netsight_api.schemas_actions import (
    ActionCreateRequest,
    ActionDecisionRequest,
    ActionFromFindingRequest,
    ActionReasonRequest,
    ActionRequest,
    ActionStatusResponse,
    KillSwitchRequest,
)
from netsight_api.schemas_unknown_devices import UnknownDeviceFinding
from netsight_api.storage import StorageError

router = APIRouter(prefix="/actions")
P = Permission
_PROPOSAL_MESSAGES = {
    "action-not-allowed": (422, "That action type is not allowed"),
    "parameter-unknown": (422, "A parameter is not allowed for this action"),
    "parameter-missing": (422, "A required parameter is missing"),
    "parameter-type": (422, "A parameter has the wrong type"),
    "parameter-range": (422, "A parameter is out of range"),
    "parameter-choice": (422, "A parameter value is not allowed"),
    "target-not-allowed": (422, "The target is not valid for this action"),
    "no-proposal": (409, "The finding has no proposed action"),
    "finding-closed": (409, "The finding is closed"),
    "stale-evidence": (409, "The evidence changed since you opened this finding; reload"),
}
_PROPOSAL_CODES = {
    "no-proposal": "NO_PROPOSAL",
    "finding-closed": "FINDING_CLOSED",
    "stale-evidence": "STALE_EVIDENCE",
}

Proposer = Annotated[
    Identity, Depends(support.collection_writer(P.ACTIONS_PROPOSE, action="actions.create"))
]
HighProposer = Annotated[
    Identity,
    Depends(
        support.collection_writer(P.ACTIONS_PROPOSE_HIGH, action="actions.create-from-finding")
    ),
]
Approver = Annotated[
    Identity,
    Depends(support.item_writer(P.ACTIONS_APPROVE, action="actions.approve", step_up=True)),
]
Rejecter = Annotated[
    Identity, Depends(support.item_writer(P.ACTIONS_APPROVE, action="actions.reject"))
]
Canceller = Annotated[
    Identity,
    Depends(support.item_writer(P.ACTIONS_PROPOSE, P.ACTIONS_APPROVE, action="actions.cancel")),
]
Executor = Annotated[
    Identity,
    Depends(
        support.item_writer(
            P.ACTIONS_EXECUTE, action="actions.execute", step_up=True, kind="execute"
        )
    ),
]
Stopper = Annotated[
    Identity,
    Depends(
        support.collection_writer(P.ACTIONS_KILL_SWITCH, action="actions.kill-switch", kind="kill")
    ),
]
_WRITE_ERRORS = support.ERRORS


def _proposal_error(
    request: Request, identity: Identity, action: str, exc: ProposalError
) -> ApiError:
    status, message = _PROPOSAL_MESSAGES.get(exc.code, (422, "The action request is not valid"))
    support.audit(request, identity, action, "failure", reason=exc.code)
    code = _PROPOSAL_CODES.get(exc.code, "INVALID_ACTION")
    return ApiError(status, code, message)


def _created_details(body: ActionRequest, reason_length: int) -> dict[str, object]:
    return {
        "action_type": body.action_type,
        "risk": body.risk,
        "state": body.state,
        "version": body.version,
        "reason_length": reason_length,
        "param_count": len(body.params),
    }


# --- propose ------------------------------------------------------------------------------------------------


@router.post(
    "",
    status_code=201,
    response_model=ActionRequest,
    responses=_WRITE_ERRORS,
    operation_id="createAction",
)
async def create_action(
    request: Request,
    response: Response,
    body: ActionCreateRequest,
    key: support.IdempotencyKey,
    identity: Proposer,
    runtime: support.Runtime,
    now: support.Clock,
) -> ActionRequest:
    """Propose an allow-listed action. It waits for approval; nothing is executed."""
    action = "actions.create"
    no_store(response)
    active = support.require_runtime(request, identity, action, runtime)
    try:
        new = propose(
            actor=support.actor_of(identity),
            action_type=body.action_type,
            target_id=body.target_id,
            params=body.params,
            reason=body.reason,
            source=None,
            now=now(),
        )
    except ProposalError as exc:
        raise _proposal_error(request, identity, action, exc) from None
    return await _store_new(
        request, response, identity, action, active, new, key, now, len(body.reason)
    )


async def _store_new(
    request: Request,
    response: Response,
    identity: Identity,
    action: str,
    runtime: ActionRuntime,
    new: NewAction,
    key: str,
    now: support.Clock,
    reason_length: int,
) -> ActionRequest:
    definition = get_definition(new.action_type)
    needed = (
        Permission.ACTIONS_PROPOSE_HIGH if definition and definition.risk in ("C", "D") else None
    )
    if needed is not None and not is_allowed(identity, needed.value):
        support.audit(
            request, identity, action, "denied", reason="permission-high-risk", risk=new.risk
        )
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    result = await support.run_call(
        request,
        identity,
        action,
        None,
        lambda: runtime.store.create(new, idempotency_key=key, now=now()),
    )
    if result.replayed:
        response.headers["Idempotent-Replay"] = "true"
    support.audit(
        request,
        identity,
        action,
        "success",
        result.request.id,
        replayed=result.replayed,
        **_created_details(result.request, reason_length),
    )
    return support.checked("action_request", result.request)  # type: ignore[no-any-return]


@router.post(
    "/from-finding",
    status_code=201,
    response_model=ActionRequest,
    responses=_WRITE_ERRORS,
    operation_id="createActionFromFinding",
)
async def create_action_from_finding(
    request: Request,
    response: Response,
    body: ActionFromFindingRequest,
    key: support.IdempotencyKey,
    identity: HighProposer,
    runtime: support.Runtime,
    findings: support.FindingsReader,
    now: support.Clock,
) -> ActionRequest:
    """Create the action request for a Step 8 quarantine proposal. Proposal only."""
    action = "actions.create-from-finding"
    no_store(response)
    if not is_allowed(identity, Permission.UNKNOWN_DEVICES_READ.value):
        support.audit(request, identity, action, "denied", reason="permission-findings")
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    active = support.require_runtime(request, identity, action, runtime)
    if findings is None:
        support.audit(request, identity, action, "failure", reason="findings-not-connected")
        raise ApiError(503, "FINDINGS_NOT_CONNECTED", "Finding storage is not connected")

    def read_finding() -> UnknownDeviceFinding | None:
        try:
            return findings.get_finding(body.finding_id)
        except StorageError:
            raise FindingsUnavailable from None

    finding = await support.run_call(request, identity, action, None, read_finding)
    if finding is None:
        support.audit(request, identity, action, "failure", reason="finding-not-found")
        raise ApiError(404, "NOT_FOUND", "Finding was not found")
    try:
        new = propose_from_finding(
            actor=support.actor_of(identity),
            finding=finding,
            expected_evidence_version=body.expected_evidence_version,
            reason=body.reason,
            now=now(),
        )
    except ProposalError as exc:
        raise _proposal_error(request, identity, action, exc) from None
    return await _store_new(
        request, response, identity, action, active, new, key, now, len(body.reason)
    )


# --- decide -------------------------------------------------------------------------------------------------


@router.post(
    "/{action_id}/approve",
    response_model=ActionRequest,
    responses=_WRITE_ERRORS,
    operation_id="approveAction",
)
async def approve_action(
    request: Request,
    response: Response,
    action_id: support.ActionIdPath,
    body: ActionDecisionRequest,
    identity: Approver,
    runtime: support.Runtime,
    now: support.Clock,
) -> ActionRequest:
    """Approve exactly what the person saw. Human only, never the requester, needs step-up."""
    action = "actions.approve"
    no_store(response)
    active = support.require_runtime(request, identity, action, runtime)
    result = await support.run_call(
        request,
        identity,
        action,
        action_id,
        lambda: active.store.approve(
            action_id,
            approver=support.actor_of(identity),
            expected_digest=body.expected_digest,
            expected_version=body.expected_version,
            now=now(),
        ),
    )
    support.audit(
        request,
        identity,
        action,
        "success",
        action_id,
        risk=result.risk,
        state=result.state,
        approvals=len(result.approvals),
        required=result.approvals_required,
        version=result.version,
    )
    return support.checked("action_request", result)  # type: ignore[no-any-return]


@router.post(
    "/{action_id}/reject",
    response_model=ActionRequest,
    responses=_WRITE_ERRORS,
    operation_id="rejectAction",
)
async def reject_action(
    request: Request,
    response: Response,
    action_id: support.ActionIdPath,
    body: ActionReasonRequest,
    identity: Rejecter,
    runtime: support.Runtime,
    now: support.Clock,
) -> ActionRequest:
    """Reject a pending request with a reason (human only)."""
    return await _close(request, response, action_id, body, identity, runtime, now, "reject")


@router.post(
    "/{action_id}/cancel",
    response_model=ActionRequest,
    responses=_WRITE_ERRORS,
    operation_id="cancelAction",
)
async def cancel_action(
    request: Request,
    response: Response,
    action_id: support.ActionIdPath,
    body: ActionReasonRequest,
    identity: Canceller,
    runtime: support.Runtime,
    now: support.Clock,
) -> ActionRequest:
    """Cancel an open request: its requester, or an approver."""
    return await _close(request, response, action_id, body, identity, runtime, now, "cancel")


async def _close(
    request: Request,
    response: Response,
    action_id: str,
    body: ActionReasonRequest,
    identity: Identity,
    runtime: ActionRuntime | None,
    now: support.Clock,
    verb: str,
) -> ActionRequest:
    action = f"actions.{verb}"
    no_store(response)
    active = support.require_runtime(request, identity, action, runtime)
    actor = support.actor_of(identity)

    def apply() -> ActionRequest:
        current = active.store.get(action_id)
        if current is None:
            raise ActionNotFound
        if verb == "cancel" and not (
            is_allowed(identity, Permission.ACTIONS_APPROVE.value)
            or current.requester.id == identity.id
        ):
            raise NotOwner
        method = active.store.cancel if verb == "cancel" else active.store.reject
        return method(
            action_id,
            actor=actor,
            expected_digest=body.expected_digest,
            expected_version=body.expected_version,
            reason=body.reason,
            now=now(),
        )

    result = await support.run_call(request, identity, action, action_id, apply)
    support.audit(
        request,
        identity,
        action,
        "success",
        action_id,
        risk=result.risk,
        state=result.state,
        reason_length=len(body.reason),
        version=result.version,
    )
    return support.checked("action_request", result)  # type: ignore[no-any-return]


# --- execute and the kill switch ----------------------------------------------------------------------------------


@router.post(
    "/{action_id}/execute",
    response_model=ActionRequest,
    responses=_WRITE_ERRORS,
    operation_id="executeAction",
)
async def execute_action(
    request: Request,
    response: Response,
    action_id: support.ActionIdPath,
    body: ActionDecisionRequest,
    key: support.IdempotencyKey,
    identity: Executor,
    runtime: support.Runtime,
) -> ActionRequest:
    """Run an approved request through its executor. Only the dry-run executor exists today."""
    action = "actions.execute"
    no_store(response)
    active = support.require_runtime(request, identity, action, runtime)
    outcome = await support.run_call(
        request,
        identity,
        action,
        action_id,
        lambda: active.engine.execute(
            action_id,
            actor=support.actor_of(identity),
            expected_digest=body.expected_digest,
            expected_version=body.expected_version,
            idempotency_key=key,
        ),
    )
    result = outcome.request
    if outcome.replayed:
        response.headers["Idempotent-Replay"] = "true"
    execution = result.execution
    support.audit(
        request,
        identity,
        action,
        "success" if result.state == "succeeded" else "failure",
        action_id,
        risk=result.risk,
        state=result.state,
        mode=execution.mode if execution else None,
        effect=execution.effect if execution else None,
        failure=execution.failure if execution else None,
        replayed=outcome.replayed,
        version=result.version,
    )
    return support.checked("action_request", result)  # type: ignore[no-any-return]


@router.post(
    "/kill-switch",
    response_model=ActionStatusResponse,
    responses=_WRITE_ERRORS,
    operation_id="setActionKillSwitch",
)
async def set_kill_switch(
    request: Request,
    response: Response,
    body: KillSwitchRequest,
    identity: Stopper,
    runtime: support.Runtime,
    now: support.Clock,
) -> ActionStatusResponse:
    """Engage (any time) or release (needs step-up) the runtime kill switch."""
    action = "actions.kill-switch"
    no_store(response)
    active = support.require_runtime(request, identity, action, runtime)
    if not body.engaged:
        refusal = step_up_refusal(request)
        if refusal is not None:
            support.audit(request, identity, action, "denied", reason=refusal.reason)
            raise ApiError(403, refusal.code, refusal.message)

    def apply() -> None:
        if body.engaged:
            active.kill_switch.engage(now())
        else:
            active.kill_switch.release()

    await support.run_call(request, identity, action, None, apply)
    support.audit(
        request, identity, action, "success", engaged=body.engaged, reason_length=len(body.reason)
    )
    return support.checked("action_status", status_body(active, now))  # type: ignore[no-any-return]
