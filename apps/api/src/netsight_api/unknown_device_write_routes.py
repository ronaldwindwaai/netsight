"""Unknown-device writes (Step 8c): the human workflow and the on-demand scan.

Every write is a human judgement, so each one is human-only and goes through the gates described in
``unknown_device_support`` (authenticate, authorise, CSRF and origin, step-up on resolve, budget).
A decision about a finding quotes the ``evidence_version`` the person was shown and loses with
``409 STALE_EVIDENCE`` if the evidence changed since, so nobody dismisses a finding on evidence
they did not see.

There is no route that executes, approves or even creates an isolation: a quarantine is a
``proposed_action`` the scanner records and nothing here (or anywhere in this release) can carry out.
Free text is stored and returned verbatim as data.

The scan reads NetBox, LibreNMS and Wazuh and writes only Netsight's own finding store; it is single
flight and rate limited by the scanner's ``ScanGuard`` (shared with the scheduled scan): a scan
already running is a ``429 SCAN_BUSY`` with ``Retry-After``, one inside the minimum interval returns
the last result.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request

from netsight_api.audit import record_audit
from netsight_api.contracts import validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity
from netsight_api.schemas_unknown_devices import (
    UnknownDeviceAssignRequest,
    UnknownDeviceCommentRequest,
    UnknownDeviceEvent,
    UnknownDeviceFinding,
    UnknownDeviceResolveRequest,
    UnknownDeviceScanResponse,
    UnknownDeviceTransitionRequest,
)
from netsight_api.unknown_device_support import (
    LOGGER,
    WRITE_ERRORS,
    AcknowledgeActor,
    AssignActor,
    CommentActor,
    FindingId,
    InvestigateActor,
    ResolveActor,
    ScanActor,
    Scanner,
    Store,
    correlation_id,
    mutate,
)
from netsight_api.unknown_devices.audit_keys import keyed_fingerprint
from netsight_api.unknown_devices.scanner import ScanBusy, ScanResult

router = APIRouter(prefix="/unknown-devices", tags=["unknown-devices"])


# --- the scan -----------------------------------------------------------------------------------------------


def _scan_response(result: ScanResult) -> UnknownDeviceScanResponse:
    return UnknownDeviceScanResponse(
        state=result.state,
        generated_at=result.generated_at,
        sources=list(result.sources),
        created=result.created,
        refreshed=result.refreshed,
        suppressed=result.suppressed,
        unverified=result.unverified,
        truncated=result.truncated,
        incomplete_sources=list(result.incomplete_sources),
    )


def _audit_scan(
    action: str, identity: Identity, request: Request, body: UnknownDeviceScanResponse
) -> None:
    record_audit(
        action,
        outcome="success",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        state=body.state,
        created=body.created,
        refreshed=body.refreshed,
        suppressed=body.suppressed,
        unverified=body.unverified,
        truncated=body.truncated,
        incomplete=",".join(body.incomplete_sources),
    )


def _failure(identity: Identity, request: Request, reason: str, error: ApiError) -> ApiError:
    record_audit(
        "unknown-device.scan",
        outcome="failure",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        reason=reason,
    )
    return error


@router.post(
    "/scan",
    response_model=UnknownDeviceScanResponse,
    responses={**WRITE_ERRORS},
    operation_id="scanUnknownDevices",
)
async def scan(
    request: Request, identity: ScanActor, store: Store, scanner: Scanner
) -> UnknownDeviceScanResponse:
    """Compare discovered telemetry with NetBox now and record what NetBox does not know.

    Reads NetBox, LibreNMS and Wazuh; writes only Netsight's own finding store; never NetBox.
    """
    if store is None or scanner is None:
        raise _failure(
            identity,
            request,
            "STORE_NOT_CONNECTED",
            ApiError(503, "STORE_NOT_CONNECTED", "Finding storage is not connected"),
        )
    try:
        result: ScanResult = await scanner.scan()
    except ScanBusy as busy:
        raise _failure(
            identity,
            request,
            "SCAN_BUSY",
            ApiError(
                429,
                "SCAN_BUSY",
                "A scan is already running; try again shortly",
                headers={"Retry-After": str(busy.retry_after)},
            ),
        ) from None
    except Exception as exc:  # noqa: BLE001 - deliberate source/store boundary; never leaked
        LOGGER.warning(
            "unknown-device scan failed",
            extra={"correlation_id": correlation_id(request), "error_type": type(exc).__name__},
        )
        raise _failure(
            identity,
            request,
            "SCAN_FAILED",
            ApiError(503, "SCAN_FAILED", "The scan could not be completed"),
        ) from None
    body = _scan_response(result)
    validate("unknown_device_scan", json.loads(body.model_dump_json(by_alias=True)))
    _audit_scan("unknown-device.scan", identity, request, body)
    return body


# --- the workflow -------------------------------------------------------------------------------------------


@router.post(
    "/{finding_id}/acknowledge",
    response_model=UnknownDeviceFinding,
    responses=WRITE_ERRORS,
    operation_id="acknowledgeUnknownDevice",
)
async def acknowledge(
    request: Request,
    finding_id: FindingId,
    body: UnknownDeviceTransitionRequest,
    identity: AcknowledgeActor,
    store: Store,
) -> UnknownDeviceFinding:
    """new -> acknowledged. A second acknowledgement loses with 409."""
    actor = identity.id
    return await mutate(
        request,
        store,
        identity,
        action="unknown-device.acknowledge",
        finding_id=finding_id,
        operation=lambda s: s.transition_state(
            finding_id,
            to_state="acknowledged",
            actor_id=actor,
            expected_evidence_version=body.expected_evidence_version,
        ),
        to_state="acknowledged",
    )


@router.post(
    "/{finding_id}/investigate",
    response_model=UnknownDeviceFinding,
    responses=WRITE_ERRORS,
    operation_id="investigateUnknownDevice",
)
async def investigate(
    request: Request,
    finding_id: FindingId,
    body: UnknownDeviceTransitionRequest,
    identity: InvestigateActor,
    store: Store,
) -> UnknownDeviceFinding:
    """acknowledged -> investigating."""
    actor = identity.id
    return await mutate(
        request,
        store,
        identity,
        action="unknown-device.investigate",
        finding_id=finding_id,
        operation=lambda s: s.transition_state(
            finding_id,
            to_state="investigating",
            actor_id=actor,
            expected_evidence_version=body.expected_evidence_version,
        ),
        to_state="investigating",
    )


def _assignee_details(assignee_id: str | None) -> dict[str, object]:
    """What the audit may say about an assignee: that one was set, how long, a keyed fingerprint."""
    if assignee_id is None:
        return {"assignee_cleared": True}
    details: dict[str, object] = {"assignee_length": len(assignee_id)}
    fingerprint = keyed_fingerprint("assignee", assignee_id)
    if fingerprint is not None:  # no usable key: omitted, never a plain (reversible) hash
        details["assignee_fp"] = fingerprint
    return details


@router.post(
    "/{finding_id}/assign",
    response_model=UnknownDeviceFinding,
    responses=WRITE_ERRORS,
    operation_id="assignUnknownDevice",
)
async def assign(
    request: Request,
    finding_id: FindingId,
    body: UnknownDeviceAssignRequest,
    identity: AssignActor,
    store: Store,
) -> UnknownDeviceFinding:
    """Assign to an identity, or unassign with null."""
    actor = identity.id
    return await mutate(
        request,
        store,
        identity,
        action="unknown-device.assign",
        finding_id=finding_id,
        operation=lambda s: s.set_assignee(
            finding_id,
            assignee_id=body.assignee_id,
            actor_id=actor,
            expected_evidence_version=body.expected_evidence_version,
        ),
        **_assignee_details(body.assignee_id),
    )


@router.post(
    "/{finding_id}/comment",
    response_model=UnknownDeviceEvent,
    status_code=201,
    responses=WRITE_ERRORS,
    operation_id="commentUnknownDevice",
)
async def comment(
    request: Request,
    finding_id: FindingId,
    body: UnknownDeviceCommentRequest,
    identity: CommentActor,
    store: Store,
) -> UnknownDeviceEvent:
    """Append a comment; the text is stored and returned verbatim as data."""
    actor = identity.id
    return await mutate(
        request,
        store,
        identity,
        action="unknown-device.comment",
        finding_id=finding_id,
        operation=lambda s: s.add_comment(finding_id, actor_id=actor, message=body.message),
        comment_length=len(body.message),
    )


@router.post(
    "/{finding_id}/resolve",
    response_model=UnknownDeviceFinding,
    responses=WRITE_ERRORS,
    operation_id="resolveUnknownDevice",
)
async def resolve(
    request: Request,
    finding_id: FindingId,
    body: UnknownDeviceResolveRequest,
    identity: ResolveActor,
    store: Store,
) -> UnknownDeviceFinding:
    """Resolve, or dismiss as a false positive (which suppresses later sightings); needs step-up."""
    actor = identity.id
    return await mutate(
        request,
        store,
        identity,
        action="unknown-device.resolve",
        finding_id=finding_id,
        operation=lambda s: s.transition_state(
            finding_id,
            to_state=body.outcome,
            actor_id=actor,
            reason=body.reason,
            expected_evidence_version=body.expected_evidence_version,
        ),
        outcome_state=body.outcome,
        reason_length=len(body.reason),
    )
