"""Unknown-device routes (Step 8c): findings, their workflow and an on-demand scan.

Reads need ``unknown-devices:read`` (rows, detail, timeline) or ``unknown-devices:read-summary``
(counts only: Technician and Management). Every write is a human judgement, so each one is
human-only, and goes through the same gates as the incident writes, in this order:

1. authentication (401), then authorisation (403, deny-by-default, audited);
2. CSRF token and origin allow-list for cookie sessions (403, audited);
3. a recent second factor for the one write that can silence a detection (resolve or dismiss as a
   false positive: ``403 STEP_UP_REQUIRED``, decided after CSRF and before the limiter, audited);
4. a per-identity write budget (429, audited).

The store is the PostgreSQL application-role connection (``DATABASE_URL``). Without it reads answer
``not-connected`` and writes 503; a failing store is ``unknown`` on reads and 503 on writes, never a
connection string or driver message. Storage outcomes map to HTTP: not found 404, illegal transition
or lost race 409, invalid request 422, unavailable 503. Every mutation, refused ones included, is
audited from the worker thread right after the store call, with the actor, the target and static
details (lengths and states, a hash of an assignee), never the comment, reason or assignee text.

There is no route that executes, approves or even creates an isolation: a quarantine is a
``proposed_action`` the scanner records and nothing here (or anywhere in this release) can carry out.
Free text is stored and returned verbatim as data.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Annotated, Any, Final, get_args

from fastapi import APIRouter, Depends, Path, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from netsight_api.audit import AuditOutcome, fingerprint, record_audit
from netsight_api.auth.csrf import write_refusal
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.step_up import step_up_refusal
from netsight_api.contracts import ContractViolation, validate
from netsight_api.errors import ApiError
from netsight_api.inventory.wiring import utc_now
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_query import QueryError, boolean, integer, single_values, word
from netsight_api.read_support import CurrentIdentity, no_store, reader, rejected
from netsight_api.schemas import ErrorEnvelope
from netsight_api.schemas_inventory import BlockState
from netsight_api.schemas_unknown_devices import (
    FINDING_ID_PATTERN,
    OPEN_STATES,
    FindingState,
    Severity,
    UnknownDeviceAssignRequest,
    UnknownDeviceCommentRequest,
    UnknownDeviceDetailResponse,
    UnknownDeviceEvent,
    UnknownDeviceFinding,
    UnknownDeviceListResponse,
    UnknownDeviceResolveRequest,
    UnknownDeviceScanResponse,
    UnknownDeviceSummaryResponse,
    UnknownDeviceTimelineResponse,
)
from netsight_api.storage import (
    IllegalTransitionError,
    InvalidOperationError,
    NotFoundError,
    StorageConflictError,
    StorageError,
)
from netsight_api.storage.unknown_devices import UnknownDeviceRepository
from netsight_api.traffic import audit_trail
from netsight_api.unknown_devices.scanner import ScanResult
from netsight_api.unknown_devices.wiring import build_scanner, get_optional_store

_LOGGER: Final = logging.getLogger("netsight_api")

router = APIRouter(prefix="/unknown-devices", tags=["unknown-devices"])

LIST_LIMIT_PER_MINUTE: Final = 120
DETAIL_LIMIT_PER_MINUTE: Final = 120
SUMMARY_LIMIT_PER_MINUTE: Final = 60
# Per identity and minute. A runaway client or a compromised session cannot flood a finding's
# timeline; one operator working through the findings stays far below it.
WRITE_LIMIT_PER_MINUTE: Final = 60
# A scan reads NetBox, LibreNMS and Wazuh, so it has a much smaller budget than a note.
SCAN_LIMIT_PER_MINUTE: Final = 6
_WINDOW_SECONDS: Final = 60.0
_write_limiter = RateLimiter()
_scan_limiter = RateLimiter()
DEFAULT_PAGE_SIZE: Final = 25
MAX_PAGE_SIZE: Final = 50
MAX_TIMELINE_LIMIT: Final = 200
_LIST_PARAMETERS: Final = frozenset({"page", "page_size", "state", "severity", "assigned"})
_TIMELINE_PARAMETERS: Final = frozenset({"after_seq", "limit"})
_STATE_FILTERS: Final = (*get_args(FindingState), "open")
_ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    404: {"model": ErrorEnvelope, "description": "Finding not found"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
    429: {"model": ErrorEnvelope, "description": "Rate limit exceeded"},
}
_WRITE_ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    **_ERRORS,
    409: {"model": ErrorEnvelope, "description": "Illegal transition or concurrent change"},
    503: {"model": ErrorEnvelope, "description": "Finding store not connected or unavailable"},
}

FindingId = Annotated[str, Path(min_length=51, max_length=51, pattern=FINDING_ID_PATTERN)]
OptionalStore = Annotated[UnknownDeviceRepository | None, Depends(get_optional_store)]


def get_unknown_device_store() -> UnknownDeviceRepository | None:
    """The finding store (tests override this); ``None`` means not-connected."""
    return get_optional_store()


def get_unknown_device_scanner() -> Any:
    """The scanner over the configured store (tests override this)."""
    store = get_optional_store()
    return build_scanner(store) if store is not None else None


Store = Annotated[UnknownDeviceRepository | None, Depends(get_unknown_device_store)]
Scanner = Annotated[Any, Depends(get_unknown_device_scanner)]


# --- authorisation, CSRF, step-up, budgets ------------------------------------------------------------------


def _list_reader() -> Callable[..., Identity]:
    return reader(
        Permission.UNKNOWN_DEVICES_READ,
        "unknown-device.list.read",
        "unknown-devices",
        lambda: LIST_LIMIT_PER_MINUTE,
    )


ListReader = Annotated[Identity, Depends(_list_reader())]
DetailReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.UNKNOWN_DEVICES_READ,
            "unknown-device.item.read",
            "unknown-device",
            lambda: DETAIL_LIMIT_PER_MINUTE,
        )
    ),
]
TimelineReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.UNKNOWN_DEVICES_READ,
            "unknown-device.timeline.read",
            "unknown-device-timeline",
            lambda: DETAIL_LIMIT_PER_MINUTE,
        )
    ),
]
SummaryReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.UNKNOWN_DEVICES_READ_SUMMARY,
            "unknown-device.summary.read",
            "unknown-device-summary",
            lambda: SUMMARY_LIMIT_PER_MINUTE,
        )
    ),
]


def _correlation_id(request: Request) -> str:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else "unknown"


def _refuse(
    request: Request, action: str, identity: Identity, reason: str, target: str | None
) -> None:
    record_audit(
        action,
        outcome="denied",
        actor_id=identity.id,
        correlation_id=_correlation_id(request),
        target=target,
        reason=reason,
    )


def _guards(
    request: Request,
    identity: Identity,
    permission: Permission,
    action: str,
    target: str | None,
    *,
    step_up: bool,
    limiter: RateLimiter,
    limit: int,
) -> None:
    """Authorise, CSRF/origin, optional step-up, then spend one write from the budget (in that order)."""
    if not is_allowed(identity, permission.value):
        _refuse(request, action, identity, "permission", target)
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    refusal = write_refusal(request, identity)
    if refusal is not None:
        _refuse(request, action, identity, refusal.reason, target)
        raise ApiError(403, refusal.code, refusal.message)
    if step_up:
        refusal = step_up_refusal(request)
        if refusal is not None:
            _refuse(request, action, identity, refusal.reason, target)
            raise ApiError(403, refusal.code, refusal.message)
    if not limiter.allow(identity.id, limit, _WINDOW_SECONDS):
        _refuse(request, action, identity, "rate-limit", target)
        raise ApiError(429, "RATE_LIMITED", "Too many changes; slow down")


def finding_writer(
    permission: Permission, *, action: str, step_up: bool = False
) -> Callable[..., Identity]:
    def dependency(request: Request, identity: CurrentIdentity, finding_id: FindingId) -> Identity:
        # ``finding_id`` is declared so FastAPI validates it first: a malformed id never reaches
        # the audit log or the store.
        _guards(
            request,
            identity,
            permission,
            action,
            finding_id,
            step_up=step_up,
            limiter=_write_limiter,
            limit=WRITE_LIMIT_PER_MINUTE,
        )
        return identity

    return dependency


def _scan_writer(request: Request, identity: CurrentIdentity) -> Identity:
    _guards(
        request,
        identity,
        Permission.UNKNOWN_DEVICES_SCAN,
        "unknown-device.scan",
        None,
        step_up=False,
        limiter=_scan_limiter,
        limit=SCAN_LIMIT_PER_MINUTE,
    )
    return identity


AcknowledgeActor = Annotated[
    Identity,
    Depends(
        finding_writer(Permission.UNKNOWN_DEVICES_ACKNOWLEDGE, action="unknown-device.acknowledge")
    ),
]
InvestigateActor = Annotated[
    Identity,
    Depends(
        finding_writer(Permission.UNKNOWN_DEVICES_ACKNOWLEDGE, action="unknown-device.investigate")
    ),
]
AssignActor = Annotated[
    Identity,
    Depends(finding_writer(Permission.UNKNOWN_DEVICES_ASSIGN, action="unknown-device.assign")),
]
CommentActor = Annotated[
    Identity,
    Depends(finding_writer(Permission.UNKNOWN_DEVICES_COMMENT, action="unknown-device.comment")),
]
ResolveActor = Annotated[
    Identity,
    Depends(
        finding_writer(
            Permission.UNKNOWN_DEVICES_RESOLVE, action="unknown-device.resolve", step_up=True
        )
    ),
]
ScanActor = Annotated[Identity, Depends(_scan_writer)]


# --- error translation and the audited mutation --------------------------------------------------------------


class _AuditedFailure(Exception):
    """A store failure already mapped and audited in the worker thread."""

    def __init__(self, error: ApiError, cause: Exception) -> None:
        super().__init__(error.code)
        self.error = error
        self.cause_type = type(cause).__name__


def _translate(exc: Exception) -> tuple[ApiError, AuditOutcome, str]:
    if isinstance(exc, NotFoundError):
        return ApiError(404, "NOT_FOUND", "Finding was not found"), "failure", "NOT_FOUND"
    if isinstance(exc, IllegalTransitionError):
        return ApiError(409, "ILLEGAL_TRANSITION", str(exc)), "failure", "ILLEGAL_TRANSITION"
    if isinstance(exc, StorageConflictError):
        error = ApiError(409, "CONFLICT", "The finding was changed concurrently; reload and retry")
        return error, "failure", "CONFLICT"
    if isinstance(exc, InvalidOperationError):
        return ApiError(422, "INVALID_OPERATION", str(exc)), "failure", "INVALID_OPERATION"
    if isinstance(exc, ValidationError):
        return (
            ApiError(422, "VALIDATION_ERROR", "Request validation failed"),
            "failure",
            "VALIDATION_ERROR",
        )
    if isinstance(exc, StorageError):
        error = ApiError(503, "STORE_UNAVAILABLE", "Finding storage is temporarily unavailable")
        return error, "failure", "STORE_UNAVAILABLE"
    return ApiError(500, "INTERNAL_ERROR", "An internal error occurred"), "failure", "INTERNAL"


async def _mutate[T](
    request: Request,
    store: UnknownDeviceRepository | None,
    identity: Identity,
    *,
    action: str,
    finding_id: str | None,
    operation: Callable[[UnknownDeviceRepository], T],
    **details: object,
) -> T:
    """Run one store mutation off the event loop and audit its outcome from the worker thread.

    ``run_in_threadpool`` is not cancellable, so the thread always runs to completion; auditing there
    (not after the ``await``) means a client that disconnects mid-request cannot make a committed
    write unaudited.
    """
    correlation_id = _correlation_id(request)

    def audit(outcome: AuditOutcome, **extra: object) -> None:
        record_audit(
            action,
            outcome=outcome,
            actor_id=identity.id,
            correlation_id=correlation_id,
            target=finding_id,
            **details,
            **extra,
        )

    if store is None:
        audit("failure", reason="STORE_NOT_CONNECTED")
        raise ApiError(503, "STORE_NOT_CONNECTED", "Finding storage is not connected")
    repository = store

    def work() -> T:
        try:
            result = operation(repository)
        except Exception as exc:  # noqa: BLE001 - deliberate store boundary; mapped here
            error, outcome, reason = _translate(exc)
            audit(outcome, reason=reason)
            raise _AuditedFailure(error, exc) from None
        audit("success")
        return result

    try:
        return await run_in_threadpool(work)
    except _AuditedFailure as failure:
        if failure.error.status_code >= 500:
            _LOGGER.warning(
                "finding write failed",
                extra={"correlation_id": correlation_id, "error_type": failure.cause_type},
            )
        raise failure.error from None


# --- reads ------------------------------------------------------------------------------------------------------


def _checked[
    M: UnknownDeviceListResponse
    | UnknownDeviceDetailResponse
    | UnknownDeviceSummaryResponse
    | UnknownDeviceTimelineResponse
](schema: str, body: M) -> M | None:
    try:
        validate(schema, json.loads(body.model_dump_json(by_alias=True)))
    except ContractViolation:
        _LOGGER.error("finding response failed its canonical contract")
        return None
    return body


def _log_read_failure(request: Request, exc: Exception) -> None:
    _LOGGER.warning(
        "finding store read failed",
        extra={"correlation_id": _correlation_id(request), "error_type": type(exc).__name__},
    )


@router.get(
    "",
    response_model=UnknownDeviceListResponse,
    responses=_ERRORS,
    operation_id="listUnknownDevices",
)
async def list_findings(
    request: Request, response: Response, identity: ListReader, store: Store
) -> UnknownDeviceListResponse:
    """Findings, newest sighting first, filtered and paged on the server."""
    action = "unknown-device.list.read"
    no_store(response)
    try:
        values = single_values(request, _LIST_PARAMETERS)
        page = integer(values, "page", 1, 1, 100_000)
        page_size = integer(values, "page_size", DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE)
        state = word(values, "state", _STATE_FILTERS)
        severity: Severity | None = word(values, "severity", get_args(Severity))
        assigned = boolean(values, "assigned")
    except QueryError:
        raise rejected(request, identity, action) from None
    states = None if state is None else (list(OPEN_STATES) if state == "open" else [state])
    now = utc_now()

    def empty(kind: BlockState) -> UnknownDeviceListResponse:
        return UnknownDeviceListResponse(
            state=kind, generated_at=now, page=page, page_size=page_size, total=0, items=[]
        )

    if store is None:
        body = empty("not-connected")
    else:
        repository = store
        try:
            rows, total = await run_in_threadpool(
                lambda: repository.list_findings(
                    states=states,
                    severity=severity,
                    assigned=assigned,
                    limit=page_size,
                    offset=(page - 1) * page_size,
                )
            )
            body = _checked(
                "unknown_device_list",
                UnknownDeviceListResponse(
                    state="ok",
                    generated_at=now,
                    page=page,
                    page_size=page_size,
                    total=total,
                    items=rows,
                ),
            ) or empty("unknown")
        except Exception as exc:  # noqa: BLE001 - deliberate store/contract boundary
            _log_read_failure(request, exc)
            body = empty("unknown")
    filters = [
        n
        for n, v in (("state", state), ("severity", severity), ("assigned", assigned))
        if v is not None
    ]
    audit_trail.read(
        request,
        identity.id,
        action,
        state=body.state,
        returned=len(body.items),
        total=body.total,
        filters=",".join(filters),
    )
    return body


@router.get(
    "/summary",
    response_model=UnknownDeviceSummaryResponse,
    responses=_ERRORS,
    operation_id="getUnknownDevicesSummary",
)
async def summary(
    request: Request, response: Response, identity: SummaryReader, store: Store
) -> UnknownDeviceSummaryResponse:
    """Counts by state and severity: no ids, endpoints or assignees (Technician and Management)."""
    action = "unknown-device.summary.read"
    no_store(response)
    if request.query_params:
        raise rejected(request, identity, action)
    now = utc_now()
    body = UnknownDeviceSummaryResponse(state="not-connected", generated_at=now, counts=None)
    if store is not None:
        repository = store
        try:
            counts = await run_in_threadpool(repository.counts)
            body = _checked(
                "unknown_device_summary",
                UnknownDeviceSummaryResponse(state="ok", generated_at=now, counts=counts),
            ) or UnknownDeviceSummaryResponse(state="unknown", generated_at=now, counts=None)
        except Exception as exc:  # noqa: BLE001 - deliberate store boundary
            _log_read_failure(request, exc)
            body = UnknownDeviceSummaryResponse(state="unknown", generated_at=now, counts=None)
    audit_trail.read(request, identity.id, action, state=body.state)
    return body


@router.get(
    "/{finding_id}",
    response_model=UnknownDeviceDetailResponse,
    responses=_ERRORS,
    operation_id="getUnknownDevice",
)
async def get_finding(
    request: Request,
    response: Response,
    finding_id: FindingId,
    identity: DetailReader,
    store: Store,
) -> UnknownDeviceDetailResponse:
    """One finding; an unknown id is a 404, never a fabricated record."""
    action = "unknown-device.item.read"
    no_store(response)
    if request.query_params:
        raise rejected(request, identity, action)
    now = utc_now()
    if store is None:
        body = UnknownDeviceDetailResponse(state="not-connected", generated_at=now, item=None)
    else:
        repository = store
        try:
            item = await run_in_threadpool(repository.get_finding, finding_id)
        except Exception as exc:  # noqa: BLE001 - deliberate store boundary
            _log_read_failure(request, exc)
            item = None
            body = UnknownDeviceDetailResponse(state="unknown", generated_at=now, item=None)
        else:
            if item is None:
                audit_trail.failed(request, identity.id, action, "not-found")
                raise ApiError(404, "NOT_FOUND", "Finding was not found")
            body = _checked(
                "unknown_device_detail",
                UnknownDeviceDetailResponse(state="ok", generated_at=now, item=item),
            ) or UnknownDeviceDetailResponse(state="unknown", generated_at=now, item=None)
    audit_trail.read(request, identity.id, action, state=body.state, target=finding_id)
    return body


@router.get(
    "/{finding_id}/timeline",
    response_model=UnknownDeviceTimelineResponse,
    responses=_ERRORS,
    operation_id="getUnknownDeviceTimeline",
)
async def get_timeline(
    request: Request,
    response: Response,
    finding_id: FindingId,
    identity: TimelineReader,
    store: Store,
) -> UnknownDeviceTimelineResponse:
    """The append-only timeline in order, bounded per page."""
    action = "unknown-device.timeline.read"
    no_store(response)
    try:
        values = single_values(request, _TIMELINE_PARAMETERS)
        after_seq = integer(values, "after_seq", 0, 0, 1_000_000)
        limit = integer(values, "limit", MAX_TIMELINE_LIMIT, 1, MAX_TIMELINE_LIMIT)
    except QueryError:
        raise rejected(request, identity, action) from None
    now = utc_now()

    def empty(kind: BlockState) -> UnknownDeviceTimelineResponse:
        return UnknownDeviceTimelineResponse(
            state=kind,
            generated_at=now,
            finding_id=finding_id,
            events=[],
            after_seq=after_seq,
            next_after_seq=None,
        )

    if store is None:
        body = empty("not-connected")
    else:
        repository = store
        try:
            events: list[UnknownDeviceEvent] = await run_in_threadpool(
                lambda: repository.list_timeline(finding_id, after_seq=after_seq, limit=limit)
            )
            body = _checked(
                "unknown_device_timeline",
                UnknownDeviceTimelineResponse(
                    state="ok",
                    generated_at=now,
                    finding_id=finding_id,
                    events=events,
                    after_seq=after_seq,
                    next_after_seq=events[-1].seq if events and len(events) == limit else None,
                ),
            ) or empty("unknown")
        except NotFoundError:
            audit_trail.failed(request, identity.id, action, "not-found")
            raise ApiError(404, "NOT_FOUND", "Finding was not found") from None
        except Exception as exc:  # noqa: BLE001 - deliberate store boundary
            _log_read_failure(request, exc)
            body = empty("unknown")
    audit_trail.read(
        request, identity.id, action, state=body.state, target=finding_id, returned=len(body.events)
    )
    return body


# --- writes -------------------------------------------------------------------------------------------------------


@router.post(
    "/scan",
    response_model=UnknownDeviceScanResponse,
    responses={**_WRITE_ERRORS},
    operation_id="scanUnknownDevices",
)
async def scan(
    request: Request, identity: ScanActor, store: Store, scanner: Scanner
) -> UnknownDeviceScanResponse:
    """Compare discovered telemetry with NetBox now and record what NetBox does not know.

    Reads NetBox, LibreNMS and Wazuh; writes only Netsight's own finding store; never NetBox.
    """
    action = "unknown-device.scan"
    correlation_id = _correlation_id(request)

    def fail(reason: str, error: ApiError) -> ApiError:
        record_audit(
            action,
            outcome="failure",
            actor_id=identity.id,
            correlation_id=correlation_id,
            reason=reason,
        )
        return error

    if store is None or scanner is None:
        raise fail(
            "STORE_NOT_CONNECTED",
            ApiError(503, "STORE_NOT_CONNECTED", "Finding storage is not connected"),
        )
    try:
        result: ScanResult = await scanner.scan()
    except Exception as exc:  # noqa: BLE001 - deliberate source/store boundary; never leaked
        _LOGGER.warning(
            "unknown-device scan failed",
            extra={"correlation_id": correlation_id, "error_type": type(exc).__name__},
        )
        raise fail(
            "SCAN_FAILED", ApiError(503, "SCAN_FAILED", "The scan could not be completed")
        ) from None
    body = UnknownDeviceScanResponse(
        state=result.state,
        generated_at=result.generated_at,
        sources=list(result.sources),
        created=result.created,
        refreshed=result.refreshed,
        suppressed=result.suppressed,
        unverified=result.unverified,
        truncated=result.truncated,
    )
    validate("unknown_device_scan", json.loads(body.model_dump_json(by_alias=True)))
    record_audit(
        action,
        outcome="success",
        actor_id=identity.id,
        correlation_id=correlation_id,
        state=body.state,
        created=body.created,
        refreshed=body.refreshed,
        suppressed=body.suppressed,
        unverified=body.unverified,
        truncated=body.truncated,
    )
    return body


@router.post(
    "/{finding_id}/acknowledge",
    response_model=UnknownDeviceFinding,
    responses=_WRITE_ERRORS,
    operation_id="acknowledgeUnknownDevice",
)
async def acknowledge(
    request: Request, finding_id: FindingId, identity: AcknowledgeActor, store: Store
) -> UnknownDeviceFinding:
    """new -> acknowledged. A second acknowledgement loses with 409."""
    actor = identity.id
    return await _mutate(
        request,
        store,
        identity,
        action="unknown-device.acknowledge",
        finding_id=finding_id,
        operation=lambda s: s.transition_state(finding_id, to_state="acknowledged", actor_id=actor),
        to_state="acknowledged",
    )


@router.post(
    "/{finding_id}/investigate",
    response_model=UnknownDeviceFinding,
    responses=_WRITE_ERRORS,
    operation_id="investigateUnknownDevice",
)
async def investigate(
    request: Request, finding_id: FindingId, identity: InvestigateActor, store: Store
) -> UnknownDeviceFinding:
    """acknowledged -> investigating."""
    actor = identity.id
    return await _mutate(
        request,
        store,
        identity,
        action="unknown-device.investigate",
        finding_id=finding_id,
        operation=lambda s: s.transition_state(
            finding_id, to_state="investigating", actor_id=actor
        ),
        to_state="investigating",
    )


@router.post(
    "/{finding_id}/assign",
    response_model=UnknownDeviceFinding,
    responses=_WRITE_ERRORS,
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
    details: dict[str, object] = (
        {"assignee_cleared": True}
        if body.assignee_id is None
        else {
            "assignee_hash": fingerprint(body.assignee_id),
            "assignee_length": len(body.assignee_id),
        }
    )
    return await _mutate(
        request,
        store,
        identity,
        action="unknown-device.assign",
        finding_id=finding_id,
        operation=lambda s: s.set_assignee(
            finding_id, assignee_id=body.assignee_id, actor_id=actor
        ),
        **details,
    )


@router.post(
    "/{finding_id}/comment",
    response_model=UnknownDeviceEvent,
    status_code=201,
    responses=_WRITE_ERRORS,
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
    return await _mutate(
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
    responses=_WRITE_ERRORS,
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
    return await _mutate(
        request,
        store,
        identity,
        action="unknown-device.resolve",
        finding_id=finding_id,
        operation=lambda s: s.transition_state(
            finding_id, to_state=body.outcome, actor_id=actor, reason=body.reason
        ),
        outcome_state=body.outcome,
        reason_length=len(body.reason),
    )
