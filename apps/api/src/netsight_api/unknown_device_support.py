"""Shared parts of the unknown-device routes (Step 8c): dependencies, guards, errors, audited writes.

The routes are split by what they do: ``unknown_device_read_routes`` (rows, detail, timeline, counts),
``unknown_device_write_routes`` (the human workflow and the scan) and ``unknown_device_routes`` (the
router that mounts them). This module holds what both halves need so neither imports the other.

Every write goes through the same gates, in this order:

1. authentication (401), then authorisation (403, deny-by-default, audited);
2. CSRF token and origin allow-list for cookie sessions (403, audited);
3. a recent second factor for the one write that can silence a detection (resolve or dismiss as a
   false positive: ``403 STEP_UP_REQUIRED``, decided after CSRF and before the limiter, audited);
4. a per-identity write budget (429, audited).

The store is the PostgreSQL application-role connection (``DATABASE_URL``). Without it reads answer
``not-connected`` and writes 503; a failing store is ``unknown`` on reads and 503 on writes, never a
connection string or driver message. Storage outcomes map to HTTP: not found 404, illegal transition
or lost race 409, evidence changed since the person saw it 409 ``STALE_EVIDENCE``, invalid request
422, unavailable 503. Every mutation, refused ones included, is audited from the worker thread right
after the store call, with the actor, the target and static details (lengths and states, a keyed
fingerprint of an assignee), never the comment, reason or assignee text.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Annotated, Any, Final

from fastapi import Depends, Path, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from netsight_api.audit import AuditOutcome, record_audit
from netsight_api.auth.csrf import write_refusal
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.step_up import step_up_refusal
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_support import CurrentIdentity, reader
from netsight_api.schemas import ErrorEnvelope
from netsight_api.schemas_unknown_devices import FINDING_ID_PATTERN
from netsight_api.storage import (
    IllegalTransitionError,
    InvalidOperationError,
    NotFoundError,
    StaleEvidenceError,
    StorageConflictError,
    StorageError,
)
from netsight_api.storage.unknown_devices import UnknownDeviceRepository
from netsight_api.unknown_devices.wiring import build_scanner, get_optional_store

LOGGER: Final = logging.getLogger("netsight_api")

LIST_LIMIT_PER_MINUTE: Final = 120
DETAIL_LIMIT_PER_MINUTE: Final = 120
SUMMARY_LIMIT_PER_MINUTE: Final = 60
# Per identity and minute. A runaway client or a compromised session cannot flood a finding's
# timeline; one operator working through the findings stays far below it.
WRITE_LIMIT_PER_MINUTE: Final = 60
# A scan reads NetBox, LibreNMS and Wazuh, so it has a much smaller budget than a note. (On top of
# this budget, one scan runs at a time and at most one a minute: ``scanner.ScanGuard``.)
SCAN_LIMIT_PER_MINUTE: Final = 6
WINDOW_SECONDS: Final = 60.0
_write_limiter = RateLimiter()
_scan_limiter = RateLimiter()
DEFAULT_PAGE_SIZE: Final = 25
MAX_PAGE_SIZE: Final = 50
MAX_TIMELINE_LIMIT: Final = 200

ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    404: {"model": ErrorEnvelope, "description": "Finding not found"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
    429: {"model": ErrorEnvelope, "description": "Rate limit exceeded"},
}
WRITE_ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    **ERRORS,
    409: {
        "model": ErrorEnvelope,
        "description": "Illegal transition, concurrent change or stale evidence",
    },
    503: {"model": ErrorEnvelope, "description": "Finding store not connected or unavailable"},
}

FindingId = Annotated[str, Path(min_length=51, max_length=51, pattern=FINDING_ID_PATTERN)]


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


ListReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.UNKNOWN_DEVICES_READ,
            "unknown-device.list.read",
            "unknown-devices",
            lambda: LIST_LIMIT_PER_MINUTE,
        )
    ),
]
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


def correlation_id(request: Request) -> str:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else "unknown"


def _refuse(
    request: Request, action: str, identity: Identity, reason: str, target: str | None
) -> None:
    record_audit(
        action,
        outcome="denied",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
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
    if not limiter.allow(identity.id, limit, WINDOW_SECONDS):
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


def translate(exc: Exception) -> tuple[ApiError, AuditOutcome, str]:
    """The HTTP error, audit outcome and static audit reason for a storage failure."""
    if isinstance(exc, NotFoundError):
        return ApiError(404, "NOT_FOUND", "Finding was not found"), "failure", "NOT_FOUND"
    if isinstance(exc, IllegalTransitionError):
        return ApiError(409, "ILLEGAL_TRANSITION", str(exc)), "failure", "ILLEGAL_TRANSITION"
    if isinstance(exc, StaleEvidenceError):  # before the generic conflict: it is a kind of one
        error = ApiError(
            409, "STALE_EVIDENCE", "The evidence changed since you opened this finding; reload"
        )
        return error, "failure", "STALE_EVIDENCE"
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


def _auditor(
    action: str, identity: Identity, request: Request, finding_id: str | None, details: dict[str, Any]
) -> Callable[..., None]:
    request_correlation = correlation_id(request)

    def audit(outcome: AuditOutcome, **extra: object) -> None:
        record_audit(
            action,
            outcome=outcome,
            actor_id=identity.id,
            correlation_id=request_correlation,
            target=finding_id,
            **details,
            **extra,
        )

    return audit


async def mutate[T](
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
    audit = _auditor(action, identity, request, finding_id, details)
    if store is None:
        audit("failure", reason="STORE_NOT_CONNECTED")
        raise ApiError(503, "STORE_NOT_CONNECTED", "Finding storage is not connected")
    repository = store

    def work() -> T:
        try:
            result = operation(repository)
        except Exception as exc:  # noqa: BLE001 - deliberate store boundary; mapped here
            error, outcome, reason = translate(exc)
            audit(outcome, reason=reason)
            raise _AuditedFailure(error, exc) from None
        audit("success")
        return result

    try:
        return await run_in_threadpool(work)
    except _AuditedFailure as failure:
        if failure.error.status_code >= 500:
            LOGGER.warning(
                "finding write failed",
                extra={
                    "correlation_id": correlation_id(request),
                    "error_type": failure.cause_type,
                },
            )
        raise failure.error from None
