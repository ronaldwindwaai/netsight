"""Incident API (S6-2): read, acknowledge/transition, assign, comment, evidence, resolve, reopen.

Behaviour, in the order a request meets it:

* Authentication (401) then per-operation authorisation (403, deny-by-default, see
  ``rbac.py``): resolve and reopen additionally need a *human* principal, and the
  technician role ("Assigned" in RBAC-MATRIX.md) may only progress, comment on and attach
  evidence to incidents assigned to them.
* Cookie-authenticated writes must present the session CSRF token and come from an
  allow-listed origin when the browser labels them (403, ``auth/csrf.py``; the dev
  bridge needs the CSRF header too), then a per identity write rate limit applies (429).
* The incident store is the PostgreSQL app-role connection from ``DATABASE_URL``.
  Without it reads answer an explicit ``not-connected`` state and writes 503; a store
  failure is an explicit ``unknown`` on reads and 503 on writes. Neither ever leaks a
  connection string or driver message.
* Storage outcomes map to HTTP: not found 404, illegal transition and stale/lost
  concurrent write 409, invalid request 422, unavailable 503.
* Every mutation, including refused ones, emits an audit record (``audit.py``), written
  from the worker thread right after the store call so a client disconnect cannot lose
  it. The state machine is the optimistic-concurrency check: a transition is applied
  under a row lock only from the state it is legal from, so the loser of a race gets 409.
* The technician's assigned-incidents-only scope is enforced by the store under the same
  row lock as the write (``required_assignee``), never from a separate earlier read.
* All text a caller supplies (titles, comments, reasons, root causes) is stored and
  returned verbatim as data; nothing here interprets it.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any, NoReturn, cast

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from netsight_api.audit import AuditOutcome, fingerprint, record_audit
from netsight_api.auth.csrf import write_refusal
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.step_up import step_up_refusal
from netsight_api.contracts import validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
from netsight_api.schemas import (
    INCIDENT_ID_PATTERN,
    MAX_INCIDENT_LIST_OFFSET,
    MAX_INCIDENT_PAGE_SIZE,
    MAX_TIMELINE_PAGE_SIZE,
    MAX_TIMELINE_SEQ,
    ErrorEnvelope,
    Incident,
    IncidentAssignRequest,
    IncidentCommentRequest,
    IncidentDetailResponse,
    IncidentEvidenceRequest,
    IncidentListResponse,
    IncidentReopenRequest,
    IncidentResolveRequest,
    IncidentSeverity,
    IncidentState,
    IncidentSummary,
    IncidentSummaryListResponse,
    IncidentTimelineEvent,
    IncidentTimelineResponse,
    IncidentTransitionRequest,
    StoreState,
)
from netsight_api.storage import (
    IllegalTransitionError,
    IncidentRepository,
    InvalidOperationError,
    NotFoundError,
    ScopeViolationError,
    StorageConfigurationError,
    StorageConflictError,
    StorageError,
)

_LOGGER = logging.getLogger("netsight_api")

# Per identity and minute. A runaway client or a compromised session cannot flood the
# incident timeline; a single operator working an incident stays far below it.
WRITE_LIMIT_PER_MINUTE = 60
_WRITE_WINDOW_SECONDS = 60.0
_write_limiter = RateLimiter()

router = APIRouter(prefix="/incidents", tags=["incidents"])

_READ_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
}
_ITEM_READ_ERRORS: dict[int | str, dict[str, Any]] = {
    **_READ_ERRORS,
    404: {"model": ErrorEnvelope, "description": "Incident not found"},
}
_WRITE_ERRORS: dict[int | str, dict[str, Any]] = {
    **_ITEM_READ_ERRORS,
    409: {"model": ErrorEnvelope, "description": "Illegal transition or concurrent change"},
    429: {"model": ErrorEnvelope, "description": "Write rate limit exceeded"},
    503: {"model": ErrorEnvelope, "description": "Incident store not connected or unavailable"},
}
_STEP_UP_ERRORS: dict[int | str, dict[str, Any]] = {
    **_WRITE_ERRORS,
    403: {
        "model": ErrorEnvelope,
        "description": "Permission denied, or STEP_UP_REQUIRED: recent MFA is needed (sign in again)",
    },
}


# --- store wiring -----------------------------------------------------------------------------


class _UnavailableStore:
    """Stands in when ``DATABASE_URL`` is set but unusable: every call fails as unavailable."""

    def __getattr__(self, name: str) -> Callable[..., NoReturn]:
        def unavailable(*_args: object, **_kwargs: object) -> NoReturn:
            raise StorageError("the incident store is not usable")

        return unavailable


def get_optional_incident_store() -> IncidentRepository | None:
    """PostgreSQL store for the app role (``DATABASE_URL``); ``None`` means not-connected.

    Only the least-privilege application DSN is ever read here, never the migrator's.
    A configured-but-invalid DSN yields a store whose calls fail, so the endpoints degrade
    to explicit ``unknown`` (configured does not imply connected) without echoing it.
    """
    if not os.environ.get("DATABASE_URL", "").strip():
        return None
    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.postgres import PostgresIncidentRepository

    try:
        settings = PostgresSettings.from_env()
    except StorageConfigurationError:
        return cast(IncidentRepository, _UnavailableStore())
    return PostgresIncidentRepository(settings)


OptionalIncidentStore = Annotated[IncidentRepository | None, Depends(get_optional_incident_store)]
CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]
IncidentId = Annotated[str, Path(min_length=45, max_length=45, pattern=INCIDENT_ID_PATTERN)]


def _assignee_details(assignee_id: str | None) -> dict[str, object]:
    """Audit details for an assignment: a hash and length, never the identity value."""
    if assignee_id is None:
        return {"assignee_cleared": True}
    return {"assignee_hash": fingerprint(assignee_id), "assignee_length": len(assignee_id)}


def _correlation_id(request: Request) -> str:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else "unknown"


# --- authorisation, CSRF, rate limiting --------------------------------------------------------


def require_incident_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.INCIDENTS_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    enforce_read_limit(identity, "incidents")
    return identity


IncidentReader = Annotated[Identity, Depends(require_incident_reader)]


def require_incident_summary_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.INCIDENTS_READ_SUMMARY.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    enforce_read_limit(identity, "incidents")
    return identity


IncidentSummaryReader = Annotated[Identity, Depends(require_incident_summary_reader)]


@dataclass(frozen=True)
class IncidentActor:
    """An authorised writer. ``full_access`` False means assigned-incidents-only (technician)."""

    identity: Identity
    full_access: bool

    @property
    def required_assignee(self) -> str | None:
        """What the store must find on the locked row; None for the full roles."""
        return None if self.full_access else self.identity.id


def _audit_refusal(
    request: Request, action: str, identity: Identity, reason: str, incident_id: str
) -> None:
    """``incident_id`` is the validated path parameter, never the raw request value."""
    record_audit(
        action,
        outcome="denied",
        actor_id=identity.id,
        correlation_id=_correlation_id(request),
        target=incident_id,
        reason=reason,
    )


def _guard_write(request: Request, action: str, identity: Identity, incident_id: str) -> None:
    """CSRF token and origin checks (``auth/csrf.py``), failing closed, audited when refused."""
    refusal = write_refusal(request, identity)
    if refusal is not None:
        _audit_refusal(request, action, identity, refusal.reason, incident_id)
        raise ApiError(403, refusal.code, refusal.message)


def _guard_step_up(request: Request, action: str, identity: Identity, incident_id: str) -> None:
    """Recent-MFA check (``auth/step_up.py``); a distinct, audited 403 the UI can act on."""
    refusal = step_up_refusal(request)
    if refusal is not None:
        _audit_refusal(request, action, identity, refusal.reason, incident_id)
        raise ApiError(403, refusal.code, refusal.message)


def incident_writer(
    permission: Permission,
    *,
    action: str,
    assigned_scope: bool = False,
    step_up: bool = False,
) -> Callable[..., IncidentActor]:
    """Dependency: authorise, CSRF-check, optionally require step-up, then rate-limit.

    The order matters: a caller without the permission never learns anything about its MFA
    recency, and a request that fails CSRF never reaches the step-up decision.
    """

    def dependency(
        request: Request, identity: CurrentIdentity, incident_id: IncidentId
    ) -> IncidentActor:
        # ``incident_id`` is declared so FastAPI validates it before this runs: a malformed
        # id never reaches the audit log or the store.
        full_access = is_allowed(identity, permission.value)
        assigned_only = assigned_scope and is_allowed(
            identity, Permission.INCIDENTS_WRITE_ASSIGNED.value
        )
        if not (full_access or assigned_only):
            _audit_refusal(request, action, identity, "permission", incident_id)
            raise ApiError(403, "FORBIDDEN", "Permission is required")
        _guard_write(request, action, identity, incident_id)
        if step_up:
            _guard_step_up(request, action, identity, incident_id)
        if not _write_limiter.allow(identity.id, WRITE_LIMIT_PER_MINUTE, _WRITE_WINDOW_SECONDS):
            _audit_refusal(request, action, identity, "rate-limit", incident_id)
            raise ApiError(429, "RATE_LIMITED", "Too many incident changes; slow down")
        return IncidentActor(identity=identity, full_access=full_access)

    return dependency


_AcknowledgeActor = Annotated[
    IncidentActor,
    Depends(
        incident_writer(
            Permission.INCIDENTS_TRANSITION, action="incident.acknowledge", assigned_scope=True
        )
    ),
]
_TransitionActor = Annotated[
    IncidentActor,
    Depends(
        incident_writer(
            Permission.INCIDENTS_TRANSITION, action="incident.transition", assigned_scope=True
        )
    ),
]
_AssignActor = Annotated[
    IncidentActor,
    Depends(incident_writer(Permission.INCIDENTS_ASSIGN, action="incident.assign")),
]
_CommentActor = Annotated[
    IncidentActor,
    Depends(
        incident_writer(
            Permission.INCIDENTS_COMMENT, action="incident.comment", assigned_scope=True
        )
    ),
]
_EvidenceActor = Annotated[
    IncidentActor,
    Depends(
        incident_writer(
            Permission.INCIDENTS_COMMENT, action="incident.evidence", assigned_scope=True
        )
    ),
]
_ResolveActor = Annotated[
    IncidentActor,
    Depends(
        incident_writer(Permission.INCIDENTS_RESOLVE, action="incident.resolve", step_up=True)
    ),
]
_ReopenActor = Annotated[
    IncidentActor,
    Depends(incident_writer(Permission.INCIDENTS_REOPEN, action="incident.reopen", step_up=True)),
]


# --- error translation ----------------------------------------------------------------------------


class _AuditedFailure(Exception):
    """A store failure already mapped and audited in the worker thread."""

    def __init__(self, error: ApiError, cause: Exception) -> None:
        super().__init__(error.code)
        self.error = error
        self.cause_type = type(cause).__name__


def _translate(exc: Exception) -> tuple[ApiError, AuditOutcome, str]:
    """Map a store failure to (response error, audit outcome, audit reason code).

    Messages are fixed or come from the domain layer's own static texts; driver messages
    and connection strings never reach a response.
    """
    if isinstance(exc, ScopeViolationError):
        return ApiError(403, "FORBIDDEN", "Permission is required"), "denied", "scope"
    if isinstance(exc, NotFoundError):
        return ApiError(404, "NOT_FOUND", "Incident was not found"), "failure", "NOT_FOUND"
    if isinstance(exc, IllegalTransitionError):
        return ApiError(409, "ILLEGAL_TRANSITION", str(exc)), "failure", "ILLEGAL_TRANSITION"
    if isinstance(exc, StorageConflictError):
        error = ApiError(409, "CONFLICT", "The incident was changed concurrently; reload and retry")
        return error, "failure", "CONFLICT"
    if isinstance(exc, InvalidOperationError):
        return ApiError(422, "INVALID_OPERATION", str(exc)), "failure", "INVALID_OPERATION"
    if isinstance(exc, ValidationError):  # a plain ValueError is a bug, not a client error
        error = ApiError(422, "VALIDATION_ERROR", "Request validation failed")
        return error, "failure", "VALIDATION_ERROR"
    if isinstance(exc, StorageError):
        error = ApiError(503, "STORE_UNAVAILABLE", "Incident storage is temporarily unavailable")
        return error, "failure", "STORE_UNAVAILABLE"
    return ApiError(500, "INTERNAL_ERROR", "An internal error occurred"), "failure", "INTERNAL"


async def _mutate[T](
    request: Request,
    store: IncidentRepository | None,
    actor: IncidentActor,
    *,
    action: str,
    incident_id: str,
    operation: Callable[[IncidentRepository], T],
    **details: object,
) -> T:
    """Run one store mutation off the event loop and audit its outcome.

    The audit record is written by the worker thread itself, right after the store call
    returns or raises. ``run_in_threadpool`` is not cancellable, so the thread always
    runs to completion; auditing there (not after the ``await``) means a client that
    disconnects mid-request cannot make a committed write unaudited. Assigned scope is the
    store's job (``required_assignee`` under the row lock), not this function's.
    """
    correlation_id = _correlation_id(request)

    def audit(outcome: AuditOutcome, **extra: object) -> None:
        record_audit(
            action,
            outcome=outcome,
            actor_id=actor.identity.id,
            correlation_id=correlation_id,
            target=incident_id,
            **details,
            **extra,
        )

    if store is None:
        audit("failure", reason="STORE_NOT_CONNECTED")
        raise ApiError(503, "STORE_NOT_CONNECTED", "Incident storage is not connected")
    incident_store = store

    def work() -> T:
        try:
            result = operation(incident_store)
        except Exception as exc:  # noqa: BLE001 — deliberate store boundary; mapped here
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
                "incident write failed",
                extra={"correlation_id": correlation_id, "error_type": failure.cause_type},
            )
        raise failure.error from None


# --- reads ------------------------------------------------------------------------------------------


def _log_read_failure(request: Request, exc: Exception) -> None:
    _LOGGER.warning(
        "incident store read failed",
        extra={"correlation_id": _correlation_id(request), "error_type": type(exc).__name__},
    )


def _checked[
    M: IncidentListResponse
    | IncidentSummaryListResponse
    | IncidentDetailResponse
    | IncidentTimelineResponse
](name: str, body: M) -> M:
    """Canonical boundary validation applied on every successful return path."""
    validate(name, body.model_dump(mode="json", by_alias=True))
    return body


@router.get(
    "",
    response_model=IncidentListResponse,
    responses=_READ_ERRORS,
    operation_id="listIncidents",
)
async def list_incidents(
    request: Request,
    _identity: IncidentReader,
    store: OptionalIncidentStore,
    state: Annotated[IncidentState | None, Query()] = None,
    severity: Annotated[IncidentSeverity | None, Query()] = None,
    assignee_id: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_INCIDENT_PAGE_SIZE)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_INCIDENT_LIST_OFFSET)] = 0,
) -> IncidentListResponse:
    """Incidents newest first with an explicit store state.

    not-connected without a store; unknown when the read fails; ok only with stored
    incidents. ``next_offset`` is set when the page was full and the capped offset allows
    another page (a full final page yields one empty trailing page).
    """

    def empty(state_name: StoreState) -> IncidentListResponse:
        return _checked(
            "incident_list",
            IncidentListResponse(
                state=state_name,
                incidents=[],
                limit=limit,
                offset=offset,
                next_offset=None,
            ),
        )

    if store is None:
        return empty("not-connected")
    incident_store = store
    try:
        rows = await run_in_threadpool(
            lambda: incident_store.list_incidents(
                state=state,
                severity=severity,
                assignee_id=assignee_id,
                limit=limit,
                offset=offset,
            )
        )
        following = offset + limit
        more = len(rows) == limit and following <= MAX_INCIDENT_LIST_OFFSET
        return _checked(
            "incident_list",
            IncidentListResponse(
                state="ok",
                incidents=rows,
                limit=limit,
                offset=offset,
                next_offset=following if more else None,
            ),
        )
    except Exception as exc:  # noqa: BLE001 — deliberate store/contract boundary
        _log_read_failure(request, exc)
        return empty("unknown")


@router.get(
    "/summary",
    response_model=IncidentSummaryListResponse,
    responses=_READ_ERRORS,
    operation_id="listIncidentSummaries",
)
async def list_incident_summaries(
    request: Request,
    _identity: IncidentSummaryReader,
    store: OptionalIncidentStore,
    state: Annotated[IncidentState | None, Query()] = None,
    severity: Annotated[IncidentSeverity | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_INCIDENT_PAGE_SIZE)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_INCIDENT_LIST_OFFSET)] = 0,
) -> IncidentSummaryListResponse:
    """Management's reduced incident list (``incidents:read-summary``).

    Rows are projected from the stored incident into ``IncidentSummary`` here, so evidence
    ids, resolution text and the assignee identity never reach the response model. There is
    deliberately no assignee filter: it would let a summary reader probe who holds what.
    Declared before ``/{incident_id}`` so the static path is never read as an id.
    """

    def empty(state_name: StoreState) -> IncidentSummaryListResponse:
        return _checked(
            "incident_summary_list",
            IncidentSummaryListResponse(
                state=state_name, incidents=[], limit=limit, offset=offset, next_offset=None
            ),
        )

    if store is None:
        return empty("not-connected")
    incident_store = store
    try:
        rows = await run_in_threadpool(
            lambda: incident_store.list_incidents(
                state=state, severity=severity, assignee_id=None, limit=limit, offset=offset
            )
        )
        following = offset + limit
        more = len(rows) == limit and following <= MAX_INCIDENT_LIST_OFFSET
        return _checked(
            "incident_summary_list",
            IncidentSummaryListResponse(
                state="ok",
                incidents=[IncidentSummary.from_incident(row) for row in rows],
                limit=limit,
                offset=offset,
                next_offset=following if more else None,
            ),
        )
    except Exception as exc:  # noqa: BLE001 — deliberate store/contract boundary
        _log_read_failure(request, exc)
        return empty("unknown")


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    responses=_ITEM_READ_ERRORS,
    operation_id="getIncident",
)
async def get_incident(
    request: Request,
    incident_id: IncidentId,
    _identity: IncidentReader,
    store: OptionalIncidentStore,
) -> IncidentDetailResponse:
    """One incident; an unknown id is a 404, never a fabricated record."""
    if store is None:
        return _checked(
            "incident_detail", IncidentDetailResponse(state="not-connected", incident=None)
        )
    incident_store = store
    try:
        incident = await run_in_threadpool(incident_store.get_incident, incident_id)
    except Exception as exc:  # noqa: BLE001 — deliberate store boundary
        _log_read_failure(request, exc)
        return _checked("incident_detail", IncidentDetailResponse(state="unknown", incident=None))
    if incident is None:
        raise ApiError(404, "NOT_FOUND", "Incident was not found")
    return _checked("incident_detail", IncidentDetailResponse(state="ok", incident=incident))


@router.get(
    "/{incident_id}/timeline",
    response_model=IncidentTimelineResponse,
    responses=_ITEM_READ_ERRORS,
    operation_id="getIncidentTimeline",
)
async def get_incident_timeline(
    request: Request,
    incident_id: IncidentId,
    _identity: IncidentReader,
    store: OptionalIncidentStore,
    after_seq: Annotated[int, Query(ge=0, le=MAX_TIMELINE_SEQ)] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_TIMELINE_PAGE_SIZE)] = 200,
) -> IncidentTimelineResponse:
    """Append-only timeline in seq order, bounded per page."""

    def empty(state_name: StoreState) -> IncidentTimelineResponse:
        return _checked(
            "incident_timeline",
            IncidentTimelineResponse(
                state=state_name,
                incident_id=incident_id,
                events=[],
                after_seq=after_seq,
                next_after_seq=None,
            ),
        )

    if store is None:
        return empty("not-connected")
    incident_store = store
    try:
        events = await run_in_threadpool(
            lambda: incident_store.list_timeline(incident_id, after_seq=after_seq, limit=limit)
        )
        return _checked(
            "incident_timeline",
            IncidentTimelineResponse(
                state="ok",
                incident_id=incident_id,
                events=events,
                after_seq=after_seq,
                next_after_seq=events[-1].seq if events and len(events) == limit else None,
            ),
        )
    except NotFoundError:
        raise ApiError(404, "NOT_FOUND", "Incident was not found") from None
    except Exception as exc:  # noqa: BLE001 — deliberate store/contract boundary
        _log_read_failure(request, exc)
        return empty("unknown")


# --- writes -----------------------------------------------------------------------------------------


@router.post(
    "/{incident_id}/acknowledge",
    response_model=Incident,
    responses=_WRITE_ERRORS,
    operation_id="acknowledgeIncident",
)
async def acknowledge_incident(
    request: Request,
    incident_id: IncidentId,
    actor: _AcknowledgeActor,
    store: OptionalIncidentStore,
) -> Incident:
    """open -> acknowledged. A second acknowledgement loses with 409."""
    actor_id, scope = actor.identity.id, actor.required_assignee
    return await _mutate(
        request,
        store,
        actor,
        action="incident.acknowledge",
        incident_id=incident_id,
        operation=lambda s: s.transition_state(
            incident_id,
            to_state="acknowledged",
            actor_id=actor_id,
            required_assignee=scope,
        ),
        to_state="acknowledged",
    )


@router.post(
    "/{incident_id}/transition",
    response_model=Incident,
    responses=_WRITE_ERRORS,
    operation_id="transitionIncident",
)
async def transition_incident(
    request: Request,
    incident_id: IncidentId,
    body: IncidentTransitionRequest,
    actor: _TransitionActor,
    store: OptionalIncidentStore,
) -> Incident:
    """Advance one step: acknowledged, investigating, mitigated or closed.

    Closing is a lifecycle decision reserved for the full roles. Resolve and reopen are
    separate operations with human-only permissions.
    """
    actor_id, scope = actor.identity.id, actor.required_assignee
    if body.to_state == "closed" and not actor.full_access:
        _audit_refusal(request, "incident.transition", actor.identity, "permission", incident_id)
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    return await _mutate(
        request,
        store,
        actor,
        action="incident.transition",
        incident_id=incident_id,
        operation=lambda s: s.transition_state(
            incident_id,
            to_state=body.to_state,
            actor_id=actor_id,
            reason=body.reason,
            required_assignee=scope,
        ),
        to_state=body.to_state,
    )


@router.post(
    "/{incident_id}/assign",
    response_model=Incident,
    responses=_WRITE_ERRORS,
    operation_id="assignIncident",
)
async def assign_incident(
    request: Request,
    incident_id: IncidentId,
    body: IncidentAssignRequest,
    actor: _AssignActor,
    store: OptionalIncidentStore,
) -> Incident:
    """Assign to an identity, or unassign with null."""
    actor_id = actor.identity.id
    return await _mutate(
        request,
        store,
        actor,
        action="incident.assign",
        incident_id=incident_id,
        operation=lambda s: s.set_assignee(
            incident_id, assignee_id=body.assignee_id, actor_id=actor_id
        ),
        **_assignee_details(body.assignee_id),
    )


@router.post(
    "/{incident_id}/comment",
    response_model=IncidentTimelineEvent,
    status_code=201,
    responses=_WRITE_ERRORS,
    operation_id="commentIncident",
)
async def comment_incident(
    request: Request,
    incident_id: IncidentId,
    body: IncidentCommentRequest,
    actor: _CommentActor,
    store: OptionalIncidentStore,
) -> IncidentTimelineEvent:
    """Append a comment; the text is stored and returned verbatim as data."""
    actor_id, scope = actor.identity.id, actor.required_assignee
    return await _mutate(
        request,
        store,
        actor,
        action="incident.comment",
        incident_id=incident_id,
        operation=lambda s: s.append_event(
            incident_id,
            kind="comment",
            actor_id=actor_id,
            message=body.message,
            required_assignee=scope,
        ),
        comment_length=len(body.message),
    )


@router.post(
    "/{incident_id}/evidence",
    response_model=Incident,
    responses=_WRITE_ERRORS,
    operation_id="addIncidentEvidence",
)
async def add_incident_evidence(
    request: Request,
    incident_id: IncidentId,
    body: IncidentEvidenceRequest,
    actor: _EvidenceActor,
    store: OptionalIncidentStore,
) -> Incident:
    """Attach an evidence reference; re-adding the same reference changes nothing."""
    actor_id, scope = actor.identity.id, actor.required_assignee
    return await _mutate(
        request,
        store,
        actor,
        action="incident.evidence",
        incident_id=incident_id,
        operation=lambda s: s.add_evidence(
            incident_id,
            evidence_id=body.evidence_id,
            actor_id=actor_id,
            required_assignee=scope,
        ),
        evidence_hash=fingerprint(body.evidence_id),
        evidence_length=len(body.evidence_id),
    )


@router.post(
    "/{incident_id}/resolve",
    response_model=Incident,
    responses=_STEP_UP_ERRORS,
    operation_id="resolveIncident",
)
async def resolve_incident(
    request: Request,
    incident_id: IncidentId,
    body: IncidentResolveRequest,
    actor: _ResolveActor,
    store: OptionalIncidentStore,
) -> Incident:
    """mitigated -> resolved with a mandatory resolution; human principals only.

    The resolution (summary, root cause or "not-determined", impact, restoration time,
    follow-ups) is what the authenticated operator submits; resolved_by is the session
    identity, never a client-supplied value.
    """
    actor_id = actor.identity.id
    return await _mutate(
        request,
        store,
        actor,
        action="incident.resolve",
        incident_id=incident_id,
        # Re-validated inside the audited boundary: a failure is a 422 with an audit record.
        operation=lambda s: s.transition_state(
            incident_id, to_state="resolved", actor_id=actor_id, resolution=body.to_resolution()
        ),
        root_cause_status=body.root_cause_status,
    )


@router.post(
    "/{incident_id}/reopen",
    response_model=Incident,
    responses=_STEP_UP_ERRORS,
    operation_id="reopenIncident",
)
async def reopen_incident(
    request: Request,
    incident_id: IncidentId,
    body: IncidentReopenRequest,
    actor: _ReopenActor,
    store: OptionalIncidentStore,
) -> Incident:
    """resolved|closed -> open with a mandatory, audited reason; human principals only."""
    actor_id = actor.identity.id
    return await _mutate(
        request,
        store,
        actor,
        action="incident.reopen",
        incident_id=incident_id,
        operation=lambda s: s.transition_state(
            incident_id, to_state="open", actor_id=actor_id, reason=body.reason
        ),
        reason_length=len(body.reason),
    )
