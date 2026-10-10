"""Stored diagnostic sessions: ``GET /api/v1/diagnostics`` and ``GET /api/v1/diagnostics/{id}`` (S7 Step 4a).

Read-only and immutable: sessions are created only by a finished run (``POST /diagnostics``) and
there is no route that changes or removes one. Both reads need ``diagnostics:read``, are rate
limited per identity, and are bounded (a capped page and a capped offset). Without a session
store the answer is an explicit ``not-connected`` state; a store that cannot be read, or a stored
row that no longer satisfies the contract, is an explicit ``unknown`` state. Neither ever carries
a connection string or a driver message, and an unknown id is a 404, not a state.

Free text in a session (target, symptom, probe details, device and alert titles) is untrusted
data: it is returned as JSON and never interpreted.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.concurrency import run_in_threadpool

from netsight_api.alerting_route_support import READ_ERRORS, correlation_id
from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import validate
from netsight_api.diagnostic_context import OptionalSessionStore
from netsight_api.diagnostic_titles import with_incident_titles
from netsight_api.errors import ApiError
from netsight_api.incident_deps import OptionalIncidentStore
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
from netsight_api.schemas import ErrorEnvelope, StoreState
from netsight_api.schemas_diagnostic_session import (
    MAX_SESSION_LIST_OFFSET,
    MAX_SESSION_PAGE_SIZE,
    DiagnosticSessionListResponse,
    DiagnosticSessionResponse,
)
from netsight_api.schemas_diagnostics import DIAGNOSTIC_ID_PATTERN, DIAGNOSTIC_RUN_ID_LENGTH

_LOGGER = logging.getLogger("netsight_api")

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])

ITEM_ERRORS = {**READ_ERRORS, 404: {"model": ErrorEnvelope, "description": "No such session"}}

CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]
DiagnosticId = Annotated[
    str,
    Path(
        min_length=DIAGNOSTIC_RUN_ID_LENGTH,
        max_length=DIAGNOSTIC_RUN_ID_LENGTH,
        pattern=DIAGNOSTIC_ID_PATTERN,
    ),
]


def require_session_reader(identity: CurrentIdentity) -> Identity:
    """authorise (deny by default) -> per-identity read limit; authorisation never reveals the limiter."""
    if not is_allowed(identity, Permission.DIAGNOSTICS_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    enforce_read_limit(identity, "diagnostics")
    return identity


SessionReader = Annotated[Identity, Depends(require_session_reader)]


def _log_failure(request: Request, exc: Exception) -> None:
    _LOGGER.warning(
        "diagnostic session store read failed",
        extra={"correlation_id": correlation_id(request), "error_type": type(exc).__name__},
    )


@router.get(
    "",
    response_model=DiagnosticSessionListResponse,
    responses=READ_ERRORS,
    operation_id="listDiagnosticSessions",
)
async def list_diagnostic_sessions(
    request: Request,
    _identity: SessionReader,
    store: OptionalSessionStore,
    limit: Annotated[int, Query(ge=1, le=MAX_SESSION_PAGE_SIZE)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_SESSION_LIST_OFFSET)] = 0,
) -> DiagnosticSessionListResponse:
    """Stored sessions newest first; ``next_offset`` is set when the page was full."""

    def empty(state: StoreState) -> DiagnosticSessionListResponse:
        return DiagnosticSessionListResponse(
            state=state, sessions=[], limit=limit, offset=offset, next_offset=None
        )

    if store is None:
        return empty("not-connected")
    reader = store
    try:
        rows = await run_in_threadpool(lambda: reader.list_sessions(limit=limit, offset=offset))
        following = offset + limit
        more = len(rows) == limit and following <= MAX_SESSION_LIST_OFFSET
        body = DiagnosticSessionListResponse(
            state="ok",
            sessions=rows,
            limit=limit,
            offset=offset,
            next_offset=following if more else None,
        )
        validate("diagnostic_session_list_response", body.model_dump(mode="json", by_alias=True))
        return body
    except Exception as exc:  # noqa: BLE001 — deliberate store/contract boundary
        _log_failure(request, exc)
        return empty("unknown")


@router.get(
    "/{diagnostic_id}",
    response_model=DiagnosticSessionResponse,
    responses=ITEM_ERRORS,
    operation_id="getDiagnosticSession",
)
async def get_diagnostic_session(
    request: Request,
    diagnostic_id: DiagnosticId,
    identity: SessionReader,
    store: OptionalSessionStore,
    incidents: OptionalIncidentStore,
) -> DiagnosticSessionResponse:
    """One stored session by its run id.

    Incident titles are not stored; they are joined here, per read, for a caller who holds
    ``incidents:read`` (everyone else sees the placeholder).
    """
    if store is None:
        return DiagnosticSessionResponse(state="not-connected", session=None)
    reader = store
    try:
        session = await run_in_threadpool(lambda: reader.get_session(diagnostic_id))
        if session is not None:
            session = await with_incident_titles(session, identity, incidents)
            body = DiagnosticSessionResponse(state="ok", session=session)
            validate("diagnostic_session_response", body.model_dump(mode="json", by_alias=True))
    except Exception as exc:  # noqa: BLE001 — deliberate store/contract boundary
        _log_failure(request, exc)
        return DiagnosticSessionResponse(state="unknown", session=None)
    if session is None:
        raise ApiError(404, "DIAGNOSTIC_NOT_FOUND", "No such diagnostic session")
    return body
