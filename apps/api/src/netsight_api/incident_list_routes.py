"""Incident list endpoints: the full list and management's summary-only list.

Registered *before* ``incident_routes`` in ``main`` so the static ``/incidents/summary`` path is
matched ahead of ``/incidents/{incident_id}`` (the summary tests pin this).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.concurrency import run_in_threadpool

from netsight_api.incident_deps import (
    READ_ERRORS,
    IncidentReader,
    IncidentSummaryReader,
    OptionalIncidentStore,
    checked_response,
    log_read_failure,
)
from netsight_api.schemas import IncidentSeverity, IncidentState, StoreState
from netsight_api.schemas_incidents import (
    MAX_INCIDENT_LIST_OFFSET,
    MAX_INCIDENT_PAGE_SIZE,
    IncidentListResponse,
    IncidentSummary,
    IncidentSummaryListResponse,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get(
    "",
    response_model=IncidentListResponse,
    responses=READ_ERRORS,
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
        return checked_response(
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
        return checked_response(
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
        log_read_failure(request, exc)
        return empty("unknown")


@router.get(
    "/summary",
    response_model=IncidentSummaryListResponse,
    responses=READ_ERRORS,
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
        return checked_response(
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
        return checked_response(
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
        log_read_failure(request, exc)
        return empty("unknown")
