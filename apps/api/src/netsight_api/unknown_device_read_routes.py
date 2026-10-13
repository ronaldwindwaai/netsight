"""Unknown-device reads (Step 8c): findings, one finding, its timeline and the counts.

Reads need ``unknown-devices:read`` (rows, detail, timeline) or ``unknown-devices:read-summary``
(counts only: Technician and Management). The shared guards, limits and error mapping live in
``unknown_device_support``; the writes are in ``unknown_device_write_routes``.
"""

from __future__ import annotations

import json
from typing import Final, get_args

from fastapi import APIRouter, Request, Response
from fastapi.concurrency import run_in_threadpool

from netsight_api.contracts import ContractViolation, validate
from netsight_api.errors import ApiError
from netsight_api.inventory.wiring import utc_now
from netsight_api.rbac import Identity
from netsight_api.read_query import QueryError, boolean, integer, single_values, word
from netsight_api.read_support import no_store, rejected
from netsight_api.schemas_inventory import BlockState
from netsight_api.schemas_unknown_devices import (
    OPEN_STATES,
    FindingState,
    Severity,
    UnknownDeviceDetailResponse,
    UnknownDeviceListResponse,
    UnknownDeviceSummaryResponse,
    UnknownDeviceTimelineResponse,
)
from netsight_api.storage import NotFoundError
from netsight_api.storage.unknown_devices import MAX_OFFSET, UnknownDeviceRepository
from netsight_api.traffic import audit_trail
from netsight_api.unknown_device_support import (
    DEFAULT_PAGE_SIZE,
    ERRORS,
    MAX_PAGE_SIZE,
    MAX_TIMELINE_LIMIT,
    DetailReader,
    FindingId,
    ListReader,
    Store,
    SummaryReader,
    TimelineReader,
    correlation_id,
)
from netsight_api.unknown_device_support import LOGGER as _LOGGER

router = APIRouter(prefix="/unknown-devices", tags=["unknown-devices"])

_LIST_PARAMETERS: Final = frozenset({"page", "page_size", "state", "severity", "assigned"})
_TIMELINE_PARAMETERS: Final = frozenset({"after_seq", "limit"})
_STATE_FILTERS: Final = (*get_args(FindingState), "open")
MAX_PAGE: Final = 100_000


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
        extra={"correlation_id": correlation_id(request), "error_type": type(exc).__name__},
    )


# --- the list -----------------------------------------------------------------------------------------------


class _ListQuery:
    """The validated query of the list: filters and the page, parsed once."""

    def __init__(self, request: Request) -> None:
        values = single_values(request, _LIST_PARAMETERS)
        self.page = integer(values, "page", 1, 1, MAX_PAGE)
        self.page_size = integer(values, "page_size", DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE)
        self.state = word(values, "state", _STATE_FILTERS)
        self.severity: Severity | None = word(values, "severity", get_args(Severity))
        self.assigned = boolean(values, "assigned")
        if (self.page - 1) * self.page_size > MAX_OFFSET:
            raise QueryError("page")  # a deep page is a narrower filter, not a bigger offset

    @property
    def states(self) -> list[FindingState] | None:
        if self.state is None:
            return None
        return list(OPEN_STATES) if self.state == "open" else [self.state]

    @property
    def filter_names(self) -> str:
        pairs = (("state", self.state), ("severity", self.severity), ("assigned", self.assigned))
        return ",".join(n for n, v in pairs if v is not None)


def _empty_list(query: _ListQuery, state: BlockState) -> UnknownDeviceListResponse:
    return UnknownDeviceListResponse(
        state=state,
        generated_at=utc_now(),
        page=query.page,
        page_size=query.page_size,
        total=0,
        items=[],
    )


async def _list_body(
    request: Request, store: UnknownDeviceRepository | None, query: _ListQuery
) -> UnknownDeviceListResponse:
    if store is None:
        return _empty_list(query, "not-connected")
    repository = store
    try:
        rows, total = await run_in_threadpool(
            lambda: repository.list_findings(
                states=query.states,
                severity=query.severity,
                assigned=query.assigned,
                limit=query.page_size,
                offset=(query.page - 1) * query.page_size,
            )
        )
        body = UnknownDeviceListResponse(
            state="ok",
            generated_at=utc_now(),
            page=query.page,
            page_size=query.page_size,
            total=total,
            items=rows,
        )
        return _checked("unknown_device_list", body) or _empty_list(query, "unknown")
    except Exception as exc:  # noqa: BLE001 - deliberate store/contract boundary
        _log_read_failure(request, exc)
        return _empty_list(query, "unknown")


@router.get(
    "",
    response_model=UnknownDeviceListResponse,
    responses=ERRORS,
    operation_id="listUnknownDevices",
)
async def list_findings(
    request: Request, response: Response, identity: ListReader, store: Store
) -> UnknownDeviceListResponse:
    """Findings, newest sighting first, filtered and paged on the server."""
    action = "unknown-device.list.read"
    no_store(response)
    try:
        query = _ListQuery(request)
    except QueryError:
        raise rejected(request, identity, action) from None
    body = await _list_body(request, store, query)
    audit_trail.read(
        request,
        identity.id,
        action,
        state=body.state,
        returned=len(body.items),
        total=body.total,
        filters=query.filter_names,
    )
    return body


# --- counts, one finding ------------------------------------------------------------------------------------


@router.get(
    "/summary",
    response_model=UnknownDeviceSummaryResponse,
    responses=ERRORS,
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


async def _detail_body(
    request: Request, identity: Identity, store: UnknownDeviceRepository | None, finding_id: str
) -> UnknownDeviceDetailResponse:
    now = utc_now()
    if store is None:
        return UnknownDeviceDetailResponse(state="not-connected", generated_at=now, item=None)
    repository = store
    unknown = UnknownDeviceDetailResponse(state="unknown", generated_at=now, item=None)
    try:
        item = await run_in_threadpool(repository.get_finding, finding_id)
    except Exception as exc:  # noqa: BLE001 - deliberate store boundary
        _log_read_failure(request, exc)
        return unknown
    if item is None:
        audit_trail.failed(request, identity.id, "unknown-device.item.read", "not-found")
        raise ApiError(404, "NOT_FOUND", "Finding was not found")
    ok = UnknownDeviceDetailResponse(state="ok", generated_at=now, item=item)
    return _checked("unknown_device_detail", ok) or unknown


@router.get(
    "/{finding_id}",
    response_model=UnknownDeviceDetailResponse,
    responses=ERRORS,
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
    body = await _detail_body(request, identity, store, finding_id)
    audit_trail.read(request, identity.id, action, state=body.state, target=finding_id)
    return body


# --- the timeline -------------------------------------------------------------------------------------------


def _timeline_response(
    state: BlockState, finding_id: str, after_seq: int, events: list[object] | None = None
) -> UnknownDeviceTimelineResponse:
    return UnknownDeviceTimelineResponse.model_validate(
        {
            "state": state,
            "generated_at": utc_now(),
            "finding_id": finding_id,
            "events": events or [],
            "after_seq": after_seq,
            "next_after_seq": None,
        }
    )


async def _timeline_body(
    request: Request,
    identity: Identity,
    store: UnknownDeviceRepository | None,
    finding_id: str,
    after_seq: int,
    limit: int,
) -> UnknownDeviceTimelineResponse:
    if store is None:
        return _timeline_response("not-connected", finding_id, after_seq)
    repository = store
    try:
        events = await run_in_threadpool(
            lambda: repository.list_timeline(finding_id, after_seq=after_seq, limit=limit)
        )
        body = UnknownDeviceTimelineResponse(
            state="ok",
            generated_at=utc_now(),
            finding_id=finding_id,
            events=events,
            after_seq=after_seq,
            next_after_seq=events[-1].seq if events and len(events) == limit else None,
        )
        return _checked("unknown_device_timeline", body) or _timeline_response(
            "unknown", finding_id, after_seq
        )
    except NotFoundError:
        audit_trail.failed(request, identity.id, "unknown-device.timeline.read", "not-found")
        raise ApiError(404, "NOT_FOUND", "Finding was not found") from None
    except Exception as exc:  # noqa: BLE001 - deliberate store boundary
        _log_read_failure(request, exc)
        return _timeline_response("unknown", finding_id, after_seq)


@router.get(
    "/{finding_id}/timeline",
    response_model=UnknownDeviceTimelineResponse,
    responses=ERRORS,
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
    body = await _timeline_body(request, identity, store, finding_id, after_seq, limit)
    audit_trail.read(
        request, identity.id, action, state=body.state, target=finding_id, returned=len(body.events)
    )
    return body
