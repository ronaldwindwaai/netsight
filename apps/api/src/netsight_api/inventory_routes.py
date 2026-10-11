"""Asset inventory routes (Step 8a): ``GET /api/v1/inventory``, ``/inventory/summary``, ``/inventory/{id}``.

Read-only. Every route needs a permission (rows and per-asset detail: ``inventory:read``; counts only:
``inventory:read-summary``, which Management holds), then a per-identity rate limit (authorise first,
so an unauthorised caller never learns limiter state), then a strict query (unknown, repeated or
malformed parameters are a 422 that echoes nothing). The answer is explicit:

* NetBox not configured: ``not-connected``; unreadable: ``unknown`` (HTTP 200, no rows, no counts);
* a discovery source failing only degrades what is compared and is named in ``sources``;
* a body that fails its own canonical contract is never sent as data: it degrades to ``unknown``.

Every read is audited (actor, state, counts, the *names* of the filters used; never a filter value),
and so is every refusal. Names, roles and sites come from NetBox and telemetry: they are returned as
data and never interpreted. Responses are ``Cache-Control: no-store``.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, Any, Final, get_args

from fastapi import APIRouter, Depends, Path, Request, Response

from netsight_api.contracts import ContractViolation, validate
from netsight_api.errors import ApiError
from netsight_api.inventory.service import (
    InventoryFilters,
    InventoryService,
    InventorySnapshot,
    filter_items,
    find_item,
    page_items,
)
from netsight_api.inventory.wiring import build_inventory_service, utc_now
from netsight_api.rbac import Identity, Permission
from netsight_api.read_query import QueryError, boolean, integer, single_values, text, word
from netsight_api.read_support import CurrentIdentity, no_store, reader, rejected  # noqa: F401
from netsight_api.schemas import DeviceStatus, ErrorEnvelope
from netsight_api.schemas_inventory import (
    DEVICE_ID_PATTERN,
    AssetClass,
    InventoryDetailResponse,
    InventoryListResponse,
    InventorySummaryResponse,
    ItemSource,
)
from netsight_api.schemas_sources import SourceStatus
from netsight_api.traffic import audit_trail

_LOGGER: Final = logging.getLogger("netsight_api")

router = APIRouter(prefix="/inventory", tags=["inventory"])

LIST_LIMIT_PER_MINUTE: Final = 60
SUMMARY_LIMIT_PER_MINUTE: Final = 60
DETAIL_LIMIT_PER_MINUTE: Final = 120
DEFAULT_PAGE_SIZE: Final = 25
MAX_PAGE_SIZE: Final = 100
_LIST_PARAMETERS: Final = frozenset(
    {"page", "page_size", "asset_class", "site", "status", "source", "known", "q"}
)
_ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    404: {"model": ErrorEnvelope, "description": "Asset not found"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
    429: {"model": ErrorEnvelope, "description": "Read rate limit exceeded"},
}

DeviceId = Annotated[str, Path(min_length=43, max_length=43, pattern=DEVICE_ID_PATTERN)]


def get_inventory_service() -> InventoryService:
    return build_inventory_service()


Service = Annotated[InventoryService, Depends(get_inventory_service)]


# --- authorisation ----------------------------------------------------------------------------------------

ListReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.INVENTORY_READ,
            "inventory.list.read",
            "inventory",
            lambda: LIST_LIMIT_PER_MINUTE,
        )
    ),
]
DetailReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.INVENTORY_READ,
            "inventory.item.read",
            "inventory-item",
            lambda: DETAIL_LIMIT_PER_MINUTE,
        )
    ),
]
SummaryReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.INVENTORY_READ_SUMMARY,
            "inventory.summary.read",
            "inventory-summary",
            lambda: SUMMARY_LIMIT_PER_MINUTE,
        )
    ),
]


# --- helpers ------------------------------------------------------------------------------------------------


def _parse_list_query(request: Request) -> tuple[InventoryFilters, int, int]:
    values = single_values(request, _LIST_PARAMETERS)
    filters = InventoryFilters(
        asset_class=word(values, "asset_class", get_args(AssetClass)),
        site=text(values, "site", 255),
        status=word(values, "status", get_args(DeviceStatus)),
        source=word(values, "source", get_args(ItemSource)),
        known=boolean(values, "known"),
        q=text(values, "q", 64),
    )
    page = integer(values, "page", 1, 1, 100_000)
    page_size = integer(values, "page_size", DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE)
    return filters, page, page_size


async def _snapshot(
    request: Request, identity: Identity, action: str, service: InventoryService
) -> InventorySnapshot | None:
    """The snapshot, or ``None`` after the failure was logged and audited (the route answers unknown)."""
    try:
        return await service.snapshot()
    except Exception as error:  # noqa: BLE001 - a source boundary: unknown, never a 500 or a leak
        _LOGGER.warning("inventory read failed", extra={"error_type": type(error).__name__})
        audit_trail.failed(request, identity.id, action, "source-error")
        return None


def _unknown_sources(snapshot: InventorySnapshot | None) -> list[SourceStatus]:
    if snapshot is not None:
        return list(snapshot.sources)
    return [SourceStatus(source="netbox", state="unknown", observed_at=None)]


def _checked[M: InventoryListResponse | InventoryDetailResponse | InventorySummaryResponse](
    schema: str, body: M
) -> M | None:
    try:
        validate(schema, json.loads(body.model_dump_json(by_alias=True)))
    except ContractViolation:
        _LOGGER.error("inventory response failed its canonical contract")
        return None
    return body


# --- routes -----------------------------------------------------------------------------------------------------


@router.get(
    "", response_model=InventoryListResponse, responses=_ERRORS, operation_id="listInventory"
)
async def list_inventory(
    request: Request, response: Response, identity: ListReader, service: Service
) -> InventoryListResponse:
    """A page of assets: NetBox intended state merged with discovered telemetry, filtered server-side."""
    action = "inventory.list.read"
    no_store(response)
    try:
        filters, page, page_size = _parse_list_query(request)
    except QueryError:
        raise rejected(request, identity, action) from None
    snapshot = await _snapshot(request, identity, action, service)
    now = snapshot.generated_at if snapshot is not None else utc_now()
    state = snapshot.state if snapshot is not None else "unknown"
    matching = filter_items(snapshot.items, filters) if snapshot is not None else []
    body = InventoryListResponse(
        state=state,
        generated_at=now,
        page=page,
        page_size=page_size,
        total=len(matching),
        sources=_unknown_sources(snapshot),
        summary=snapshot.summary if snapshot is not None else None,
        items=page_items(matching, page=page, page_size=page_size),
    )
    checked = _checked("inventory_list", body)
    if checked is None:
        checked = InventoryListResponse(
            state="unknown",
            generated_at=now,
            page=page,
            page_size=page_size,
            total=0,
            sources=_unknown_sources(None),
            summary=None,
            items=[],
        )
    audit_trail.read(
        request,
        identity.id,
        action,
        state=checked.state,
        returned=len(checked.items),
        total=checked.total,
        filters=",".join(filters.active()),
    )
    return checked


@router.get(
    "/summary",
    response_model=InventorySummaryResponse,
    responses=_ERRORS,
    operation_id="getInventorySummary",
)
async def inventory_summary(
    request: Request, response: Response, identity: SummaryReader, service: Service
) -> InventorySummaryResponse:
    """Counts only (the rung Management holds): no names, addresses or identifiers."""
    action = "inventory.summary.read"
    no_store(response)
    if request.query_params:
        raise rejected(request, identity, action)
    snapshot = await _snapshot(request, identity, action, service)
    now = snapshot.generated_at if snapshot is not None else utc_now()
    body = InventorySummaryResponse(
        state=snapshot.state if snapshot is not None else "unknown",
        generated_at=now,
        sources=_unknown_sources(snapshot),
        summary=snapshot.summary if snapshot is not None else None,
    )
    checked = _checked("inventory_summary_response", body) or InventorySummaryResponse(
        state="unknown", generated_at=now, sources=_unknown_sources(None), summary=None
    )
    audit_trail.read(request, identity.id, action, state=checked.state)
    return checked


@router.get(
    "/{device_id}",
    response_model=InventoryDetailResponse,
    responses=_ERRORS,
    operation_id="getInventoryItem",
)
async def inventory_item(
    request: Request,
    response: Response,
    device_id: DeviceId,
    identity: DetailReader,
    service: Service,
) -> InventoryDetailResponse:
    """One asset with the provenance of every field; an unknown id is a 404, never a fabricated record."""
    action = "inventory.item.read"
    no_store(response)
    if request.query_params:
        raise rejected(request, identity, action)
    snapshot = await _snapshot(request, identity, action, service)
    now = snapshot.generated_at if snapshot is not None else utc_now()
    item = find_item(snapshot.items, device_id) if snapshot is not None else None
    if snapshot is not None and snapshot.state == "ok" and item is None:
        audit_trail.failed(request, identity.id, action, "not-found")
        raise ApiError(404, "NOT_FOUND", "Asset was not found")
    body = InventoryDetailResponse(
        state=snapshot.state if snapshot is not None else "unknown",
        generated_at=now,
        sources=_unknown_sources(snapshot),
        item=item,
    )
    checked = _checked("inventory_detail", body) or InventoryDetailResponse(
        state="unknown", generated_at=now, sources=_unknown_sources(None), item=None
    )
    audit_trail.read(request, identity.id, action, state=checked.state, target=device_id)
    return checked
