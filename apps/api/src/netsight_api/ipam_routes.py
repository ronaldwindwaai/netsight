"""IPAM routes (Step 8b): ``GET /api/v1/ipam`` (counts), ``/ipam/prefixes``, ``/ipam/vlans``, ``/ipam/addresses``.

Read-only. The prefix, VLAN and address lists need ``ipam:read``; the overview (sources, telemetry
coverage and counts only, the rung Management holds) needs ``ipam:read-summary``. Authorise first,
then a per-identity budget, then a strict query (unknown, repeated or malformed parameters are a 422
that echoes nothing). Each list answers for its own NetBox dataset: ``not-connected`` without NetBox,
``unknown`` when that read failed (HTTP 200, no rows), so the VLANs stay visible when the prefixes
cannot be read. Utilisation always names its basis; an address is stale only when telemetry was
readable. Every read and refusal is audited with counts and the names of the filters, never values.
Everything is returned as data (descriptions and names come from NetBox) with ``no-store``.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, Final, cast, get_args

from fastapi import APIRouter, Depends, Request, Response

from netsight_api.contracts import ContractViolation, validate
from netsight_api.inventory.wiring import utc_now
from netsight_api.ipam.engine import IpamBuild
from netsight_api.ipam.lists import (
    AddressFilters,
    PrefixFilters,
    VlanFilters,
    filter_addresses,
    filter_prefixes,
    filter_vlans,
    page_of,
)
from netsight_api.ipam.service import IpamService, IpamSnapshot
from netsight_api.ipam.wiring import build_ipam_service
from netsight_api.rbac import Identity, Permission
from netsight_api.read_query import QueryError, integer, single_values, text, word
from netsight_api.read_support import no_store, reader, rejected
from netsight_api.schemas import ErrorEnvelope
from netsight_api.schemas_inventory import BlockState
from netsight_api.schemas_ipam import (
    PREFIX_ID_PATTERN,
    Activity,
    AddressSource,
    IpamAddressList,
    IpamPrefixList,
    IpamSummaryResponse,
    IpamTelemetry,
    IpamVlanList,
)
from netsight_api.schemas_sources import SourceStatus
from netsight_api.traffic import audit_trail

_LOGGER: Final = logging.getLogger("netsight_api")

router = APIRouter(prefix="/ipam", tags=["ipam"])

LIST_LIMIT_PER_MINUTE: Final = 60
SUMMARY_LIMIT_PER_MINUTE: Final = 60
DEFAULT_PAGE_SIZE: Final = 25
MAX_PAGE_SIZE: Final = 100
DEFAULT_WINDOW_SECONDS: Final = 86400
_PAGING: Final = {"page", "page_size"}
_PREFIX_ID: Final = re.compile(PREFIX_ID_PATTERN)
_ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
    429: {"model": ErrorEnvelope, "description": "Read rate limit exceeded"},
}


def get_ipam_service() -> IpamService:
    return build_ipam_service()


Service = Annotated[IpamService, Depends(get_ipam_service)]


def _list_reader(action: str, family: str) -> Callable[..., Identity]:
    return reader(Permission.IPAM_READ, action, family, lambda: LIST_LIMIT_PER_MINUTE)


PrefixReader = Annotated[Identity, Depends(_list_reader("ipam.prefixes.read", "ipam-prefixes"))]
VlanReader = Annotated[Identity, Depends(_list_reader("ipam.vlans.read", "ipam-vlans"))]
AddressReader = Annotated[Identity, Depends(_list_reader("ipam.addresses.read", "ipam-addresses"))]
SummaryReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.IPAM_READ_SUMMARY,
            "ipam.summary.read",
            "ipam-summary",
            lambda: SUMMARY_LIMIT_PER_MINUTE,
        )
    ),
]


# --- helpers ----------------------------------------------------------------------------------------------


def _paging(values: dict[str, str]) -> tuple[int, int]:
    return (
        integer(values, "page", 1, 1, 100_000),
        integer(values, "page_size", DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE),
    )


async def _snapshot(
    request: Request, identity: Identity, action: str, service: IpamService
) -> IpamSnapshot | None:
    try:
        return await service.snapshot()
    except Exception as error:  # noqa: BLE001 - a source boundary: unknown, never a 500 or a leak
        _LOGGER.warning("ipam read failed", extra={"error_type": type(error).__name__})
        audit_trail.failed(request, identity.id, action, "source-error")
        return None


def _unknown_sources() -> list[SourceStatus]:
    return [SourceStatus(source="netbox", state="unknown", observed_at=None)]


def _unknown_telemetry() -> IpamTelemetry:
    return IpamTelemetry(state="unknown", window_seconds=DEFAULT_WINDOW_SECONDS, sources=[])


def _frame(snapshot: IpamSnapshot | None) -> tuple[datetime, list[SourceStatus], IpamTelemetry]:
    """generated_at, sources and telemetry; a failed read names NetBox unknown and no telemetry."""
    if snapshot is not None:
        return snapshot.generated_at, list(snapshot.sources), snapshot.telemetry
    return utc_now(), _unknown_sources(), _unknown_telemetry()


def _dataset_state(snapshot: IpamSnapshot | None, rows: object | None) -> BlockState:
    """The state of one NetBox dataset: NetBox's own, or unknown when only this dataset failed."""
    if snapshot is None:
        return "unknown"
    if snapshot.state != "ok":
        return snapshot.state
    return "ok" if rows is not None else "unknown"


def _build_of(snapshot: IpamSnapshot | None) -> IpamBuild | None:
    return snapshot.build if snapshot is not None else None


def _checked[M: IpamPrefixList | IpamVlanList | IpamAddressList | IpamSummaryResponse](
    schema: str, body: M
) -> M | None:
    try:
        validate(schema, json.loads(body.model_dump_json(by_alias=True)))
    except ContractViolation:
        _LOGGER.error("ipam response failed its canonical contract")
        return None
    return body


def _empty_list[M: IpamPrefixList | IpamVlanList | IpamAddressList](
    model: type[M], page: int, page_size: int
) -> M:
    """A contract failure never ships as data: it degrades to an empty ``unknown`` page."""
    fields: dict[str, Any] = {
        "state": "unknown",
        "generated_at": utc_now(),
        "sources": _unknown_sources(),
        "telemetry": _unknown_telemetry(),
        "page": page,
        "page_size": page_size,
        "total": 0,
        "items": [],
    }
    if model is IpamAddressList:
        fields["activity_counts"] = None
    return cast(M, model(**fields))


def _audit_list(
    request: Request,
    identity: Identity,
    action: str,
    body: IpamPrefixList | IpamVlanList | IpamAddressList,
    filters: list[str],
) -> None:
    audit_trail.read(
        request,
        identity.id,
        action,
        state=body.state,
        returned=len(body.items),
        total=body.total,
        filters=",".join(filters),
    )


# --- routes ------------------------------------------------------------------------------------------------


@router.get("", response_model=IpamSummaryResponse, responses=_ERRORS, operation_id="getIpam")
async def ipam_overview(
    request: Request, response: Response, identity: SummaryReader, service: Service
) -> IpamSummaryResponse:
    """What is known and from where, with counts only (no prefix, VLAN or address)."""
    action = "ipam.summary.read"
    no_store(response)
    if request.query_params:
        raise rejected(request, identity, action)
    snapshot = await _snapshot(request, identity, action, service)
    now, sources, telemetry = _frame(snapshot)
    build = _build_of(snapshot)
    body = IpamSummaryResponse(
        state=snapshot.state if snapshot is not None else "unknown",
        generated_at=now,
        sources=sources,
        telemetry=telemetry,
        counts=build.counts if build is not None else None,
    )
    checked = _checked("ipam_summary_response", body) or IpamSummaryResponse(
        state="unknown",
        generated_at=now,
        sources=_unknown_sources(),
        telemetry=_unknown_telemetry(),
        counts=None,
    )
    audit_trail.read(request, identity.id, action, state=checked.state)
    return checked


@router.get(
    "/prefixes", response_model=IpamPrefixList, responses=_ERRORS, operation_id="listIpamPrefixes"
)
async def list_prefixes(
    request: Request, response: Response, identity: PrefixReader, service: Service
) -> IpamPrefixList:
    """Prefixes in tree order with utilisation, its basis, reserved ranges and the VLAN they name."""
    action = "ipam.prefixes.read"
    no_store(response)
    try:
        values = single_values(request, _PAGING | {"site", "status", "family", "q"})
        page, page_size = _paging(values)
        family = word(values, "family", ("4", "6"))
        filters = PrefixFilters(
            site=text(values, "site", 128),
            status=text(values, "status", 64),
            family=int(family) if family is not None else None,
            q=text(values, "q", 64),
        )
    except QueryError:
        raise rejected(request, identity, action) from None
    snapshot = await _snapshot(request, identity, action, service)
    build = _build_of(snapshot)
    rows = build.prefixes if build is not None else None
    matching = filter_prefixes(rows, filters) if rows is not None else []
    now, sources, telemetry = _frame(snapshot)
    state = _dataset_state(snapshot, rows)
    shown = state == "ok"
    body = IpamPrefixList(
        state=state,
        generated_at=now,
        sources=sources,
        telemetry=telemetry,
        page=page,
        page_size=page_size,
        total=len(matching) if shown else 0,
        items=page_of(matching, page=page, page_size=page_size) if shown else [],
    )
    checked = _checked("ipam_prefix_list", body) or _empty_list(IpamPrefixList, page, page_size)
    _audit_list(request, identity, action, checked, filters.active())
    return checked


@router.get("/vlans", response_model=IpamVlanList, responses=_ERRORS, operation_id="listIpamVlans")
async def list_vlans(
    request: Request, response: Response, identity: VlanReader, service: Service
) -> IpamVlanList:
    """VLANs by number, with how many NetBox prefixes name each."""
    action = "ipam.vlans.read"
    no_store(response)
    try:
        values = single_values(request, _PAGING | {"site", "q"})
        page, page_size = _paging(values)
        filters = VlanFilters(site=text(values, "site", 128), q=text(values, "q", 64))
    except QueryError:
        raise rejected(request, identity, action) from None
    snapshot = await _snapshot(request, identity, action, service)
    build = _build_of(snapshot)
    rows = build.vlans if build is not None else None
    matching = filter_vlans(rows, filters) if rows is not None else []
    now, sources, telemetry = _frame(snapshot)
    state = _dataset_state(snapshot, rows)
    shown = state == "ok"
    body = IpamVlanList(
        state=state,
        generated_at=now,
        sources=sources,
        telemetry=telemetry,
        page=page,
        page_size=page_size,
        total=len(matching) if shown else 0,
        items=page_of(matching, page=page, page_size=page_size) if shown else [],
    )
    checked = _checked("ipam_vlan_list", body) or _empty_list(IpamVlanList, page, page_size)
    _audit_list(request, identity, action, checked, filters.active())
    return checked


@router.get(
    "/addresses",
    response_model=IpamAddressList,
    responses=_ERRORS,
    operation_id="listIpamAddresses",
)
async def list_addresses(
    request: Request, response: Response, identity: AddressReader, service: Service
) -> IpamAddressList:
    """IP usage: NetBox addresses and addresses telemetry saw, active versus stale with the basis."""
    action = "ipam.addresses.read"
    no_store(response)
    try:
        values = single_values(request, _PAGING | {"activity", "source", "prefix", "q"})
        page, page_size = _paging(values)
        prefix = values.get("prefix")
        if prefix is not None and _PREFIX_ID.fullmatch(prefix) is None:
            raise QueryError("invalid identifier")
        filters = AddressFilters(
            activity=word(values, "activity", get_args(Activity)),
            source=word(values, "source", get_args(AddressSource)),
            prefix=prefix,
            q=text(values, "q", 64),
        )
    except QueryError:
        raise rejected(request, identity, action) from None
    snapshot = await _snapshot(request, identity, action, service)
    build = _build_of(snapshot)
    rows = build.addresses if build is not None else None
    matching = filter_addresses(rows, filters) if rows is not None else []
    now, sources, telemetry = _frame(snapshot)
    state = _dataset_state(snapshot, rows)
    shown = state == "ok"
    body = IpamAddressList(
        state=state,
        generated_at=now,
        sources=sources,
        telemetry=telemetry,
        page=page,
        page_size=page_size,
        total=len(matching) if shown else 0,
        activity_counts=build.activity_counts if build is not None and shown else None,
        items=page_of(matching, page=page, page_size=page_size) if shown else [],
    )
    checked = _checked("ipam_address_list", body) or _empty_list(IpamAddressList, page, page_size)
    _audit_list(request, identity, action, checked, filters.active())
    return checked
