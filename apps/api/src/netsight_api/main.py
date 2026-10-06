"""Netsight platform API entrypoint."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections.abc import AsyncIterator, Awaitable, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, NoReturn, Protocol, cast
from urllib.parse import urlsplit
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from netsight_api.adapters.librenms import (
    AdapterError,
    AdapterStatus,
    DeviceNotFoundError,
    LibrenmsClient,
)
from netsight_api.adapters.netbox import (
    AdapterError as NetboxAdapterError,
)
from netsight_api.adapters.netbox import (
    AdapterStatus as NetboxAdapterStatus,
)
from netsight_api.adapters.netbox import (
    DeviceCollection,
    NetboxClient,
)
from netsight_api.adapters.netbox import (
    DeviceNotFoundError as NetboxDeviceNotFoundError,
)
from netsight_api.adapters.netbox import (
    canonical_device_id as netbox_canonical_device_id,
)
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.oidc import aclose as oidc_aclose
from netsight_api.auth.routes import router as auth_router
from netsight_api.contracts import ContractViolation, validate
from netsight_api.errors import ApiError
from netsight_api.localauth.routes import router as localauth_router
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.reconcile import reconcile
from netsight_api.schemas import (
    Alert,
    AlertListResponse,
    DeviceDetailResponse,
    DeviceHealthSummary,
    DeviceListResponse,
    DeviceStatus,
    DeviceStatusCount,
    ErrorDetail,
    ErrorEnvelope,
    Freshness,
    HealthResponse,
    InterfaceListResponse,
    OverviewResponse,
    ReconciliationFinding,
    ReconciliationFindingsResponse,
    SourceHealthResponse,
    SourceState,
    TopologyEdge,
    TopologyNode,
    TopologyNodeFinding,
    TopologyResponse,
    TrafficDimension,
    TrafficFlow,
    TrafficFlowsResponse,
    TrafficItem,
    TrafficPreset,
    TrafficTimeRange,
    TrafficTopResponse,
)

API_PREFIX = "/api/v1"
CORRELATION_ID_HEADER = "X-Correlation-ID"
_CORRELATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_LOGGER = logging.getLogger("netsight_api")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    yield
    await oidc_aclose()


app = FastAPI(title="Netsight Platform API", version="0.1.0", lifespan=lifespan)
api = APIRouter(prefix=API_PREFIX)


def _request_correlation_id(request: Request) -> str:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else str(uuid4())


def _error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    correlation_id = _request_correlation_id(request)
    response_headers = dict(headers or {})
    response_headers[CORRELATION_ID_HEADER] = correlation_id
    content = ErrorEnvelope(
        error=ErrorDetail(
            code=code,
            message=message,
            correlation_id=correlation_id,
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=content.model_dump(mode="json"),
        headers=response_headers,
    )


@app.middleware("http")
async def correlation_id_middleware(
    request: Request,
    call_next: RequestResponseEndpoint,
) -> Response:
    supplied = request.headers.get(CORRELATION_ID_HEADER)
    request.state.correlation_id = (
        supplied
        if supplied is not None and _CORRELATION_ID_PATTERN.fullmatch(supplied)
        else str(uuid4())
    )
    response = await call_next(request)
    response.headers[CORRELATION_ID_HEADER] = request.state.correlation_id
    return response


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return _error_response(
        request,
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    del exc
    return _error_response(
        request,
        status_code=422,
        code="VALIDATION_ERROR",
        message="Request validation failed",
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    if exc.status_code == 404:
        return _error_response(
            request,
            status_code=404,
            code="NOT_FOUND",
            message="Resource was not found",
            headers=exc.headers,
        )
    return _error_response(
        request,
        status_code=exc.status_code,
        code="HTTP_ERROR",
        message="Request could not be completed",
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    _LOGGER.error(
        json.dumps(
            {
                "event": "unhandled_api_error",
                "correlation_id": _request_correlation_id(request),
                "exception_type": type(exc).__name__,
            }
        )
    )
    return _error_response(
        request,
        status_code=500,
        code="INTERNAL_ERROR",
        message="An internal error occurred",
    )


def get_client() -> LibrenmsClient:
    base_url = os.environ.get("LIBRENMS_BASE_URL", "").strip()
    token = os.environ.get("LIBRENMS_TOKEN", "").strip()
    timezone_name = os.environ.get("LIBRENMS_TIMEZONE", "").strip()
    try:
        parsed_url = urlsplit(base_url)
        valid_url = (
            parsed_url.scheme in {"http", "https"}
            and parsed_url.hostname is not None
            and parsed_url.username is None
            and parsed_url.password is None
            and not parsed_url.query
            and not parsed_url.fragment
        )
    except ValueError:
        valid_url = False
    if not valid_url or not token or not timezone_name:
        raise ApiError(
            503,
            "SOURCE_UNAVAILABLE",
            "LibreNMS source is not configured",
        )
    try:
        source_timezone = ZoneInfo(timezone_name)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise ApiError(
            503,
            "SOURCE_UNAVAILABLE",
            "LibreNMS source is not configured",
        ) from exc
    return LibrenmsClient(
        base_url=base_url,
        token=token,
        source_timezone=source_timezone,
    )


def get_netbox_client() -> NetboxClient:
    base_url = os.environ.get("NETBOX_BASE_URL", "").strip()
    token = os.environ.get("NETBOX_TOKEN", "").strip()
    try:
        parsed_url = urlsplit(base_url)
        valid_url = (
            parsed_url.scheme in {"http", "https"}
            and parsed_url.hostname is not None
            and parsed_url.username is None
            and parsed_url.password is None
            and not parsed_url.query
            and not parsed_url.fragment
        )
    except ValueError:
        valid_url = False
    if not valid_url or not token:
        raise ApiError(
            503,
            "SOURCE_UNAVAILABLE",
            "NetBox source is not configured",
        )
    return NetboxClient(base_url=base_url, token=token)


CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]
LibrenmsDependency = Annotated[LibrenmsClient, Depends(get_client)]
NetboxDependency = Annotated[NetboxClient, Depends(get_netbox_client)]


def get_optional_netbox_client() -> NetboxClient | None:
    """NetBox client when configured, else None (topology: not-connected)."""
    try:
        return get_netbox_client()
    except ApiError:
        return None


OptionalNetboxDependency = Annotated[
    NetboxClient | None, Depends(get_optional_netbox_client)
]


def get_optional_librenms_client() -> LibrenmsClient | None:
    """LibreNMS client when configured, else None (reconciliation not checked)."""
    try:
        return get_client()
    except ApiError:
        return None


OptionalLibrenmsDependency = Annotated[
    LibrenmsClient | None, Depends(get_optional_librenms_client)
]


class TrafficSource(Protocol):
    """Read-only, bounded flow-aggregate source (ClickHouse lands in S4-2).

    Implementations must run parameterised queries with explicit time
    bounds and a row limit; they never receive unbounded requests.
    """

    async def top(
        self,
        *,
        dimension: TrafficDimension,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[list[TrafficItem], datetime]:
        """Return ranked items and the newest flow timestamp included."""
        ...

    async def flows(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[list[TrafficFlow], datetime]:
        """Return high-volume flows and the newest flow timestamp included."""
        ...


def get_optional_traffic_source() -> TrafficSource | None:
    """Flow source when configured; None means explicit not-connected.

    S4-1 defines the protocol only — the ClickHouse adapter arrives in
    S4-2, so this returns None rather than any fabricated sample data.
    """
    return None


OptionalTrafficDependency = Annotated[
    TrafficSource | None, Depends(get_optional_traffic_source)
]


async def _capture[T](operation: Awaitable[T]) -> T | Exception:
    """Await a source read, returning the error instead of raising it.

    Cancellation (`CancelledError`) is a `BaseException` and is therefore
    never captured — it must propagate.
    """

    try:
        return await operation
    except Exception as exc:  # noqa: BLE001 — deliberate source-read boundary
        return exc


async def _absent() -> None:
    """Awaitable placeholder for a source that is not configured."""
    return


def require_device_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.DEVICES_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    return identity


def require_alert_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.ALERTS_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    return identity


def require_traffic_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.TRAFFIC_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    return identity


DeviceReader = Annotated[Identity, Depends(require_device_reader)]
AlertReader = Annotated[Identity, Depends(require_alert_reader)]
TrafficReader = Annotated[Identity, Depends(require_traffic_reader)]

_STANDARD_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
    502: {"model": ErrorEnvelope, "description": "Invalid source response"},
    503: {"model": ErrorEnvelope, "description": "Source unavailable"},
}


def _raise_adapter_error(exc: AdapterError) -> NoReturn:
    if exc.status is AdapterStatus.UNAVAILABLE:
        raise ApiError(503, "SOURCE_UNAVAILABLE", "LibreNMS source is unavailable") from exc
    if exc.status is AdapterStatus.FORBIDDEN:
        raise ApiError(
            502,
            "SOURCE_FORBIDDEN",
            "LibreNMS source rejected the service request",
        ) from exc
    raise ApiError(
        502,
        "SOURCE_INVALID_DATA",
        "LibreNMS returned invalid data",
    ) from exc


def _raise_netbox_adapter_error(exc: NetboxAdapterError) -> NoReturn:
    if exc.status is NetboxAdapterStatus.UNAVAILABLE:
        raise ApiError(503, "SOURCE_UNAVAILABLE", "NetBox source is unavailable") from exc
    if exc.status is NetboxAdapterStatus.FORBIDDEN:
        raise ApiError(
            502,
            "SOURCE_FORBIDDEN",
            "NetBox source rejected the service request",
        ) from exc
    raise ApiError(
        502,
        "SOURCE_INVALID_DATA",
        "NetBox returned invalid data",
    ) from exc


@api.get("/health", response_model=HealthResponse, tags=["platform"])
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@api.get(
    "/sources/librenms/health",
    response_model=SourceHealthResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["sources"],
)
async def librenms_health(
    _identity: DeviceReader,
    client: LibrenmsDependency,
) -> SourceHealthResponse:
    result = await client.health()
    return SourceHealthResponse.model_validate(
        {
            "source": result.source,
            "status": result.status.value,
            "reachable": result.reachable,
            "latency_ms": result.latency_ms,
            "checked_at": result.checked_at,
            "detail": result.detail,
        }
    )


@api.get(
    "/devices",
    response_model=DeviceListResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["devices"],
)
async def devices(
    _identity: DeviceReader,
    client: LibrenmsDependency,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> DeviceListResponse:
    try:
        collection = await client.devices()
        for device in collection.items:
            validate("device", device.model_dump(mode="json"))
    except AdapterError as exc:
        _raise_adapter_error(exc)
    except ContractViolation as exc:
        raise ApiError(
            502,
            "SOURCE_INVALID_DATA",
            "LibreNMS returned invalid data",
        ) from exc

    offset = (page - 1) * page_size
    selected_items = list(collection.items[offset : offset + page_size])
    return DeviceListResponse(
        items=selected_items,
        page=page,
        page_size=page_size,
        total=len(collection.items),
        freshness=Freshness(
            state="fresh",
            observed_at=collection.observed_at,
            source="librenms",
        ),
    )


@api.get(
    "/devices/{device_id}",
    response_model=DeviceDetailResponse,
    responses={
        **_STANDARD_ERROR_RESPONSES,
        404: {"model": ErrorEnvelope, "description": "Device not found"},
    },
    tags=["devices"],
)
async def device_detail(
    device_id: Annotated[str, Path(min_length=1, max_length=128)],
    _identity: DeviceReader,
    client: LibrenmsDependency,
) -> DeviceDetailResponse:
    try:
        device = await client.device(device_id)
        validate("device", device.model_dump(mode="json"))
    except DeviceNotFoundError as exc:
        raise ApiError(404, "DEVICE_NOT_FOUND", "Device was not found") from exc
    except AdapterError as exc:
        _raise_adapter_error(exc)
    except ContractViolation as exc:
        raise ApiError(
            502,
            "SOURCE_INVALID_DATA",
            "LibreNMS returned invalid data",
        ) from exc
    return DeviceDetailResponse(item=device)


@api.get(
    "/sources/netbox/health",
    response_model=SourceHealthResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["sources"],
)
async def netbox_health(
    _identity: DeviceReader,
    client: NetboxDependency,
) -> SourceHealthResponse:
    result = await client.health()
    return SourceHealthResponse.model_validate(
        {
            "source": result.source,
            "status": result.status.value,
            "reachable": result.reachable,
            "latency_ms": result.latency_ms,
            "checked_at": result.checked_at,
            "detail": result.detail,
        }
    )


@api.get(
    "/netbox/devices",
    response_model=DeviceListResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["devices"],
)
async def netbox_devices(
    _identity: DeviceReader,
    client: NetboxDependency,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> DeviceListResponse:
    try:
        collection = await client.devices()
        for device in collection.items:
            validate("device", device.model_dump(mode="json"))
    except NetboxAdapterError as exc:
        _raise_netbox_adapter_error(exc)
    except ContractViolation as exc:
        raise ApiError(
            502,
            "SOURCE_INVALID_DATA",
            "NetBox returned invalid data",
        ) from exc

    offset = (page - 1) * page_size
    selected_items = list(collection.items[offset : offset + page_size])
    return DeviceListResponse(
        items=selected_items,
        page=page,
        page_size=page_size,
        total=len(collection.items),
        freshness=Freshness(
            state="fresh",
            observed_at=collection.observed_at,
            source="netbox",
        ),
    )


@api.get(
    "/netbox/devices/{device_id}",
    response_model=DeviceDetailResponse,
    responses={
        **_STANDARD_ERROR_RESPONSES,
        404: {"model": ErrorEnvelope, "description": "Device not found"},
    },
    tags=["devices"],
)
async def netbox_device_detail(
    device_id: Annotated[str, Path(min_length=1, max_length=128)],
    _identity: DeviceReader,
    client: NetboxDependency,
) -> DeviceDetailResponse:
    try:
        device = await client.device(device_id)
        validate("device", device.model_dump(mode="json"))
    except NetboxDeviceNotFoundError as exc:
        raise ApiError(404, "DEVICE_NOT_FOUND", "Device was not found") from exc
    except NetboxAdapterError as exc:
        _raise_netbox_adapter_error(exc)
    except ContractViolation as exc:
        raise ApiError(
            502,
            "SOURCE_INVALID_DATA",
            "NetBox returned invalid data",
        ) from exc
    return DeviceDetailResponse(item=device)


@api.get(
    "/topology",
    response_model=TopologyResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["topology"],
)
async def topology(
    request: Request,
    _identity: DeviceReader,
    netbox: OptionalNetboxDependency,
    librenms: OptionalLibrenmsDependency,
) -> TopologyResponse:
    """Explicit topology state.

    NetBox active cables are the only edge source today. No source means
    not-connected; a configured source that cannot be read means unknown.
    The graph is never inferred from anything else. Reconciliation findings
    are attached to nodes (edge context) but never modify source data.
    """
    correlation_id = _request_correlation_id(request)
    if netbox is None:
        return TopologyResponse(
            state="not-connected",
            nodes=[],
            edges=[],
            freshness=Freshness(state="unknown", observed_at=None, source=None),
        )
    cables_result, devices_result, discovery_result = await asyncio.gather(
        _capture(netbox.cables()),
        _capture(netbox.devices()),
        _capture(librenms.devices()) if librenms is not None else _capture(_absent()),
    )
    if isinstance(cables_result, Exception):
        # Source configured but not confirmable: report unknown, never guess.
        _LOGGER.warning(
            "topology source read failed",
            extra={
                "correlation_id": correlation_id,
                "source": "netbox",
                "adapter_status": str(
                    getattr(cables_result, "status", "unknown")
                ),
            },
        )
        return TopologyResponse(
            state="unknown",
            nodes=[],
            edges=[],
            freshness=Freshness(state="unknown", observed_at=None, source="netbox"),
        )
    collection = cables_result
    # Device names are cosmetic: if the name lookup fails, nodes keep
    # name=None rather than the graph being dropped.
    names: dict[str, str] = {}
    netbox_devices: DeviceCollection | None
    if isinstance(devices_result, Exception):
        _LOGGER.warning(
            "topology node name lookup failed; nodes will carry no names",
            extra={
                "correlation_id": correlation_id,
                "source": "netbox",
                "adapter_status": str(
                    getattr(devices_result, "status", "unknown")
                ),
            },
        )
        netbox_devices = None
    else:
        netbox_devices = devices_result
        for device in netbox_devices.items:
            names[device.source_aliases[0].native_id] = device.name

    # Reconciliation: only reported when both sides were actually read, so
    # "not checked" is never presented as "in sync".
    discovered: DeviceCollection | None
    if isinstance(discovery_result, Exception):
        _LOGGER.warning(
            "topology reconciliation skipped; discovery source unavailable",
            extra={
                "correlation_id": correlation_id,
                "source": "librenms",
                "adapter_status": str(
                    getattr(discovery_result, "status", "unknown")
                ),
            },
        )
        discovered = None
    else:
        discovered = cast(DeviceCollection | None, discovery_result)

    reconciled = netbox_devices is not None and discovered is not None
    findings: dict[str, TopologyNodeFinding] = {}
    if netbox_devices is not None and discovered is not None:
        for finding in reconcile(
            list(netbox_devices.items), list(discovered.items)
        ):
            if finding.netbox_device_id is None:
                continue
            if finding.kind == "unknown-discovered":
                continue  # no NetBox node to attach it to
            findings[finding.netbox_device_id] = TopologyNodeFinding(
                kind=finding.kind,
                detail=finding.detail,
            )

    nodes_by_id: dict[str, str | None] = {}
    edges: list[TopologyEdge] = []
    for link in collection.links:
        source_id = netbox_canonical_device_id(link.device_a_native_id)
        target_id = netbox_canonical_device_id(link.device_b_native_id)
        if source_id == target_id:
            continue
        nodes_by_id.setdefault(source_id, names.get(link.device_a_native_id))
        nodes_by_id.setdefault(target_id, names.get(link.device_b_native_id))
        edges.append(
            TopologyEdge(
                source_device_id=source_id,
                target_device_id=target_id,
                source="netbox",
                observed_at=link.observed_at,
            )
        )
    try:
        response = TopologyResponse(
            state="ok",
            nodes=[
                TopologyNode(
                    device_id=node_id,
                    name=nodes_by_id[node_id],
                    reconciled=reconciled,
                    finding=findings.get(node_id),
                )
                for node_id in sorted(nodes_by_id)
            ],
            edges=edges,
            freshness=Freshness(
                state="fresh",
                observed_at=collection.observed_at,
                source="netbox",
            ),
        )
        # Canonical contract enforced at the boundary, like every other endpoint.
        validate("topology", response.model_dump(mode="json"))
    except (ValidationError, ContractViolation) as exc:
        _LOGGER.warning(
            "topology graph rejected by canonical contract",
            extra={
                "correlation_id": correlation_id,
                "source": "netbox",
                "error_type": type(exc).__name__,
            },
        )
        return TopologyResponse(
            state="unknown",
            nodes=[],
            edges=[],
            freshness=Freshness(state="unknown", observed_at=None, source="netbox"),
        )
    return response


_TRAFFIC_PRESETS: Mapping[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}
_TRAFFIC_MAX_WINDOW = timedelta(days=31)


def _resolve_traffic_window(
    preset: TrafficPreset,
    start: datetime | None,
    end: datetime | None,
) -> tuple[datetime, datetime, TrafficPreset | None]:
    """Resolve the requested window: explicit bounds or a bounded preset.

    Windows are server-bounded per API guidelines. Invalid combinations
    fail with 422 rather than silently substituting a different range.
    """
    if (start is None) != (end is None):
        raise ApiError(422, "VALIDATION_ERROR", "from and to must be provided together")
    if start is not None and end is not None:
        if start.tzinfo is None or end.tzinfo is None:
            raise ApiError(422, "VALIDATION_ERROR", "from and to must be timezone-aware")
        if start >= end:
            raise ApiError(422, "VALIDATION_ERROR", "from must be before to")
        if end - start > _TRAFFIC_MAX_WINDOW:
            raise ApiError(422, "VALIDATION_ERROR", "time window exceeds 31 days")
        return start.astimezone(UTC), end.astimezone(UTC), None
    duration = _TRAFFIC_PRESETS.get(preset)
    if duration is None:
        raise ApiError(422, "VALIDATION_ERROR", "unknown time preset")
    now = datetime.now(UTC)
    return now - duration, now, preset


async def _traffic_top(
    request: Request,
    source: TrafficSource | None,
    dimension: TrafficDimension,
    preset: TrafficPreset,
    start: datetime | None,
    end: datetime | None,
    limit: int,
) -> TrafficTopResponse:
    """Explicit traffic state: not-connected / unknown / source-reported ok."""
    window_start, window_end, resolved_preset = _resolve_traffic_window(
        preset, start, end
    )
    time_range = TrafficTimeRange.model_validate(
        {"from": window_start, "to": window_end, "preset": resolved_preset}
    )
    correlation_id = _request_correlation_id(request)

    def _degraded() -> TrafficTopResponse:
        return TrafficTopResponse(
            state="unknown",
            dimension=dimension,
            time_range=time_range,
            items=[],
            freshness=Freshness(state="unknown", observed_at=None, source="clickhouse"),
        )

    if source is None:
        return TrafficTopResponse(
            state="not-connected",
            dimension=dimension,
            time_range=time_range,
            items=[],
            freshness=Freshness(state="unknown", observed_at=None, source=None),
        )
    result = await _capture(
        source.top(dimension=dimension, start=window_start, end=window_end, limit=limit)
    )
    if isinstance(result, Exception):
        # Source configured but not confirmable: unknown, never guess.
        _LOGGER.warning(
            "traffic source read failed",
            extra={
                "correlation_id": correlation_id,
                "source": "clickhouse",
                "error_type": type(result).__name__,
            },
        )
        return _degraded()
    items, observed_at = result
    response = TrafficTopResponse(
        state="ok",
        dimension=dimension,
        time_range=time_range,
        items=items,
        freshness=Freshness(state="fresh", observed_at=observed_at, source="clickhouse"),
    )
    try:
        validate("traffic_top", response.model_dump(mode="json", by_alias=True))
    except ContractViolation:
        _LOGGER.warning(
            "traffic response rejected by canonical contract",
            extra={
                "correlation_id": correlation_id,
                "source": "clickhouse",
                "error_type": "ContractViolation",
            },
        )
        return _degraded()
    return response


@api.get(
    "/traffic/top-talkers",
    response_model=TrafficTopResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["traffic"],
)
async def traffic_top_talkers(
    request: Request,
    _identity: TrafficReader,
    source: OptionalTrafficDependency,
    preset: Annotated[TrafficPreset, Query()] = "24h",
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> TrafficTopResponse:
    """Top talkers for a bounded window.

    States are explicit: not-connected without a source, unknown when the
    source read fails, ok only with source-reported aggregates.
    """
    return await _traffic_top(request, source, "talkers", preset, start, end, limit)


@api.get(
    "/traffic/top-destinations",
    response_model=TrafficTopResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["traffic"],
)
async def traffic_top_destinations(
    request: Request,
    _identity: TrafficReader,
    source: OptionalTrafficDependency,
    preset: Annotated[TrafficPreset, Query()] = "24h",
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> TrafficTopResponse:
    """Top destinations for a bounded window (same explicit states)."""
    return await _traffic_top(
        request, source, "destinations", preset, start, end, limit
    )


@api.get(
    "/traffic/flows",
    response_model=TrafficFlowsResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["traffic"],
)
async def traffic_flows(
    request: Request,
    _identity: TrafficReader,
    source: OptionalTrafficDependency,
    preset: Annotated[TrafficPreset, Query()] = "24h",
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> TrafficFlowsResponse:
    """Recent high-volume flows for a bounded window (explicit states)."""
    window_start, window_end, resolved_preset = _resolve_traffic_window(
        preset, start, end
    )
    time_range = TrafficTimeRange.model_validate(
        {"from": window_start, "to": window_end, "preset": resolved_preset}
    )
    correlation_id = _request_correlation_id(request)

    def _degraded() -> TrafficFlowsResponse:
        return TrafficFlowsResponse(
            state="unknown",
            time_range=time_range,
            flows=[],
            freshness=Freshness(state="unknown", observed_at=None, source="clickhouse"),
        )

    if source is None:
        return TrafficFlowsResponse(
            state="not-connected",
            time_range=time_range,
            flows=[],
            freshness=Freshness(state="unknown", observed_at=None, source=None),
        )
    result = await _capture(
        source.flows(start=window_start, end=window_end, limit=limit)
    )
    if isinstance(result, Exception):
        _LOGGER.warning(
            "traffic flow source read failed",
            extra={
                "correlation_id": correlation_id,
                "source": "clickhouse",
                "error_type": type(result).__name__,
            },
        )
        return _degraded()
    flows, observed_at = result
    response = TrafficFlowsResponse(
        state="ok",
        time_range=time_range,
        flows=flows,
        freshness=Freshness(state="fresh", observed_at=observed_at, source="clickhouse"),
    )
    try:
        validate("traffic_flows", response.model_dump(mode="json", by_alias=True))
    except ContractViolation:
        _LOGGER.warning(
            "traffic flow response rejected by canonical contract",
            extra={
                "correlation_id": correlation_id,
                "source": "clickhouse",
                "error_type": "ContractViolation",
            },
        )
        return _degraded()
    return response


@api.get(
    "/reconcile/findings",
    response_model=ReconciliationFindingsResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["reconciliation"],
)
async def reconcile_findings(
    _identity: DeviceReader,
    netbox: NetboxDependency,
    librenms: LibrenmsDependency,
) -> ReconciliationFindingsResponse:
    try:
        netbox_collection = await netbox.devices()
    except NetboxAdapterError as exc:
        _raise_netbox_adapter_error(exc)
    try:
        discovered_collection = await librenms.devices()
    except AdapterError as exc:
        _raise_adapter_error(exc)
    findings = reconcile(list(netbox_collection.items), list(discovered_collection.items))
    return ReconciliationFindingsResponse(
        items=[
            ReconciliationFinding(
                kind=f.kind,
                netbox_device_id=f.netbox_device_id,
                discovered_device_id=f.discovered_device_id,
                detail=f.detail,
            )
            for f in findings
        ]
    )


@api.get(
    "/alerts",
    response_model=AlertListResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["alerts"],
)
async def alerts(
    _identity: AlertReader,
    client: LibrenmsDependency,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> AlertListResponse:
    try:
        rows = await client.alerts()
        observed_at = datetime.now(UTC)
        for row in rows:
            validate("alert", row)
        typed_rows = [Alert.model_validate(row) for row in rows]
    except AdapterError as exc:
        _raise_adapter_error(exc)
    except (ContractViolation, ValidationError) as exc:
        raise ApiError(
            502,
            "SOURCE_INVALID_DATA",
            "LibreNMS returned invalid data",
        ) from exc

    offset = (page - 1) * page_size
    return AlertListResponse(
        items=typed_rows[offset : offset + page_size],
        page=page,
        page_size=page_size,
        total=len(typed_rows),
        freshness=Freshness(
            state="fresh",
            observed_at=observed_at,
            source="librenms",
        ),
    )


@api.get(
    "/devices/{device_id}/interfaces",
    response_model=InterfaceListResponse,
    responses={
        **_STANDARD_ERROR_RESPONSES,
        404: {"model": ErrorEnvelope, "description": "Device not found"},
    },
    tags=["interfaces"],
)
async def device_interfaces(
    device_id: Annotated[str, Path(min_length=1, max_length=128)],
    _identity: DeviceReader,
    client: LibrenmsDependency,
) -> InterfaceListResponse:
    """Canonical interface records for one device (NS-022).

    Interfaces the source does not report keep an explicit ``unknown`` state;
    Netsight does not infer a healthy link from missing data.
    """
    try:
        device = await client.device(device_id)
    except DeviceNotFoundError as exc:
        raise ApiError(404, "DEVICE_NOT_FOUND", "Device was not found") from exc
    except AdapterError as exc:
        _raise_adapter_error(exc)

    native_device_id = device.source_aliases[0].native_id
    try:
        collection = await client.interfaces(native_device_id)
        for interface in collection.items:
            validate("interface", interface.model_dump(mode="json"))
    except AdapterError as exc:
        _raise_adapter_error(exc)
    except ContractViolation as exc:
        raise ApiError(
            502,
            "SOURCE_INVALID_DATA",
            "LibreNMS returned invalid data",
        ) from exc

    return InterfaceListResponse(
        items=list(collection.items),
        total=len(collection.items),
        freshness=Freshness(
            state="fresh",
            observed_at=collection.observed_at,
            source="librenms",
        ),
    )


async def _netbox_source_state() -> SourceState:
    """NetBox may be unconfigured in dev; report that rather than failing the page."""
    base_url = os.environ.get("NETBOX_BASE_URL", "").strip()
    token = os.environ.get("NETBOX_TOKEN", "").strip()
    if not base_url or not token:
        return SourceState(configured=False, status="not-configured")
    client = NetboxClient(base_url=base_url, token=token)
    health = await client.health()
    if health.status is NetboxAdapterStatus.SUCCESS:
        return SourceState(configured=True, status="success")
    if health.status is NetboxAdapterStatus.FORBIDDEN:
        return SourceState(configured=True, status="forbidden")
    if health.status is NetboxAdapterStatus.INVALID_SOURCE_DATA:
        return SourceState(configured=True, status="invalid-source-data")
    return SourceState(configured=True, status="unavailable")


@api.get(
    "/overview",
    response_model=OverviewResponse,
    responses=_STANDARD_ERROR_RESPONSES,
    tags=["platform"],
)
async def overview(
    _identity: DeviceReader,
    client: LibrenmsDependency,
) -> OverviewResponse:
    """Aggregate operational summary for the network overview page.

    Returns canonical device health counts and per-source state. Panels
    without a connected source render explicit unknown states in the UI;
    this endpoint never fabricates values for unavailable sources.
    """
    try:
        collection = await client.devices()
        for device in collection.items:
            validate("device", device.model_dump(mode="json"))
    except AdapterError as exc:
        _raise_adapter_error(exc)
    except ContractViolation as exc:
        raise ApiError(
            502,
            "SOURCE_INVALID_DATA",
            "LibreNMS returned invalid data",
        ) from exc

    counts: dict[str, int] = {}
    for device in collection.items:
        counts[device.status] = counts.get(device.status, 0) + 1
    ordered_statuses: tuple[DeviceStatus, ...] = (
        "healthy",
        "warning",
        "degraded",
        "critical",
        "offline",
        "unknown",
        "maintenance",
    )
    by_status = [
        DeviceStatusCount(status=status, count=counts.get(status, 0))
        for status in ordered_statuses
    ]
    return OverviewResponse(
        devices=DeviceHealthSummary(
            total=len(collection.items),
            by_status=by_status,
            freshness=Freshness(
                state="fresh",
                observed_at=collection.observed_at,
                source="librenms",
            ),
        ),
        sources={
            "librenms": SourceState(
                configured=True,
                status="success",
            ),
            "netbox": await _netbox_source_state(),
        },
    )


app.include_router(api)
# Authentication lives under the same versioned prefix as every other platform
# route (contracts/openapi/netsight-api.yaml declares `servers: /api/v1` with
# `/auth/providers` relative to it). Serving it unversioned broke the server
# components, which read the session through the versioned prefix.
app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(localauth_router, prefix=API_PREFIX)
