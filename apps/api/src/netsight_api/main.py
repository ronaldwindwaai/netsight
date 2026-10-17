"""Netsight platform API entrypoint."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections.abc import AsyncIterator, Awaitable, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
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

from netsight_api.adapters.clickhouse_shared import shared_client
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
from netsight_api.alert_rule_routes import router as alert_rule_router
from netsight_api.audit import configure_audit_logging
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.oidc import aclose as oidc_aclose
from netsight_api.auth.routes import router as auth_router
from netsight_api.auth.settings import session_policy
from netsight_api.body_limit import BodySizeLimitMiddleware
from netsight_api.configuration_routes import router as configuration_router
from netsight_api.contracts import ContractViolation, validate
from netsight_api.diagnostic_routes import router as diagnostic_router
from netsight_api.diagnostic_session_routes import router as diagnostic_session_router
from netsight_api.errors import ApiError
from netsight_api.evaluation.wiring import build_evaluation_service, start_evaluation
from netsight_api.identity_routes import router as identity_router
from netsight_api.incident_list_routes import router as incident_list_router
from netsight_api.incident_routes import router as incident_router
from netsight_api.internet_routes import router as internet_router
from netsight_api.inventory_routes import router as inventory_router
from netsight_api.ipam_routes import router as ipam_router
from netsight_api.localauth.routes import router as localauth_router
from netsight_api.maintenance_routes import router as maintenance_router
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
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
    TrafficItem,
)
from netsight_api.security_routes import router as security_router
from netsight_api.traffic_routes import router as traffic_router
from netsight_api.unknown_device_routes import router as unknown_device_router
from netsight_api.unknown_devices.wiring import build_scan_service, start_scan
from netsight_api.wan.wiring import build_wan_collector, start_wan_sampling

API_PREFIX = "/api/v1"
CORRELATION_ID_HEADER = "X-Correlation-ID"
_CORRELATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_LOGGER = logging.getLogger("netsight_api")


@asynccontextmanager
async def lifespan(app_: FastAPI) -> AsyncIterator[None]:
    # Fail fast on an unsafe session policy (for example SameSite=None without opt-in), on an
    # invalid audit-log setting and on an enabled-but-unbuildable evaluator, instead of failing
    # on the first request (or, worse, running a weaker evaluator than configured).
    session_policy()
    configure_audit_logging()
    service = build_evaluation_service(librenms_client=get_optional_librenms_client)
    # All three services are built before any starts: a bad setting fails start-up, not later.
    wan_service = build_wan_collector()
    scan_service = build_scan_service()
    evaluation = start_evaluation(service)
    app_.state.evaluation_task = evaluation.task
    wan_sampling = start_wan_sampling(wan_service)
    app_.state.wan_sampling_task = wan_sampling.task
    unknown_scan = start_scan(scan_service)
    app_.state.unknown_scan_task = unknown_scan.task
    try:
        yield
    finally:
        await unknown_scan.shutdown()
        app_.state.unknown_scan_task = None
        await wan_sampling.shutdown()
        app_.state.wan_sampling_task = None
        await evaluation.shutdown()
        app_.state.evaluation_task = None
        await oidc_aclose()


# Routes whose error responses must carry ``Cache-Control: no-store`` as well (the success path sets
# it in the route): the people and identity surfaces.
_NO_STORE_ERROR_PREFIXES = (
    f"{API_PREFIX}/users",
    f"{API_PREFIX}/identity/",
    f"{API_PREFIX}/traffic/",
    f"{API_PREFIX}/config/",
)

app = FastAPI(title="Netsight Platform API", version="0.1.0", lifespan=lifespan)
# Registered before the correlation middleware below, so it runs inside it and its 413
# responses carry the request's correlation id.
app.add_middleware(BodySizeLimitMiddleware)
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
    if response.status_code >= 400 and request.url.path.startswith(_NO_STORE_ERROR_PREFIXES):
        # Per-user routes: not even an error (a 403 for a named person, a 429) may be stored.
        response.headers["Cache-Control"] = "no-store"
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


OptionalNetboxDependency = Annotated[NetboxClient | None, Depends(get_optional_netbox_client)]


def get_optional_librenms_client() -> LibrenmsClient | None:
    """LibreNMS client when configured, else None (reconciliation not checked)."""
    try:
        return get_client()
    except ApiError:
        return None


OptionalLibrenmsDependency = Annotated[LibrenmsClient | None, Depends(get_optional_librenms_client)]


class TrafficSource(Protocol):
    """Read-only, bounded flow source (the ClickHouse client).

    Implementations must run parameterised queries with explicit time
    bounds and a row limit; they never receive unbounded requests.

    ``top`` ranks raw addresses and is NOT reachable from any route of the
    aggregate tier: the legacy ``/traffic/top-*`` routes were retired because
    they bypassed the small-cohort rule. Its one remaining caller is the
    identity service (per-person traffic), which is handed the source only for
    a caller holding ``traffic:read-detail`` (see ``identity_routes``).
    """

    async def top(
        self,
        *,
        dimension: TrafficDimension,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[list[TrafficItem], datetime | None]:
        """Return ranked items and the newest flow timestamp included.

        ``None`` means the window carried no rows: the read succeeded but
        reports no data currency.
        """
        ...


def get_optional_traffic_source() -> TrafficSource | None:
    """ClickHouse-backed flow source when configured; None = not-connected.

    A configured-but-invalid DSN still yields a client: its queries then
    fail and the endpoints degrade to explicit ``unknown`` — configured
    does not imply connected (same rule as the S3 NetBox decision). The client
    is shared for the life of the process while the configuration is unchanged.
    """
    return shared_client()


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
    enforce_read_limit(identity, "devices")
    return identity


def require_alert_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.ALERTS_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    enforce_read_limit(identity, "alerts")
    return identity


DeviceReader = Annotated[Identity, Depends(require_device_reader)]
AlertReader = Annotated[Identity, Depends(require_alert_reader)]

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
                "adapter_status": str(getattr(cables_result, "status", "unknown")),
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
                "adapter_status": str(getattr(devices_result, "status", "unknown")),
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
                "adapter_status": str(getattr(discovery_result, "status", "unknown")),
            },
        )
        discovered = None
    else:
        discovered = cast(DeviceCollection | None, discovery_result)

    reconciled = netbox_devices is not None and discovered is not None
    findings: dict[str, TopologyNodeFinding] = {}
    if netbox_devices is not None and discovered is not None:
        for finding in reconcile(list(netbox_devices.items), list(discovered.items)):
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
        DeviceStatusCount(status=status, count=counts.get(status, 0)) for status in ordered_statuses
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
app.include_router(security_router, prefix=API_PREFIX)
# The list router first: its static /incidents/summary must precede /incidents/{incident_id}.
app.include_router(incident_list_router, prefix=API_PREFIX)
app.include_router(incident_router, prefix=API_PREFIX)
app.include_router(alert_rule_router, prefix=API_PREFIX)
app.include_router(maintenance_router, prefix=API_PREFIX)
app.include_router(diagnostic_router, prefix=API_PREFIX)
app.include_router(diagnostic_session_router, prefix=API_PREFIX)
app.include_router(internet_router, prefix=API_PREFIX)
app.include_router(identity_router, prefix=API_PREFIX)
app.include_router(configuration_router, prefix=API_PREFIX)
app.include_router(inventory_router, prefix=API_PREFIX)
app.include_router(ipam_router, prefix=API_PREFIX)
app.include_router(unknown_device_router, prefix=API_PREFIX)
app.include_router(traffic_router, prefix=API_PREFIX)
# Authentication lives under the same versioned prefix as every other platform
# route (contracts/openapi/netsight-api.yaml declares `servers: /api/v1` with
# `/auth/providers` relative to it). Serving it unversioned broke the server
# components, which read the session through the versioned prefix.
app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(localauth_router, prefix=API_PREFIX)
