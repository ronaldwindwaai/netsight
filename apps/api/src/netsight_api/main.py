"""Netsight platform API entrypoint."""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Any, NoReturn
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
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.oidc import aclose as oidc_aclose
from netsight_api.auth.routes import router as auth_router
from netsight_api.contracts import ContractViolation, validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
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
    SourceHealthResponse,
    SourceState,
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


CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]
LibrenmsDependency = Annotated[LibrenmsClient, Depends(get_client)]


def require_device_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.DEVICES_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    return identity


def require_alert_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.ALERTS_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
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
            )
        },
    )


app.include_router(api)
app.include_router(auth_router)
