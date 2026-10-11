"""Internet/WAN routes (Step 5): ``GET /api/v1/internet``, ``/internet/sla`` and ``/internet/sla/export``.

Read-only. Every route needs ``internet:read`` (the export needs ``internet:export``; the ISP name,
gateway, public IP and throughput need ``internet:read_detail`` and are withheld otherwise), is rate
limited per identity *after* authorisation (an unauthorised caller never learns limiter state),
and answers an explicit state instead of a guess:

* nothing declared / no sample store: ``not-connected``;
* an unusable declaration, a failing source or store, or a response that fails its own canonical
  contract: ``unknown`` (HTTP 200, no values, nothing the source said);
* months are server-bounded (the current month back to 24 months): anything else is a 422.

Sources are LibreNMS port readings (existing read-only adapter) and the append-only probe-sample
store; the routes themselves never probe, write or send. The export is audited (actor, month,
format, link and row counts, and a failure outcome when the state is unknown; never its content). Operator-declared text (link names, ISP) and any value a source
reported is returned as data and never interpreted.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from functools import cache, partial
from typing import Annotated, Literal, NoReturn, cast

from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response

from netsight_api.alerting_route_support import READ_ERRORS, correlation_id
from netsight_api.audit import record_audit
from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
from netsight_api.schemas_internet import (
    MONTH_PATTERN,
    InternetResponse,
    SlaExport,
    SlaResponse,
    WanFailover,
)
from netsight_api.storage import StorageConfigurationError, StorageError
from netsight_api.storage.wan import WanSampleRepository, cycle_read_cap
from netsight_api.wan import sla
from netsight_api.wan.config import (
    DEFAULT_INTERVAL_SECONDS,
    LINKS_ENV,
    SamplingSettings,
    WanConfig,
    load_wan_links,
)
from netsight_api.wan.reading import WanPortSource, build_internet, redact_detail
from netsight_api.wan.sla_report import (
    BASIS,
    ClosedMonthCache,
    build_export,
    build_sla,
    export_csv,
)

_LOGGER = logging.getLogger("netsight_api")

router = APIRouter(prefix="/internet", tags=["internet"])

STATUS_FAMILY = "internet"
SLA_FAMILY = "internet-sla"
EXPORT_FAMILY = "internet-export"
SLA_LIMIT_PER_MINUTE = 30
EXPORT_LIMIT_PER_MINUTE = 10
_FORMAT_PATTERN = r"^(json|csv)$"
_MONTH_RE = re.compile(MONTH_PATTERN)

CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]


# --- wiring (overridden in tests) -----------------------------------------------------------------


def get_now() -> datetime:
    return datetime.now(UTC)


@cache
def _declared(raw: str) -> WanConfig:
    """Parsed once per distinct declaration (a bad one is logged once, not on every request)."""
    return load_wan_links({LINKS_ENV: raw})


def get_wan_config() -> WanConfig:
    return _declared(os.environ.get(LINKS_ENV, ""))


def get_wan_ports() -> WanPortSource | None:
    """The configured LibreNMS client; ``main`` is imported lazily because it owns the factory."""
    from netsight_api import main

    return cast("WanPortSource | None", main.get_optional_librenms_client())


class _UnavailableStore:
    """Stands in when ``DATABASE_URL`` is set but unusable: every call fails as unavailable."""

    def __getattr__(self, name: str) -> Callable[..., NoReturn]:
        def unavailable(*_args: object, **_kwargs: object) -> NoReturn:
            raise StorageError("the WAN sample store is not usable")

        return unavailable


def _cycle_cap() -> int:
    """The read cap for the configured sampling interval (the default's if it is unusable)."""
    try:
        interval = SamplingSettings.from_env(os.environ).interval_seconds
    except ValueError:
        interval = DEFAULT_INTERVAL_SECONDS  # the collector, not a read, reports a bad setting
    return cycle_read_cap(interval)


def get_wan_store() -> WanSampleRepository | None:
    """PostgreSQL store for the app role (``DATABASE_URL``, SELECT only on the WAN tables);
    ``None`` means not-connected."""
    if not os.environ.get("DATABASE_URL", "").strip():
        return None
    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.postgres_wan import PostgresWanSampleRepository

    try:
        settings = PostgresSettings.from_env()
    except StorageConfigurationError:
        return cast(WanSampleRepository, _UnavailableStore())
    return PostgresWanSampleRepository(settings, max_cycles=_cycle_cap())


@cache
def get_closed_month_cache() -> ClosedMonthCache:
    """One memo per process for months that can no longer change (see ``wan.sla_report``)."""
    return ClosedMonthCache()


Now = Annotated[datetime, Depends(get_now)]
MonthCache = Annotated[ClosedMonthCache, Depends(get_closed_month_cache)]
Config = Annotated[WanConfig, Depends(get_wan_config)]
Ports = Annotated[WanPortSource | None, Depends(get_wan_ports)]
Store = Annotated[WanSampleRepository | None, Depends(get_wan_store)]


# --- authorisation, then the rate limit ----------------------------------------------------------------


def _reader(family: str, limit: int | None = None) -> Callable[[Identity], Identity]:
    def dependency(identity: CurrentIdentity) -> Identity:
        if not is_allowed(identity, Permission.INTERNET_READ.value):
            raise ApiError(403, "FORBIDDEN", "Permission is required")
        if limit is None:
            enforce_read_limit(identity, family)
        else:
            enforce_read_limit(identity, family, limit)
        return identity

    return dependency


require_status_reader = _reader(STATUS_FAMILY)
require_sla_reader = _reader(SLA_FAMILY, SLA_LIMIT_PER_MINUTE)


def require_exporter(request: Request, identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.INTERNET_EXPORT.value):
        record_audit(
            "internet.export",
            outcome="denied",
            actor_id=identity.id,
            correlation_id=correlation_id(request),
            reason="permission",
        )
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    enforce_read_limit(identity, EXPORT_FAMILY, EXPORT_LIMIT_PER_MINUTE)
    return identity


StatusReader = Annotated[Identity, Depends(require_status_reader)]
SlaReader = Annotated[Identity, Depends(require_sla_reader)]
Exporter = Annotated[Identity, Depends(require_exporter)]
MonthQuery = Annotated[
    str | None,
    Query(pattern=MONTH_PATTERN, min_length=7, max_length=7, description="UTC month, YYYY-MM"),
]


def _month(month: str | None, now: datetime) -> str:
    """The requested month, or the current one; out-of-range months are a 422, never substituted."""
    chosen = month if month is not None else f"{now.astimezone(UTC):%Y-%m}"
    try:
        sla.month_window(chosen, now)
    except ValueError as error:
        raise ApiError(
            422, "VALIDATION_ERROR", "month must be YYYY-MM, this month or up to 24 months ago"
        ) from error
    return chosen


# --- GET /internet -----------------------------------------------------------------------------------


def _unknown_internet(now: datetime, *, detail: bool) -> InternetResponse:
    return InternetResponse(
        state="unknown",
        generated_at=now,
        links=[],
        failover=WanFailover(state="unknown", basis="unknown"),
        detail_redacted=not detail,
    )


@router.get(
    "",
    response_model=InternetResponse,
    responses=READ_ERRORS,
    operation_id="getInternet",
)
async def get_internet(
    request: Request,
    identity: StatusReader,
    config: Config,
    ports: Ports,
    store: Store,
    now: Now,
) -> InternetResponse:
    """Per-link WAN status from LibreNMS and stored probe samples; every field reported or null."""
    detail = is_allowed(identity, Permission.INTERNET_READ_DETAIL.value)
    try:
        body = await build_internet(config, ports, store, now)
        if not detail:
            body = redact_detail(body)
        validate("internet_response", body.model_dump(mode="json", by_alias=True))
    except Exception as error:  # noqa: BLE001 - a source or contract failure is `unknown`, not a 500
        _LOGGER.warning(
            "internet reading failed",
            extra={"correlation_id": correlation_id(request), "error_type": type(error).__name__},
        )
        return _unknown_internet(now, detail=detail)
    return body


# --- GET /internet/sla ---------------------------------------------------------------------------------


def _unknown_sla(month: str, now: datetime) -> SlaResponse:
    return SlaResponse(
        state="unknown", month=month, period_start=None, period_end=None, generated_at=now, links=[]
    )


@router.get(
    "/sla",
    response_model=SlaResponse,
    responses=READ_ERRORS,
    operation_id="getInternetSla",
)
async def get_internet_sla(
    request: Request,
    _identity: SlaReader,
    config: Config,
    store: Store,
    now: Now,
    cache: MonthCache,
    month: MonthQuery = None,
) -> SlaResponse:
    """Uptime, downtime, degraded time and violations for one month, from stored probe cycles."""
    chosen = _month(month, now)
    try:
        body = await run_in_threadpool(partial(build_sla, config, store, chosen, now, cache=cache))
        validate("internet_sla_response", body.model_dump(mode="json", by_alias=True))
    except Exception as error:  # noqa: BLE001 - a store or contract failure is `unknown`
        _LOGGER.warning(
            "internet SLA failed",
            extra={"correlation_id": correlation_id(request), "error_type": type(error).__name__},
        )
        return _unknown_sla(chosen, now)
    return body


# --- GET /internet/sla/export ----------------------------------------------------------------------------


def _unknown_export(month: str, now: datetime, *, detail: bool) -> SlaExport:
    return SlaExport(
        state="unknown",
        month=month,
        period_start=None,
        period_end=None,
        generated_at=now,
        basis=BASIS,
        detail_redacted=not detail,
        links=[],
    )


def _attachment(month: str, extension: str) -> dict[str, str]:
    # The filename carries only the month, so it must be digits and a hyphen (never reflected text).
    if _MONTH_RE.fullmatch(month) is None:
        raise ValueError("month is not a valid YYYY-MM value")
    return {
        "Content-Disposition": f'attachment; filename="netsight-wan-sla-{month}.{extension}"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }


def _audit_export(
    request: Request, identity: Identity, month: str, fmt: str, export: SlaExport
) -> None:
    """Audit the export: a failure when the evidence could not be read (state unknown)."""
    record_audit(
        "internet.export",
        outcome="failure" if export.state == "unknown" else "success",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        target=month,
        format=fmt,
        state=export.state,
        link_count=len(export.links),
        row_count=sum(len(item.windows) for item in export.links),
    )


@router.get(
    "/sla/export",
    response_model=None,
    responses={
        **READ_ERRORS,
        200: {
            "model": SlaExport,
            "description": "The evidence as JSON, or as CSV with format=csv",
            "content": {"text/csv": {"schema": {"type": "string"}}},
        },
    },
    operation_id="exportInternetSla",
)
async def export_internet_sla(
    request: Request,
    identity: Exporter,
    config: Config,
    store: Store,
    now: Now,
    cache: MonthCache,
    month: MonthQuery = None,
    format: Annotated[Literal["json", "csv"], Query(pattern=_FORMAT_PATTERN)] = "json",
) -> Response:
    """Bounded, read-only evidence of outage, degraded and unknown windows for an ISP dispute."""
    chosen = _month(month, now)
    detail = is_allowed(identity, Permission.INTERNET_READ_DETAIL.value)
    try:
        export = await run_in_threadpool(
            partial(build_export, config, store, chosen, now, detail=detail, cache=cache)
        )
        payload = export.model_dump(mode="json", by_alias=True)
        validate("internet_sla_export", payload)
    except Exception as error:  # noqa: BLE001 - a store or contract failure is `unknown`
        _LOGGER.warning(
            "internet export failed",
            extra={"correlation_id": correlation_id(request), "error_type": type(error).__name__},
        )
        export = _unknown_export(chosen, now, detail=detail)
        payload = export.model_dump(mode="json", by_alias=True)
    _audit_export(request, identity, chosen, format, export)
    if format == "csv":
        return Response(
            content=export_csv(export),
            media_type="text/csv; charset=utf-8",
            headers=_attachment(chosen, "csv"),
        )
    return Response(
        content=json.dumps(payload),
        media_type="application/json",
        headers=_attachment(chosen, "json"),
    )
