"""Security Centre read API (S5): explicit-state security events.

Events come from the read-only Wazuh indexer adapter (which also carries
Suricata EVE alerts), wired from ``WAZUH_INDEXER_URL`` / ``_USER`` /
``_PASSWORD``. While it is unset the endpoint reports ``not-connected`` and
never fabricates events.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, Protocol
from uuid import uuid4

from fastapi import APIRouter, Depends, Query, Request
from pydantic import ValidationError

from netsight_api.adapters.wazuh import AdapterError, WazuhIndexerClient
from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import ContractViolation, validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
from netsight_api.schemas import (
    ErrorEnvelope,
    Freshness,
    SecurityEvent,
    SecurityEventsResponse,
    TrafficPreset,
    TrafficTimeRange,
)
from netsight_api.timewindow import resolve_window

_LOGGER = logging.getLogger("netsight_api")
_FRESH_THRESHOLD = timedelta(hours=1)
_SOURCE_LABEL = "security-events"

router = APIRouter()

_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
}


class SecuritySource(Protocol):
    """Read-only security event source (Wazuh / Suricata adapters)."""

    async def events(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[list[SecurityEvent], datetime | None]:
        """Return events and the newest event timestamp included.

        ``None`` means the window carried no events: the read succeeded but
        reports no data currency.
        """
        ...


def get_optional_security_source() -> SecuritySource | None:
    """Wazuh-indexer source when configured; None = not-connected.

    A configured-but-invalid URL still yields a client: its reads then fail
    and the endpoint degrades to explicit ``unknown`` — configured does not
    imply connected.
    """
    url = os.environ.get("WAZUH_INDEXER_URL", "").strip()
    if not url:
        return None
    ca_bundle = os.environ.get("WAZUH_INDEXER_CA_BUNDLE", "").strip()
    # Plain http with credentials is a development-only escape hatch: it needs the flag
    # and NETSIGHT_ENV=development, so a production host can never enable it by flag alone.
    allow_http = (
        os.environ.get("WAZUH_INDEXER_ALLOW_HTTP", "").strip().lower() == "true"
        and os.environ.get("NETSIGHT_ENV", "").strip().lower() == "development"
    )
    return WazuhIndexerClient(
        base_url=url,
        user=os.environ.get("WAZUH_INDEXER_USER", "").strip(),
        password=os.environ.get("WAZUH_INDEXER_PASSWORD", ""),
        index_pattern=os.environ.get("WAZUH_ALERTS_INDEX", "").strip() or "wazuh-alerts-*",
        verify=ca_bundle or True,
        allow_insecure_http=allow_http,
    )


OptionalSecuritySource = Annotated[SecuritySource | None, Depends(get_optional_security_source)]
CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]


def require_security_reader(identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.SECURITY_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    enforce_read_limit(identity, "security")
    return identity


SecurityReader = Annotated[Identity, Depends(require_security_reader)]


def _freshness(window_end: datetime, observed_at: datetime | None) -> Freshness:
    if observed_at is None:
        return Freshness(state="unknown", observed_at=None, source=_SOURCE_LABEL)
    return Freshness(
        state="fresh" if observed_at >= window_end - _FRESH_THRESHOLD else "stale",
        observed_at=observed_at,
        source=_SOURCE_LABEL,
    )


def _validated(body: SecurityEventsResponse) -> SecurityEventsResponse:
    """Canonical boundary validation applied on every return path."""
    validate("security_events", body.model_dump(mode="json", by_alias=True))
    return body


def _correlation_id(request: Request) -> str:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else str(uuid4())


@router.get(
    "/security/events",
    response_model=SecurityEventsResponse,
    responses=_ERROR_RESPONSES,
    tags=["security"],
)
async def security_events(
    request: Request,
    _identity: SecurityReader,
    source: OptionalSecuritySource,
    preset: Annotated[TrafficPreset, Query()] = "24h",
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> SecurityEventsResponse:
    """Security events for a bounded window with explicit source state.

    not-connected without a source; unknown when the read fails or returns a
    contract-invalid row; ok only with source-reported events.
    """
    window_start, window_end, resolved_preset = resolve_window(preset, start, end)
    time_range = TrafficTimeRange.model_validate(
        {"from": window_start, "to": window_end, "preset": resolved_preset}
    )

    def _empty(
        state: Literal["not-connected", "unknown"], freshness: Freshness
    ) -> SecurityEventsResponse:
        return _validated(
            SecurityEventsResponse(
                state=state, time_range=time_range, events=[], freshness=freshness
            )
        )

    if source is None:
        return _empty("not-connected", Freshness(state="unknown", observed_at=None, source=None))
    degraded = Freshness(state="unknown", observed_at=None, source=_SOURCE_LABEL)
    try:
        events, observed_at = await source.events(start=window_start, end=window_end, limit=limit)
    except Exception as exc:  # noqa: BLE001 — deliberate source-read boundary
        _LOGGER.warning(
            "security source read failed",
            extra={
                "correlation_id": _correlation_id(request),
                "error_type": type(exc).__name__,
                "adapter_status": exc.status.value if isinstance(exc, AdapterError) else None,
            },
        )
        return _empty("unknown", degraded)
    try:
        return _validated(
            SecurityEventsResponse(
                state="ok",
                time_range=time_range,
                events=events,
                freshness=_freshness(window_end, observed_at),
            )
        )
    except (ValidationError, ContractViolation) as exc:
        _LOGGER.warning(
            "security response rejected by canonical contract",
            extra={
                "correlation_id": _correlation_id(request),
                "error_type": type(exc).__name__,
            },
        )
        return _empty("unknown", degraded)
