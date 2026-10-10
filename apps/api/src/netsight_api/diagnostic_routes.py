"""Diagnostics API (S7-2): ``POST /api/v1/diagnostics``.

A bounded, read-only diagnostic run. It is a cookie-authenticated POST that performs privileged
outbound probing, so it meets the same guard order as the alerting writes: authorise
(``diagnostics:read``, deny by default) -> CSRF token and origin -> per-identity rate limit.
Every refusal and every run outcome is audited.

The probe client is allowlisted and bounded (``adapters.blackbox``): with no allow-list configured
the endpoint answers an explicit ``not-connected`` state rather than pretending a check ran; a
probe that raises or that exceeds the overall run budget answers ``unknown`` without leaking a
driver message. A run is created by a POST: there is no read-by-id yet, so listing the collection
is deliberately absent.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request

from netsight_api.adapters.blackbox import (
    BlackboxClient,
    get_optional_blackbox_client,
    run_checks,
)
from netsight_api.alerting_route_support import READ_ERRORS, audit_refusal, correlation_id
from netsight_api.audit import record_audit
from netsight_api.auth.csrf import write_refusal
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.diagnostics import Observation, build_run
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.schemas import ErrorEnvelope
from netsight_api.schemas_diagnostics import DiagnosticRunRequest, DiagnosticRunResponse

_LOGGER = logging.getLogger("netsight_api")

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])

# A run performs up to twelve bounded outbound probes: a few per identity per minute is plenty,
# and the overall budget stops one pathological target from pinning the worker.
DIAGNOSTIC_RUN_LIMIT_PER_MINUTE = 10
DIAGNOSTIC_RUN_TIMEOUT_SECONDS = 20.0
_WINDOW_SECONDS = 60.0
_run_limiter = RateLimiter()

RUN_ERRORS: dict[int | str, dict[str, Any]] = {
    **READ_ERRORS,
    429: {"model": ErrorEnvelope, "description": "Run rate limit exceeded"},
}

CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]
OptionalBlackbox = Annotated[BlackboxClient | None, Depends(get_optional_blackbox_client)]


def get_now() -> datetime:
    """The server clock; a dependency so tests (and only tests) can pin it."""
    return datetime.now(UTC)


Now = Annotated[datetime, Depends(get_now)]


def _observed_vantage(observations: Sequence[Observation]) -> str | None:
    """The vantage a run reports is where its checks actually ran, never the requested one.

    All checks in a run come from the same prober, so the distinct set is either empty (no vantage
    configured) or a single value. A mixed set can only mean observations from different probers,
    which this endpoint cannot produce; report ``None`` rather than pick one.
    """
    distinct = {observation.vantage for observation in observations}
    return distinct.pop() if len(distinct) == 1 else None


def require_run_permission(request: Request, identity: CurrentIdentity) -> Identity:
    """authorise -> CSRF + origin -> rate limit; the first refusal wins and is audited."""
    if not is_allowed(identity, Permission.DIAGNOSTICS_READ.value):
        audit_refusal(request, "diagnostic.run", identity, "permission", None)
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    refusal = write_refusal(request, identity)
    if refusal is not None:
        audit_refusal(request, "diagnostic.run", identity, refusal.reason, None)
        raise ApiError(403, refusal.code, refusal.message)
    if not _run_limiter.allow(identity.id, DIAGNOSTIC_RUN_LIMIT_PER_MINUTE, _WINDOW_SECONDS):
        audit_refusal(request, "diagnostic.run", identity, "rate-limit", None)
        raise ApiError(429, "RATE_LIMITED", "Too many diagnostic runs; slow down")
    return identity


@router.post(
    "",
    response_model=DiagnosticRunResponse,
    responses=RUN_ERRORS,
    operation_id="createDiagnosticRun",
)
async def create_diagnostic_run(
    request: Request,
    body: DiagnosticRunRequest,
    identity: Annotated[Identity, Depends(require_run_permission)],
    client: OptionalBlackbox,
    now: Now,
) -> DiagnosticRunResponse:
    if client is None:
        return DiagnosticRunResponse(state="not-connected", run=None)

    started_at = now
    try:
        observations = await asyncio.wait_for(
            run_checks(
                client,
                target=body.target,
                vantage=body.vantage,
                checks=body.requested_checks,
            ),
            timeout=DIAGNOSTIC_RUN_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 — a probe failure is an explicit unknown, never a 500
        _LOGGER.warning(
            "diagnostic run could not complete",
            extra={"error_type": type(exc).__name__},
        )
        record_audit(
            "diagnostic.run",
            outcome="failure",
            actor_id=identity.id,
            correlation_id=correlation_id(request),
            target=None,
            checks=len(body.requested_checks),
        )
        return DiagnosticRunResponse(state="unknown", run=None)

    completed_at = datetime.now(UTC)
    completed_at = max(completed_at, started_at)
    run = build_run(
        target=body.target,
        target_id=None,
        symptom=body.symptom,
        vantage=_observed_vantage(observations),
        observations=observations,
        started_at=started_at,
        completed_at=completed_at,
    )
    record_audit(
        "diagnostic.run",
        outcome="success",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        target=None,
        state="ok",
        checks=len(observations),
    )
    return DiagnosticRunResponse(state="ok", run=run)
