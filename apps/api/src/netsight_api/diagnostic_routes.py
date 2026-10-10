"""Diagnostics API (S7-2): ``POST /api/v1/diagnostics``.

A bounded, read-only diagnostic run. It is a cookie-authenticated POST that performs privileged
outbound probing, so it meets the same guard order as the alerting writes: authorise
(``diagnostics:read``, deny by default) -> CSRF token and origin -> per-identity rate limit.
Every refusal and every run outcome is audited.

The probe clients are allowlisted and bounded (``adapters.blackbox``, ``adapters.blackbox_exporter``):
with no allow-list configured the endpoint answers an explicit ``not-connected`` state rather than
pretending a check ran; a probe that raises or that exceeds the overall run budget answers
``unknown`` without leaking a driver message.

A finished run is persisted as an immutable session (S7 Step 4) so it can be revisited at
``GET /diagnostics/{id}`` (``diagnostic_session_routes``). The run is the product of this request:
a missing, slow or failing context source (topology, recent changes) or session store degrades the
session sections to explicit states or ``stored: false``, never to an error that loses the run.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool

from netsight_api.adapters.blackbox import (
    BlackboxClient,
    get_optional_blackbox_client,
    run_checks,
)
from netsight_api.adapters.blackbox_exporter import get_exporter_clients
from netsight_api.alerting_route_support import READ_ERRORS, audit_refusal, correlation_id
from netsight_api.audit import record_audit
from netsight_api.auth.csrf import write_refusal
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.contracts import ContractViolation, validate
from netsight_api.diagnostic_changes import SourceRead
from netsight_api.diagnostic_context import Context, ContextSources, OptionalSessionStore
from netsight_api.diagnostic_growth import check_daily_cap
from netsight_api.diagnostic_path import TopologyRead
from netsight_api.diagnostic_session_builder import (
    assemble_session,
    change_window,
    resolved_target_id,
)
from netsight_api.diagnostics import Observation, build_run
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.schemas import ErrorEnvelope
from netsight_api.schemas_diagnostic_session import DiagnosticSession
from netsight_api.schemas_diagnostics import (
    DiagnosticRun,
    DiagnosticRunRequest,
    DiagnosticRunResponse,
)
from netsight_api.storage.diagnostics import DiagnosticSessionRepository

_LOGGER = logging.getLogger("netsight_api")

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])

# A run performs up to twelve bounded outbound probes: a few per identity per minute is plenty,
# and the overall budget stops one pathological target from pinning the worker.
DIAGNOSTIC_RUN_LIMIT_PER_MINUTE = 10
DIAGNOSTIC_RUN_TIMEOUT_SECONDS = 20.0
# Topology and change reads are context, not the run: each is bounded on its own.
CONTEXT_TIMEOUT_SECONDS = 8.0
_WINDOW_SECONDS = 60.0
_run_limiter = RateLimiter()

RUN_ERRORS: dict[int | str, dict[str, Any]] = {
    **READ_ERRORS,
    429: {"model": ErrorEnvelope, "description": "Run rate limit exceeded"},
}

CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]
OptionalBlackbox = Annotated[BlackboxClient | None, Depends(get_optional_blackbox_client)]


def get_probe_clients(local: OptionalBlackbox) -> list[BlackboxClient]:
    """The local prober plus every configured exporter source; empty means not-connected.

    Exporter sources only exist alongside the allow-list the local prober needs, so with no
    allow-list nothing is probed at all.
    """
    return [] if local is None else [local, *get_exporter_clients()]


ProbeClients = Annotated[list[BlackboxClient], Depends(get_probe_clients)]


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


_UNKNOWN_TOPOLOGY = TopologyRead("unknown", (), (), None)
_UNKNOWN_CHANGES = (SourceRead("unknown"), SourceRead("unknown"))


async def _topology(context: ContextSources) -> TopologyRead:
    try:
        return await asyncio.wait_for(context.topology(), timeout=CONTEXT_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 — context is best effort; the run is not lost
        _LOGGER.warning("diagnostic topology unavailable", extra={"error_type": type(exc).__name__})
        return _UNKNOWN_TOPOLOGY


async def _changes(context: ContextSources, run: DiagnosticRun) -> tuple[SourceRead, SourceRead]:
    start, end = change_window(run.completed_at)
    try:
        return await asyncio.wait_for(
            context.changes(window_start=start, window_end=end, target=run.target),
            timeout=CONTEXT_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning("diagnostic changes unavailable", extra={"error_type": type(exc).__name__})
        return _UNKNOWN_CHANGES


async def _persist(
    store: DiagnosticSessionRepository | None, session: DiagnosticSession | None, actor_id: str
) -> tuple[bool, str | None]:
    """Store the finished session: (stored, reason it was not). Never an error: a lost session
    must not lose the run."""
    if session is None:
        return False, "session-rejected"
    if store is None:
        return False, "no-store"
    try:
        decision = await run_in_threadpool(lambda: check_daily_cap(store, session.run.completed_at))
        if not decision.allowed:
            return False, decision.reason
        await run_in_threadpool(lambda: store.save_session(session, actor_id=actor_id))
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning("diagnostic session not stored", extra={"error_type": type(exc).__name__})
        return False, "store-error"
    return True, None


async def _session_for(
    run: DiagnosticRun, context: ContextSources, topology: TopologyRead
) -> DiagnosticSession | None:
    incidents, alerts = await _changes(context, run)
    try:
        session = assemble_session(run=run, topology=topology, incidents=incidents, alerts=alerts)
        validate("diagnostic_session", session.model_dump(mode="json", by_alias=True))
    except (ValueError, ContractViolation) as exc:
        _LOGGER.warning("diagnostic session rejected", extra={"error_type": type(exc).__name__})
        return None
    return session


async def _observe(
    clients: list[BlackboxClient], body: DiagnosticRunRequest
) -> list[Observation] | None:
    """Run the bounded probes; ``None`` (never an exception) when they cannot complete."""
    try:
        return await asyncio.wait_for(
            run_checks(
                clients,
                target=body.target,
                vantage=body.vantage,
                checks=body.requested_checks,
            ),
            timeout=DIAGNOSTIC_RUN_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 — a probe failure is an explicit unknown, never a 500
        _LOGGER.warning(
            "diagnostic run could not complete", extra={"error_type": type(exc).__name__}
        )
        return None


async def _finish(
    request: Request,
    identity: Identity,
    body: DiagnosticRunRequest,
    observations: Sequence[Observation],
    started_at: datetime,
    context: ContextSources,
    store: DiagnosticSessionRepository | None,
) -> DiagnosticRunResponse:
    """Assemble the run and its session from the observations, store it, audit the outcome."""
    completed_at = max(datetime.now(UTC), started_at)
    topology = await _topology(context)
    run = build_run(
        target=body.target,
        target_id=resolved_target_id(topology, body.target),
        symptom=body.symptom,
        vantage=_observed_vantage(observations),
        observations=observations,
        started_at=started_at,
        completed_at=completed_at,
    )
    session = await _session_for(run, context, topology)
    stored, not_stored_reason = await _persist(store, session, identity.id)
    extra = {} if stored else {"not_stored_reason": not_stored_reason}
    record_audit(
        "diagnostic.run",
        outcome="success",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        target=run.id,
        state="ok",
        checks=len(observations),
        stored=stored,
        **extra,
    )
    return DiagnosticRunResponse(state="ok", run=run, stored=stored)


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
    clients: ProbeClients,
    context: Context,
    store: OptionalSessionStore,
    now: Now,
) -> DiagnosticRunResponse:
    if not clients:
        return DiagnosticRunResponse(state="not-connected", run=None, stored=False)
    observations = await _observe(clients, body)
    if observations is None:
        record_audit(
            "diagnostic.run",
            outcome="failure",
            actor_id=identity.id,
            correlation_id=correlation_id(request),
            target=None,
            checks=len(body.requested_checks),
        )
        return DiagnosticRunResponse(state="unknown", run=None, stored=False)
    return await _finish(request, identity, body, observations, now, context, store)
