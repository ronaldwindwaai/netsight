"""Shared parts of the controlled-action routes (Step 12): dependencies, guards, errors, audit.

Every write goes through the same gates, in this order, and the first refusal wins and is audited:

1. authentication (401), then authorisation (403, deny-by-default);
2. CSRF token and origin allow-list for cookie sessions (403);
3. step-up, for the writes that approve, run or release (``403 STEP_UP_REQUIRED``);
4. a per-identity budget (429 with ``Retry-After``).

Only then is the body used. The engine's rules (self-approval, stale digest or version, replay, the
target lock, deadlines, the kill switch) live in the store under one lock, not here; this module maps
their refusals to HTTP and records them. Audit records name the actor, the action, the request id and
static facts (risk, state, lengths, codes). They never carry the reason, a parameter value or a target.
"""

from __future__ import annotations

import json
import logging
import math
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, Final

from fastapi import Depends, Header, Path, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from netsight_api.actions.engine import FindingReader
from netsight_api.actions.errors import ActionError
from netsight_api.actions.wiring import ActionRuntime, get_runtime_singleton, utc_now
from netsight_api.alerting_route_support import correlation_id
from netsight_api.audit import AuditOutcome, record_audit
from netsight_api.auth.csrf import write_refusal
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.step_up import step_up_refusal
from netsight_api.contracts import ContractViolation, validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_support import CurrentIdentity
from netsight_api.schemas import ErrorEnvelope
from netsight_api.schemas_actions import (
    ID_PATTERN,
    IDEMPOTENCY_KEY_PATTERN,
    ActionActor,
)

LOGGER: Final = logging.getLogger("netsight_api")
READ_LIMIT_PER_MINUTE: Final = 120
WRITE_LIMIT_PER_MINUTE: Final = 30
EXECUTE_LIMIT_PER_MINUTE: Final = 10
KILL_SWITCH_LIMIT_PER_MINUTE: Final = 5
WINDOW_SECONDS: Final = 60.0
_write_limiter = RateLimiter()
_execute_limiter = RateLimiter()
_kill_limiter = RateLimiter()

ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied, CSRF, origin or step-up"},
    404: {"model": ErrorEnvelope, "description": "Action request not found"},
    409: {"model": ErrorEnvelope, "description": "Stale, replayed or not allowed in this state"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
    429: {"model": ErrorEnvelope, "description": "Rate limit exceeded"},
    503: {"model": ErrorEnvelope, "description": "Engine not enabled or kill switch engaged"},
}

ActionIdPath = Annotated[str, Path(min_length=43, max_length=43, pattern=ID_PATTERN)]
IdempotencyKey = Annotated[
    str,
    Header(alias="Idempotency-Key", min_length=16, max_length=64, pattern=IDEMPOTENCY_KEY_PATTERN),
]


# --- dependencies (overridable in tests) --------------------------------------------------------------------------


def get_runtime() -> ActionRuntime | None:
    return get_runtime_singleton()


def get_clock() -> Callable[[], datetime]:
    return utc_now


def get_finding_reader() -> FindingReader | None:
    from netsight_api.unknown_devices.wiring import get_optional_store

    return get_optional_store()


Runtime = Annotated[ActionRuntime | None, Depends(get_runtime)]
Clock = Annotated[Callable[[], datetime], Depends(get_clock)]
FindingsReader = Annotated[FindingReader | None, Depends(get_finding_reader)]


def reset_for_tests() -> None:
    global _write_limiter, _execute_limiter, _kill_limiter
    _write_limiter, _execute_limiter, _kill_limiter = RateLimiter(), RateLimiter(), RateLimiter()
    from netsight_api.actions import wiring

    wiring.reset_for_tests()


# --- audit ---------------------------------------------------------------------------------------------------------


def audit(
    request: Request,
    identity: Identity,
    action: str,
    outcome: AuditOutcome,
    target: str | None = None,
    **details: object,
) -> None:
    record_audit(
        action,
        outcome=outcome,
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        target=target,
        **details,
    )


def actor_of(identity: Identity) -> ActionActor:
    return ActionActor(id=identity.id, kind=identity.principal.value)


# --- guards ------------------------------------------------------------------------------------------------------------


def _guard(
    request: Request,
    identity: Identity,
    permissions: tuple[Permission, ...],
    action: str,
    target: str | None,
    *,
    step_up: bool,
    limiter: Callable[[], RateLimiter],
    limit: Callable[[], int],
) -> None:
    if not any(is_allowed(identity, p.value) for p in permissions):
        audit(request, identity, action, "denied", target, reason="permission")
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    refusal = write_refusal(request, identity)
    if refusal is not None:
        audit(request, identity, action, "denied", target, reason=refusal.reason)
        raise ApiError(403, refusal.code, refusal.message)
    if step_up:
        refusal = step_up_refusal(request)
        if refusal is not None:
            audit(request, identity, action, "denied", target, reason=refusal.reason)
            raise ApiError(403, refusal.code, refusal.message)
    if not limiter().allow(identity.id, limit(), WINDOW_SECONDS):
        audit(request, identity, action, "denied", target, reason="rate-limit")
        raise ApiError(
            429,
            "RATE_LIMITED",
            "Too many changes; slow down",
            headers={"Retry-After": str(math.ceil(WINDOW_SECONDS))},
        )


def collection_writer(
    *permissions: Permission, action: str, step_up: bool = False, kind: str = "write"
) -> Callable[..., Identity]:
    def dependency(request: Request, identity: CurrentIdentity) -> Identity:
        _guard(request, identity, permissions, action, None, step_up=step_up, **_budget(kind))
        return identity

    return dependency


def item_writer(
    *permissions: Permission, action: str, step_up: bool = False, kind: str = "write"
) -> Callable[..., Identity]:
    def dependency(
        request: Request, identity: CurrentIdentity, action_id: ActionIdPath
    ) -> Identity:
        # ``action_id`` is declared so FastAPI validates it first: a malformed id never reaches the
        # audit log or the store.
        _guard(request, identity, permissions, action, action_id, step_up=step_up, **_budget(kind))
        return identity

    return dependency


def _budget(kind: str) -> dict[str, Callable[[], Any]]:
    if kind == "execute":
        return {"limiter": lambda: _execute_limiter, "limit": lambda: EXECUTE_LIMIT_PER_MINUTE}
    if kind == "kill":
        return {"limiter": lambda: _kill_limiter, "limit": lambda: KILL_SWITCH_LIMIT_PER_MINUTE}
    return {"limiter": lambda: _write_limiter, "limit": lambda: WRITE_LIMIT_PER_MINUTE}


def item_reader(action: str) -> Callable[..., Identity]:
    from netsight_api.read_limit import enforce_read_limit
    from netsight_api.traffic import audit_trail

    def dependency(
        request: Request, identity: CurrentIdentity, action_id: ActionIdPath
    ) -> Identity:
        if not is_allowed(identity, Permission.ACTIONS_READ.value):
            audit_trail.denied(request, identity.id, action, "permission")
            raise ApiError(403, "FORBIDDEN", "Permission is required")
        try:
            enforce_read_limit(identity, "actions", READ_LIMIT_PER_MINUTE)
        except ApiError:
            audit_trail.denied(request, identity.id, action, "rate-limit")
            raise
        return identity

    return dependency


# --- running store calls and answering ----------------------------------------------------------------------------


NOT_ENABLED: Final = ApiError(503, "ACTIONS_NOT_ENABLED", "The action engine is not enabled")


def require_runtime(
    request: Request, identity: Identity, action: str, runtime: ActionRuntime | None
) -> ActionRuntime:
    if runtime is None:
        audit(request, identity, action, "failure", reason="not-enabled")
        raise NOT_ENABLED
    return runtime


async def run_call[T](
    request: Request, identity: Identity, action: str, target: str | None, call: Callable[[], T]
) -> T:
    """Run a store or engine call off the event loop; translate and audit a refusal."""
    try:
        return await run_in_threadpool(call)
    except ActionError as exc:
        outcome: AuditOutcome = "denied" if exc.status == 403 else "failure"
        audit(request, identity, action, outcome, target, reason=exc.code)
        raise ApiError(exc.status, exc.code, exc.message) from None
    except ApiError:
        raise
    except Exception:
        LOGGER.exception(
            "an action call failed unexpectedly",
            extra={"correlation_id": correlation_id(request), "action": action},
        )
        audit(request, identity, action, "failure", target, reason="internal")
        raise ApiError(500, "INTERNAL_ERROR", "An internal error occurred") from None


def checked(name: str, model: BaseModel) -> Any:
    """A body that fails its own canonical contract is never sent."""
    try:
        validate(name, json.loads(model.model_dump_json(by_alias=True)))
    except ContractViolation:
        LOGGER.error("an action response failed its canonical contract")
        raise ApiError(500, "INTERNAL_ERROR", "An internal error occurred") from None
    return model
