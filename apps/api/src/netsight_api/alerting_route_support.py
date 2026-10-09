"""Shared plumbing for the alert-rule and maintenance-window routes (S6-3).

Writers meet the same dependency order as the incident writes: authorise (403, deny by
default, human-only permissions), then CSRF token and origin (403), then the per identity
rate limit (429). Every refusal and every outcome is audited; the success and failure records
are written by the worker thread right after the store call, so a client disconnect cannot
lose them. The store is the PostgreSQL app-role connection from ``DATABASE_URL``; without it
reads answer an explicit ``not-connected`` state and writes 503, a store failure is an
explicit ``unknown`` on reads and 503 on writes, and neither ever leaks a connection string
or a driver message.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from threading import BoundedSemaphore, Lock
from typing import Annotated, Any, NoReturn, cast

from fastapi import Depends, Path, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from netsight_api.audit import AuditOutcome, record_audit
from netsight_api.auth.csrf import write_refusal
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.schemas import (
    ALERT_RULE_ID_PATTERN,
    MAINTENANCE_WINDOW_ID_PATTERN,
    ErrorEnvelope,
)
from netsight_api.storage import (
    AlertRuleRepository,
    IllegalTransitionError,
    InvalidOperationError,
    LimitExceededError,
    NotFoundError,
    ScopeViolationError,
    StorageConfigurationError,
    StorageConflictError,
    StorageError,
)

_LOGGER = logging.getLogger("netsight_api")

# Per identity and minute, shared by rule and maintenance writes: a runaway client or a
# compromised session cannot flood the configuration; an operator editing rules stays far below.
WRITE_LIMIT_PER_MINUTE = 30
# The dry-run costs up to about 0.6 s of CPU for the largest accepted body: few per identity,
# and at most EVALUATE_MAX_CONCURRENT at once across all identities in this worker process.
EVALUATE_LIMIT_PER_MINUTE = 6
EVALUATE_MAX_CONCURRENT = 2
EVALUATE_BUSY_MESSAGE = "The dry-run is busy; retry shortly"
_WINDOW_SECONDS = 60.0
_write_limiter = RateLimiter()
_evaluate_limiter = RateLimiter()
_evaluate_slots = BoundedSemaphore(EVALUATE_MAX_CONCURRENT)

# Fixed text for every capacity refusal (limits live in ``storage.lifecycle``).
LIMIT_MESSAGE = "A configuration limit was reached; remove unused entries and retry"

READ_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
}
ITEM_READ_ERRORS: dict[int | str, dict[str, Any]] = {
    **READ_ERRORS,
    404: {"model": ErrorEnvelope, "description": "Not found"},
}
WRITE_ERRORS: dict[int | str, dict[str, Any]] = {
    **ITEM_READ_ERRORS,
    409: {"model": ErrorEnvelope, "description": "Stale version, illegal change or conflict"},
    429: {"model": ErrorEnvelope, "description": "Write rate limit exceeded"},
    503: {"model": ErrorEnvelope, "description": "Storage not connected or unavailable"},
}
CREATE_ERRORS: dict[int | str, dict[str, Any]] = {
    key: value for key, value in WRITE_ERRORS.items() if key != 404
}


# --- store and clock wiring ------------------------------------------------------------------------


class _UnavailableStore:
    """Stands in when ``DATABASE_URL`` is set but unusable: every call fails as unavailable."""

    def __getattr__(self, name: str) -> Callable[..., NoReturn]:
        def unavailable(*_args: object, **_kwargs: object) -> NoReturn:
            raise StorageError("the alert-rule store is not usable")

        return unavailable


def get_optional_alert_rule_store() -> AlertRuleRepository | None:
    """PostgreSQL store for the app role (``DATABASE_URL``); ``None`` means not-connected.

    Only the least-privilege application DSN is read here, never the migrator's. A
    configured-but-invalid DSN yields a store whose calls fail, so endpoints degrade to
    explicit ``unknown`` (configured does not imply connected) without echoing it.
    """
    if not os.environ.get("DATABASE_URL", "").strip():
        return None
    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.postgres import PostgresAlertRuleRepository

    try:
        settings = PostgresSettings.from_env()
    except StorageConfigurationError:
        return cast(AlertRuleRepository, _UnavailableStore())
    return PostgresAlertRuleRepository(settings)


def get_now() -> datetime:
    """The server clock; a dependency so tests (and only tests) can pin it."""
    return datetime.now(UTC)


CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]
OptionalAlertRuleStore = Annotated[
    AlertRuleRepository | None, Depends(get_optional_alert_rule_store)
]
Now = Annotated[datetime, Depends(get_now)]
RuleId = Annotated[str, Path(min_length=47, max_length=47, pattern=ALERT_RULE_ID_PATTERN)]
WindowId = Annotated[str, Path(min_length=48, max_length=48, pattern=MAINTENANCE_WINDOW_ID_PATTERN)]


def correlation_id(request: Request) -> str:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else "unknown"


# --- authorisation, CSRF, rate limiting ----------------------------------------------------------------


def reader(permission: Permission) -> Callable[..., Identity]:
    """Dependency: the caller must hold ``permission`` (403 otherwise)."""

    def dependency(identity: CurrentIdentity) -> Identity:
        if not is_allowed(identity, permission.value):
            raise ApiError(403, "FORBIDDEN", "Permission is required")
        return identity

    return dependency


def audit_refusal(
    request: Request, action: str, identity: Identity, reason: str, target: str | None
) -> None:
    """``target`` is a validated path id (or None), never a raw request value."""
    record_audit(
        action,
        outcome="denied",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        target=target,
        reason=reason,
    )


def authorise_and_guard(
    request: Request,
    identity: Identity,
    permission: Permission,
    *,
    action: str,
    target: str | None,
    limiter: Callable[[], RateLimiter],
    limit: Callable[[], int],
) -> None:
    """authorise -> CSRF + origin -> rate limit; the first refusal wins and is audited."""
    if not is_allowed(identity, permission.value):
        audit_refusal(request, action, identity, "permission", target)
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    refusal = write_refusal(request, identity)
    if refusal is not None:
        audit_refusal(request, action, identity, refusal.reason, target)
        raise ApiError(403, refusal.code, refusal.message)
    if not limiter().allow(identity.id, limit(), _WINDOW_SECONDS):
        audit_refusal(request, action, identity, "rate-limit", target)
        raise ApiError(429, "RATE_LIMITED", "Too many changes; slow down")


def _write_limits() -> tuple[Callable[[], RateLimiter], Callable[[], int]]:
    return (lambda: _write_limiter), (lambda: WRITE_LIMIT_PER_MINUTE)


def collection_writer(permission: Permission, *, action: str) -> Callable[..., Identity]:
    """Dependency for writes with no id in the path (create)."""
    limiter, limit = _write_limits()

    def dependency(request: Request, identity: CurrentIdentity) -> Identity:
        authorise_and_guard(
            request, identity, permission, action=action, target=None, limiter=limiter, limit=limit
        )
        return identity

    return dependency


def rule_writer(permission: Permission, *, action: str) -> Callable[..., Identity]:
    """Dependency for writes on one rule; the validated id is declared so a malformed one is
    refused (422) before it can reach the audit log or the store."""
    limiter, limit = _write_limits()

    def dependency(request: Request, identity: CurrentIdentity, rule_id: RuleId) -> Identity:
        authorise_and_guard(
            request,
            identity,
            permission,
            action=action,
            target=rule_id,
            limiter=limiter,
            limit=limit,
        )
        return identity

    return dependency


def window_writer(permission: Permission, *, action: str) -> Callable[..., Identity]:
    limiter, limit = _write_limits()

    def dependency(request: Request, identity: CurrentIdentity, window_id: WindowId) -> Identity:
        authorise_and_guard(
            request,
            identity,
            permission,
            action=action,
            target=window_id,
            limiter=limiter,
            limit=limit,
        )
        return identity

    return dependency


def evaluate_guard(request: Request, identity: CurrentIdentity) -> Identity:
    """The dry-run changes nothing, so it needs only read permission, but it is a cookie POST
    that costs CPU: it still meets the CSRF/origin checks and has its own rate limit."""
    authorise_and_guard(
        request,
        identity,
        Permission.ALERT_RULES_READ,
        action="alert_rule.evaluate",
        target=None,
        limiter=lambda: _evaluate_limiter,
        limit=lambda: EVALUATE_LIMIT_PER_MINUTE,
    )
    return identity


class EvaluationSlot:
    """One claimed dry-run concurrency slot, given back exactly once.

    The worker thread takes ownership as soon as it starts, so a client that disconnects
    mid-request cannot return a slot while its computation is still running. The request
    path takes the slot back only when no worker ever started (the dispatch itself failed),
    so a slot is neither stranded nor released twice into the bounded semaphore.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._started = False
        self._released = False

    def worker_started(self) -> None:
        with self._lock:
            self._started = True

    def worker_finished(self) -> None:
        self._give_back(only_if_idle=False)

    def request_failed(self) -> None:
        self._give_back(only_if_idle=True)

    def _give_back(self, *, only_if_idle: bool) -> None:
        with self._lock:
            if self._released or (only_if_idle and self._started):
                return
            self._released = True
        release_evaluation_slot()


def claim_evaluation_slot(request: Request, identity: Identity) -> EvaluationSlot:
    """Take one of the global dry-run slots or answer 503 at once (never queue).

    The returned slot is released by the worker thread when it ends, so a client that
    disconnects mid-request cannot return a slot while its computation still runs; the
    request path gives it back only if dispatch never produced a worker.
    """
    if not _evaluate_slots.acquire(blocking=False):
        audit_refusal(request, "alert_rule.evaluate", identity, "busy", None)
        raise ApiError(503, "EVALUATE_BUSY", EVALUATE_BUSY_MESSAGE, headers={"Retry-After": "5"})
    return EvaluationSlot()


def release_evaluation_slot() -> None:
    _evaluate_slots.release()


# --- error translation ------------------------------------------------------------------------------------


class RuleInvalidError(Exception):
    """The rule cannot be evaluated here (fail closed): carries static problem codes only."""

    def __init__(self, codes: tuple[str, ...]) -> None:
        super().__init__("rule is invalid")
        self.codes = codes


class _AuditedFailure(Exception):
    """A store failure already mapped and audited in the worker thread."""

    def __init__(self, error: ApiError, cause: Exception) -> None:
        super().__init__(error.code)
        self.error = error
        self.cause_type = type(cause).__name__


def translate(exc: Exception, noun: str) -> tuple[ApiError, AuditOutcome, str]:
    """Map a failure to (response error, audit outcome, audit reason code).

    Messages are fixed or the domain layer's own static texts; driver messages and
    connection strings never reach a response.
    """
    if isinstance(exc, NotFoundError):
        return ApiError(404, "NOT_FOUND", f"{noun} was not found"), "failure", "NOT_FOUND"
    if isinstance(exc, IllegalTransitionError):
        return ApiError(409, "ILLEGAL_TRANSITION", str(exc)), "failure", "ILLEGAL_TRANSITION"
    if isinstance(exc, LimitExceededError):
        return ApiError(409, "LIMIT_REACHED", LIMIT_MESSAGE), "failure", "LIMIT_REACHED"
    if isinstance(exc, ScopeViolationError):  # judged on the locked row: organisation windows
        error = ApiError(403, "FORBIDDEN", "Permission is required")
        return error, "denied", "organisation-scope"
    if isinstance(exc, StorageConflictError):
        error = ApiError(409, "CONFLICT", f"The {noun} was changed concurrently; reload and retry")
        return error, "failure", "CONFLICT"
    if isinstance(exc, RuleInvalidError):
        message = "The rule cannot be evaluated: " + ", ".join(exc.codes)
        return ApiError(422, "RULE_INVALID", message), "failure", "RULE_INVALID"
    if isinstance(exc, InvalidOperationError):
        return ApiError(422, "INVALID_OPERATION", str(exc)), "failure", "INVALID_OPERATION"
    if isinstance(exc, ValidationError):  # a plain ValueError is a bug, not a client error
        error = ApiError(422, "VALIDATION_ERROR", "Request validation failed")
        return error, "failure", "VALIDATION_ERROR"
    if isinstance(exc, StorageError):
        error = ApiError(503, "STORE_UNAVAILABLE", "Storage is temporarily unavailable")
        return error, "failure", "STORE_UNAVAILABLE"
    return ApiError(500, "INTERNAL_ERROR", "An internal error occurred"), "failure", "INTERNAL"


_Audit = Callable[..., None]


def _auditor(
    action: str, identity: Identity, correlation: str, fixed: Mapping[str, object]
) -> _Audit:
    def audit(outcome: AuditOutcome, audit_target: str | None, **extra: object) -> None:
        record_audit(
            action,
            outcome=outcome,
            actor_id=identity.id,
            correlation_id=correlation,
            target=audit_target,
            **{**fixed, **extra},
        )

    return audit


def _audited_work[T](
    repository: AlertRuleRepository,
    operation: Callable[[AlertRuleRepository], T],
    audit: _Audit,
    *,
    noun: str,
    target: str | None,
    target_of: Callable[[T], str] | None,
    details_of: Callable[[T], Mapping[str, object]] | None,
) -> Callable[[], T]:
    """The unit the worker thread runs: store call, then its audit record, as one step."""

    def work() -> T:
        try:
            result = operation(repository)
        except Exception as exc:  # noqa: BLE001 - deliberate store boundary; mapped here
            error, outcome, reason = translate(exc, noun)
            audit(outcome, target, reason=reason)
            raise _AuditedFailure(error, exc) from None
        extra = dict(details_of(result)) if details_of is not None else {}
        audit("success", target_of(result) if target_of is not None else target, **extra)
        return result

    return work


async def mutate[T](
    request: Request,
    store: AlertRuleRepository | None,
    identity: Identity,
    *,
    action: str,
    noun: str,
    operation: Callable[[AlertRuleRepository], T],
    target: str | None,
    target_of: Callable[[T], str] | None = None,
    details: Mapping[str, object] | None = None,
    details_of: Callable[[T], Mapping[str, object]] | None = None,
) -> T:
    """Run one store mutation off the event loop and audit its outcome.

    The audit record is written by the worker thread itself, right after the store call
    returns or raises: ``run_in_threadpool`` is not cancellable, so the thread always runs to
    completion and a client that disconnects mid-request cannot make a committed write
    unaudited. On success ``target_of``/``details_of`` read the new record (id, version).
    """
    correlation = correlation_id(request)
    audit = _auditor(action, identity, correlation, dict(details or {}))
    if store is None:
        audit("failure", target, reason="STORE_NOT_CONNECTED")
        raise ApiError(503, "STORE_NOT_CONNECTED", "Storage is not connected")
    work = _audited_work(
        store,
        operation,
        audit,
        noun=noun,
        target=target,
        target_of=target_of,
        details_of=details_of,
    )
    try:
        return await run_in_threadpool(work)
    except _AuditedFailure as failure:
        if failure.error.status_code >= 500:
            _LOGGER.warning(
                "alerting write failed",
                extra={"correlation_id": correlation, "error_type": failure.cause_type},
            )
        raise failure.error from None


def log_read_failure(request: Request, exc: Exception) -> None:
    _LOGGER.warning(
        "alerting store read failed",
        extra={"correlation_id": correlation_id(request), "error_type": type(exc).__name__},
    )
