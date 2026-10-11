"""Identity routes (Step 6d): ``/users``, ``/users/summary``, ``/users/{id}`` and ``/identity/resolve``.

Read-only and privacy-first (PRD 10, 92):

* three permissions form a ladder. ``users:read`` browses people and names the person behind an
  address; ``users:read-limited`` resolves an address to its endpoint but never to a person (the
  attribution says ``restricted``); ``users:read-summary`` returns counts only (Management). The two
  per-user permissions are human-only;
* authorisation first, then a per-identity rate limit (so a denied caller never learns limiter
  state); resolving has the smallest budget because it is the scraping vector;
* every per-user read is audited with the actor, the target and counts only: never a name, an
  e-mail address, a purpose or any text a source supplied. A resolve target is a fingerprint, never
  the address, MAC or hostname asked about. Denials, rate limits (429), global-limit and busy
  refusals and rejected resolve input (422) are audited too, each with a static reason code;
* responses are ``Cache-Control: no-store`` (error responses too, set in the API middleware);
* a question about a past time cannot be cached, so it also spends a global (all identities)
  budget and a cap on concurrent reads (``identity.guards``);
* an explicit state instead of a guess: nothing configured is ``not-connected``, a failing source or
  an unusable policy is ``unknown`` (HTTP 200, no values, nothing the source said), and every
  response is validated against its canonical schema before it leaves.

Correlation is computed on read from bounded evidence (see ``identity.service``); nothing is stored.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Path, Query, Request, Response

from netsight_api import schemas_identity as api
from netsight_api.adapters.wazuh import WazuhIndexerClient
from netsight_api.alerting_route_support import ITEM_READ_ERRORS, correlation_id
from netsight_api.audit import fingerprint, record_audit
from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import validate
from netsight_api.errors import ApiError
from netsight_api.identity import guards
from netsight_api.identity.guards import Refusal
from netsight_api.identity.model import CorrelationPolicy, ip_ref, mac_ref
from netsight_api.identity.netbox_source import (
    AGENT_FIELD_ENV,
    OWNER_ROLES_ENV,
    NetboxAssignmentSource,
    agent_key_field_from_env,
    owner_roles_from_env,
)
from netsight_api.identity.service import (
    EVIDENCE_LOOKBACK,
    IdentityService,
    SecurityReader,
    SnapshotCache,
    TrafficReader,
)
from netsight_api.identity.sources import SourceSlot
from netsight_api.identity.wazuh_source import WazuhAgentSource
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
from netsight_api.schemas import ErrorEnvelope, Freshness

_LOGGER = logging.getLogger("netsight_api")

router = APIRouter(tags=["identity"])

LIST_LIMIT_PER_MINUTE = 120
SUMMARY_LIMIT_PER_MINUTE = 60
RESOLVE_LIMIT_PER_MINUTE = 30
MAX_HISTORY = timedelta(days=7)
CLOCK_SKEW = timedelta(seconds=60)
CURRENT_TOLERANCE = timedelta(seconds=5)
AGENTS_INDEX_ENV = "WAZUH_AGENTS_INDEX"
DEFAULT_AGENTS_INDEX = "wazuh-monitoring-*"
PERSON_ID_PATTERN = r"^person-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

_ERRORS: dict[int | str, dict[str, Any]] = {
    **ITEM_READ_ERRORS,
    429: {"model": ErrorEnvelope, "description": "Read rate limit exceeded"},
}
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\.?$")
_MAC_FORMS = re.compile(
    r"^(?:[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
    r"|[0-9A-Fa-f]{12}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})$"
)

CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]


# --- wiring (overridden in tests) -------------------------------------------------------------------


def get_now() -> datetime:
    return datetime.now(UTC)


def get_identity_slots() -> list[SourceSlot]:
    """The configured evidence sources; an unconfigured one is a slot without a source."""
    from netsight_api import main  # lazy: main owns the NetBox factory
    from netsight_api.security_routes import get_optional_security_source

    indexer = get_optional_security_source()
    wazuh: WazuhAgentSource | None = None
    if isinstance(indexer, WazuhIndexerClient):
        pattern = os.environ.get(AGENTS_INDEX_ENV, "").strip() or DEFAULT_AGENTS_INDEX
        wazuh = WazuhAgentSource(dataclasses.replace(indexer, agents_index_pattern=pattern))
    netbox_client = main.get_optional_netbox_client()
    netbox = (
        NetboxAssignmentSource(
            netbox_client,
            owner_roles_from_env(os.environ.get(OWNER_ROLES_ENV, "")),
            agent_key_field=agent_key_field_from_env(os.environ.get(AGENT_FIELD_ENV, "")),
        )
        if netbox_client is not None
        else None
    )
    return [SourceSlot("wazuh", wazuh), SourceSlot("netbox", netbox)]


@cache
def _policy_for(environment: tuple[tuple[str, str], ...]) -> CorrelationPolicy | None:
    try:
        return CorrelationPolicy.from_env(dict(environment))
    except ValueError:
        _LOGGER.warning("identity correlation policy is invalid; answering unknown")
        return None


_POLICY_VARIABLES = (
    "NETSIGHT_IDENTITY_SHARED_CIDRS",
    "NETSIGHT_IDENTITY_INTERNAL_CIDRS",
    "NETSIGHT_IDENTITY_VPN_CIDRS",
    "NETSIGHT_IDENTITY_GUEST_CIDRS",
    "NETSIGHT_IDENTITY_GUEST_VLANS",
    "NETSIGHT_IDENTITY_STATIC_CIDRS",
)


def get_policy() -> CorrelationPolicy | None:
    """The network classification (NAT, VPN, guest); ``None`` when it is unusable (never guessed)."""
    return _policy_for(tuple((name, os.environ.get(name, "")) for name in _POLICY_VARIABLES))


@cache
def _shared_cache() -> SnapshotCache:
    return SnapshotCache()


def get_snapshot_cache() -> SnapshotCache:
    return _shared_cache()


def get_traffic_source() -> TrafficReader | None:
    from netsight_api import main

    return cast("TrafficReader | None", main.get_optional_traffic_source())


def get_security_source() -> SecurityReader | None:
    from netsight_api.security_routes import get_optional_security_source

    return get_optional_security_source()


Now = Annotated[datetime, Depends(get_now)]
Slots = Annotated[list[SourceSlot], Depends(get_identity_slots)]
Policy = Annotated[CorrelationPolicy | None, Depends(get_policy)]
Cache = Annotated[SnapshotCache, Depends(get_snapshot_cache)]
Traffic = Annotated[TrafficReader | None, Depends(get_traffic_source)]
Security = Annotated[SecurityReader | None, Depends(get_security_source)]


# --- authorisation, then the rate limit ----------------------------------------------------------------


def _audit_refusal(
    request: Request,
    identity: Identity,
    action: str,
    *,
    outcome: Literal["denied", "failure"],
    reason: str,
    target: str | None = None,
) -> None:
    """One audit record for a refused request: a static reason code, never any caller input."""
    record_audit(
        action,
        outcome=outcome,
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        target=target,
        reason=reason,
    )


def _deny(request: Request, identity: Identity, action: str, target: str | None = None) -> ApiError:
    _audit_refusal(request, identity, action, outcome="denied", reason="permission", target=target)
    return ApiError(403, "FORBIDDEN", "Permission is required")


def _limited(
    request: Request,
    identity: Identity,
    action: str,
    family: str,
    limit: int,
    target: str | None = None,
) -> None:
    """The per-identity read limit; a 429 is audited (after authorisation, so it leaks nothing)."""
    try:
        enforce_read_limit(identity, family, limit)
    except ApiError as error:
        if error.status_code == 429:
            _audit_refusal(
                request, identity, action, outcome="denied", reason="rate-limited", target=target
            )
        raise


def _person_target(request: Request) -> str | None:
    """The person id in the path when it is a canonical id; anything else is not logged."""
    raw = request.path_params.get("user_id")
    return raw if isinstance(raw, str) and re.fullmatch(PERSON_ID_PATTERN, raw) else None


def require_people_reader(request: Request, identity: CurrentIdentity) -> Identity:
    detail = "user_id" in request.path_params
    action = "identity.user.read" if detail else "identity.users.list"
    target = _person_target(request) if detail else None
    if not is_allowed(identity, Permission.USERS_READ.value):
        raise _deny(request, identity, action, target)
    _limited(request, identity, action, "identity-users", LIST_LIMIT_PER_MINUTE, target)
    return identity


def require_resolver(request: Request, identity: CurrentIdentity) -> Identity:
    if not (
        is_allowed(identity, Permission.USERS_READ.value)
        or is_allowed(identity, Permission.USERS_READ_LIMITED.value)
    ):
        raise _deny(request, identity, "identity.resolve")
    _limited(request, identity, "identity.resolve", "identity-resolve", RESOLVE_LIMIT_PER_MINUTE)
    return identity


def require_summary_reader(request: Request, identity: CurrentIdentity) -> Identity:
    if not is_allowed(identity, Permission.USERS_READ_SUMMARY.value):
        raise _deny(request, identity, "identity.summary")
    _limited(request, identity, "identity.summary", "identity-summary", SUMMARY_LIMIT_PER_MINUTE)
    return identity


PeopleReader = Annotated[Identity, Depends(require_people_reader)]
Resolver = Annotated[Identity, Depends(require_resolver)]
SummaryReader = Annotated[Identity, Depends(require_summary_reader)]


# --- the answer when the service cannot answer -------------------------------------------------------------


def _unknown_window(now: datetime) -> api.TimeWindow:
    return api.TimeWindow(**{"from": now - EVIDENCE_LOOKBACK, "to": now})


def _failed_sources(name: str) -> list[api.SourceStatus]:
    return [
        api.SourceStatus(
            source=name,
            state="unknown",
            record_count=0,
            truncated=False,
            freshness=Freshness(state="unknown", observed_at=None, source=None),
        )
    ]


def _service(
    slots: list[SourceSlot], policy: CorrelationPolicy, cache: SnapshotCache
) -> IdentityService:
    return IdentityService(slots, policy, cache=cache)


def _log_failure(request: Request, error: BaseException) -> None:
    _LOGGER.warning(
        "identity read failed",
        extra={"correlation_id": correlation_id(request), "error_type": type(error).__name__},
    )


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


# --- GET /users ------------------------------------------------------------------------------------------------


def _unknown_list(now: datetime, page: int, page_size: int, name: str) -> api.UserListResponse:
    return api.UserListResponse(
        state="unknown",
        as_of=now,
        window=_unknown_window(now),
        sources=_failed_sources(name),
        items=[],
        page=page,
        page_size=page_size,
        total=0,
    )


@router.get(
    "/users", response_model=api.UserListResponse, responses=_ERRORS, operation_id="listUsers"
)
async def list_users(
    request: Request,
    response: Response,
    identity: PeopleReader,
    slots: Slots,
    policy: Policy,
    cache: Cache,
    now: Now,
    page: Annotated[int, Query(ge=1, le=1000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> api.UserListResponse:
    """People known to the evidence, bounded and paged; per-user data, audited."""
    _no_store(response)
    try:
        if policy is None:
            raise ValueError("the correlation policy is unusable")
        body = await _service(slots, policy, cache).list_users(now, page=page, page_size=page_size)
        validate("user_list", body.model_dump(mode="json", by_alias=True))
    except Exception as error:  # noqa: BLE001 - a source or contract failure is `unknown`
        _log_failure(request, error)
        body = _unknown_list(now, page, page_size, "identity")
    record_audit(
        "identity.users.list",
        outcome="failure" if body.state == "unknown" else "success",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        state=body.state,
        result_count=len(body.items),
        page=page,
        page_size=page_size,
    )
    return body


# --- GET /users/summary -------------------------------------------------------------------------------------------


@router.get(
    "/users/summary",
    response_model=api.UsersAggregateResponse,
    responses=_ERRORS,
    operation_id="getUsersSummary",
)
async def users_summary(
    request: Request,
    response: Response,
    _identity: SummaryReader,
    slots: Slots,
    policy: Policy,
    cache: Cache,
    now: Now,
) -> api.UsersAggregateResponse:
    """Aggregate counts only: no names, no identifiers (the only users surface for Management)."""
    _no_store(response)
    try:
        if policy is None:
            raise ValueError("the correlation policy is unusable")
        body = await _service(slots, policy, cache).summary(now)
        validate("users_aggregate", body.model_dump(mode="json", by_alias=True))
    except Exception as error:  # noqa: BLE001
        _log_failure(request, error)
        body = api.UsersAggregateResponse(
            state="unknown",
            as_of=now,
            window=_unknown_window(now),
            sources=_failed_sources("identity"),
            people_total=None,
            with_observed_session=None,
            with_inferred_session=None,
            without_session_evidence=None,
            vpn_sessions=None,
        )
    return body


# --- GET /users/{id} ----------------------------------------------------------------------------------------------------


@router.get(
    "/users/{user_id}",
    response_model=api.UserDetailResponse,
    responses=_ERRORS,
    operation_id="getUser",
)
async def get_user(
    request: Request,
    response: Response,
    identity: PeopleReader,
    slots: Slots,
    policy: Policy,
    cache: Cache,
    now: Now,
    traffic: Traffic,
    security: Security,
    user_id: Annotated[str, Path(pattern=PERSON_ID_PATTERN, min_length=43, max_length=43)],
) -> api.UserDetailResponse:
    """One person's profile, sessions and attributed activity; per-user data, audited."""
    _no_store(response)
    audit = {"actor_id": identity.id, "correlation_id": correlation_id(request), "target": user_id}
    try:
        if policy is None:
            raise ValueError("the correlation policy is unusable")
        body = await _service(slots, policy, cache).user_detail(
            now,
            user_id,
            traffic=traffic if is_allowed(identity, Permission.TRAFFIC_READ_DETAIL.value) else None,
            security=security if is_allowed(identity, Permission.SECURITY_READ.value) else None,
        )
        if body is not None:
            validate("user_detail", body.model_dump(mode="json", by_alias=True))
    except Exception as error:  # noqa: BLE001
        _log_failure(request, error)
        record_audit("identity.user.read", outcome="failure", state="unknown", **audit)
        return api.UserDetailResponse(
            state="unknown",
            as_of=now,
            window=_unknown_window(now),
            sources=_failed_sources("identity"),
            user=None,
            traffic=None,
            security=None,
        )
    if body is None:
        record_audit("identity.user.read", outcome="failure", reason="not-found", **audit)
        raise ApiError(404, "NOT_FOUND", "Person was not found")
    record_audit(
        "identity.user.read",
        outcome="failure" if body.state == "unknown" else "success",
        state=body.state,
        session_count=len(body.user.sessions) if body.user else 0,
        **audit,
    )
    return body


# --- GET /identity/resolve ----------------------------------------------------------------------------------------------------

_MAX_ADDRESS_QUERY = 64
_MAX_HOSTNAME_QUERY = 256
_MAX_AT_QUERY = 64


def _invalid(reason: str, message: str) -> Refusal:
    """A 422 that echoes nothing; ``reason`` is the static code the audit trail records."""
    return Refusal(422, "VALIDATION_ERROR", message, reason)


def _subject(ip: str | None, mac: str | None, hostname: str | None) -> tuple[str, str]:
    """Exactly one valid subject, canonicalised; anything else is a 422 that echoes nothing."""
    supplied = [
        (kind, value)
        for kind, value in (("ip", ip), ("mac", mac), ("hostname", hostname))
        if value is not None
    ]
    if len(supplied) != 1:
        raise _invalid("subject-count", "Give exactly one of ip, mac and hostname")
    kind, value = supplied[0]
    try:
        return kind, _canonical(kind, value)
    except ValueError as error:
        raise _invalid("invalid-subject", f"The {kind} is not valid") from error


def _canonical(kind: str, value: str) -> str:
    if kind == "ip":
        if len(value) > 45 or "/" in value:
            raise ValueError("not an address")
        return ip_ref(value).id
    if kind == "mac":
        if len(value) > _MAX_ADDRESS_QUERY or _MAC_FORMS.fullmatch(value) is None:
            raise ValueError("not a MAC address")
        return mac_ref(value).id
    if len(value) > _MAX_HOSTNAME_QUERY or _HOSTNAME.fullmatch(value) is None:
        raise ValueError("not a hostname")
    return value.lower().rstrip(".")


def _historical(raw: str | None, now: datetime) -> datetime | None:
    """The requested instant, or ``None`` for "now"; an unusable instant is a 422."""
    if raw is None:
        return None
    try:
        at = datetime.fromisoformat(raw) if len(raw) <= _MAX_AT_QUERY else None
    except ValueError:
        at = None
    if at is None:
        raise _invalid("invalid-time", "at must be an RFC 3339 date-time")
    if at.tzinfo is None or at.utcoffset() is None:
        raise _invalid("invalid-time", "at must include a timezone")
    at = at.astimezone(UTC)
    if at > now + CLOCK_SKEW:
        raise _invalid("invalid-time", "at must not be in the future")
    if at < now - MAX_HISTORY:
        raise _invalid("invalid-time", "at must be within the last 7 days")
    return None if at >= now - CURRENT_TOLERANCE else at


def _question(
    request: Request,
    identity: Identity,
    ip: str | None,
    mac: str | None,
    hostname: str | None,
    at: str | None,
    now: datetime,
) -> tuple[str, str, datetime | None]:
    """Validate the question; a rejected one is audited with a static reason and re-raised."""
    try:
        kind, value = _subject(ip, mac, hostname)
        return kind, value, _historical(at, now)
    except Refusal as refusal:
        _audit_refusal(
            request, identity, "identity.resolve", outcome="failure", reason=refusal.reason
        )
        raise


def _admit_history(stack: ExitStack, request: Request, identity: Identity, target: str) -> None:
    """A past-time question spends the global budget and holds a read slot; refusals are audited."""
    try:
        guards.admit_historical()
        stack.enter_context(guards.historical_slot())
    except Refusal as refusal:
        _audit_refusal(
            request,
            identity,
            "identity.resolve",
            outcome="denied",
            reason=refusal.reason,
            target=target,
        )
        raise


def _unknown_resolve(kind: str, value: str, as_of: datetime) -> api.ResolveResponse:
    return api.ResolveResponse(
        state="unknown",
        subject=api.ResolveSubject(kind=kind, value=value),  # type: ignore[arg-type]
        as_of=as_of,
        window=_unknown_window(as_of),
        sources=_failed_sources("identity"),
        attribution=api.Attribution(
            basis="unknown", reason="source-unavailable", ambiguous=False, links=[], candidates=[]
        ),
        endpoint=[],
        notes=[],
    )


@router.get(
    "/identity/resolve",
    response_model=api.ResolveResponse,
    responses=_ERRORS,
    operation_id="resolveIdentity",
)
async def resolve_identity(
    request: Request,
    response: Response,
    identity: Resolver,
    slots: Slots,
    policy: Policy,
    cache: Cache,
    now: Now,
    ip: Annotated[str | None, Query()] = None,
    mac: Annotated[str | None, Query()] = None,
    hostname: Annotated[str | None, Query()] = None,
    at: Annotated[str | None, Query()] = None,
) -> api.ResolveResponse:
    """Who is behind an address at a time. An IP address alone is never identity."""
    _no_store(response)
    kind, value, when = _question(request, identity, ip, mac, hostname, at, now)
    redact = not is_allowed(identity, Permission.USERS_READ.value)
    target = f"{kind}:{fingerprint(value)}"
    with ExitStack() as stack:
        if when is not None:
            _admit_history(stack, request, identity, target)
        try:
            if policy is None:
                raise ValueError("the correlation policy is unusable")
            body = await _service(slots, policy, cache).resolve(
                now, when, kind, value, redact_person=redact
            )
            validate("identity_resolve", body.model_dump(mode="json", by_alias=True))
        except Exception as error:  # noqa: BLE001 - a source, key or contract failure is `unknown`
            _log_failure(request, error)
            body = _unknown_resolve(kind, value, when or now)
    disclosed = len(body.attribution.links) + len(body.attribution.candidates)
    record_audit(
        "identity.resolve",
        outcome="failure" if body.state == "unknown" else "success",
        actor_id=identity.id,
        correlation_id=correlation_id(request),
        target=target,
        state=body.state,
        basis=body.attribution.basis,
        redacted=redact,
        historical=when is not None,
        identified_count=disclosed,
        endpoint_links=len(body.endpoint),
    )
    return body
