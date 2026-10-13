"""Traffic intelligence routes (Step 7): the Flow Explorer, Applications, Destinations and Anomalies.

``GET /api/v1/traffic/flows``, ``/applications``, ``/destinations`` and ``/anomalies``. Read-only,
bounded and honest:

* **Two permission rungs.** ``traffic:read`` is the aggregate rung (volumes, application mix,
  destinations, baselines: nothing that names an endpoint). ``traffic:read-detail`` adds flow rows and
  any filter that narrows to one address, one device or one VLAN. Management holds the first only, so
  its Explorer shows aggregates and *no rows are read from the flow store for it*;
* **Small cohorts.** The aggregate rung is held to a minimum cohort of internal endpoints
  (``traffic.cohort``): an answer about fewer is withheld whole, a row (application, destination, mix
  item) that fewer stood behind keeps its name and loses every figure, an hourly series with too few
  contributors is not evaluated, a destination inside the organisation is not listed, and the
  freshness it is told is the source's, never the filtered answer's. There is no route that ranks raw
  addresses for this rung (the legacy ``/traffic/top-*`` routes were retired);
* **People only through the identity service.** Naming the person behind a source address needs
  ``users:read`` (a human); ``users:read-limited`` gets the device and the word "restricted"; every
  other role gets rows without attribution. The flow store's own user field is never used. Every
  attribution carries its basis (observed / inferred / unknown) and is never stronger than the
  identity service's answer;
* **Filters are an allow-list.** Unknown or repeated parameters, malformed values and out-of-range
  windows are a 422 that echoes nothing; values only ever reach the store as typed parameters;
* **Authorise, then limit.** The permission is checked first, so a denied caller never learns limiter
  state; each family then has its own per-identity budget, and the heavy reads share a small
  admission control (one per identity, a slot kept for the detail tier; 429 / 503 + ``Retry-After``
  when refused, never a queue);
* **Explicit states.** Nothing configured is ``not-connected``; a failing source, a filter the source
  can not honour, or a response that fails its canonical contract is ``unknown`` (HTTP 200, no
  values, nothing the source said); every response is validated against its canonical schema;
* **Audited.** Every read records the actor, the state, counts, the *names* of the filters used, the
  tier and the cohort verdict, never a filter value, an address or a person's name (a detail-tier
  lookup may add a keyed fingerprint, see ``traffic.audit_trail``). Denials, refusals and rejected
  input are audited too, each with a static reason code.

Classification (approval, risk, reputation, working hours) comes only from the operator policy
(``traffic.policy``); the baselines are the deterministic comparison in ``traffic.anomaly``.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache, partial
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import ValidationError

from netsight_api.alerting_route_support import READ_ERRORS
from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import ContractViolation
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_limit import enforce_read_limit
from netsight_api.schemas import ErrorEnvelope, TrafficPreset
from netsight_api.schemas_traffic import (
    PolicyStatus,
    TrafficAnomaliesResponse,
    TrafficApplicationsResponse,
    TrafficDestinationsResponse,
    TrafficFlowsResponse,
)
from netsight_api.traffic import anomaly_report, audit_trail, cohort
from netsight_api.traffic.cache import TtlCache
from netsight_api.traffic.filters import (
    FILTER_NAMES,
    FilterError,
    parse_filters,
)
from netsight_api.traffic.flows_response import (
    FlowsQuery,
    attribution_level,
    ok_response,
    withheld_status,
)
from netsight_api.traffic.lists_response import applications_ok, destinations_ok
from netsight_api.traffic.policy import TrafficPolicy, policy_from_environment
from netsight_api.traffic.responses import checked, static_response
from netsight_api.traffic.route_support import (
    WINDOW_PARAMETERS,
    Window,
    admit,
    heavy_read,
    log_failure,
    no_store,
    parse_window,
    reject,
)
from netsight_api.traffic.source import ExplorerSource

FLOWS_ACTION = "traffic.flows.read"
APPLICATIONS_ACTION = "traffic.applications.read"
DESTINATIONS_ACTION = "traffic.destinations.read"
ANOMALIES_ACTION = "traffic.anomalies.read"
EXPLORER_FAMILY = "traffic-explorer"
EXPLORER_LIMIT_PER_MINUTE = 30
SUMMARY_LIMIT_PER_MINUTE = 30
ANOMALY_LIMIT_PER_MINUTE = 10
FLOWS_PARAMETERS = WINDOW_PARAMETERS | {"limit"} | frozenset(FILTER_NAMES)
LIST_PARAMETERS = WINDOW_PARAMETERS | {"limit"}
ANOMALY_PARAMETERS = WINDOW_PARAMETERS
ANOMALY_CACHE_TTL_SECONDS = 300.0

_ERRORS: dict[int | str, dict[str, Any]] = {
    **READ_ERRORS,
    429: {"model": ErrorEnvelope, "description": "Read rate limit exceeded, or a read is running"},
    503: {"model": ErrorEnvelope, "description": "The flow source is busy"},
}

CurrentIdentity = Annotated[Identity, Depends(get_current_identity)]


class _AuditedRoute(APIRoute):
    """Audits a request FastAPI itself rejects (a malformed ``limit``, ``preset`` or ``from``)."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except RequestValidationError:
                audited = getattr(request.state, "traffic_audit", None)
                if audited is not None:
                    audit_trail.failed(request, audited[1], audited[0], "invalid-request")
                raise

        return handler


router = APIRouter(prefix="/traffic", tags=["traffic"], route_class=_AuditedRoute)


# --- wiring (overridden in tests) -------------------------------------------------------------------


def get_now() -> datetime:
    return datetime.now(UTC)


def get_explorer_source() -> ExplorerSource | None:
    """The ClickHouse-backed flow source when configured; ``None`` is ``not-connected``."""
    from netsight_api import main

    return cast("ExplorerSource | None", main.get_optional_traffic_source())


def get_identity_service() -> Any:
    """The Step 6 correlation service over the configured evidence; ``None`` is not-connected.

    A correlation policy that does not validate is also ``None`` here: the Explorer then reports the
    attribution as not connected rather than attributing under a guessed network classification.
    """
    from netsight_api import identity_routes
    from netsight_api.identity.service import IdentityService

    policy = identity_routes.get_policy()
    slots = identity_routes.get_identity_slots()
    if policy is None or all(slot.source is None for slot in slots):
        return None
    return IdentityService(slots, policy, cache=identity_routes.get_snapshot_cache())


def get_policy() -> TrafficPolicy:
    return policy_from_environment()


@lru_cache(maxsize=1)
def _anomaly_cache() -> TtlCache:
    return TtlCache(ttl_seconds=ANOMALY_CACHE_TTL_SECONDS, max_entries=16)


def get_anomaly_cache() -> TtlCache:
    return _anomaly_cache()


Now = Annotated[datetime, Depends(get_now)]
Source = Annotated[ExplorerSource | None, Depends(get_explorer_source)]
IdentityDep = Annotated[Any, Depends(get_identity_service)]
PolicyDep = Annotated[TrafficPolicy, Depends(get_policy)]
CacheDep = Annotated[TtlCache, Depends(get_anomaly_cache)]


# --- authorisation, then the rate limit ---------------------------------------------------------------


def _reader(
    action: str, family: str, limit: int, permission: Permission = Permission.TRAFFIC_READ
) -> Callable[[Request, Identity], Identity]:
    def dependency(request: Request, identity: CurrentIdentity) -> Identity:
        if not is_allowed(identity, permission.value):
            audit_trail.denied(request, identity.id, action, "permission")
            raise ApiError(403, "FORBIDDEN", "Permission is required")
        try:
            enforce_read_limit(identity, family, limit)
        except ApiError as error:
            if error.status_code == 429:
                audit_trail.denied(request, identity.id, action, "rate-limited")
            raise
        request.state.traffic_audit = (action, identity.id)
        return identity

    return dependency


ExplorerReader = Annotated[
    Identity, Depends(_reader(FLOWS_ACTION, EXPLORER_FAMILY, EXPLORER_LIMIT_PER_MINUTE))
]
ApplicationsReader = Annotated[
    Identity,
    Depends(_reader(APPLICATIONS_ACTION, "traffic-applications", SUMMARY_LIMIT_PER_MINUTE)),
]
DestinationsReader = Annotated[
    Identity,
    Depends(_reader(DESTINATIONS_ACTION, "traffic-destinations", SUMMARY_LIMIT_PER_MINUTE)),
]
AnomaliesReader = Annotated[
    Identity,
    Depends(_reader(ANOMALIES_ACTION, "traffic-anomalies", ANOMALY_LIMIT_PER_MINUTE)),
]


def _tier(identity: Identity) -> tuple[bool, int | None]:
    """(detail tier?, cohort minimum): the aggregate tier is held to the small-cohort rule."""
    detail = is_allowed(identity, Permission.TRAFFIC_READ_DETAIL.value)
    return detail, None if detail else cohort.min_cohort()


def _audit_fields(detail: bool, body: Any, window: Window) -> dict[str, object]:
    return {
        "state": body.state,
        "tier": "detail" if detail else "aggregate",
        "cohort": body.cohort.state,
        "window_seconds": window.seconds,
    }


# --- GET /traffic/flows ---------------------------------------------------------------------------------------


@dataclass
class FilterQuery:
    """The allow-listed Explorer filters; declared so the OpenAPI document lists exactly these.

    The route reads the raw query string (never these coerced values), so nothing is reinterpreted
    between the wire and the validator in ``traffic.filters``.
    """

    source_ip: Annotated[str | None, Query()] = None
    destination_ip: Annotated[str | None, Query()] = None
    device: Annotated[str | None, Query()] = None
    vlan: Annotated[str | None, Query()] = None
    application: Annotated[str | None, Query()] = None
    protocol: Annotated[str | None, Query()] = None
    port: Annotated[str | None, Query()] = None
    country: Annotated[str | None, Query()] = None
    asn: Annotated[str | None, Query()] = None
    direction: Annotated[str | None, Query()] = None


def _flows_query(
    request: Request,
    identity: Identity,
    preset: TrafficPreset,
    start: datetime | None,
    end: datetime | None,
) -> FlowsQuery:
    """Validate the request, then decide the caller's tier (an endpoint-level filter needs detail)."""
    window = parse_window(request, identity, FLOWS_ACTION, preset, start, end, FLOWS_PARAMETERS)
    try:
        filters = parse_filters(
            {name: value for name, value in request.query_params.items() if name in FILTER_NAMES}
        )
    except FilterError as error:
        raise reject(request, identity, FLOWS_ACTION, error) from error
    detail, minimum = _tier(identity)
    if filters.endpoint_level() and not detail:
        audit_trail.denied(
            request,
            identity.id,
            FLOWS_ACTION,
            "filter-needs-detail",
            filters=",".join(filters.active()),
            **audit_trail.filter_fingerprints(filters),
        )
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    return FlowsQuery(
        filters, window, detail, attribution_level(identity, restricted=not detail), minimum
    )


async def _flows_body(
    request: Request,
    result: Any,
    query: FlowsQuery,
    service: Any,
    now: datetime,
    static: Callable[..., TrafficFlowsResponse],
) -> TrafficFlowsResponse:
    if isinstance(result, Exception):
        log_failure(request, "traffic explorer read failed", result)
        return static("unknown", connected=True)
    if result.unsupported:
        return static("unknown", connected=True, unsupported=list(result.unsupported))
    try:
        return checked("traffic_flows", await ok_response(result, query, service, now))
    except (ValidationError, ContractViolation, ValueError) as error:
        log_failure(request, "traffic explorer response rejected by canonical contract", error)
        return static("unknown", connected=True)


def _audit_flows(
    request: Request, identity: Identity, query: FlowsQuery, body: TrafficFlowsResponse
) -> None:
    attributed = sum(1 for flow in body.flows if flow.attribution and flow.attribution.person)
    audit_trail.read(
        request,
        identity.id,
        FLOWS_ACTION,
        failure=body.state == "unknown",
        row_count=len(body.flows),
        attributed_count=attributed,
        restricted=body.flows_restricted,
        attribution_level=body.attribution.level,
        attribution_state=body.attribution.state,
        filters=",".join(query.filters.active()),
        **_audit_fields(query.detail, body, query.window),
        **audit_trail.filter_fingerprints(query.filters),
    )


@router.get(
    "/flows",
    response_model=TrafficFlowsResponse,
    responses=_ERRORS,
    operation_id="getTrafficFlows",
)
async def traffic_flows(
    request: Request,
    response: Response,
    identity: ExplorerReader,
    source: Source,
    service: IdentityDep,
    now: Now,
    filters: Annotated[FilterQuery, Depends()],
    preset: Annotated[TrafficPreset, Query()] = "24h",
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> TrafficFlowsResponse:
    """Filtered flows with bounded aggregations and attribution by basis; explicit states."""
    del filters
    no_store(response)
    query = _flows_query(request, identity, preset, start, end)
    static = partial(
        static_response,
        "traffic_flows",
        TrafficFlowsResponse,
        time_range=query.window.time_range,
        filters=query.filters.to_model(),
        unsupported=[],
        flows_restricted=not query.detail,
        attribution=withheld_status(query.level),
        flows=[],
        aggregations=None,
    )
    if source is None:
        body = static("not-connected", connected=False)
    else:
        result = await heavy_read(
            request,
            identity,
            FLOWS_ACTION,
            detail=query.detail,
            read=lambda: source.explore(
                start=query.window.start,
                end=query.window.end,
                limit=limit,
                filters=query.filters,
                include_rows=query.detail,
            ),
        )
        body = await _flows_body(request, result, query, service, now, static)
    _audit_flows(request, identity, query, body)
    return body


# --- GET /traffic/applications and /traffic/destinations ---------------------------------------------------------


def _audit_list(
    request: Request,
    identity: Identity,
    action: str,
    detail: bool,
    body: TrafficApplicationsResponse | TrafficDestinationsResponse,
    window: Window,
) -> None:
    audit_trail.read(
        request,
        identity.id,
        action,
        failure=body.state == "unknown",
        row_count=len(body.items),
        policy=body.policy.state,
        **_audit_fields(detail, body, window),
    )


@router.get(
    "/applications",
    response_model=TrafficApplicationsResponse,
    responses=_ERRORS,
    operation_id="getTrafficApplications",
)
async def traffic_applications(
    request: Request,
    response: Response,
    identity: ApplicationsReader,
    source: Source,
    policy: PolicyDep,
    preset: Annotated[TrafficPreset, Query()] = "24h",
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> TrafficApplicationsResponse:
    """Applications by volume with trend, and approval and risk from the operator policy."""
    no_store(response)
    window = parse_window(
        request, identity, APPLICATIONS_ACTION, preset, start, end, LIST_PARAMETERS
    )
    detail, minimum = _tier(identity)
    static = partial(
        static_response,
        "traffic_applications",
        TrafficApplicationsResponse,
        time_range=window.time_range,
        previous_range=None,
        policy=PolicyStatus(state=policy.state),
        unsupported=[],
        total_bytes=None,
        items=[],
    )
    if source is None:
        body = static("not-connected", connected=False)
    else:
        result = await heavy_read(
            request,
            identity,
            APPLICATIONS_ACTION,
            detail=detail,
            read=lambda: source.applications(start=window.start, end=window.end, limit=limit),
        )
        body = _applications_body(request, result, policy, window, minimum, static)
    _audit_list(request, identity, APPLICATIONS_ACTION, detail, body, window)
    return body


def _applications_body(
    request: Request,
    result: Any,
    policy: TrafficPolicy,
    window: Window,
    minimum: int | None,
    static: Callable[..., TrafficApplicationsResponse],
) -> TrafficApplicationsResponse:
    if isinstance(result, Exception):
        log_failure(request, "traffic applications read failed", result)
        return static("unknown", connected=True)
    if result.unsupported:
        return static("unknown", connected=True, unsupported=list(result.unsupported))
    try:
        return checked("traffic_applications", applications_ok(result, policy, window, minimum))
    except (ValidationError, ContractViolation) as error:
        log_failure(request, "traffic applications response rejected by canonical contract", error)
        return static("unknown", connected=True)


@router.get(
    "/destinations",
    response_model=TrafficDestinationsResponse,
    responses=_ERRORS,
    operation_id="getTrafficDestinations",
)
async def traffic_destinations(
    request: Request,
    response: Response,
    identity: DestinationsReader,
    source: Source,
    policy: PolicyDep,
    preset: Annotated[TrafficPreset, Query()] = "24h",
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> TrafficDestinationsResponse:
    """Destinations by volume with first and last seen, and reputation from the operator lists."""
    no_store(response)
    window = parse_window(
        request, identity, DESTINATIONS_ACTION, preset, start, end, LIST_PARAMETERS
    )
    detail, minimum = _tier(identity)
    static = partial(
        static_response,
        "traffic_destinations",
        TrafficDestinationsResponse,
        time_range=window.time_range,
        first_seen_since=None,
        policy=PolicyStatus(state=policy.state),
        total_bytes=None,
        items=[],
    )
    if source is None:
        body = static("not-connected", connected=False)
    else:
        result = await heavy_read(
            request,
            identity,
            DESTINATIONS_ACTION,
            detail=detail,
            read=lambda: source.destinations(start=window.start, end=window.end, limit=limit),
        )
        body = _destinations_body(request, result, policy, window, minimum, static)
    _audit_list(request, identity, DESTINATIONS_ACTION, detail, body, window)
    return body


def _destinations_body(
    request: Request,
    result: Any,
    policy: TrafficPolicy,
    window: Window,
    minimum: int | None,
    static: Callable[..., TrafficDestinationsResponse],
) -> TrafficDestinationsResponse:
    if isinstance(result, Exception):
        log_failure(request, "traffic destinations read failed", result)
        return static("unknown", connected=True)
    try:
        return checked("traffic_destinations", destinations_ok(result, policy, window, minimum))
    except (ValidationError, ContractViolation) as error:
        log_failure(request, "traffic destinations response rejected by canonical contract", error)
        return static("unknown", connected=True)


# --- GET /traffic/anomalies ---------------------------------------------------------------------------------------------


async def _anomalies_body(
    request: Request,
    identity: Identity,
    source: ExplorerSource,
    cache: TtlCache,
    policy: TrafficPolicy,
    window: Window,
    detail: bool,
    minimum: int | None,
    static: Callable[..., TrafficAnomaliesResponse],
) -> TrafficAnomaliesResponse:
    first_hour, last_hour = anomaly_report.observation_hours(window.start, window.end)

    async def load() -> Any:
        async with admit(request, identity, ANOMALIES_ACTION, detail=detail):
            return await source.anomaly_inputs(first_hour=first_hour, last_hour=last_hour)

    try:
        inputs = await cache.get_or_load((first_hour.isoformat(), last_hour.isoformat()), load)
    except ApiError:
        raise
    except Exception as error:  # noqa: BLE001 - the source boundary: any failure is `unknown`
        log_failure(request, "traffic baseline read failed", error)
        return static("unknown", connected=True)
    try:
        return checked(
            "traffic_anomalies",
            anomaly_report.build_anomalies(
                inputs,
                policy,
                time_range=window.time_range,
                first_hour=first_hour,
                last_hour=last_hour,
                minimum=minimum,
            ),
        )
    except (ValidationError, ContractViolation, ValueError) as error:
        log_failure(request, "traffic anomalies response rejected by canonical contract", error)
        return static("unknown", connected=True)


@router.get(
    "/anomalies",
    response_model=TrafficAnomaliesResponse,
    responses=_ERRORS,
    operation_id="getTrafficAnomalies",
)
async def traffic_anomalies(
    request: Request,
    response: Response,
    identity: AnomaliesReader,
    source: Source,
    policy: PolicyDep,
    cache: CacheDep,
    preset: Annotated[TrafficPreset, Query()] = "24h",
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
) -> TrafficAnomaliesResponse:
    """Hours that differ from the same hour in prior weeks (median and MAD); context, not verdicts."""
    no_store(response)
    window = parse_window(
        request, identity, ANOMALIES_ACTION, preset, start, end, ANOMALY_PARAMETERS
    )
    if window.end - window.start > anomaly_report.MAX_WINDOW:
        audit_trail.failed(request, identity.id, ANOMALIES_ACTION, "window-too-long")
        raise ApiError(422, "VALIDATION_ERROR", "time window exceeds 7 days")
    detail, minimum = _tier(identity)
    static = cast(
        "Callable[..., TrafficAnomaliesResponse]",
        partial(
            static_response,
            "traffic_anomalies",
            TrafficAnomaliesResponse,
            **anomaly_report.static_fields(window.time_range, policy),
        ),
    )
    if source is None:
        body = static("not-connected", connected=False)
    else:
        body = await _anomalies_body(
            request, identity, source, cache, policy, window, detail, minimum, static
        )
    audit_trail.read(
        request,
        identity.id,
        ANOMALIES_ACTION,
        failure=body.state == "unknown",
        row_count=len(body.anomalies),
        first_seen_count=len(body.first_seen),
        evaluation=body.evaluation.status,
        daylight_saving=body.evaluation.daylight_saving,
        **_audit_fields(detail, body, window),
    )
    return body
