"""Diagnostic session models (S7 Step 4).

Mirrors ``contracts/json-schema/diagnostic-session.schema.json`` and the session parts of
``diagnostic-api.schema.json`` and the OpenAPI components of the same names; the four-way
agreement tests drive all of them from ``contracts/test-vectors/diagnostic-session.vectors.json``.

A session is the finished run plus four snapshots taken when it finished: what each configured
probe location reported, the labelled probable cause, the known recent changes and the
explicit-topology path. Everything is derived or validated here so a stored document can never
claim more than the run's own checks support: per-location results must equal what the run's
checks imply, the cause must equal the run's own conclusion, and the path may highlight only the
tier the cause points at.
"""

from __future__ import annotations

from collections.abc import Sequence
from itertools import pairwise
from typing import Final, Literal

from pydantic import AwareDatetime, Field, model_validator

from netsight_api.schemas import (
    _DEVICE_ID_PATTERN,
    NON_BLANK,
    ContractModel,
    IncidentSeverity,
    StoreState,
    _require_unique,
)
from netsight_api.schemas_diagnostics import (
    DIAGNOSTIC_ID_PATTERN,
    DIAGNOSTIC_RUN_ID_LENGTH,
    PROBE_LOCATIONS,
    DiagnosticConfidence,
    DiagnosticProbeResult,
    DiagnosticRun,
    FaultDomain,
    ProbeLocation,
)

# --- bounds -----------------------------------------------------------------------------------

MAX_LOCATION_CHECKS = 64
MAX_CAUSE_EVIDENCE = 32
MAX_CHANGE_ITEMS = 20
MAX_SESSION_PAGE_SIZE = 100
MAX_SESSION_LIST_OFFSET = 10_000

# What an incident change shows in place of its title. A session never stores an incident title (it
# would outlive the caller's permission to read it); the title is joined at read time, and only for
# a caller holding incidents:read. Everyone else, and a failed lookup, sees this.
INCIDENT_TITLE_PLACEHOLDER = "Incident title withheld"

# --- vocabularies -----------------------------------------------------------------------------

LocationState = Literal["observed", "unknown", "not-connected"]
LocationStatus = Literal["pass", "fail"]
EvidenceBasis = Literal["observed", "inferred", "unknown"]
CauseBasis = Literal["inferred", "unknown"]
CausePattern = Literal["external-only-failure", "service-failure", "other", "none"]
ChangeSourceName = Literal["incidents", "alerts", "configuration-changes"]
CHANGE_SOURCES: Final[tuple[ChangeSourceName, ...]] = (
    "incidents",
    "alerts",
    "configuration-changes",
)
ChangeKind = Literal["incident", "alert"]
ChangeScope = Literal["target", "time-window"]
PathTier = Literal["user", "access-point", "access-switch", "core", "firewall", "server"]
PATH_TIERS: Final[tuple[PathTier, ...]] = (
    "user",
    "access-point",
    "access-switch",
    "core",
    "firewall",
    "server",
)
HopState = Literal["known", "unknown"]

# The path tier a fault domain points at, or None when the domain lies outside the path
# (external DNS / WAN) and no hop may be highlighted.
SUSPECTED_TIER: Final[dict[FaultDomain, PathTier | None]] = {
    "target": "server",
    "service": "server",
    "host": "server",
    "interface": "server",
    "access-device": "access-switch",
    "core": "core",
    "firewall": "firewall",
    "wan-dns-external": None,
}


def suspected_tier(domain: FaultDomain | None) -> PathTier | None:
    return None if domain is None else SUSPECTED_TIER[domain]


def pattern_for(domain: FaultDomain | None) -> CausePattern:
    """The named pattern a domain stands for.

    ``firewall`` is only ever named when the service answers from the internal locations while
    the external one fails; ``service`` when it fails even from the server's own VLAN.
    """
    if domain is None:
        return "none"
    if domain == "firewall":
        return "external-only-failure"
    return "service-failure" if domain == "service" else "other"


# --- per-location results ---------------------------------------------------------------------


class DiagnosticLocationResult(ContractModel):
    """What one configured probe location reported (not-connected is never healthy)."""

    location: ProbeLocation
    state: LocationState
    status: LocationStatus | None = Field(...)
    passed: int = Field(ge=0, le=MAX_LOCATION_CHECKS)
    failed: int = Field(ge=0, le=MAX_LOCATION_CHECKS)
    unknown_checks: int = Field(ge=0, le=MAX_LOCATION_CHECKS)
    check_ids: list[str] = Field(max_length=MAX_LOCATION_CHECKS)

    @model_validator(mode="after")
    def _consistent(self) -> DiagnosticLocationResult:
        _require_unique(self.check_ids, "check_ids")
        if self.passed + self.failed + self.unknown_checks != len(self.check_ids):
            raise ValueError("the counts must equal the number of check_ids")
        if self.state == "not-connected" and self.check_ids:
            raise ValueError("a not-connected location has no checks")
        if self.state == "unknown" and (self.passed or self.failed or not self.unknown_checks):
            raise ValueError("an unknown location has only unanswered checks")
        if self.state == "observed" and not (self.passed or self.failed):
            raise ValueError("an observed location has at least one answered check")
        expected: LocationStatus | None = None
        if self.state == "observed":
            expected = "fail" if self.failed else "pass"
        if self.status != expected:
            raise ValueError(
                "status must be fail when a check failed, else pass, and only if observed"
            )
        return self


def derive_location_results(
    checks: Sequence[DiagnosticProbeResult],
) -> list[DiagnosticLocationResult]:
    """The six location results a run's checks imply, in the fixed location order.

    A location with no check has no configured source that took part: not-connected, never healthy.
    A location whose checks were all unanswered is unknown.
    """
    results: list[DiagnosticLocationResult] = []
    for location in PROBE_LOCATIONS:
        mine = [check for check in checks if check.location == location]
        passed = sum(1 for check in mine if check.status == "pass")
        failed = sum(1 for check in mine if check.status == "fail")
        unanswered = len(mine) - passed - failed
        state: LocationState = "not-connected"
        status: LocationStatus | None = None
        if mine:
            state = "observed" if passed or failed else "unknown"
        if state == "observed":
            status = "fail" if failed else "pass"
        results.append(
            DiagnosticLocationResult(
                location=location,
                state=state,
                status=status,
                passed=passed,
                failed=failed,
                unknown_checks=unanswered,
                check_ids=[check.id for check in mine],
            )
        )
    return results


# --- probable cause ---------------------------------------------------------------------------


class DiagnosticEvidenceItem(ContractModel):
    """One evidence line, labelled observed / inferred / unknown."""

    basis: EvidenceBasis
    statement: str = Field(min_length=1, max_length=1000, pattern=NON_BLANK)
    check_ids: list[str] = Field(max_length=MAX_LOCATION_CHECKS)

    @model_validator(mode="after")
    def _unique(self) -> DiagnosticEvidenceItem:
        _require_unique(self.check_ids, "check_ids")
        return self


class DiagnosticProbableCause(ContractModel):
    """The conservative cause with its evidence; null domain means nothing was narrowed."""

    domain: FaultDomain | None = Field(...)
    confidence: DiagnosticConfidence
    basis: CauseBasis
    pattern: CausePattern
    summary: str = Field(min_length=1, max_length=1000, pattern=NON_BLANK)
    evidence: list[DiagnosticEvidenceItem] = Field(max_length=MAX_CAUSE_EVIDENCE)

    @model_validator(mode="after")
    def _named_exactly_when_narrowed(self) -> DiagnosticProbableCause:
        named = self.domain is not None
        if (
            named != (self.confidence != "unknown")
            or named != (self.basis == "inferred")
            or named != (self.pattern != "none")
        ):
            raise ValueError(
                "domain is null exactly when confidence is unknown, basis is unknown and pattern is none"
            )
        if self.pattern != pattern_for(self.domain):
            raise ValueError("pattern must be the one the domain stands for")
        return self


# --- recent changes ---------------------------------------------------------------------------


class DiagnosticChangeSource(ContractModel):
    source: ChangeSourceName
    state: StoreState


class DiagnosticChangeItem(ContractModel):
    """A known change near the failure; correlation is never causation.

    An incident is a reference (id, severity, time) whose title is never stored: ``title`` is the
    placeholder and ``title_redacted`` true unless a read-time join revealed it to a caller holding
    ``incidents:read``. An alert has no severity and its title is stored.
    """

    kind: ChangeKind
    ref_id: str = Field(min_length=1, max_length=128)
    severity: IncidentSeverity | None = Field(...)
    title: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    title_redacted: bool
    occurred_at: AwareDatetime
    scope: ChangeScope
    relation: Literal["may-correlate"]

    @model_validator(mode="after")
    def _kind_fields(self) -> DiagnosticChangeItem:
        if self.kind == "incident" and self.severity is None:
            raise ValueError("an incident change carries its severity")
        if self.kind == "alert" and (self.severity is not None or self.title_redacted):
            raise ValueError("an alert change has no severity and a stored title")
        return self


def changes_state(sources: Sequence[DiagnosticChangeSource]) -> StoreState:
    """ok when any source was read, not-connected when none is connected, else unknown."""
    if any(source.state == "ok" for source in sources):
        return "ok"
    if all(source.state == "not-connected" for source in sources):
        return "not-connected"
    return "unknown"


class DiagnosticRecentChanges(ContractModel):
    state: StoreState
    window_start: AwareDatetime
    window_end: AwareDatetime
    sources: list[DiagnosticChangeSource] = Field(min_length=3, max_length=3)
    items: list[DiagnosticChangeItem] = Field(max_length=MAX_CHANGE_ITEMS)

    @model_validator(mode="after")
    def _consistent(self) -> DiagnosticRecentChanges:
        if self.window_end < self.window_start:
            raise ValueError("window_end must not be before window_start")
        if tuple(source.source for source in self.sources) != CHANGE_SOURCES:
            raise ValueError("sources must be incidents, alerts, configuration-changes in order")
        if self.state != changes_state(self.sources):
            raise ValueError(
                "state must follow the sources: ok if any was read, else not-connected/unknown"
            )
        if self.state != "ok" and self.items:
            raise ValueError("items are only present when the state is ok")
        read = {source.source for source in self.sources if source.state == "ok"}
        for item in self.items:
            kind_source = "incidents" if item.kind == "incident" else "alerts"
            if kind_source not in read:
                raise ValueError("an item must come from a source that was read")
        return self


# --- path -------------------------------------------------------------------------------------


class DiagnosticPathHop(ContractModel):
    tier: PathTier
    state: HopState
    device_id: str | None = Field(..., min_length=43, max_length=43, pattern=_DEVICE_ID_PATTERN)
    name: str | None = Field(..., min_length=1, max_length=255, pattern=NON_BLANK)
    highlight: Literal["suspected"] | None = Field(...)

    @model_validator(mode="after")
    def _known_iff_device(self) -> DiagnosticPathHop:
        known = self.state == "known"
        if known != (self.device_id is not None) or known != (self.name is not None):
            raise ValueError("a hop is known exactly when it has a device id and a name")
        return self


class DiagnosticPathLink(ContractModel):
    from_tier: PathTier
    to_tier: PathTier
    state: HopState


class DiagnosticPath(ContractModel):
    state: StoreState
    observed_at: AwareDatetime | None = Field(...)
    hops: list[DiagnosticPathHop] = Field(max_length=len(PATH_TIERS))
    links: list[DiagnosticPathLink] = Field(max_length=len(PATH_TIERS) - 1)

    @model_validator(mode="after")
    def _consistent(self) -> DiagnosticPath:
        if self.state != "ok":
            if self.hops or self.links or self.observed_at is not None:
                raise ValueError("only an ok path carries hops, links and a topology time")
            return self
        if self.observed_at is None:
            raise ValueError("an ok path states when the topology was read")
        if tuple(hop.tier for hop in self.hops) != PATH_TIERS:
            raise ValueError("an ok path lists the six tiers in order")
        pairs = list(pairwise(PATH_TIERS))
        if [(link.from_tier, link.to_tier) for link in self.links] != pairs:
            raise ValueError("links join adjacent tiers in order")
        if self.hops[-1].state != "known":
            raise ValueError("an ok path starts from the resolved target")
        if sum(1 for hop in self.hops if hop.highlight is not None) > 1:
            raise ValueError("at most one hop is suspected")
        for link, (left, right) in zip(self.links, pairwise(self.hops), strict=True):
            if link.state == "known" and not (left.state == "known" and right.state == "known"):
                raise ValueError("a link is known only between two known hops")
        return self

    def highlighted_tier(self) -> PathTier | None:
        for hop in self.hops:
            if hop.highlight is not None:
                return hop.tier
        return None


# --- session ----------------------------------------------------------------------------------


class DiagnosticSession(ContractModel):
    """A stored, immutable diagnostic session; its id is the run id."""

    run: DiagnosticRun
    locations: list[DiagnosticLocationResult] = Field(
        min_length=len(PROBE_LOCATIONS), max_length=len(PROBE_LOCATIONS)
    )
    probable_cause: DiagnosticProbableCause
    recent_changes: DiagnosticRecentChanges
    path: DiagnosticPath

    @model_validator(mode="after")
    def _agrees_with_the_run(self) -> DiagnosticSession:
        if self.locations != derive_location_results(self.run.checks):
            raise ValueError("locations must be exactly what the run's checks imply")
        if (
            self.probable_cause.domain != self.run.probable_fault_domain
            or self.probable_cause.confidence != self.run.confidence
        ):
            raise ValueError("the probable cause must equal the run's own conclusion")
        known_checks = {check.id for check in self.run.checks}
        for line in self.probable_cause.evidence:
            if not set(line.check_ids) <= known_checks:
                raise ValueError("evidence may only cite checks of the run")
        highlighted = self.path.highlighted_tier()
        if self.path.state == "ok" and highlighted != suspected_tier(self.probable_cause.domain):
            raise ValueError("only the tier the probable cause points at may be highlighted")
        return self


class DiagnosticSessionSummary(ContractModel):
    id: str = Field(
        min_length=DIAGNOSTIC_RUN_ID_LENGTH,
        max_length=DIAGNOSTIC_RUN_ID_LENGTH,
        pattern=DIAGNOSTIC_ID_PATTERN,
    )
    target: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    started_at: AwareDatetime
    completed_at: AwareDatetime
    probable_fault_domain: FaultDomain | None = Field(...)
    confidence: DiagnosticConfidence

    @model_validator(mode="after")
    def _confidence_matches_domain(self) -> DiagnosticSessionSummary:
        if (self.probable_fault_domain is not None) != (self.confidence != "unknown"):
            raise ValueError("confidence is unknown exactly when no probable fault domain is named")
        return self

    @classmethod
    def from_session(cls, session: DiagnosticSession) -> DiagnosticSessionSummary:
        run = session.run
        return cls(
            id=run.id,
            target=run.target,
            started_at=run.started_at,
            completed_at=run.completed_at,
            probable_fault_domain=run.probable_fault_domain,
            confidence=run.confidence,
        )


class DiagnosticSessionResponse(ContractModel):
    state: StoreState
    session: DiagnosticSession | None = Field(...)

    @model_validator(mode="after")
    def _session_exactly_when_ok(self) -> DiagnosticSessionResponse:
        if (self.state == "ok") != (self.session is not None):
            raise ValueError("session is present exactly when state is ok")
        return self


class DiagnosticSessionListResponse(ContractModel):
    state: StoreState
    sessions: list[DiagnosticSessionSummary] = Field(max_length=MAX_SESSION_PAGE_SIZE)
    limit: int = Field(ge=1, le=MAX_SESSION_PAGE_SIZE)
    offset: int = Field(ge=0, le=MAX_SESSION_LIST_OFFSET)
    next_offset: int | None = Field(..., ge=1, le=MAX_SESSION_LIST_OFFSET + MAX_SESSION_PAGE_SIZE)

    @model_validator(mode="after")
    def _rows_only_when_ok(self) -> DiagnosticSessionListResponse:
        if self.state != "ok" and (self.sessions or self.next_offset is not None):
            raise ValueError("only an ok state carries sessions or a following page")
        return self


__all__ = [
    "CHANGE_SOURCES",
    "INCIDENT_TITLE_PLACEHOLDER",
    "PATH_TIERS",
    "DiagnosticChangeItem",
    "DiagnosticChangeSource",
    "DiagnosticEvidenceItem",
    "DiagnosticLocationResult",
    "DiagnosticPath",
    "DiagnosticPathHop",
    "DiagnosticPathLink",
    "DiagnosticProbableCause",
    "DiagnosticRecentChanges",
    "DiagnosticSession",
    "DiagnosticSessionListResponse",
    "DiagnosticSessionResponse",
    "DiagnosticSessionSummary",
    "changes_state",
    "derive_location_results",
    "suspected_tier",
]
