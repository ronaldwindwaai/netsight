"""Diagnostics API models (S7).

Mirrors ``contracts/json-schema/diagnostic.schema.json`` and
``contracts/json-schema/diagnostic-api.schema.json`` and the OpenAPI components of the same
names; the four-way agreement tests drive all of them from one vector file. Result records are
strict, frozen ``ContractModel``s built by the server; the request body is a lax ``ApiModel``
(FastAPI validates JSON bodies in python mode, where a strict model would reject an ISO string
timestamp) re-validated before it reaches the probe adapter.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from netsight_api.schemas import (
    _DEVICE_ID_PATTERN,
    NON_BLANK,
    ApiModel,
    ContractModel,
    EvidenceRef,
    StoreState,
    _require_unique,
)

# --- diagnostics (S7) -------------------------------------------------------------------------
#
# The canonical ProbeResult / DiagnosticRun records and the /diagnostics envelope. A run names a
# probable fault domain exactly when it has the evidence to; with no domain the confidence is
# unknown, so a degraded run can never overstate certainty.

DiagnosticCheckKind = Literal[
    "identity",
    "source-freshness",
    "target-health",
    "dns",
    "icmp",
    "tcp",
    "http",
    "https",
    "service",
    "dependencies",
    "recent-changes",
    "baseline",
]
DiagnosticCheckStatus = Literal["pass", "fail", "unknown"]
FaultDomain = Literal[
    "target",
    "service",
    "host",
    "interface",
    "access-device",
    "core",
    "firewall",
    "wan-dns-external",
]
DiagnosticConfidence = Literal["low", "medium", "high", "unknown"]

DIAGNOSTIC_ID_PATTERN = (
    r"^diagnostic-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
DIAGNOSTIC_RUN_ID_LENGTH = 47
MAX_DIAGNOSTIC_CHECKS = 64
MAX_DIAGNOSTIC_FINDINGS = 64
MAX_DIAGNOSTIC_CONTRADICTIONS = 32
MAX_DIAGNOSTIC_UNKNOWNS = 32
MAX_DIAGNOSTIC_HYPOTHESES = 16
MAX_DIAGNOSTIC_NEXT_CHECKS = 32
MAX_DIAGNOSTIC_EVIDENCE = 256
MAX_FINDING_EVIDENCE = 32
MAX_DIAGNOSTIC_REQUEST_CHECKS = 12
_PORT_CHECK_KINDS = ("tcp", "http", "https")


class DiagnosticFinding(ContractModel):
    """One statement plus the evidence it rests on (facts/contradictions/unknowns/hypotheses)."""

    statement: str = Field(min_length=1, max_length=1000, pattern=NON_BLANK)
    evidence_ids: list[EvidenceRef] = Field(max_length=MAX_FINDING_EVIDENCE)

    @model_validator(mode="after")
    def _unique_evidence(self) -> DiagnosticFinding:
        _require_unique(self.evidence_ids, "evidence_ids")
        return self


class DiagnosticProbeResult(ContractModel):
    """One bounded read-only check (the canonical ProbeResult).

    ``status`` never asserts more than the check measured: a successful ping is not application
    availability and an ICMP failure is not host failure, so an unresolved check is ``unknown``.
    ``port`` is set only for tcp/http/https checks.
    """

    id: str = Field(min_length=1, max_length=128)
    kind: DiagnosticCheckKind
    label: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    status: DiagnosticCheckStatus
    vantage: str | None = Field(..., min_length=1, max_length=128, pattern=NON_BLANK)
    port: int | None = Field(..., ge=1, le=65535)
    latency_ms: float | None = Field(..., ge=0, le=3_600_000, allow_inf_nan=False)
    detail: str | None = Field(..., min_length=1, max_length=1000, pattern=NON_BLANK)
    observed_at: AwareDatetime | None = Field(...)
    evidence_id: EvidenceRef | None = Field(...)

    @model_validator(mode="after")
    def _port_only_for_port_checks(self) -> DiagnosticProbeResult:
        if self.port is not None and self.kind not in _PORT_CHECK_KINDS:
            raise ValueError("port is only valid for tcp, http and https checks")
        return self


class DiagnosticRun(ContractModel):
    """The completed root-cause run: bounded checks plus the inferred fault domain."""

    id: str = Field(
        min_length=DIAGNOSTIC_RUN_ID_LENGTH,
        max_length=DIAGNOSTIC_RUN_ID_LENGTH,
        pattern=DIAGNOSTIC_ID_PATTERN,
    )
    target: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    target_id: str | None = Field(
        ..., min_length=43, max_length=43, pattern=_DEVICE_ID_PATTERN
    )
    symptom: str | None = Field(..., min_length=1, max_length=1000, pattern=NON_BLANK)
    vantage: str | None = Field(..., min_length=1, max_length=128, pattern=NON_BLANK)
    started_at: AwareDatetime
    completed_at: AwareDatetime
    checks: list[DiagnosticProbeResult] = Field(max_length=MAX_DIAGNOSTIC_CHECKS)
    facts: list[DiagnosticFinding] = Field(max_length=MAX_DIAGNOSTIC_FINDINGS)
    contradictions: list[DiagnosticFinding] = Field(max_length=MAX_DIAGNOSTIC_CONTRADICTIONS)
    unknowns: list[DiagnosticFinding] = Field(max_length=MAX_DIAGNOSTIC_UNKNOWNS)
    probable_fault_domain: FaultDomain | None = Field(...)
    confidence: DiagnosticConfidence
    alternative_hypotheses: list[DiagnosticFinding] = Field(max_length=MAX_DIAGNOSTIC_HYPOTHESES)
    recommended_next_checks: list[DiagnosticFinding] = Field(max_length=MAX_DIAGNOSTIC_NEXT_CHECKS)
    evidence_ids: list[EvidenceRef] = Field(max_length=MAX_DIAGNOSTIC_EVIDENCE)

    @model_validator(mode="after")
    def _completed_not_before_started(self) -> DiagnosticRun:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not be before started_at")
        return self

    @model_validator(mode="after")
    def _confidence_matches_domain(self) -> DiagnosticRun:
        """A named fault domain carries a real confidence; no domain means unknown."""
        named = self.probable_fault_domain is not None
        if named != (self.confidence != "unknown"):
            raise ValueError(
                "confidence is unknown exactly when no probable fault domain is named"
            )
        return self

    @model_validator(mode="after")
    def _unique_ids(self) -> DiagnosticRun:
        _require_unique([check.id for check in self.checks], "check ids")
        _require_unique(self.evidence_ids, "evidence_ids")
        return self


class DiagnosticRunRequest(ApiModel):
    """Request body for POST /api/v1/diagnostics."""

    target: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    symptom: str | None = Field(..., min_length=1, max_length=1000, pattern=NON_BLANK)
    vantage: str | None = Field(..., min_length=1, max_length=128, pattern=NON_BLANK)
    requested_checks: list[DiagnosticCheckKind] = Field(
        min_length=1, max_length=MAX_DIAGNOSTIC_REQUEST_CHECKS
    )

    @model_validator(mode="after")
    def _unique_checks(self) -> DiagnosticRunRequest:
        _require_unique(list(self.requested_checks), "requested_checks")
        return self


class DiagnosticRunResponse(ContractModel):
    """POST /api/v1/diagnostics result; the run is present exactly when the state is ok."""

    state: StoreState
    run: DiagnosticRun | None = Field(...)

    @model_validator(mode="after")
    def _run_exactly_when_ok(self) -> DiagnosticRunResponse:
        if (self.state == "ok") != (self.run is not None):
            raise ValueError("run is present exactly when state is ok")
        return self
