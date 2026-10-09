"""Alert-rule / maintenance-window API envelopes and requests (S6-3).

Split out of ``schemas.py`` (which holds the entity models these wrap) to keep both files
cohesive; behaviour is unchanged. Import these names from here, not from ``schemas``.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from itertools import pairwise
from typing import Annotated, Literal

from pydantic import AwareDatetime, BeforeValidator, Field, model_validator

from netsight_api.schemas import (
    _THRESHOLD_BOUND,
    MAX_MAINTENANCE_DURATION,
    NON_BLANK,
    AlertRule,
    AlertRuleDefinition,
    AlertScope,
    ContractModel,
    MaintenanceEvaluation,
    MaintenanceWindow,
    MaintenanceWindowDefinition,
    ShortName,
    StoreState,
    _require_unique,
)

# --- alert-rule / maintenance-window API (S6-3) ---------------------------------------------------
#
# Mirrors contracts/json-schema/alert-rule-api.schema.json. Responses and requests are strict
# contract models. Request timestamps are the one lax field: FastAPI validates JSON bodies in
# python mode, where a strict datetime would reject an ISO string, so those fields accept text
# only (never a number) and are re-validated against the strict definition models before use.

MAX_RULE_PAGE_SIZE = 100
MAX_RULE_LIST_OFFSET = 10_000
MAX_EVALUATE_OBSERVATIONS = 200
MAX_EVALUATE_WINDOWS = 20
MAX_OBSERVATION_SCOPES = 16
MAX_OBSERVATION_TEXT = 4096
# Combined observation text of one dry-run: bounds CPU (the matcher is linear in text length)
# without limiting the number of short observations.
MAX_EVALUATE_TOTAL_TEXT = 64 * MAX_OBSERVATION_TEXT
MAX_MAINTENANCE_LEAD = timedelta(days=366)
MAX_RULE_VERSION = 1_000_000

EvaluateOutcome = Literal[
    "firing",
    "pending",
    "not-met",
    "excepted",
    "outside-schedule",
    "no-data",
    "out-of-scope",
    "stale",
    "future",
    "maintenance-disabled",
    "invalid-config",
    "rule-not-active",
]
EvaluatePhase = Literal["inactive", "pending", "firing"]
EvaluateTransition = Literal["fired", "resolved"]
EvaluateBlockedBy = Literal["maintenance", "cooldown"]
ObservationAnomaly = Literal["above", "below", "normal"]
SampleWindowStatus = Literal["scheduled", "cancelled"]
_PROBLEM_CODE = r"^[A-Z0-9_]+$"


def _require_text(value: object) -> object:
    if not isinstance(value, str):
        raise ValueError("an RFC 3339 timestamp must be a string")  # noqa: TRY004 (pydantic)
    return value


RequestInstant = Annotated[AwareDatetime, BeforeValidator(_require_text), Field(strict=False)]
RuleVersion = Annotated[int, Field(ge=1, le=MAX_RULE_VERSION)]


class AlertRuleListResponse(ContractModel):
    state: StoreState
    rules: list[AlertRule] = Field(max_length=MAX_RULE_PAGE_SIZE)
    limit: int = Field(ge=1, le=MAX_RULE_PAGE_SIZE)
    offset: int = Field(ge=0, le=MAX_RULE_LIST_OFFSET)
    next_offset: int | None = Field(..., ge=1, le=MAX_RULE_LIST_OFFSET)

    @model_validator(mode="after")
    def _non_ok_carries_no_rows(self) -> AlertRuleListResponse:
        if self.state != "ok" and (self.rules or self.next_offset is not None):
            raise ValueError("non-ok rule state must not carry rules or a cursor")
        return self


class AlertRuleDetailResponse(ContractModel):
    state: StoreState
    rule: AlertRule | None = Field(...)

    @model_validator(mode="after")
    def _rule_exactly_when_ok(self) -> AlertRuleDetailResponse:
        if (self.state == "ok") != (self.rule is not None):
            raise ValueError("rule is present exactly when state is ok")
        return self


class MaintenanceWindowListResponse(ContractModel):
    state: StoreState
    windows: list[MaintenanceWindow] = Field(max_length=MAX_RULE_PAGE_SIZE)
    limit: int = Field(ge=1, le=MAX_RULE_PAGE_SIZE)
    offset: int = Field(ge=0, le=MAX_RULE_LIST_OFFSET)
    next_offset: int | None = Field(..., ge=1, le=MAX_RULE_LIST_OFFSET)

    @model_validator(mode="after")
    def _non_ok_carries_no_rows(self) -> MaintenanceWindowListResponse:
        if self.state != "ok" and (self.windows or self.next_offset is not None):
            raise ValueError("non-ok window state must not carry windows or a cursor")
        return self


class MaintenanceWindowDetailResponse(ContractModel):
    state: StoreState
    window: MaintenanceWindow | None = Field(...)

    @model_validator(mode="after")
    def _window_exactly_when_ok(self) -> MaintenanceWindowDetailResponse:
        if (self.state == "ok") != (self.window is not None):
            raise ValueError("window is present exactly when state is ok")
        return self


class AlertRuleUpdateRequest(ContractModel):
    expected_version: RuleVersion
    definition: AlertRuleDefinition


class AlertRuleApproveRequest(ContractModel):
    expected_version: RuleVersion


def _check_window_span(starts_at: datetime, ends_at: datetime) -> None:
    duration = ends_at - starts_at
    if duration <= timedelta(0):
        raise ValueError("ends_at must be after starts_at")
    if duration > MAX_MAINTENANCE_DURATION:
        raise ValueError("a maintenance window may last at most 30 days")


class MaintenanceWindowCreateRequest(ContractModel):
    name: str = Field(min_length=1, max_length=255, pattern=NON_BLANK)
    scope: AlertScope
    starts_at: RequestInstant
    ends_at: RequestInstant
    evaluation: MaintenanceEvaluation
    reason: str = Field(min_length=1, max_length=1000, pattern=NON_BLANK)

    @model_validator(mode="after")
    def _bounded_positive_duration(self) -> MaintenanceWindowCreateRequest:
        _check_window_span(self.starts_at, self.ends_at)
        return self

    def to_definition(self) -> MaintenanceWindowDefinition:
        """Re-validate against the strict definition model the store accepts."""
        return MaintenanceWindowDefinition.model_validate_json(self.model_dump_json())


class AlertRuleEvaluateObservation(ContractModel):
    at: RequestInstant
    entity: str = Field(min_length=1, max_length=255)
    scopes: list[AlertScope] = Field(min_length=1, max_length=MAX_OBSERVATION_SCOPES)
    value: float | None = Field(..., ge=-_THRESHOLD_BOUND, le=_THRESHOLD_BOUND, allow_inf_nan=False)
    text: str | None = Field(..., max_length=MAX_OBSERVATION_TEXT)
    anomaly: ObservationAnomaly | None = Field(...)
    destination: str | None = Field(..., min_length=1, max_length=255)
    device_groups: list[ShortName] = Field(max_length=16)

    @model_validator(mode="after")
    def _unique(self) -> AlertRuleEvaluateObservation:
        _require_unique(self.device_groups, "device_groups")
        _require_unique([f"{scope.kind}\x1f{scope.ref}" for scope in self.scopes], "scopes")
        return self


class AlertRuleEvaluateWindow(ContractModel):
    scope: AlertScope
    starts_at: RequestInstant
    ends_at: RequestInstant
    evaluation: MaintenanceEvaluation
    status: SampleWindowStatus

    @model_validator(mode="after")
    def _bounded_positive_duration(self) -> AlertRuleEvaluateWindow:
        _check_window_span(self.starts_at, self.ends_at)
        return self


class AlertRuleEvaluateRequest(ContractModel):
    definition: AlertRuleDefinition
    observations: list[AlertRuleEvaluateObservation] = Field(
        min_length=1, max_length=MAX_EVALUATE_OBSERVATIONS
    )
    windows: list[AlertRuleEvaluateWindow] = Field(max_length=MAX_EVALUATE_WINDOWS)

    @model_validator(mode="after")
    def _strictly_ascending(self) -> AlertRuleEvaluateRequest:
        times = [observation.at for observation in self.observations]
        if any(later <= earlier for earlier, later in pairwise(times)):
            raise ValueError("observations must be in strictly ascending time order")
        return self

    @model_validator(mode="after")
    def _bounded_total_text(self) -> AlertRuleEvaluateRequest:
        total = sum(len(item.text) for item in self.observations if item.text is not None)
        if total > MAX_EVALUATE_TOTAL_TEXT:
            raise ValueError("the combined observation text is too large")
        return self


class AlertRuleEvaluateProblem(ContractModel):
    code: str = Field(min_length=1, max_length=64, pattern=_PROBLEM_CODE)
    field: str = Field(min_length=1, max_length=64)


class AlertRuleEvaluateResult(ContractModel):
    at: AwareDatetime
    outcome: EvaluateOutcome
    phase: EvaluatePhase
    transition: EvaluateTransition | None = Field(...)
    notify: bool
    blocked_by: EvaluateBlockedBy | None = Field(...)
    maintenance_windows: list[Annotated[int, Field(ge=0, le=MAX_EVALUATE_WINDOWS - 1)]] = Field(
        max_length=MAX_EVALUATE_WINDOWS
    )

    @model_validator(mode="after")
    def _unique_indexes(self) -> AlertRuleEvaluateResult:
        if len(set(self.maintenance_windows)) != len(self.maintenance_windows):
            raise ValueError("maintenance_windows must be unique")
        return self


class AlertRuleEvaluateResponse(ContractModel):
    valid: bool
    problems: list[AlertRuleEvaluateProblem] = Field(max_length=8)
    results: list[AlertRuleEvaluateResult] = Field(max_length=MAX_EVALUATE_OBSERVATIONS)

    @model_validator(mode="after")
    def _problems_exactly_when_invalid(self) -> AlertRuleEvaluateResponse:
        """An unevaluable rule explains why and carries no decisions (fail closed)."""
        if self.valid and self.problems:
            raise ValueError("a valid dry-run carries no problems")
        if not self.valid and (not self.problems or self.results):
            raise ValueError("an invalid dry-run carries problems and no results")
        return self
