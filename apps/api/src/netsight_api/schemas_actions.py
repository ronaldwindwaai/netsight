"""Typed boundary models for controlled remote actions (Step 12, roadmap E11).

Mirrors ``contracts/json-schema/actions.schema.json``, the OpenAPI components and the browser
parsers (shared vectors: ``contracts/test-vectors/actions.vectors.json``).

Honesty rules, enforced here and not only by construction:

* an action is one of the allow-listed ``ActionType`` values with typed parameters; there is no
  field that can carry a command, a script or an argument vector;
* a ``dry-run`` execution never changed anything (``effect`` is ``none``); ``applied`` exists only
  for a live executor, and none ships in this release;
* the history is append-only and hash-chained, so a gap or an edit is detectable;
* free text (``reason``) is data: bounded, stripped of control and format characters, shown as text.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Annotated, Final, Literal

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, StrictStr, model_validator
from pydantic.functional_validators import AfterValidator

from netsight_api.schemas import ApiModel
from netsight_api.schemas_unknown_devices import FindingId

ActionType = Literal["endpoint.isolate", "switch.port.disable", "switch.port.enable"]
Risk = Literal["A", "B", "C", "D"]
RequestState = Literal[
    "proposed",
    "pending-approval",
    "approved",
    "rejected",
    "expired",
    "cancelled",
    "executing",
    "succeeded",
    "failed",
    "rolled-back",
]
TERMINAL_STATES: Final[frozenset[str]] = frozenset(
    {"rejected", "expired", "cancelled", "succeeded", "failed", "rolled-back"}
)
OPEN_STATES: Final[frozenset[str]] = frozenset(
    {"proposed", "pending-approval", "approved", "executing"}
)
# The only moves the lifecycle allows. Anything not listed is refused by the store.
ALLOWED_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "proposed": frozenset({"pending-approval", "rejected", "cancelled"}),
    "pending-approval": frozenset({"approved", "rejected", "expired", "cancelled"}),
    "approved": frozenset({"executing", "expired", "cancelled"}),
    "executing": frozenset({"succeeded", "failed", "rolled-back"}),
    "rejected": frozenset(),
    "expired": frozenset(),
    "cancelled": frozenset(),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "rolled-back": frozenset(),
}
ActorKind = Literal["human", "service", "ai"]
CheckState = Literal["pass", "fail", "unknown"]
VerificationState = Literal["passed", "failed", "not-applicable", "unknown"]
RollbackState = Literal["completed", "failed", "not-needed"]
ExecutionMode = Literal["dry-run", "live"]
Effect = Literal["none", "applied", "unknown"]
EngineState = Literal["ok", "not-connected"]
ExecutorState = Literal["ok", "disabled", "not-connected"]
KillSwitchSource = Literal["none", "runtime", "environment"]
EventType = Literal[
    "proposed",
    "policy-checked",
    "submitted",
    "approved",
    "rejected",
    "cancelled",
    "expired",
    "execution-started",
    "pre-check-failed",
    "executed",
    "verification-passed",
    "verification-failed",
    "rolled-back",
    "rollback-failed",
    "failed",
]
ParamKind = Literal["integer", "boolean", "choice"]

ID_PATTERN: Final = r"^action-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
TARGET_PATTERN: Final = r"^[a-z0-9][a-z0-9._:-]{0,127}$"
DIGEST_PATTERN: Final = r"^sha256:[0-9a-f]{64}$"
HASH_PATTERN: Final = r"^[0-9a-f]{64}$"
CODE_PATTERN: Final = r"^[a-z][a-z0-9-]{1,63}$"
PARAM_NAME_PATTERN: Final = r"^[a-z][a-z0-9_]{0,31}$"
IDEMPOTENCY_KEY_PATTERN: Final = r"^[A-Za-z0-9._-]{16,64}$"
ZERO_HASH: Final = "0" * 64
MAX_REASON: Final = 500
MIN_REASON: Final = 3
MAX_PARAMS: Final = 8
MAX_APPROVALS: Final = 2
MAX_STEPS: Final = 10
MAX_HISTORY: Final = 100
MAX_PAGE_SIZE: Final = 50
MAX_COUNT: Final = 1_000_000

_ID = re.compile(ID_PATTERN)
_REFUSED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def clean_text(value: str) -> str:
    """Free text is data: no control, format (bidi, zero-width), surrogate or separator characters."""
    if not value.strip():
        raise ValueError("text must not be blank")
    for char in value:
        if unicodedata.category(char) in _REFUSED_CATEGORIES:
            raise ValueError("text must not contain control or format characters")
    return value


ActionId = Annotated[str, Field(min_length=43, max_length=43, pattern=ID_PATTERN)]
TargetId = Annotated[str, Field(min_length=1, max_length=128, pattern=TARGET_PATTERN)]
Digest = Annotated[str, Field(min_length=71, max_length=71, pattern=DIGEST_PATTERN)]
Hash = Annotated[str, Field(min_length=64, max_length=64, pattern=HASH_PATTERN)]
Code = Annotated[str, Field(min_length=2, max_length=64, pattern=CODE_PATTERN)]
Reason = Annotated[
    str, Field(min_length=MIN_REASON, max_length=MAX_REASON), AfterValidator(clean_text)
]
ParamName = Annotated[str, Field(pattern=PARAM_NAME_PATTERN)]
ParamValue = StrictBool | StrictInt | Annotated[StrictStr, Field(min_length=1, max_length=64)]
Version = Annotated[int, Field(ge=1, le=MAX_COUNT, strict=True)]


def is_action_id(value: str) -> bool:
    return bool(_ID.fullmatch(value))


class ActionActor(ApiModel):
    id: str = Field(min_length=1, max_length=255)
    kind: ActorKind


class ActionSource(ApiModel):
    """Where a proposal came from. Only the Step 8 quarantine proposal exists today."""

    kind: Literal["unknown-device-finding"]
    id: FindingId
    evidence_version: Version


class ActionApproval(ApiModel):
    approver_id: str = Field(min_length=1, max_length=255)
    approved_at: AwareDatetime


class ActionCheck(ApiModel):
    """One policy or pre-execution check. ``detail`` is a static code, never derived from input."""

    name: Code
    state: CheckState
    detail: Code


class ActionVerification(ApiModel):
    state: VerificationState
    detail: Code


class ActionRollback(ApiModel):
    state: RollbackState
    detail: Code


class ActionExecution(ApiModel):
    executor: Code
    mode: ExecutionMode
    effect: Effect
    started_at: AwareDatetime
    finished_at: AwareDatetime | None
    planned_steps: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        max_length=MAX_STEPS
    )
    verification: ActionVerification
    rollback: ActionRollback | None
    failure: Code | None

    @model_validator(mode="after")
    def _a_dry_run_changed_nothing(self) -> ActionExecution:
        if self.mode == "dry-run" and self.effect != "none":
            raise ValueError("a dry run never changes anything")
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("an execution does not finish before it starts")
        return self


class ActionRequest(ApiModel):
    id: ActionId
    action_type: ActionType
    target_id: TargetId
    params: dict[ParamName, ParamValue] = Field(max_length=MAX_PARAMS)
    risk: Risk
    state: RequestState
    requester: ActionActor
    reason: Reason
    source: ActionSource | None
    approvals_required: int = Field(ge=1, le=MAX_APPROVALS)
    approvals: list[ActionApproval] = Field(max_length=MAX_APPROVALS)
    created_at: AwareDatetime
    approve_by: AwareDatetime
    execute_by: AwareDatetime | None
    version: Version
    digest: Digest
    policy_checks: list[ActionCheck] = Field(max_length=16)
    pre_checks: list[ActionCheck] = Field(max_length=16)
    execution: ActionExecution | None

    @model_validator(mode="after")
    def _approvals_follow_the_state(self) -> ActionRequest:
        approvers = [a.approver_id for a in self.approvals]
        if len(set(approvers)) != len(approvers):
            raise ValueError("one person approves once")
        if self.requester.id in approvers:
            raise ValueError("a requester never approves their own request")
        if len(approvers) > self.approvals_required:
            raise ValueError("more approvals than required")
        past_approval = self.state in (
            "approved",
            "executing",
            "succeeded",
            "failed",
            "rolled-back",
        )
        if past_approval and len(approvers) < self.approvals_required:
            # A failure can precede approval only by expiry/cancel, which have their own states.
            raise ValueError("execution needs every required approval")
        if self.state == "approved" and self.execute_by is None:
            raise ValueError("an approved request has an execution deadline")
        if self.state in ("succeeded", "rolled-back") and self.execution is None:
            raise ValueError("a finished execution is recorded")
        if (
            self.state in ("proposed", "pending-approval", "approved")
            and self.execution is not None
        ):
            raise ValueError("nothing has executed yet")
        return self


class ActionHistoryEvent(ApiModel):
    seq: int = Field(ge=1, le=MAX_COUNT, strict=True)
    at: AwareDatetime
    type: EventType
    actor_id: str | None = Field(..., min_length=1, max_length=255)
    from_state: RequestState | None
    to_state: RequestState
    code: Code
    # What the actor wrote when rejecting or cancelling. Untrusted text: shown as text only.
    note: Reason | None
    prev_hash: Hash
    hash: Hash


class ActionParamSpec(ApiModel):
    name: ParamName
    kind: ParamKind
    required: StrictBool
    minimum: int | None = Field(..., strict=True)
    maximum: int | None = Field(..., strict=True)
    choices: list[Annotated[str, Field(min_length=1, max_length=64)]] | None = Field(
        ..., max_length=16
    )

    @model_validator(mode="after")
    def _the_bounds_fit_the_kind(self) -> ActionParamSpec:
        if self.kind == "integer":
            if self.minimum is None or self.maximum is None or self.minimum > self.maximum:
                raise ValueError("an integer parameter has ordered bounds")
            if self.choices is not None:
                raise ValueError("an integer parameter has no choices")
        elif self.kind == "choice":
            if not self.choices or self.minimum is not None or self.maximum is not None:
                raise ValueError("a choice parameter lists its choices and nothing else")
        elif self.minimum is not None or self.maximum is not None or self.choices is not None:
            raise ValueError("a boolean parameter has no bounds")
        return self


class ActionDefinition(ApiModel):
    action_type: ActionType
    title: str = Field(min_length=1, max_length=80)
    risk: Risk
    target_kind: Code
    params: list[ActionParamSpec] = Field(max_length=MAX_PARAMS)
    approvals_required: int = Field(ge=1, le=MAX_APPROVALS)
    step_up_required: Literal[True]
    approve_within_seconds: int = Field(ge=60, le=604_800, strict=True)
    execute_within_seconds: int = Field(ge=60, le=86_400, strict=True)
    timeout_seconds: int = Field(ge=1, le=600, strict=True)
    propose_permission: str = Field(pattern=r"^actions:[a-z-]+$")
    rollback_guidance: str = Field(min_length=1, max_length=300)


class ExecutorStatus(ApiModel):
    id: Code
    mode: ExecutionMode
    state: ExecutorState

    @model_validator(mode="after")
    def _only_a_dry_run_is_always_available(self) -> ExecutorStatus:
        if self.mode == "dry-run" and self.state != "ok":
            raise ValueError("the dry-run executor needs nothing and is always available")
        return self


class KillSwitchStatus(ApiModel):
    engaged: StrictBool
    source: KillSwitchSource
    since: AwareDatetime | None

    @model_validator(mode="after")
    def _source_follows_engaged(self) -> KillSwitchStatus:
        if self.engaged == (self.source == "none"):
            raise ValueError("a source is named exactly when the switch is engaged")
        return self


class StoreStatus(ApiModel):
    """Where requests are held. Only the PostgreSQL store survives a restart and is shared by workers."""

    kind: Literal["memory", "postgres"]
    durable: StrictBool

    @model_validator(mode="after")
    def _only_postgres_is_durable(self) -> StoreStatus:
        if self.durable != (self.kind == "postgres"):
            raise ValueError("a store is durable exactly when it is the PostgreSQL store")
        return self


class PolicyStatus(ApiModel):
    """Operator policy the UI needs to explain a refusal before the API gives it."""

    self_execute_allowed: StrictBool


class ActionStatusResponse(ApiModel):
    state: EngineState
    generated_at: AwareDatetime
    dry_run_only: StrictBool
    kill_switch: KillSwitchStatus
    store: StoreStatus
    policy: PolicyStatus
    executors: list[ExecutorStatus] = Field(max_length=8)
    definitions: list[ActionDefinition] = Field(max_length=16)

    @model_validator(mode="after")
    def _dry_run_only_is_derived_from_the_executors(self) -> ActionStatusResponse:
        live = any(e.mode == "live" and e.state == "ok" for e in self.executors)
        if self.dry_run_only == live:
            raise ValueError("dry_run_only is exactly 'no live executor is ready'")
        if self.state == "not-connected" and (self.executors or self.definitions):
            raise ValueError("a disabled engine offers nothing")
        return self


class ActionListResponse(ApiModel):
    state: EngineState
    generated_at: AwareDatetime
    items: list[ActionRequest] = Field(max_length=MAX_PAGE_SIZE)
    total: int = Field(ge=0, le=MAX_COUNT)
    page: int = Field(ge=1, le=1000)
    page_size: int = Field(ge=1, le=MAX_PAGE_SIZE)

    @model_validator(mode="after")
    def _not_connected_is_empty(self) -> ActionListResponse:
        if self.state == "not-connected" and (self.items or self.total):
            raise ValueError("a disabled engine lists nothing")
        return self


class ActionDetailResponse(ApiModel):
    generated_at: AwareDatetime
    request: ActionRequest
    history: list[ActionHistoryEvent] = Field(min_length=1, max_length=MAX_HISTORY)
    chain_intact: StrictBool


# --- requests -------------------------------------------------------------------------------------------


class ActionCreateRequest(ApiModel):
    action_type: ActionType
    target_id: TargetId
    params: dict[ParamName, ParamValue] = Field(max_length=MAX_PARAMS)
    reason: Reason


class ActionFromFindingRequest(ApiModel):
    finding_id: FindingId
    expected_evidence_version: Version
    reason: Reason


class ActionDecisionRequest(ApiModel):
    """Approve or execute exactly the request the person saw: its digest and its version."""

    expected_digest: Digest
    expected_version: Version


class ActionReasonRequest(ApiModel):
    expected_digest: Digest
    expected_version: Version
    reason: Reason


class KillSwitchRequest(ApiModel):
    engaged: StrictBool
    reason: Reason
