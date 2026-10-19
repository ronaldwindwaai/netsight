"""Inputs the action store accepts: a new request and the outcome of an execution.

``NewAction`` is built by the proposal code after the catalogue and policy checks, never straight
from a request body. Its ``digest`` binds every immutable field, so an approval quoting a digest is
an approval of exactly this content; its ``fingerprint`` (no id, no time) is what idempotency
compares, so a retry is recognised and a different request under the same key is refused.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from netsight_api.schemas_actions import (
    ActionActor,
    ActionCheck,
    ActionRollback,
    ActionSource,
    ActionType,
    ActionVerification,
    EventType,
    ParamValue,
    Risk,
)

FinalState = Literal["succeeded", "failed", "rolled-back"]
EffectName = Literal["none", "applied", "unknown"]


def canonical(value: Any) -> str:
    """Stable JSON: sorted keys, no whitespace, non-ASCII kept."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(frozen=True)
class NewAction:
    id: str
    action_type: ActionType
    target_id: str
    params: dict[str, ParamValue]
    risk: Risk
    requester: ActionActor
    reason: str
    source: ActionSource | None
    approvals_required: int
    policy_checks: tuple[ActionCheck, ...]
    created_at: datetime
    approve_by: datetime
    execute_within_seconds: int
    timeout_seconds: int

    def _body(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target_id": self.target_id,
            "params": self.params,
            "risk": self.risk,
            "requester": self.requester.id,
            "reason": self.reason,
            "source": self.source.model_dump(mode="json") if self.source else None,
            "approvals_required": self.approvals_required,
        }

    @property
    def digest(self) -> str:
        """Binds the id, the content and the deadline an approver is shown."""
        bound = {
            **self._body(),
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "approve_by": self.approve_by.isoformat(),
        }
        return "sha256:" + sha256_hex(canonical(bound))

    @property
    def fingerprint(self) -> str:
        return sha256_hex(canonical(self._body()))


@dataclass(frozen=True)
class ExecutionFinish:
    """What an executor run came to. The store applies it only to an ``executing`` request."""

    final_state: FinalState
    effect: EffectName
    failure: str | None
    verification: ActionVerification
    rollback: ActionRollback | None
    events: tuple[tuple[EventType, str], ...]
    finished_at: datetime
    pre_checks: tuple[ActionCheck, ...] = ()
