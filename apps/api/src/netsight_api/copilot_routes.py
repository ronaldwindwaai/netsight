"""AI copilot routes (Step 10): ``/api/v1/copilot/status`` and ``/api/v1/copilot/ask``. Read-only.

The copilot answers a question from an evidence bundle built by registered read tools that run with
the *asker's own* permissions. There is no write, execute or approval route under this prefix, and
the model is given no tools: it returns text, which is validated before anything is shown.

* ``copilot:ask`` is human-only. A service or AI principal gets 403 whatever its role.
* ``ask`` is a cookie POST that spends model budget: authorise, then CSRF and origin, then a
  per-identity limit (with ``Retry-After``) and a global cap on concurrent questions (refused, not
  queued). A body outside the strict contract is a 422 that echoes nothing.
* Without a configured model the answer is ``not-connected`` and nothing is read. A model failure or
  an answer that fails validation is ``unknown``; sources that return nothing are ``no-evidence``.
* Every ask and every tool call is audited (actor, state, counts, tool names). The question, the
  evidence and the answer are never written to the audit trail.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
from datetime import UTC, datetime
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, Request, Response

from netsight_api.alerting_route_support import correlation_id
from netsight_api.audit import record_audit
from netsight_api.auth.csrf import write_refusal
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.contracts import ContractViolation, validate
from netsight_api.copilot import knowledge, sanitize
from netsight_api.copilot.provider import ModelProvider, configured_provider
from netsight_api.copilot.service import CopilotService
from netsight_api.copilot.tools import ToolBroker
from netsight_api.errors import ApiError
from netsight_api.incident_deps import OptionalIncidentStore
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.read_support import CurrentIdentity, no_store, reader, rejected
from netsight_api.schemas import ErrorEnvelope
from netsight_api.schemas_copilot import (
    MIN_QUESTION,
    CopilotAskRequest,
    CopilotAskResponse,
    CopilotStatusResponse,
    KnowledgeStatus,
    ModelStatus,
)
from netsight_api.traffic import audit_trail

_LOGGER: Final = logging.getLogger("netsight_api")
router = APIRouter(prefix="/copilot", tags=["copilot"])

ASK_LIMIT_PER_MINUTE: Final = 10
STATUS_LIMIT_PER_MINUTE: Final = 60
MAX_CONCURRENT_ASKS: Final = 4
MAX_CONCURRENT_PER_IDENTITY: Final = 2
_WINDOW_SECONDS: Final = 60.0
_ask_limiter = RateLimiter()
_inflight = 0
_inflight_by_identity: dict[str, int] = {}
_ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
    429: {"model": ErrorEnvelope, "description": "Rate limit exceeded or the copilot is busy"},
}


def utc_now() -> datetime:
    return datetime.now(UTC)


def reset_for_tests() -> None:
    global _inflight
    _inflight = 0
    _inflight_by_identity.clear()


# --- dependencies ----------------------------------------------------------------------------------------


def get_model_provider() -> ModelProvider | None:
    return configured_provider()


def _tool_audit(request: Request) -> Any:
    def record(actor_id: str, tool: str, state: str) -> None:
        outcome = {"ok": "success", "denied": "denied"}.get(state, "failure")
        record_audit(
            "copilot.tool",
            outcome=outcome,  # type: ignore[arg-type]
            actor_id=actor_id,
            correlation_id=correlation_id(request),
            tool=tool,
            state=state,
        )

    return record


def get_broker(
    request: Request,
    store: OptionalIncidentStore,
) -> ToolBroker:
    return ToolBroker(
        knowledge=lambda: knowledge.load_index(now=utc_now()),
        incidents=lambda: store,
        clock=utc_now,
        audit=_tool_audit(request),
    )


Broker = Annotated[ToolBroker, Depends(get_broker)]
Provider = Annotated[ModelProvider | None, Depends(get_model_provider)]
StatusReader = Annotated[
    Identity,
    Depends(
        reader(
            Permission.COPILOT_ASK,
            "copilot.status.read",
            "copilot-status",
            lambda: STATUS_LIMIT_PER_MINUTE,
        )
    ),
]


def ask_guard(request: Request, identity: CurrentIdentity) -> Identity:
    """authorise -> CSRF and origin -> per-identity limit; the first refusal wins and is audited."""
    action = "copilot.ask"
    if not is_allowed(identity, Permission.COPILOT_ASK.value):
        audit_trail.denied(request, identity.id, action, "permission")
        raise ApiError(403, "FORBIDDEN", "Permission is required")
    refusal = write_refusal(request, identity)
    if refusal is not None:
        audit_trail.denied(request, identity.id, action, refusal.reason)
        raise ApiError(403, refusal.code, refusal.message)
    if not _ask_limiter.allow(identity.id, ASK_LIMIT_PER_MINUTE, _WINDOW_SECONDS):
        audit_trail.denied(request, identity.id, action, "rate-limit")
        raise _busy("Too many questions; slow down")
    return identity


def _busy(message: str) -> ApiError:
    return ApiError(
        429, "RATE_LIMITED", message, headers={"Retry-After": str(math.ceil(_WINDOW_SECONDS))}
    )


Asker = Annotated[Identity, Depends(ask_guard)]


# --- routes -----------------------------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=CopilotStatusResponse,
    responses={k: v for k, v in _ERRORS.items() if k != 422},
    operation_id="getCopilotStatus",
)
async def copilot_status(
    request: Request,
    response: Response,
    identity: StatusReader,
    broker: Broker,
    provider: Provider,
) -> CopilotStatusResponse:
    """What the copilot can do for the caller. Never the model name, endpoint or key."""
    no_store(response)
    loaded = await asyncio.to_thread(knowledge.load_index, now=utc_now())
    index = loaded.index
    body = CopilotStatusResponse(
        generated_at=utc_now(),
        read_only=True,
        model=ModelStatus(state="ok" if provider is not None else "not-connected"),
        knowledge=KnowledgeStatus(
            state=loaded.state,
            documents=index.documents if index is not None else 0,
            chunks=index.chunks if index is not None else 0,
        ),
        tools=broker.catalog(identity),
    )
    audit_trail.read(request, identity.id, "copilot.status.read", state=body.knowledge.state)
    return body


@router.post(
    "/ask",
    response_model=CopilotAskResponse,
    responses=_ERRORS,
    operation_id="askCopilot",
)
async def ask_copilot(
    request: Request,
    response: Response,
    body: CopilotAskRequest,
    identity: Asker,
    broker: Broker,
    provider: Provider,
) -> CopilotAskResponse:
    """Answer from evidence the asker is allowed to read; read-only, nothing is ever executed."""
    global _inflight
    action = "copilot.ask"
    no_store(response)
    question = sanitize.clean_question(body.question)
    if len(question) < MIN_QUESTION:
        raise rejected(request, identity, action)
    if (
        _inflight >= MAX_CONCURRENT_ASKS
        or _inflight_by_identity.get(identity.id, 0) >= MAX_CONCURRENT_PER_IDENTITY
    ):
        audit_trail.denied(request, identity.id, action, "busy")
        raise _busy("The copilot is busy; try again shortly")
    _inflight += 1
    _inflight_by_identity[identity.id] = _inflight_by_identity.get(identity.id, 0) + 1
    try:
        service = CopilotService(broker=broker, provider=provider, clock=utc_now)
        result = await service.ask(identity, question)
    except BaseException:
        # Model spend may already have happened: a crash or a cancelled request is audited too.
        audit_trail.read(
            request,
            identity.id,
            action,
            failure=True,
            state="error",
            question_chars=len(body.question),
        )
        raise
    finally:
        _inflight -= 1
        remaining = _inflight_by_identity.get(identity.id, 1) - 1
        if remaining > 0:
            _inflight_by_identity[identity.id] = remaining
        else:
            _inflight_by_identity.pop(identity.id, None)
    checked = _checked(result)
    audit_trail.read(
        request,
        identity.id,
        action,
        failure=checked.state == "unknown",
        state=checked.state,
        question_chars=len(body.question),
        evidence=len(checked.evidence),
        flagged=sum(1 for item in checked.evidence if item.instruction_like),
        tools=",".join(f"{call.tool}:{call.state}" for call in checked.tool_calls),
    )
    return checked


def _checked(result: CopilotAskResponse) -> CopilotAskResponse:
    """A body that fails its own canonical contract is never sent as an answer."""
    try:
        validate("copilot_ask", json.loads(result.model_dump_json(by_alias=True)))
    except ContractViolation:
        _LOGGER.error("a copilot response failed its canonical contract")
        return CopilotAskResponse(
            state="unknown",
            generated_at=result.generated_at,
            read_only=True,
            answer=None,
            evidence=[],
            tool_calls=[],
        )
    return result
