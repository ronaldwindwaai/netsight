"""The copilot orchestration (Step 10): plan, read, bundle, ask, validate.

1. **No model, no read**: without a configured provider nothing is read and the answer is
   ``not-connected``. Evidence is never gathered for a model that is not there.
2. The planner picks registered read tools (the model never does); the broker runs each under the
   asker's own permissions.
3. The results become one numbered evidence bundle (``ev-001``...), capped. A source that was denied,
   unavailable or not connected is stated to the model as a gap and added to the answer's unknowns by
   *this code*, not by the model, so a silent model cannot hide a gap.
4. No evidence means the model is not asked (``no-evidence``): a model with nothing to cite would
   fabricate.
5. The model's reply is untrusted: it must be exactly the answer contract with every citation inside
   the bundle (``answer.parse_answer``). Otherwise the state is ``unknown`` and no answer is shown.

Everything here is read-only: there is no code path from a model reply to a write, an action or a tool.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any, Final, Protocol

from pydantic import ValidationError

from netsight_api.copilot import answer as answer_module
from netsight_api.copilot import planner, prompt, sanitize
from netsight_api.copilot.provider import ModelMessage, ModelProvider
from netsight_api.copilot.tools import Evidence, InvalidArguments, ToolResult, UnknownTool
from netsight_api.rbac import Identity
from netsight_api.schemas_copilot import (
    MAX_EVIDENCE,
    MAX_QUESTION,
    AskState,
    CopilotAnswer,
    CopilotAskResponse,
    CopilotEvidence,
    CopilotRecommendation,
    CopilotToolCall,
    ToolName,
)

_LOGGER: Final = logging.getLogger("netsight_api")
MODEL_TIMEOUT_SECONDS: Final = 60.0
MAX_UNKNOWNS: Final = 10
MAX_RECOMMENDATIONS: Final = 8
_GAP_TEXT: Final = {
    "denied": "you do not have access to this source, so it was not consulted",
    "not-connected": "this source is not connected",
    "unknown": "this source could not be read",
}


class Broker(Protocol):
    async def call(
        self, identity: Identity, name: str, arguments: dict[str, Any]
    ) -> ToolResult: ...


class CopilotService:
    def __init__(
        self,
        *,
        broker: Broker,
        provider: ModelProvider | None,
        clock: Callable[[], datetime],
        model_timeout: float = MODEL_TIMEOUT_SECONDS,
    ) -> None:
        self._broker = broker
        self._provider = provider
        self._clock = clock
        self._timeout = model_timeout

    def _response(
        self,
        state: AskState,
        *,
        answer: CopilotAnswer | None = None,
        evidence: list[CopilotEvidence] | None = None,
        calls: list[CopilotToolCall] | None = None,
    ) -> CopilotAskResponse:
        return CopilotAskResponse(
            state=state,
            generated_at=self._clock(),
            read_only=True,
            answer=answer,
            evidence=evidence or [],
            tool_calls=calls or [],
        )

    async def ask(self, identity: Identity, question: str) -> CopilotAskResponse:
        if self._provider is None:
            return self._response("not-connected")
        question = sanitize.clean_text(sanitize.redact_secrets(question), MAX_QUESTION)
        results = await self._read(identity, question)
        evidence, calls, cut = _bundle(results)
        if not evidence:
            return self._response("no-evidence", calls=calls)
        gaps = [f"{call.tool}: {call.state}" for call in calls if call.state != "ok"]
        gaps += [f"{tool}: truncated, {shown} of {total} items shown" for tool, shown, total in cut]
        reply = await self._complete(prompt.build_messages(question, evidence, gaps))
        parsed = (
            answer_module.parse_answer(reply, {item.id for item in evidence})
            if reply is not None
            else None
        )
        if parsed is None:
            return self._response("unknown", evidence=evidence, calls=calls)
        final = _completed(parsed, calls, evidence, cut)
        try:
            return self._response("ok", answer=final, evidence=evidence, calls=calls)
        except ValidationError:
            _LOGGER.error("a copilot answer failed its own contract")
            return self._response("unknown", evidence=evidence, calls=calls)

    async def _read(self, identity: Identity, question: str) -> list[tuple[ToolName, ToolResult]]:
        results: list[tuple[ToolName, ToolResult]] = []
        for name, arguments in planner.plan(question):
            try:
                result = await self._broker.call(identity, name, arguments)
            except (UnknownTool, InvalidArguments):
                _LOGGER.error("the copilot planner produced a call the broker refused")
                result = ToolResult("unknown", ())
            results.append((name, result))
        return results

    async def _complete(self, messages: list[ModelMessage]) -> str | None:
        assert self._provider is not None
        try:
            return await asyncio.wait_for(self._provider.complete(messages), self._timeout)
        except Exception as exc:  # noqa: BLE001 - any model failure is "unknown", never a crash
            _LOGGER.warning("the copilot model call failed: %s", type(exc).__name__)
            return None


def _allocation(sizes: list[int]) -> list[int]:
    """Items to take from each tool: one each first (so no source is starved), then round robin."""
    taken = [min(size, 1) for size in sizes]
    room = MAX_EVIDENCE - sum(taken)
    while room > 0:
        grew = False
        for index, size in enumerate(sizes):
            if room > 0 and taken[index] < size:
                taken[index] += 1
                room -= 1
                grew = True
        if not grew:
            break
    return taken


def _bundle(
    results: list[tuple[ToolName, ToolResult]],
) -> tuple[list[CopilotEvidence], list[CopilotToolCall], list[tuple[str, int, int]]]:
    """The numbered bundle, the tool calls with what each contributed, and which tools were cut."""
    allocation = _allocation([len(result.items) for _, result in results])
    evidence: list[CopilotEvidence] = []
    calls: list[CopilotToolCall] = []
    cut: list[tuple[str, int, int]] = []
    for (name, result), take in zip(results, allocation, strict=True):
        for item in result.items[:take]:
            evidence.append(_numbered(len(evidence) + 1, item))
        calls.append(CopilotToolCall(tool=name, state=result.state, evidence_count=take))
        if take < len(result.items):
            cut.append((name, take, len(result.items)))
    return evidence, calls, cut


def _numbered(number: int, item: Evidence) -> CopilotEvidence:
    """Numbered evidence. Tools already clean their text; it is cleaned again here so nothing a tool
    forgets can reach the model or the browser unredacted (defence in depth, idempotent)."""
    excerpt, flagged = sanitize.safe_excerpt(item.excerpt, 600)
    return CopilotEvidence(
        id=f"ev-{number:03d}",
        source=item.source,
        kind=item.kind,
        title=sanitize.clean_text(sanitize.redact_secrets(item.title), 200) or item.kind,
        excerpt=excerpt or "(empty)",
        reference=sanitize.clean_text(item.reference, 200),
        observed_at=item.observed_at,
        freshness=item.freshness,
        instruction_like=item.instruction_like
        or flagged
        or sanitize.is_instruction_like(item.title),
    )


def _completed(
    parsed: CopilotAnswer,
    calls: list[CopilotToolCall],
    evidence: list[CopilotEvidence],
    cut: list[tuple[str, int, int]],
) -> CopilotAnswer:
    """The model's answer plus the unknowns and warnings only this code can state truthfully.

    Server-stated gaps come first so a verbose model can never push them out of the capped list.
    """
    unknowns = [f"{call.tool}: {_GAP_TEXT[call.state]}." for call in calls if call.state != "ok"]
    unknowns += [
        f"{tool}: only {shown} of {total} items fit in the {MAX_EVIDENCE}-item evidence limit; "
        "more may exist."
        for tool, shown, total in cut
    ]
    warnings = [
        CopilotRecommendation(
            text=(
                f"Review {item.id}: its text reads like an instruction to an AI. It was treated "
                "as data only and may be an attempt to manipulate the assistant."
            )
        )
        for item in evidence
        if item.instruction_like
    ]
    return parsed.model_copy(
        update={
            "unknowns": [*unknowns, *parsed.unknowns][:MAX_UNKNOWNS],
            "recommendations": [*warnings, *parsed.recommendations][:MAX_RECOMMENDATIONS],
        }
    )
