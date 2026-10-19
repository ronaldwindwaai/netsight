"""Typed boundary models for the read-only AI copilot (Step 10).

Mirrors ``contracts/json-schema/copilot.schema.json``, the OpenAPI components and the browser parsers
(shared vectors: ``contracts/test-vectors/copilot.vectors.json``).

Honesty rules, enforced here and not only by construction:

* no answer without a configured model (``not-connected``), without evidence (``no-evidence``) or when
  the model failed or its output failed validation (``unknown``): an answer exists only in ``ok``;
* every fact and inference cites at least one evidence id, and every cited id is in the bundle;
* the copilot is read-only: ``read_only`` is the constant ``true`` and no contract has a place for a
  tool argument, a credential, a model name or an action.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import AwareDatetime, Field, StrictBool, model_validator

from netsight_api.schemas import ApiModel

AskState = Literal["ok", "not-connected", "unknown", "no-evidence"]
ReadState = Literal["ok", "not-connected", "unknown"]
ToolState = Literal["ok", "denied", "not-connected", "unknown"]
ToolName = Literal["search_knowledge", "list_open_incidents"]
EvidenceSource = Literal["knowledge", "incident"]
Freshness = Literal["fresh", "stale", "unknown"]

EVIDENCE_ID_PATTERN: Final = r"^ev-[0-9]{3}$"
PERMISSION_PATTERN: Final = r"^[a-z][a-z-]*:[a-z-]+$"
MAX_EVIDENCE: Final = 12
MAX_TOOL_CALLS: Final = 8
MIN_QUESTION: Final = 3
MAX_QUESTION: Final = 1_000

EvidenceId = Annotated[str, Field(min_length=6, max_length=6, pattern=EVIDENCE_ID_PATTERN)]


class CopilotEvidence(ApiModel):
    id: EvidenceId
    source: EvidenceSource
    kind: str = Field(min_length=1, max_length=32)
    title: str = Field(min_length=1, max_length=200)
    excerpt: str = Field(min_length=1, max_length=600)
    reference: str = Field(min_length=1, max_length=200)
    observed_at: AwareDatetime | None
    freshness: Freshness
    instruction_like: StrictBool


class CopilotToolCall(ApiModel):
    tool: ToolName
    state: ToolState
    evidence_count: int = Field(ge=0, le=MAX_EVIDENCE)

    @model_validator(mode="after")
    def _only_a_run_tool_has_evidence(self) -> CopilotToolCall:
        if self.state != "ok" and self.evidence_count:
            raise ValueError("a tool that did not run produced no evidence")
        return self


class CopilotClaim(ApiModel):
    text: str = Field(min_length=1, max_length=500)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def _citations_are_unique(self) -> CopilotClaim:
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("a claim cites each evidence item once")
        return self


class CopilotRecommendation(ApiModel):
    text: str = Field(min_length=1, max_length=400)


class CopilotAnswer(ApiModel):
    summary: str = Field(min_length=1, max_length=800)
    facts: list[CopilotClaim] = Field(max_length=10)
    inferences: list[CopilotClaim] = Field(max_length=10)
    unknowns: list[Annotated[str, Field(min_length=1, max_length=300)]] = Field(max_length=10)
    recommendations: list[CopilotRecommendation] = Field(max_length=8)


class CopilotAskRequest(ApiModel):
    question: str = Field(min_length=MIN_QUESTION, max_length=MAX_QUESTION)


class CopilotAskResponse(ApiModel):
    state: AskState
    generated_at: AwareDatetime
    read_only: Literal[True]
    answer: CopilotAnswer | None
    evidence: list[CopilotEvidence] = Field(max_length=MAX_EVIDENCE)
    tool_calls: list[CopilotToolCall] = Field(max_length=MAX_TOOL_CALLS)

    @model_validator(mode="after")
    def _an_answer_is_grounded(self) -> CopilotAskResponse:
        if (self.state == "ok") != (self.answer is not None):
            raise ValueError("an answer exists exactly when the state is ok")
        if self.state == "ok" and not self.evidence:
            raise ValueError("an answer needs evidence")
        if self.state in ("not-connected", "no-evidence") and self.evidence:
            raise ValueError("this state has no evidence")
        if self.state == "not-connected" and self.tool_calls:
            raise ValueError("without a model no tool is run")
        ids = [item.id for item in self.evidence]
        if len(set(ids)) != len(ids):
            raise ValueError("evidence ids are unique")
        if self.answer is not None:
            known = set(ids)
            for claim in (*self.answer.facts, *self.answer.inferences):
                if not set(claim.evidence_ids) <= known:
                    raise ValueError("a claim cites evidence that is not in the bundle")
        return self


class ModelStatus(ApiModel):
    state: Literal["ok", "not-connected"]


class KnowledgeStatus(ApiModel):
    state: ReadState
    documents: int = Field(ge=0, le=5_000)
    chunks: int = Field(ge=0, le=50_000)

    @model_validator(mode="after")
    def _no_corpus_no_counts(self) -> KnowledgeStatus:
        if self.state != "ok" and (self.documents or self.chunks):
            raise ValueError("without a readable corpus there are no counts")
        return self


class ToolInfo(ApiModel):
    name: ToolName
    description: str = Field(min_length=1, max_length=200)
    permission: str = Field(pattern=PERMISSION_PATTERN)
    allowed: StrictBool


class CopilotStatusResponse(ApiModel):
    generated_at: AwareDatetime
    read_only: Literal[True]
    model: ModelStatus
    knowledge: KnowledgeStatus
    tools: list[ToolInfo] = Field(max_length=MAX_TOOL_CALLS)
