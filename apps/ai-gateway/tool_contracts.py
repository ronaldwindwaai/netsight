from typing import Literal
from pydantic import BaseModel, Field

class EvidenceRef(BaseModel):
    evidence_id: str
    source: str
    observed_at: str

class DiagnosticRequest(BaseModel):
    target_id: str
    checks: list[Literal["dns", "icmp", "tcp", "http", "https", "health", "changes"]] = Field(default_factory=list)

class ProposedAction(BaseModel):
    action_type: str
    target_id: str
    reason: str
    evidence_ids: list[str]
    # This object is inert. Execution is owned by the platform action workflow.
