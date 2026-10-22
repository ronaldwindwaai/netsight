"""Validation of what the model returned (Step 10): the model's output is untrusted too.

The reply must be exactly one JSON object (a single ```json fence is tolerated, prose around it is
not) with exactly the contract's keys, so it has no place for a tool call or an action. Strings are
cleaned (control/format characters), secret-redacted and bounded; every fact and inference must cite
at least one evidence id and every cited id must be in the bundle. Any violation rejects the whole
answer: a partly grounded answer is not shown.
"""

from __future__ import annotations

import json
import re
from typing import Any, Final

from pydantic import ValidationError

from netsight_api.copilot.sanitize import clean_text, redact_secrets
from netsight_api.schemas_copilot import CopilotAnswer

_FENCE: Final = re.compile(r"\A```(?:json)?\s*\n(.*)\n```\Z", re.DOTALL)
_LIMITS: Final = {"summary": 800, "text": 500, "unknown": 300, "recommendation": 400}


def _text(value: object, limit: int) -> object:
    if not isinstance(value, str):
        return value
    return clean_text(redact_secrets(value), limit)


def _claims(value: object) -> object:
    if not isinstance(value, list):
        return value
    out: list[object] = []
    for claim in value:
        if isinstance(claim, dict) and "text" in claim:
            out.append({**claim, "text": _text(claim["text"], _LIMITS["text"])})
        else:
            out.append(claim)
    return out


def _cleaned(data: dict[str, Any]) -> dict[str, Any]:
    out = dict(data)
    if "summary" in out:
        out["summary"] = _text(out["summary"], _LIMITS["summary"])
    for key in ("facts", "inferences"):
        if key in out:
            out[key] = _claims(out[key])
    if isinstance(out.get("unknowns"), list):
        out["unknowns"] = [_text(v, _LIMITS["unknown"]) for v in out["unknowns"]]
    if isinstance(out.get("recommendations"), list):
        out["recommendations"] = [
            {**r, "text": _text(r["text"], _LIMITS["recommendation"])}
            if isinstance(r, dict) and "text" in r
            else r
            for r in out["recommendations"]
        ]
    return out


def parse_answer(raw: str, evidence_ids: set[str]) -> CopilotAnswer | None:
    """The validated answer, or ``None`` when it breaks the contract or cites outside the bundle."""
    text = raw.strip()
    fenced = _FENCE.match(text)
    if fenced:
        text = fenced.group(1).strip()
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    try:
        parsed = CopilotAnswer.model_validate(_cleaned(data))
    except ValidationError:
        return None
    for claim in (*parsed.facts, *parsed.inferences):
        if not set(claim.evidence_ids) <= evidence_ids:
            return None
    return parsed
