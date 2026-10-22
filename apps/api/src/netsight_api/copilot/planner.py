"""Choosing the read tools for a question (Step 10).

Deterministic and conservative: the *model never chooses tools*, so injected text cannot cause a
tool call. The question is matched against fixed vocabulary only to decide **which registered read
tools to consult**; every argument is a fixed value except the knowledge query, which is the cleaned
question as search text. Nothing in the question can name a tool, widen a window or raise a limit.
"""

from __future__ import annotations

import re
from typing import Any, Final

from netsight_api.schemas_copilot import ToolName

INCIDENT_LIMIT: Final = 5
_DIAGNOSTIC_WORDS: Final = re.compile(
    r"\b(why|outages?|down|inaccessible|unreachable|unavailable|slow|unusual|happen\w*|"
    r"overnight|incidents?|alerts?|broken|failing|failed|failure)\b",
    re.IGNORECASE,
)


def plan(question: str) -> list[tuple[ToolName, dict[str, Any]]]:
    steps: list[tuple[ToolName, dict[str, Any]]] = [("search_knowledge", {"query": question})]
    diagnostic = _DIAGNOSTIC_WORDS.search(question) is not None
    if diagnostic:
        steps.append(("list_open_incidents", {"limit": INCIDENT_LIMIT}))
    return steps
