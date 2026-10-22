"""The read-only tool broker (Step 10, AI-TOOL-CATALOG.md, AI-SECURITY.md "Tool security").

The copilot does not decide what to run. The planner picks tool names and builds their arguments from
fixed rules; this broker is the one door every call goes through:

* **explicit allow-list**: a name that is not exactly one of the registered read tools raises
  ``UnknownTool``. There is no shell, no generic request tool and no write tool, so nothing the model
  says (or any retrieved text says) can name one;
* **typed arguments**: each tool has a strict model (extra keys refused, bounded values);
* **per-user RBAC on every call**: the call is authorised against the *asker's* identity, never a
  service identity, so the copilot can read nothing the asker could not read on the page. A denial is
  a ``denied`` state (a data gap), not an empty result, and the source is never touched;
* **bounded and timed**: at most ``MAX_ITEMS_PER_TOOL`` evidence items per call, each cleaned and
  secret-redacted, and a hard time budget per call;
* **audited**: every call, including denials, reports (actor, tool, state) to the audit callback.

Every tool returns ``Evidence``: untrusted text is cleaned, redacted and flagged where it is made.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from netsight_api.copilot import sanitize
from netsight_api.copilot.knowledge import Loaded
from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.schemas import Incident, IncidentState
from netsight_api.schemas_copilot import (
    EvidenceSource,
    Freshness,
    ToolInfo,
    ToolName,
    ToolState,
)
from netsight_api.storage import IncidentRepository

_LOGGER: Final = logging.getLogger("netsight_api")
MAX_ITEMS_PER_TOOL: Final = 6
TOOL_TIMEOUT_SECONDS: Final = 10.0
KNOWLEDGE_HITS: Final = 5
OPEN_STATES: Final[tuple[IncidentState, ...]] = (
    "open",
    "acknowledged",
    "investigating",
    "mitigated",
)
INCIDENT_READ_LIMIT: Final = 50


@dataclass(frozen=True)
class Evidence:
    source: EvidenceSource
    kind: str
    title: str
    excerpt: str
    reference: str
    observed_at: datetime | None
    freshness: Freshness
    instruction_like: bool


@dataclass(frozen=True)
class ToolResult:
    state: ToolState
    items: tuple[Evidence, ...]


class UnknownTool(LookupError):
    """The name is not a registered read tool."""


class InvalidArguments(ValueError):
    """The arguments do not satisfy the tool's strict model."""


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SearchArgs(_Args):
    query: StrictStr = Field(min_length=1, max_length=1_000)


class IncidentArgs(_Args):
    limit: StrictInt = Field(default=5, ge=1, le=10)


Audit = Callable[[str, str, str], None]
Runner = Callable[["ToolBroker", Identity, Any], Awaitable[ToolResult]]


@dataclass(frozen=True)
class ToolSpec:
    name: ToolName
    description: str
    permission: Permission
    args: type[_Args]
    run: Runner


def _item(
    source: EvidenceSource,
    kind: str,
    title: str,
    untrusted: str,
    reference: str,
    observed_at: datetime | None,
    freshness: Freshness,
) -> Evidence:
    excerpt, flagged = sanitize.safe_excerpt(untrusted, 600)
    clean_title = sanitize.clean_text(sanitize.redact_secrets(title), 200) or kind
    return Evidence(
        source,
        kind,
        clean_title,
        excerpt or "(empty)",
        sanitize.clean_text(reference, 200),
        observed_at,
        freshness,
        flagged or sanitize.is_instruction_like(title),
    )


class ToolBroker:
    def __init__(
        self,
        *,
        knowledge: Callable[[], Loaded],
        incidents: Callable[[], IncidentRepository | None],
        clock: Callable[[], datetime],
        audit: Audit | None = None,
        timeout: float = TOOL_TIMEOUT_SECONDS,
    ) -> None:
        self._knowledge = knowledge
        self._incidents = incidents
        self._clock = clock
        self._audit = audit
        self._timeout = timeout

    def catalog(self, identity: Identity) -> list[ToolInfo]:
        return [
            ToolInfo(
                name=spec.name,
                description=spec.description,
                permission=spec.permission.value,
                allowed=is_allowed(identity, spec.permission.value),
            )
            for spec in _SPECS.values()
        ]

    async def call(self, identity: Identity, name: str, arguments: dict[str, Any]) -> ToolResult:
        spec = _SPECS.get(name)
        if spec is None:
            raise UnknownTool("not a registered read tool")
        if not is_allowed(identity, spec.permission.value):
            self._report(identity, spec.name, "denied")
            return ToolResult("denied", ())
        try:
            parsed = spec.args.model_validate(arguments)
        except ValidationError:
            raise InvalidArguments("the arguments do not satisfy the tool") from None
        result = await self._run(spec, identity, parsed)
        self._report(identity, spec.name, result.state)
        return result

    async def _run(self, spec: ToolSpec, identity: Identity, parsed: _Args) -> ToolResult:
        try:
            result = await asyncio.wait_for(spec.run(self, identity, parsed), self._timeout)
        except Exception as exc:  # noqa: BLE001 - a tool failure is a gap, never a crash or a leak
            _LOGGER.warning("copilot tool %s failed: %s", spec.name, type(exc).__name__)
            return ToolResult("unknown", ())
        return ToolResult(result.state, result.items[:MAX_ITEMS_PER_TOOL])

    def _report(self, identity: Identity, tool: str, state: str) -> None:
        if self._audit is not None:
            self._audit(identity.id, tool, state)

    # --- search_knowledge ---------------------------------------------------------------------------

    async def search_knowledge(self, identity: Identity, args: SearchArgs) -> ToolResult:
        # Reading the corpus and scoring it is blocking work: off the event loop, so the tool
        # budget can apply and other requests are not stalled.
        loaded = await asyncio.to_thread(self._knowledge)
        if loaded.state != "ok" or loaded.index is None:
            return ToolResult("not-connected" if loaded.state == "not-connected" else "unknown", ())
        index = loaded.index
        hits = await asyncio.to_thread(
            lambda: index.search(args.query, roles=identity.roles, limit=KNOWLEDGE_HITS)
        )
        items = tuple(
            _item(
                "knowledge",
                "document",
                f"{hit.document}: {hit.heading}",
                hit.text,
                f"{hit.document}#{hit.heading}@{hit.version}",
                hit.modified,
                "stale" if hit.stale else "fresh",
            )
            for hit in hits
        )
        return ToolResult("ok", items)

    # --- list_open_incidents ------------------------------------------------------------------------

    async def open_incidents(self, args: IncidentArgs) -> ToolResult:
        store = self._incidents()
        if store is None:
            return ToolResult("not-connected", ())
        rows: list[Incident] = []
        capped = False
        for state in OPEN_STATES:
            found = await asyncio.to_thread(
                store.list_incidents, state=state, limit=INCIDENT_READ_LIMIT
            )
            capped = capped or len(found) >= INCIDENT_READ_LIMIT
            rows.extend(found)
        rows.sort(key=lambda r: (r.created_at, r.id), reverse=True)
        more = "; at least this many (the read was capped)" if capped else ""
        summary = _item(
            "incident",
            "incident-summary",
            "Open incidents",
            f"{len(rows)} open incidents (open, acknowledged, investigating or mitigated){more}",
            "incidents:open",
            self._clock(),
            "fresh",
        )
        listed = tuple(
            _item(
                "incident",
                "incident",
                row.title,
                f"[{row.severity}/{row.state}] {row.title}",
                row.id,
                row.created_at,
                "fresh",
            )
            for row in rows[: args.limit]
        )
        return ToolResult("ok", (summary, *listed))


def _spec(
    name: ToolName,
    description: str,
    permission: Permission,
    args: type[_Args],
    run: Runner,
) -> tuple[str, ToolSpec]:
    return name, ToolSpec(name, description, permission, args, run)


_SPECS: Final[dict[str, ToolSpec]] = dict(
    (
        _spec(
            "search_knowledge",
            "Search Netsight's approved documents and runbooks.",
            Permission.COPILOT_ASK,
            SearchArgs,
            lambda broker, who, args: broker.search_knowledge(who, args),
        ),
        _spec(
            "list_open_incidents",
            "List open incidents, newest first, with a count.",
            Permission.INCIDENTS_READ,
            IncidentArgs,
            lambda broker, _who, args: broker.open_incidents(args),
        ),
    )
)
