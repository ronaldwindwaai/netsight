"""Recent changes near a diagnostic failure (S7 Step 4c).

Pure. Known changes (incidents and alerts today; configuration changes once a source exists) in a
look-back window before the failure are shown as things that *may correlate* with it: temporal
correlation is not causation (ROOT-CAUSE-ENGINE). A source that is not connected is reported as
not connected, never as "no changes"; an unreadable one is unknown. Titles are untrusted
operator/telemetry text: stripped of control characters and bounded, never interpreted. An incident
change keeps no title at all (see ``ChangeCandidate``).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from netsight_api.schemas import IncidentSeverity, StoreState
from netsight_api.schemas_diagnostic_session import (
    INCIDENT_TITLE_PLACEHOLDER,
    MAX_CHANGE_ITEMS,
    ChangeKind,
    DiagnosticChangeItem,
    DiagnosticChangeSource,
    DiagnosticRecentChanges,
    changes_state,
)

_MAX_TITLE = 255
_MAX_REF = 128


@dataclass(frozen=True)
class ChangeCandidate:
    """One record a change source returned, before it is matched against the failure.

    ``about_target`` is the source's own answer to "is this about the diagnosed target?": True
    (matched), False (about a different device: dropped) or None (the source cannot tell, so only
    the time overlaps). It is never guessed from text.

    An incident is a reference: ``severity`` is required and ``title`` is never used (a session
    must not store a title its reader may not be allowed to see). An alert needs a ``title``.
    """

    kind: ChangeKind
    ref_id: str
    title: str | None
    occurred_at: datetime
    severity: IncidentSeverity | None = None
    about_target: bool | None = None


@dataclass(frozen=True)
class SourceRead:
    """The outcome of reading one change source: rows exist only when the state is ok."""

    state: StoreState
    candidates: tuple[ChangeCandidate, ...] = ()


def clean_title(raw: str) -> str:
    printable = "".join(
        " " if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} else ch for ch in raw
    )
    return " ".join(printable.split())[:_MAX_TITLE].strip()


def _item(candidate: ChangeCandidate) -> DiagnosticChangeItem | None:
    ref = candidate.ref_id.strip()[:_MAX_REF]
    if not ref:
        return None
    if candidate.kind == "incident":
        # A reference only: the title is joined at read time for callers holding incidents:read.
        if candidate.severity is None:
            return None
        title, severity, redacted = INCIDENT_TITLE_PLACEHOLDER, candidate.severity, True
    else:
        title, severity, redacted = clean_title(candidate.title or ""), None, False
        if not title:
            return None
    return DiagnosticChangeItem(
        kind=candidate.kind,
        ref_id=ref,
        severity=severity,
        title=title,
        title_redacted=redacted,
        occurred_at=candidate.occurred_at,
        scope="target" if candidate.about_target else "time-window",
        relation="may-correlate",
    )


def _eligible(
    candidates: Iterable[ChangeCandidate], window_start: datetime, window_end: datetime
) -> Iterable[ChangeCandidate]:
    for candidate in candidates:
        if not window_start <= candidate.occurred_at <= window_end:
            continue
        # A record about another device is not a change near this target.
        if candidate.about_target is False:
            continue
        yield candidate


def build_recent_changes(
    *,
    window_start: datetime,
    window_end: datetime,
    incidents: SourceRead,
    alerts: SourceRead,
) -> DiagnosticRecentChanges:
    sources = [
        DiagnosticChangeSource(source="incidents", state=incidents.state),
        DiagnosticChangeSource(source="alerts", state=alerts.state),
        # No configuration-change source exists yet: said plainly, never "no changes".
        DiagnosticChangeSource(source="configuration-changes", state="not-connected"),
    ]
    items: dict[tuple[str, str], DiagnosticChangeItem] = {}
    for read in (incidents, alerts):
        if read.state != "ok":
            continue
        for candidate in _eligible(read.candidates, window_start, window_end):
            item = _item(candidate)
            if item is not None:
                items.setdefault((item.kind, item.ref_id), item)
    ranked = sorted(
        items.values(),
        key=lambda i: (i.scope != "target", -i.occurred_at.timestamp(), i.kind, i.ref_id),
    )
    return DiagnosticRecentChanges(
        state=changes_state(sources),
        window_start=window_start,
        window_end=window_end,
        sources=sources,
        items=ranked[:MAX_CHANGE_ITEMS],
    )
