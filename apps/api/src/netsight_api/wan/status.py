"""Link status and failover state, derived (inferred) from source-reported evidence.

Pure rules, so they are testable and documented in one place. Inputs are *current* evidence only:
the interface operational status (``None`` when the source is silent, unreachable or stale) and the
latest probe round's state (``None`` when no round is current). Silent evidence is never read as
healthy: with none, the status is ``unknown``.

Link status: the worst current evidence wins (``down`` beats ``degraded`` beats ``up``). An
interface that is up while the probes all fail is **down** (the link is up but the Internet is
not). Failover reads link status only; routing and the gateway are not read, so it never claims
which link carries traffic. The API labels both as inferred.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

LinkStatus = Literal["up", "degraded", "down", "unknown"]
FailoverState = Literal["single-link", "normal", "failed-over", "all-down", "unknown"]
FailoverBasis = Literal["inferred", "unknown"]

_INTERFACE: dict[str, LinkStatus] = {
    "up": "up",
    "down": "down",
    "lowerLayerDown": "down",
    "notPresent": "down",
    "dormant": "degraded",
    "testing": "degraded",
}
_SEVERITY: dict[LinkStatus, int] = {"unknown": 0, "up": 1, "degraded": 2, "down": 3}


def link_status(oper_status: str | None, probe_state: str | None) -> LinkStatus:
    evidence: list[LinkStatus] = []
    if oper_status in _INTERFACE:
        evidence.append(_INTERFACE[oper_status])
    if probe_state in ("up", "degraded", "down"):
        evidence.append(probe_state)  # type: ignore[arg-type]
    return max(evidence, key=_SEVERITY.__getitem__, default="unknown")


def failover(links: Sequence[tuple[str, str]]) -> tuple[FailoverState, FailoverBasis]:
    """``(state, basis)`` from ``(role, status)`` pairs. Unknown whenever a link is silent."""
    if not links:
        return "unknown", "unknown"
    if len(links) == 1:
        return "single-link", "inferred"
    primaries = [status for role, status in links if role == "primary"]
    if len(primaries) != 1:
        return "unknown", "unknown"
    primary = primaries[0]
    if primary in ("up", "degraded"):
        return "normal", "inferred"
    if primary != "down":
        return "unknown", "unknown"
    backups = [status for role, status in links if role == "backup"]
    if any(status in ("up", "degraded") for status in backups):
        return "failed-over", "inferred"
    if all(status == "down" for status in backups):
        return "all-down", "inferred"
    return "unknown", "unknown"
