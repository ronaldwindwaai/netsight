"""Attribute Flow Explorer rows to a person or device, only through the identity service.

The flow store may carry a user field of its own; it is deliberately not used. An address is not an
identity, so the only source of "who" is the Step 6 correlation service, which answers with a basis
(observed / inferred / unknown), a reason and a confidence, and which this module passes on without
strengthening:

* **never a pick.** More than one candidate person, or an engine answer that is ambiguous, names
  nobody (``multiple-candidates``);
* **never more than the role may see.** The ``endpoint`` level (``users:read-limited``) gets the
  device and the reason ``restricted``; the person is withheld and the answer says so. A role with no
  ``users:*`` permission never reaches this module (the route reports the level as ``none``);
* **as of the flow.** Each distinct (address, time) is asked once, at the time the flow was seen. A
  flow older than the evidence window is ``source-unavailable``, not "no evidence";
* **explicit states.** No identity service is ``not-connected``; a failing one is ``unknown`` and
  leaks nothing; no rows means nothing was asked.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from netsight_api.identity.model import Basis, EntityType, Relation, Resolution, ip_ref
from netsight_api.identity.service import MAX_RESOLUTIONS, IdentityService
from netsight_api.schemas_traffic import (
    AttributionStatus,
    DeviceRef,
    FlowAttribution,
    PersonRef,
    TrafficFlow,
)

_LOGGER = logging.getLogger("netsight_api")

Level = Literal["person", "endpoint"]
MAX_ROWS = MAX_RESOLUTIONS


@dataclass(frozen=True)
class Attributed:
    status: AttributionStatus
    flows: tuple[TrafficFlow, ...]


def _unknown(
    reason: str, *, ambiguous: bool = False, device: DeviceRef | None = None
) -> FlowAttribution:
    return FlowAttribution(
        basis="unknown",
        reason=reason,  # type: ignore[arg-type]
        confidence=None,
        ambiguous=ambiguous,
        person=None,
        device=device,
    )


def _device(resolution: Resolution) -> DeviceRef | None:
    """The endpoint's device when the network evidence names exactly one."""
    found: dict[str, str | None] = {}
    for link in resolution.endpoint:
        if link.relation is not Relation.DEVICE_IP or link.target is None:
            continue
        for end in (link.source, link.target):
            if end.type is EntityType.DEVICE:
                found[end.id] = end.label
    if len(found) != 1:
        return None
    ((identifier, label),) = found.items()
    return DeviceRef(id=identifier, label=label)


def flow_attribution(resolution: Resolution | None, *, level: Level) -> FlowAttribution:
    """Map the engine's answer for one address to the boundary model, without strengthening it."""
    if resolution is None:
        return _unknown("source-unavailable")
    device = _device(resolution)
    if level == "endpoint":
        return _unknown("restricted", device=device)
    answer = resolution.attribution
    if answer.basis is Basis.UNKNOWN:
        reason = answer.reason.value if answer.reason is not None else "no-evidence"
        return _unknown(reason, ambiguous=answer.ambiguous, device=device)
    if len(answer.links) != 1 or answer.links[0].target is None:
        return _unknown("multiple-candidates", ambiguous=True, device=device)
    link = answer.links[0]
    assert link.target is not None
    return FlowAttribution(
        basis=link.basis.value,
        reason=link.reason.value if link.reason is not None else None,
        confidence=link.confidence,
        ambiguous=False,
        person=PersonRef(id=link.target.id, label=link.target.label),
        device=device,
    )


def _status(level: Level, state: str, as_of: datetime | None = None) -> AttributionStatus:
    return AttributionStatus(level=level, state=state, as_of=as_of)  # type: ignore[arg-type]


def _parseable(text: str) -> bool:
    try:
        ip_ref(text)
    except ValueError:
        return False
    return True


async def attribute_flows(
    service: IdentityService | None,
    flows: Sequence[TrafficFlow],
    *,
    level: Level,
    now: datetime,
) -> Attributed:
    """Attach an attribution to every row, or say why none was attached."""
    if len(flows) > MAX_ROWS:
        raise ValueError("too many rows to attribute")
    rows = tuple(flows)
    if not rows:
        return Attributed(_status(level, "not-evaluated"), rows)
    if service is None:
        return Attributed(_status(level, "not-connected"), rows)
    questions = list(
        dict.fromkeys((row.source_ip, row.observed_at) for row in rows if _parseable(row.source_ip))
    )
    try:
        answered = await service.resolve_many(now, questions)
    except Exception as error:  # noqa: BLE001 - the identity boundary: any failure is `unknown`
        _LOGGER.warning("flow attribution failed", extra={"error_type": type(error).__name__})
        return Attributed(_status(level, "unknown"), rows)
    if answered.state != "ok":
        return Attributed(_status(level, answered.state), rows)

    def attribution_of(row: TrafficFlow) -> FlowAttribution:
        if not _parseable(row.source_ip):
            return _unknown("no-evidence")
        key = (row.source_ip, row.observed_at)
        return flow_attribution(answered.resolutions.get(key), level=level)

    attributed = tuple(row.model_copy(update={"attribution": attribution_of(row)}) for row in rows)
    return Attributed(_status(level, "ok", answered.as_of), attributed)
