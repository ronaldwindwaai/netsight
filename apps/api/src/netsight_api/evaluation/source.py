"""The observation-source contract that feeds the pure alert engine.

An :class:`ObservationSource` turns what a monitoring system can currently say about a metric
into engine :class:`~netsight_api.alerting.engine.Observation` values. It is the only thing the
runner knows about telemetry, so every source obeys the platform's honesty rule:

* not configured -> ``not-connected`` (no observations);
* configured but the read failed, was refused or returned unusable data -> ``unknown`` (no
  observations);
* a reading the source cannot state -> an observation whose ``value`` is ``None`` (the engine
  treats it as "no data", which neither fires nor recovers an alert);
* nothing is ever substituted, interpolated or defaulted.

Sources are read-only. ``observe`` must be bounded (a row cap, a timeout in the underlying
client) and must not raise for an upstream failure; it raises ``ValueError`` only for a metric
it does not ``support`` (a programming error in the caller).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal, Protocol

from netsight_api.alerting.engine import Observation

BatchState = Literal["ok", "not-connected", "unknown"]
_STATES: Final = ("ok", "not-connected", "unknown")

# Metrics whose firing alerts a maintenance window may silence. The set is closed and names
# availability only: a window never silences, say, a security or a traffic rule, because
# planned work on a device does not explain a policy violation (ALERT-ENGINE.md).
_AVAILABILITY_METRICS: Final = frozenset({"device.status", "interface.oper_status"})
_AVAILABILITY_PREFIX: Final = "availability."


def is_availability_metric(metric: str) -> bool:
    """True for availability metrics (``device.status``, ``interface.oper_status`` and the
    ``availability.*`` namespace); everything else ignores maintenance windows."""
    if metric in _AVAILABILITY_METRICS:
        return True
    return metric.startswith(_AVAILABILITY_PREFIX) and len(metric) > len(_AVAILABILITY_PREFIX)


@dataclass(frozen=True)
class ObservationBatch:
    """All observations of one metric at one instant, or the reason there are none.

    ``detail`` is a static code for a non-ok state (never upstream text).
    """

    state: BatchState
    observations: tuple[Observation, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.state not in _STATES:
            raise ValueError("state must be ok, not-connected or unknown")
        if self.state != "ok" and self.observations:
            raise ValueError("a batch that is not ok must carry no observations")


class ObservationSource(Protocol):
    def supports(self, metric: str) -> bool:
        """Whether the source can ever produce this metric."""
        ...

    async def observe(self, metric: str, *, now: datetime) -> ObservationBatch:
        """Read ``metric`` once; observations are stamped ``now`` (the runner's clock)."""
        ...
