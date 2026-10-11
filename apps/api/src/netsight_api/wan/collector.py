"""Bounded WAN probe sampler: appends one cycle per link per round to the sample store.

Why a collector of its own (and not the alert-evaluation scheduler): evaluation is tied to alert
rules, notification channels and its own 30 s floor and per-cycle budgets, and a slow probe must
never delay an alert cycle; WAN evidence must be collectable without enabling alerting (and the
reverse). It reuses the loop, the leader lock and the shutdown handling of ``evaluation.wiring``
(``run_scheduler``) with its own advisory-lock key, so evaluators and collectors can live in
different processes while each stays a single writer.

What it does and does not do:

* It adds **no probe capability**: probes go through the existing allow-listed clients (the local
  prober and the Blackbox exporters per location), so the SSRF guards, the target allow-list and
  the fixed modules are the ones diagnostics already use. A link is served by the exporter at its
  declared ``probe_location`` (ICMP), or by the local prober (TCP, plus DNS) when the link names no
  location or the prober sits at that location. Nobody serves it: nothing is recorded (a gap,
  which the SLA shows as unknown) - never an invented ``unknown`` cycle.
* Every probe is bounded: a per-probe timeout, and a per-link deadline for the whole round. A
  probe that fails, hangs, raises or returns an unexpected status is an ``unknown`` sample, never a
  pass, and no text from the probe (details, URLs, driver messages) is stored.
* It only appends (``record_cycle``): nothing in its path changes or removes stored evidence. A
  round whose second already holds a cycle is skipped, never overwritten. Only a unique conflict
  is "skipped": a transient database failure, or a month without its partition (the migrator
  creates them; the collector has no DDL right), is a failed round and is logged.
* Cycle times are the *start* of the round, in whole seconds, UTC.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Protocol

from netsight_api.adapters.blackbox import BlackboxClient
from netsight_api.diagnostics import Observation
from netsight_api.storage.errors import StorageConflictError, StorageError
from netsight_api.storage.wan import WanPartitionMissingError, WanSampleRepository
from netsight_api.wan import sla
from netsight_api.wan.config import WanLinkConfig

_LOGGER: Final = logging.getLogger("netsight_api")

PROBE_TIMEOUT_SECONDS: Final = 15.0
_OUTCOMES: Final = frozenset({"pass", "fail", "unknown"})


class LocatedProbe(BlackboxClient, Protocol):
    """A probe client that knows where it is deployed (``None`` for an unlocated prober)."""

    @property
    def location(self) -> str | None: ...


@dataclass(frozen=True)
class CollectorReport:
    recorded: int
    skipped: int
    failed: int


class WanCollector:
    def __init__(
        self,
        *,
        links: Sequence[WanLinkConfig],
        store: WanSampleRepository,
        local: LocatedProbe | None,
        exporters: Sequence[LocatedProbe],
        interval_seconds: int,
        clock: Callable[[], datetime],
        deadline_seconds: float | None = None,
    ) -> None:
        self._links = tuple(links)
        self._store = store
        self._local = local
        self._exporters = tuple(exporters)
        self._interval = interval_seconds
        self._clock = clock
        self._deadline = float(interval_seconds) if deadline_seconds is None else deadline_seconds

    def reset_state(self) -> None:
        """Called when leadership is lost. The collector keeps no state between rounds."""

    async def run_cycle(self) -> CollectorReport:
        started = self._clock().astimezone(UTC).replace(microsecond=0)
        outcomes = await asyncio.gather(*(self._sample(link, started) for link in self._links))
        return CollectorReport(
            recorded=outcomes.count("recorded"),
            skipped=outcomes.count("skipped"),
            failed=outcomes.count("failed"),
        )

    # -- one link ---------------------------------------------------------------------------------

    async def _sample(self, link: WanLinkConfig, started: datetime) -> str:
        probe = self._probe_for(link)
        if probe is None or not link.probe_targets:
            return "skipped"
        try:
            samples = await asyncio.wait_for(self._probe_link(link, probe), self._deadline)
        except TimeoutError:
            _LOGGER.warning("WAN sampling round timed out", extra={"link_id": link.id})
            return "failed"
        cycle = sla.build_cycle(link.id, started, self._interval, samples)
        try:
            await asyncio.to_thread(self._store.record_cycle, cycle, samples)
        except StorageConflictError:
            return "skipped"  # this second already has a cycle: never overwritten
        except WanPartitionMissingError:
            # Fail closed: the runtime role has no DDL right, so nothing is recorded (a gap, shown
            # as unknown) until the migrator creates the month's partition.
            _LOGGER.error(
                "WAN sampling cannot write: no database partition exists for this month; run "
                "`python -m netsight_api.storage.migrate partitions` as the migrator",
                extra={"link_id": link.id},
            )
            return "failed"
        except (StorageError, ValueError) as error:
            _LOGGER.warning(
                "WAN sample store write failed",
                extra={"link_id": link.id, "error_type": type(error).__name__},
            )
            return "failed"
        return "recorded"

    def _probe_for(self, link: WanLinkConfig) -> LocatedProbe | None:
        if link.probe_location is not None:
            for exporter in self._exporters:
                if exporter.location == link.probe_location:
                    return exporter
        local = self._local
        if local is not None and local.location == link.probe_location:
            return local
        return None

    async def _probe_link(self, link: WanLinkConfig, probe: LocatedProbe) -> list[sla.Sample]:
        kinds = getattr(probe, "probe_kinds", None)
        reach = "icmp" if kinds is not None and "icmp" in kinds else "tcp"
        jobs = [self._one(probe, reach, target) for target in link.probe_targets]
        if link.dns_target is not None and (kinds is None or "dns" in kinds):
            jobs.append(self._one(probe, "dns", link.dns_target))
        return list(await asyncio.gather(*jobs))

    async def _one(self, probe: LocatedProbe, kind: str, target: str) -> sla.Sample:
        try:
            observation = await asyncio.wait_for(
                probe.probe(kind=kind, target=target, vantage=None),  # type: ignore[arg-type]
                PROBE_TIMEOUT_SECONDS,
            )
        except Exception as error:  # noqa: BLE001 - a failed probe is an unknown sample
            _LOGGER.debug("WAN probe raised", extra={"error_type": type(error).__name__})
            return sla.Sample(probe=kind, target=target, outcome="unknown", location=probe.location)
        return _sample_from(kind, target, observation, probe.location)


def _sample_from(
    kind: str, target: str, observation: Observation, location: str | None
) -> sla.Sample:
    outcome = observation.status if observation.status in _OUTCOMES else "unknown"
    latency = observation.latency_ms if outcome == "pass" else None
    return sla.Sample(
        probe=kind,
        target=target,
        outcome=outcome,
        latency_ms=latency,
        location=location,
    )
