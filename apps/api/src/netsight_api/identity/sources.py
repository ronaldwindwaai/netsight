"""The evidence-source interface the correlation framework reads through.

An adapter for DHCP, RADIUS, a VPN concentrator, a Wi-Fi controller, a directory or an IdP plugs
in by implementing ``EvidenceSource``: it converts its vendor's rows into ``EvidenceRecord`` values
(the only vendor-shaped code lives in the adapter) and the service does the rest. The contract is
deliberately narrow so every source is bounded, read-only and fails closed:

* ``fetch`` returns records whose validity may overlap ``[start, end)``, at most ``limit`` of them;
  when more exist it sets ``truncated`` and the service refuses the whole read (missing evidence
  hides conflicts, so a partial list must never be presented as an answer);
* a source may only emit records stamped with its own ``name`` and of the ``kinds`` it declares:
  a mis-parsing or compromised adapter cannot speak for another source or invent a stronger kind;
* any exception, timeout or malformed record makes that source ``unknown``; an unconfigured source
  is a ``SourceSlot`` with no source and is ``not-connected``. Neither is ever an empty success.

Not wired in this build: DHCP, RADIUS, VPN, Wi-Fi controller, switch MAC table, DNS and IdP/directory
adapters. The fixture ``MemoryEvidenceSource`` exists for tests and so later adapters have a model.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from netsight_api.identity.model import EvidenceKind, EvidenceRecord


@dataclass(frozen=True)
class EvidenceBatch:
    records: tuple[EvidenceRecord, ...]
    truncated: bool = False
    # Rows the adapter could not use (counted, never silently dropped); the service logs them.
    skipped: int = 0


class EvidenceSource(Protocol):
    """Read-only, bounded source of identity evidence."""

    name: str
    kinds: frozenset[EvidenceKind]

    async def fetch(self, *, start: datetime, end: datetime, limit: int) -> EvidenceBatch:
        """Records whose validity may overlap ``[start, end)``; at most ``limit``."""
        ...


@dataclass(frozen=True)
class SourceSlot:
    """One named place a source can be configured. ``source`` is ``None`` when it is not."""

    name: str
    source: EvidenceSource | None


class MemoryEvidenceSource:
    """Fixed records held in memory: tests, and the model for later adapters."""

    def __init__(
        self,
        name: str,
        records: Sequence[EvidenceRecord],
        kinds: frozenset[EvidenceKind] | None = None,
    ) -> None:
        self.name = name
        self.kinds = kinds if kinds is not None else frozenset(EvidenceKind)
        self._records = tuple(records)

    async def fetch(self, *, start: datetime, end: datetime, limit: int) -> EvidenceBatch:
        overlapping = [
            record
            for record in self._records
            if record.valid_from < end and record.effective_end > start
        ]
        return EvidenceBatch(tuple(overlapping[:limit]), truncated=len(overlapping) > limit)
