"""Reading one external source for the inventory, IPAM and unknown-device surfaces (Step 8).

A read is a value, ``not-connected`` (nothing configured) or ``unknown`` (configured, but it failed,
timed out or returned something unusable). It is never an empty success: "NetBox answered with
nothing" and "NetBox could not be read" must never look alike. The failure is logged by type only
(no message, no URL, no row content). Cancellation is not a failure and propagates.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from netsight_api.schemas_sources import ReadState, SourceName, SourceStatus

_LOGGER: Final = logging.getLogger("netsight_api")


@dataclass(frozen=True)
class SourceRead[T]:
    state: ReadState
    value: T | None = None
    observed_at: datetime | None = None

    @property
    def ok(self) -> bool:
        return self.state == "ok"

    def status(self, source: SourceName) -> SourceStatus:
        return SourceStatus(source=source, state=self.state, observed_at=self.observed_at)


def not_connected[T]() -> SourceRead[T]:
    return SourceRead("not-connected")


def unknown[T]() -> SourceRead[T]:
    return SourceRead("unknown")


async def read_bounded[T](
    source: str, call: Callable[[], Awaitable[T]], *, budget: float, now: datetime
) -> SourceRead[T]:
    """Run one read inside its time budget; any failure is ``unknown``."""
    try:
        value = await asyncio.wait_for(call(), timeout=budget)
    except Exception as error:  # noqa: BLE001 - deliberate source boundary; typed, never leaked
        _LOGGER.warning(
            "source read failed", extra={"source": source, "error_type": type(error).__name__}
        )
        return unknown()
    return SourceRead("ok", value, now)
