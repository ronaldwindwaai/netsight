"""Growth control for stored diagnostic sessions.

Sessions are immutable and there is no prune path yet (the retention period is a pending human
decision, DATA-RETENTION-MATRIX), so the table only grows. Two guards bound the rate:

* a configurable daily cap (``NETSIGHT_DIAGNOSTIC_SESSIONS_DAILY_CAP``): once that many sessions
  completed in the last 24 hours the run is still answered but not stored (``stored: false``);
* a warning is logged once usage reaches ``WARN_FRACTION`` of the cap, so an operator sees growth
  coming before storing stops.

The cap is soft: counting and inserting are separate statements, so concurrent runs can overshoot
by a few. An invalid value is never read as "off": it fails closed (nothing is stored) and says so.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from netsight_api.storage.diagnostics import DiagnosticSessionRepository

_LOGGER = logging.getLogger("netsight_api")

DAILY_CAP_ENV = "NETSIGHT_DIAGNOSTIC_SESSIONS_DAILY_CAP"
DEFAULT_DAILY_CAP = 5_000
MAX_DAILY_CAP = 1_000_000
WARN_FRACTION = 0.8
CAP_WINDOW = timedelta(hours=24)


@dataclass(frozen=True)
class StoreDecision:
    """Whether a finished run may be stored, and if not, why (a fixed audit reason code)."""

    allowed: bool
    reason: str | None = None


def read_daily_cap(env: Mapping[str, str] | None = None) -> int | None:
    """The configured cap; the default when unset, ``None`` when the value is invalid."""
    raw = (os.environ if env is None else env).get(DAILY_CAP_ENV, "").strip()
    if not raw:
        return DEFAULT_DAILY_CAP
    if not (raw.isascii() and raw.isdigit()):
        return None
    value = int(raw)
    return value if 1 <= value <= MAX_DAILY_CAP else None


def check_daily_cap(
    store: DiagnosticSessionRepository, completed_at: datetime, env: Mapping[str, str] | None = None
) -> StoreDecision:
    """Decide whether one more session may be stored; never raises for a configuration problem."""
    cap = read_daily_cap(env)
    if cap is None:
        _LOGGER.warning("%s is invalid; diagnostic sessions are not stored", DAILY_CAP_ENV)
        return StoreDecision(False, "cap-misconfigured")
    stored = store.count_sessions_since(completed_at - CAP_WINDOW)
    if stored >= cap:
        _LOGGER.warning(
            "diagnostic session daily cap reached; run not stored",
            extra={"stored_last_24h": stored, "daily_cap": cap},
        )
        return StoreDecision(False, "daily-cap")
    if stored >= cap * WARN_FRACTION:
        _LOGGER.warning(
            "diagnostic session storage nearing the daily cap",
            extra={"stored_last_24h": stored, "daily_cap": cap},
        )
    return StoreDecision(True)
