"""Operator configuration of the capacity forecast (Step 13).

The only setting is an optional daily traffic limit, in bytes per day:

* ``NETSIGHT_FORECAST_TRAFFIC_DAILY_LIMIT_BYTES``: a whole number from 1 up. When unset, no limit
  exists and no crossing is reported. Netsight never infers a limit from link speeds or history.

A value that is not a plain positive whole number is treated as unset and logged once (never with
the value), so a typo cannot turn into a surprising limit.
"""

from __future__ import annotations

import logging
import os
import re
from functools import cache
from typing import Final

from netsight_api.schemas_forecast import MAX_VALUE

_LOGGER: Final = logging.getLogger("netsight_api")
LIMIT_ENV: Final = "NETSIGHT_FORECAST_TRAFFIC_DAILY_LIMIT_BYTES"
_DIGITS: Final = re.compile(r"[0-9]{1,16}", re.ASCII)


@cache
def _log_invalid_once() -> None:
    _LOGGER.warning("%s is not a positive whole number of bytes; no limit is applied", LIMIT_ENV)


def traffic_daily_limit() -> int | None:
    raw = os.environ.get(LIMIT_ENV, "").strip()
    if not raw:
        return None
    if _DIGITS.fullmatch(raw) is None or not 1 <= int(raw) <= MAX_VALUE:
        _log_invalid_once()
        return None
    return int(raw)


def reset_for_tests() -> None:
    _log_invalid_once.cache_clear()
