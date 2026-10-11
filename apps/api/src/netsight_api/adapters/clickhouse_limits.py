"""Server-side resource limits for the ClickHouse flow reads, and what is known about enforcing them.

A flow query can scan billions of rows. The client timeout only stops *waiting*; without server-side
limits the query keeps running, so the limits are sent with every query as URL settings:

* ``readonly=2``: the statement can not write, and the other settings below may still be changed;
* ``max_execution_time`` (the client timeout), ``max_memory_usage``, ``max_rows_to_read``,
  ``max_bytes_to_read``, ``max_result_rows`` and ``max_result_bytes``;
* the three ``*_overflow_mode`` settings pinned to ``throw``: an exceeded limit fails the read, a
  profile that says ``break`` can not turn it into a silently truncated (wrong) answer;
* ``cancel_http_readonly_queries_on_client_close``: a timed-out or abandoned request stops its query.

A readonly identity (``readonly=1``) may not change settings at all, and ClickHouse answers the first
attempt with a refusal. That is learned once per (endpoint, user) and remembered for the life of the
process, so it costs one failed round trip, not one per request. In that case nothing here can bound a
query: the limits MUST then be enforced by the ClickHouse user profile (see the recommended profile in
docs/04-integrations/AKVORADO-CLICKHOUSE.md), and one warning says so.
"""

from __future__ import annotations

import logging
from typing import Final, Literal

_LOGGER = logging.getLogger("netsight_api")

GIB: Final = 1024**3
MAX_MEMORY_USAGE: Final = 2 * GIB
MAX_ROWS_TO_READ: Final = 5_000_000_000
MAX_BYTES_TO_READ: Final = 500 * GIB
MAX_RESULT_ROWS: Final = 10_000  # the widest legitimate result is the 8,401-row baseline series
MAX_RESULT_BYTES: Final = 64 * 1024 * 1024

Capability = Literal["enforced", "profile-only", "unverified"]
CapabilityKey = tuple[str, str]  # (base URL without credentials, user name)

_known: dict[CapabilityKey, Capability] = {}


def limit_settings(timeout_seconds: float) -> dict[str, str]:
    """The URL settings that bound one read."""
    return {
        "readonly": "2",
        "max_execution_time": str(max(1, int(timeout_seconds))),
        "max_memory_usage": str(MAX_MEMORY_USAGE),
        "max_rows_to_read": str(MAX_ROWS_TO_READ),
        "max_bytes_to_read": str(MAX_BYTES_TO_READ),
        "max_result_rows": str(MAX_RESULT_ROWS),
        "max_result_bytes": str(MAX_RESULT_BYTES),
        "read_overflow_mode": "throw",
        "result_overflow_mode": "throw",
        "timeout_overflow_mode": "throw",
        "cancel_http_readonly_queries_on_client_close": "1",
    }


def settings_refused(body: str) -> bool:
    """True when a ClickHouse error says the identity may not set (or pins) a setting."""
    if "Code: 164." in body or "Cannot modify" in body:
        return True
    return "Code: 452." in body and "should not be changed" in body


def capability_for(key: CapabilityKey) -> Capability:
    return _known.get(key, "unverified")


def may_send_settings(key: CapabilityKey) -> bool:
    return capability_for(key) != "profile-only"


def mark_enforced(key: CapabilityKey) -> None:
    _known[key] = "enforced"


def mark_profile_only(key: CapabilityKey) -> None:
    """Remember that this identity can not set limits; say so once."""
    if _known.get(key) == "profile-only":
        return
    _known[key] = "profile-only"
    _LOGGER.warning(
        "clickhouse identity may not set per-query limits; resource limits can not be verified "
        "here and MUST be enforced by the ClickHouse user profile "
        "(docs/04-integrations/AKVORADO-CLICKHOUSE.md)",
        extra={"source": "clickhouse", "limits": "profile-only"},
    )


def reset_for_tests() -> None:
    """Forget what was learned (the tests' autouse fixture calls this)."""
    _known.clear()
