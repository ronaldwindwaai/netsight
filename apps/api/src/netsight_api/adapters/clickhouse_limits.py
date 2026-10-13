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

**Only the server's own exception code decides.** ClickHouse puts the code of a failed query in the
``X-ClickHouse-Exception-Code`` response header. The error *text* can carry caller-controlled
material (an ``Enum`` error echoes the offending filter value), so nothing is ever matched against the
body: a caller who could write "Code: 164. Cannot modify" into the text could otherwise flip the whole
process into the profile-only mode for every user. The header is read strictly (decimal digits, one
value) and only the two codes below mean "the limits were refused":

* ``164`` (``READONLY``): the identity may not change settings at all;
* ``452`` (``SETTING_CONSTRAINT_VIOLATION``): the profile pins or bounds a setting we sent.

Either way the read is repeated without the settings, and the profile is relied on. If a ``452`` still
fails the read *without* our settings, the profile itself rejects the query: that is a distinct
warning, because no retry can help.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Final, Literal

_LOGGER = logging.getLogger("netsight_api")

GIB: Final = 1024**3
MAX_MEMORY_USAGE: Final = 2 * GIB
MAX_ROWS_TO_READ: Final = 5_000_000_000
MAX_BYTES_TO_READ: Final = 500 * GIB
MAX_RESULT_ROWS: Final = 10_000  # the widest legitimate result is the 8,401-row baseline series
MAX_RESULT_BYTES: Final = 64 * 1024 * 1024

REFUSAL_CODES: Final = frozenset({164, 452})
CONSTRAINT_CODE: Final = 452
EXCEPTION_CODE_HEADER: Final = "X-ClickHouse-Exception-Code"
_MAX_CODE_DIGITS: Final = 5

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


def exception_code(headers: Mapping[str, str]) -> int | None:
    """The server's exception code from the response header; ``None`` when absent or malformed."""
    raw = headers.get(EXCEPTION_CODE_HEADER, "").strip()
    if not raw.isascii() or not raw.isdecimal() or len(raw) > _MAX_CODE_DIGITS:
        return None
    return int(raw)


def settings_refused(headers: Mapping[str, str]) -> bool:
    """True when the server says (by its exception code) that it refused a per-query setting."""
    return exception_code(headers) in REFUSAL_CODES


def capability_for(key: CapabilityKey) -> Capability:
    return _known.get(key, "unverified")


def may_send_settings(key: CapabilityKey) -> bool:
    return capability_for(key) != "profile-only"


def mark_enforced(key: CapabilityKey) -> None:
    _known[key] = "enforced"


def mark_profile_only(key: CapabilityKey, *, code: int | None = None) -> None:
    """Remember that this identity can not set limits; say so once."""
    if _known.get(key) == "profile-only":
        return
    _known[key] = "profile-only"
    if code == CONSTRAINT_CODE:
        _LOGGER.warning(
            "a clickhouse profile constraint rejected the per-query limits (Code 452); reads go "
            "on without them, so resource limits can not be verified here and MUST be enforced by "
            "the ClickHouse user profile (docs/04-integrations/AKVORADO-CLICKHOUSE.md)",
            extra={"source": "clickhouse", "limits": "profile-only", "code": code},
        )
        return
    _LOGGER.warning(
        "clickhouse identity may not set per-query limits; resource limits can not be verified "
        "here and MUST be enforced by the ClickHouse user profile "
        "(docs/04-integrations/AKVORADO-CLICKHOUSE.md)",
        extra={"source": "clickhouse", "limits": "profile-only", "code": code},
    )


_constraint_failure_logged = False


def report_failed_by_constraint(headers: Mapping[str, str]) -> None:
    """A read failed with a settings-constraint code although no per-query setting was sent."""
    global _constraint_failure_logged
    if exception_code(headers) != CONSTRAINT_CODE or _constraint_failure_logged:
        return
    _constraint_failure_logged = True
    _LOGGER.warning(
        "a clickhouse profile constraint (Code 452) makes flow reads fail even without per-query "
        "limits; the user profile must be corrected (docs/04-integrations/AKVORADO-CLICKHOUSE.md)",
        extra={"source": "clickhouse", "code": CONSTRAINT_CODE},
    )


def reset_for_tests() -> None:
    """Forget what was learned (the tests' autouse fixture calls this)."""
    global _constraint_failure_logged
    _constraint_failure_logged = False
    _known.clear()
