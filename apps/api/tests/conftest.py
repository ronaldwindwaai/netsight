"""Shared fixtures."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from netsight_api import read_limit
from netsight_api.auth.rate_limit import RateLimiter


@pytest.fixture(autouse=True)
def _fresh_read_limiter(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Each test gets its own read limiter so request counts never leak between tests."""
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    yield


@pytest.fixture(autouse=True)
def _identity_id_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fixed evidence-id key so opaque ids work; the tests of the fail-closed path remove it."""
    monkeypatch.setenv("NETSIGHT_IDENTITY_ID_KEY", "test-only-key-0123456789abcdef0123456789")


@pytest.fixture(autouse=True)
def _fresh_identity_guards() -> Iterator[None]:
    """The global identity limits are module state: each test starts with a full budget."""
    from netsight_api.identity import guards

    guards.reset_for_tests()
    yield


@pytest.fixture(autouse=True)
def _fresh_traffic_guards() -> Iterator[None]:
    """The heavy-read cap is module state: each test starts with every slot free."""
    from netsight_api.traffic import guards

    guards.reset_for_tests()
    yield


@pytest.fixture(autouse=True)
def _fresh_clickhouse_limit_capability() -> Iterator[None]:
    """What the process learned about setting query limits is module state: tests start unlearned."""
    from netsight_api.adapters import clickhouse_limits

    clickhouse_limits.reset_for_tests()
    yield


@pytest.fixture(autouse=True)
def _fresh_step8_caches() -> Iterator[None]:
    """The inventory, IPAM and finding wiring caches are module state: each test starts cold."""
    from netsight_api.inventory import wiring as inventory_wiring
    from netsight_api.ipam import wiring as ipam_wiring
    from netsight_api.unknown_devices import wiring as unknown_wiring

    inventory_wiring.reset_for_tests()
    ipam_wiring.reset_for_tests()
    unknown_wiring.reset_for_tests()
    yield


@pytest.fixture(autouse=True)
def _fresh_internal_prefixes(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The parsed internal-prefix list is module state: no test inherits another's environment."""
    from netsight_api.traffic import addresses

    monkeypatch.delenv(addresses.PREFIXES_ENV, raising=False)
    addresses.reset_for_tests()
    yield
    addresses.reset_for_tests()


@pytest.fixture(autouse=True)
def _fresh_shared_clickhouse_client() -> Iterator[None]:
    """The process-wide flow client is module state: no test inherits another's client."""
    from netsight_api.adapters import clickhouse_shared

    clickhouse_shared.reset_for_tests()
    yield
    clickhouse_shared.reset_for_tests()


# --- CI guard: the live PostgreSQL suites must not skip silently ----------------------------
# With NETSIGHT_REQUIRE_PG=1 (set by the CI python job) a missing NETSIGHT_TEST_PG_DSN aborts the
# run, and any test skipped by the ``requires_pg`` marker fails the session. Without the variable
# nothing changes: the live suites stay opt-in for local runs.
REQUIRE_PG_ENV = "NETSIGHT_REQUIRE_PG"
PG_DSN_ENV = "NETSIGHT_TEST_PG_DSN"
_pg_skips: list[str] = []


def _require_pg() -> bool:
    return os.environ.get(REQUIRE_PG_ENV) == "1"


def pytest_configure(config: pytest.Config) -> None:
    if _require_pg() and not os.environ.get(PG_DSN_ENV):
        raise pytest.UsageError(f"{REQUIRE_PG_ENV}=1 but {PG_DSN_ENV} is not set")


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if not _require_pg() or not report.skipped:
        return
    longrepr = report.longrepr
    reason = str(longrepr[2]) if isinstance(longrepr, tuple) else str(longrepr)
    if PG_DSN_ENV in reason:
        _pg_skips.append(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if _pg_skips:
        print(
            f"\n{REQUIRE_PG_ENV}=1: {len(_pg_skips)} live PostgreSQL test(s) were skipped:\n  "
            + "\n  ".join(_pg_skips[:20])
        )
        session.exitstatus = 1
