"""Shared fixtures."""

from __future__ import annotations

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
