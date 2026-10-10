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
