"""Test guard: an attempt to open a real outbound network connection or resolve a name fails.

Notification and dry-run tests inject resolvers and transports; this fixture proves nothing
slips past them to the real network (AGENTS.md: no real outbound calls in tests). Loopback
connects stay allowed because the event loop itself (asyncio's self-pipe on Windows, the
TestClient portal) connects to 127.0.0.1; every other address, and every name that is not an
IP literal or ``localhost``, is refused.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterator
from typing import Any

import pytest


class RealNetworkAttempt(AssertionError):
    """A test tried to touch the real network."""


def _is_loopback(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    real_connect: Callable[..., Any] = socket.socket.connect
    real_connect_ex: Callable[..., Any] = socket.socket.connect_ex
    real_getaddrinfo: Callable[..., Any] = socket.getaddrinfo

    def refuse() -> Any:
        raise RealNetworkAttempt("real network access attempted in a test")

    def connect(self: socket.socket, address: Any) -> Any:
        if self.family in (socket.AF_INET, socket.AF_INET6) and not _is_loopback(address[0]):
            refuse()
        return real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> Any:
        if self.family in (socket.AF_INET, socket.AF_INET6) and not _is_loopback(address[0]):
            refuse()
        return real_connect_ex(self, address)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if not _is_loopback(host):
            refuse()
        return real_getaddrinfo(host, *args, **kwargs)

    def gethostbyname(*_args: Any, **_kwargs: Any) -> Any:
        refuse()

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", gethostbyname)
    yield
