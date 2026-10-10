"""The blackbox probe adapter (S7-2): deny by default, bounded, and honest about what it cannot do.

Hermetic: a probe never leaves the machine. The allow-list refusal and the unavailable-check
branches run without a socket; the connect paths use a loopback listener bound to an ephemeral
port. DNS success resolves ``localhost`` from the hosts file, and DNS failure is forced by
patching ``socket.getaddrinfo``.
"""

from __future__ import annotations

import asyncio
import socket

from netsight_api.adapters.blackbox import (
    AllowlistedBlackboxClient,
    _status_code,
    get_optional_blackbox_client,
)

_LOCAL = "127.0.0.1"


def test_factory_is_none_without_an_allowlist(monkeypatch) -> None:
    monkeypatch.delenv("BLACKBOX_ALLOWED_TARGETS", raising=False)
    assert get_optional_blackbox_client() is None


def test_factory_builds_a_client_from_a_blank_ridden_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("BLACKBOX_ALLOWED_TARGETS", "srv-db-01, 10.0.0.5 ,")
    monkeypatch.setenv("BLACKBOX_VANTAGE", "internal")
    assert isinstance(get_optional_blackbox_client(), AllowlistedBlackboxClient)


def test_a_non_allowlisted_target_is_unknown_without_connecting() -> None:
    client = AllowlistedBlackboxClient(allowed=["srv-db-01"])
    observation = asyncio.run(
        client.probe(kind="tcp", target="evil.example.com", vantage="internal")
    )
    assert observation.status == "unknown"
    assert observation.latency_ms is None
    assert "allow-list" in (observation.detail or "")


def test_the_allowlist_match_is_case_and_whitespace_insensitive() -> None:
    client = AllowlistedBlackboxClient(allowed=[" SRV-DB-01 "])
    observation = asyncio.run(client.probe(kind="icmp", target="srv-db-01", vantage="internal"))
    # Matched the allow-list, then honestly reported ICMP as unavailable (not refused).
    assert observation.status == "unknown"
    assert "ICMP" in (observation.detail or "")


def test_icmp_is_reported_unknown() -> None:
    client = AllowlistedBlackboxClient(allowed=["srv-db-01"])
    observation = asyncio.run(client.probe(kind="icmp", target="srv-db-01", vantage="internal"))
    assert observation.status == "unknown"
    assert "ICMP" in (observation.detail or "")


def test_a_source_dependent_check_is_unknown() -> None:
    client = AllowlistedBlackboxClient(allowed=["srv-db-01"])
    observation = asyncio.run(
        client.probe(kind="dependencies", target="srv-db-01", vantage="internal")
    )
    assert observation.status == "unknown"
    assert "source" in (observation.detail or "")


def test_the_timeout_is_clamped() -> None:
    assert AllowlistedBlackboxClient(allowed=["x"], timeout=1000.0)._timeout == 30.0
    assert AllowlistedBlackboxClient(allowed=["x"], timeout=0.0)._timeout == 0.1


def test_tcp_connect_succeeds_against_a_loopback_listener() -> None:
    async def scenario() -> object:
        server = await asyncio.start_server(lambda _r, w: w.close(), _LOCAL, 0)
        port = server.sockets[0].getsockname()[1]
        try:
            client = AllowlistedBlackboxClient(allowed=[_LOCAL])
            return await client._tcp(_LOCAL, port)
        finally:
            server.close()
            await server.wait_closed()

    outcome = asyncio.run(scenario())
    assert outcome.status == "pass"
    assert outcome.latency_ms is not None and outcome.latency_ms >= 0


def test_tcp_connect_fails_against_a_closed_port() -> None:
    async def scenario() -> object:
        server = await asyncio.start_server(lambda _r, w: w.close(), _LOCAL, 0)
        port = server.sockets[0].getsockname()[1]
        server.close()
        await server.wait_closed()
        client = AllowlistedBlackboxClient(allowed=[_LOCAL], timeout=2.0)
        return await client._tcp(_LOCAL, port)

    outcome = asyncio.run(scenario())
    assert outcome.status == "fail"


def test_dns_resolves_localhost_without_leaving_the_machine() -> None:
    client = AllowlistedBlackboxClient(allowed=["localhost"])
    observation = asyncio.run(client.probe(kind="dns", target="localhost", vantage="internal"))
    assert observation.status == "pass"
    assert "resolved to" in (observation.detail or "")


def test_dns_failure_is_reported(monkeypatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise socket.gaierror(socket.EAI_NONAME, "name not known")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    client = AllowlistedBlackboxClient(allowed=["missing.example"])
    outcome = asyncio.run(client._dns("missing.example"))
    assert outcome.status == "fail"


def test_status_line_parsing() -> None:
    assert _status_code(b"HTTP/1.1 204 No Content\r\n") == 204
    assert _status_code(b"HTTP/1.1 500 Internal Server Error\r\n") == 500
    assert _status_code(b"not http\r\n") is None
    assert _status_code(b"HTTP/1.1 abc\r\n") is None
