"""LibreNMS WAN port reading (Step 5a): throughput, speed, status and the public address.

Every value is what the source reports or ``None``: a missing, malformed or negative counter is
never a zero, a private or shared address is never a public IP, and a source failure raises (the
caller reports ``unknown``) instead of returning a plausible-looking reading.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import anyio
import httpx
import pytest

from netsight_api.adapters.librenms import AdapterError, AdapterStatus, LibrenmsClient

POLL = 1_790_000_000  # epoch seconds


def port(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "port_id": 345,
        "device_id": 12,
        "ifName": "wan0",
        "ifOperStatus": "up",
        "ifAdminStatus": "up",
        "ifSpeed": 1_000_000_000,
        "ifInOctets_rate": 12_500_000,
        "ifOutOctets_rate": 2_500_000,
        "poll_time": POLL,
    }
    row.update(overrides)
    return row


def run(handler: Any, call: Any) -> Any:
    client = LibrenmsClient(
        base_url="https://librenms.test",
        token="secret-token",
        _transport=httpx.MockTransport(handler),
    )
    return anyio.run(lambda: call(client))


def raw(payload: dict[str, Any]) -> httpx.Response:
    """A 200 whose body may hold NaN/Infinity (Python's json accepts what httpx's encoder refuses)."""
    return httpx.Response(
        200, content=json.dumps(payload).encode(), headers={"content-type": "application/json"}
    )


def ports_handler(rows: list[dict[str, Any]], ips: dict[str, Any] | None = None) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v0/devices/12/ports":
            return raw({"status": "ok", "ports": rows})
        if request.url.path == "/api/v0/ports/345/ip":
            return raw(ips if ips is not None else {"status": "ok", "addresses": []})
        return httpx.Response(404, json={"status": "error"})

    return handler


def read(rows: list[dict[str, Any]], ips: dict[str, Any] | None = None) -> Any:
    return run(ports_handler(rows, ips), lambda c: c.wan_port("12", "345"))


def test_rates_are_converted_from_bytes_to_bits_per_second() -> None:
    reading = read([port()])
    assert reading.rx_bps == 100_000_000
    assert reading.tx_bps == 20_000_000
    assert reading.speed_bps == 1_000_000_000
    assert reading.oper_status == "up"
    assert reading.polled_at == datetime.fromtimestamp(POLL, UTC)


def test_only_the_requested_port_is_read() -> None:
    reading = read([port(port_id=1, ifInOctets_rate=1), port(), port(port_id=3, ifInOctets_rate=9)])
    assert reading.rx_bps == 100_000_000


def test_a_port_the_source_does_not_list_reads_as_none() -> None:
    assert read([port(port_id=1)]) is None
    assert read([]) is None


@pytest.mark.parametrize(
    "value", [None, "12", True, -1, -0.5, float("inf"), float("nan"), [1], {"a": 1}]
)
def test_a_malformed_or_negative_counter_is_unknown_never_zero(value: Any) -> None:
    reading = read([port(ifInOctets_rate=value, ifOutOctets_rate=value)])
    assert reading.rx_bps is None and reading.tx_bps is None
    assert reading.oper_status == "up"  # the rest of the reading survives


def test_a_genuine_zero_rate_is_a_zero() -> None:
    reading = read([port(ifInOctets_rate=0, ifOutOctets_rate=0)])
    assert (reading.rx_bps, reading.tx_bps) == (0, 0)


def test_missing_poll_time_means_unknown_source_time() -> None:
    assert read([port(poll_time=None)]).polled_at is None
    assert read([port(poll_time="yesterday")]).polled_at is None
    assert read([port(poll_time=-5)]).polled_at is None
    assert read([port(poll_time=True)]).polled_at is None


def test_an_unrecognised_status_is_unknown_and_a_zero_speed_is_unreported() -> None:
    reading = read([port(ifOperStatus="weird", ifSpeed=0, ifHighSpeed=0)])
    assert reading.oper_status == "unknown" and reading.speed_bps is None


# --- public address ------------------------------------------------------------------------------


def addresses(*values: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "addresses": [
            {"ipv4_address": value, "ipv4_prefixlen": 30, "port_id": 345} for value in values
        ],
    }


def test_a_single_global_ipv4_address_is_the_public_ip() -> None:
    assert read([port()], addresses("8.8.8.8")).public_ip == "8.8.8.8"


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.2",
        "192.168.1.5",
        "172.16.4.4",
        "100.64.0.9",
        "169.254.1.1",
        "127.0.0.1",
        "not-an-ip",
    ],
)
def test_private_shared_and_malformed_addresses_are_never_a_public_ip(value: str) -> None:
    assert read([port()], addresses(value)).public_ip is None


def test_two_global_addresses_are_ambiguous_and_so_unreported() -> None:
    assert read([port()], addresses("8.8.8.8", "9.9.9.9")).public_ip is None


def test_a_global_address_among_private_ones_is_still_found() -> None:
    assert read([port()], addresses("10.0.0.2", "8.8.8.8")).public_ip == "8.8.8.8"


def test_a_failing_address_lookup_loses_only_the_address() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/ports"):
            return httpx.Response(200, json={"status": "ok", "ports": [port()]})
        return httpx.Response(500)

    reading = run(handler, lambda c: c.wan_port("12", "345"))
    assert reading.public_ip is None and reading.rx_bps == 100_000_000


def test_a_malformed_address_payload_loses_only_the_address() -> None:
    assert read([port()], {"status": "ok", "addresses": "nope"}).public_ip is None
    assert read([port()], {"status": "ok", "addresses": [None, 5]}).public_ip is None


# --- failures and safety -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (500, AdapterStatus.UNAVAILABLE),
        (503, AdapterStatus.UNAVAILABLE),
        (403, AdapterStatus.FORBIDDEN),
        (401, AdapterStatus.FORBIDDEN),
    ],
)
def test_a_source_failure_is_raised_not_read_as_a_value(
    status: int, expected: AdapterStatus
) -> None:
    with pytest.raises(AdapterError) as raised:
        run(lambda request: httpx.Response(status), lambda c: c.wan_port("12", "345"))
    assert raised.value.status is expected


def test_an_invalid_ports_payload_is_an_error() -> None:
    with pytest.raises(AdapterError) as raised:
        run(
            lambda request: httpx.Response(200, json={"status": "ok", "ports": "x"}),
            lambda c: c.wan_port("12", "345"),
        )
    assert raised.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.parametrize("native", ["../x", "a/b", "..", "a\\b", ""])
def test_native_ids_that_could_steer_the_request_are_refused(native: str) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"status": "ok", "ports": []})

    with pytest.raises(AdapterError):
        run(handler, lambda c: c.wan_port(native, "345"))
    with pytest.raises(AdapterError):
        run(handler, lambda c: c.wan_port("12", native))
    assert seen == []


def test_the_token_is_sent_as_a_bearer_header_and_never_in_the_url() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return ports_handler([port()])(request)

    run(handler, lambda c: c.wan_port("12", "345"))
    assert seen and all(r.headers["authorization"] == "Bearer secret-token" for r in seen)
    assert all("secret-token" not in str(r.url) for r in seen)
