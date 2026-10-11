"""Which destination addresses count as the organisation's own space."""

from __future__ import annotations

import pytest

from netsight_api.traffic.addresses import is_internal_address


@pytest.mark.parametrize(
    "address",
    [
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd12::1",
        "ff02::1",
        "::ffff:10.1.2.3",
        "not-an-ip",
        "",
    ],
)
def test_internal_space_and_nonsense_is_internal(address: str) -> None:
    assert is_internal_address(address)


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "203.0.113.9",
        "198.51.100.7",
        "172.32.0.1",
        "100.128.0.1",
        "2001:db8::1",
        "2606:4700::1111",
        "::ffff:8.8.8.8",
    ],
)
def test_other_space_is_external(address: str) -> None:
    assert not is_internal_address(address)
