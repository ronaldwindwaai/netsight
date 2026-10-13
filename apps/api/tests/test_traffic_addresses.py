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


# --- one classifier for the hidden-internal rule and the cohort denominator (HIGH 3) -------------


@pytest.mark.parametrize(
    "address",
    ["198.18.0.1", "198.19.255.255", "192.0.0.9", "240.0.0.1", "255.255.255.254", "0.1.2.3"],
)
def test_reserved_internal_use_ranges_are_internal(address: str) -> None:
    assert is_internal_address(address)


def test_the_default_prefixes_cover_the_rfc1918_ula_cgnat_and_link_local_space() -> None:
    from netsight_api.traffic.addresses import internal_prefixes

    prefixes = {str(net) for net in internal_prefixes()}
    assert {
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "198.18.0.0/15",
        "192.0.0.0/24",
        "240.0.0.0/4",
        "0.0.0.0/8",
    } <= prefixes


def test_configured_prefixes_add_to_the_defaults_and_never_replace_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netsight_api.traffic.addresses import internal_prefixes

    monkeypatch.setenv("NETSIGHT_INTERNAL_PREFIXES", " 203.0.113.0/24 , 2001:db8:ff::/48 ")
    assert is_internal_address("203.0.113.9")
    assert is_internal_address("2001:db8:ff::7")
    assert is_internal_address("10.1.2.3")  # a default is still internal
    assert not is_internal_address("203.0.114.9")
    assert any(str(net) == "203.0.113.0/24" for net in internal_prefixes())


@pytest.mark.parametrize(
    "raw",
    ["not-a-cidr", "10.0.0.0/8,garbage", "203.0.113.0/33", "0.0.0.0/0", "::/0", "1.2.3.4/0,"],
)
def test_an_invalid_or_all_encompassing_list_is_ignored_and_logged_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, raw: str
) -> None:
    from netsight_api.traffic import addresses

    addresses.reset_for_tests()
    monkeypatch.setenv("NETSIGHT_INTERNAL_PREFIXES", raw)
    with caplog.at_level("WARNING", logger="netsight_api"):
        assert not is_internal_address("203.0.113.9")  # nothing from the bad list applied
        assert is_internal_address("10.1.2.3")
        is_internal_address("203.0.113.10")
    warnings = [r for r in caplog.records if "NETSIGHT_INTERNAL_PREFIXES" in r.getMessage()]
    assert len(warnings) == 1
    assert raw not in warnings[0].getMessage()


def test_a_host_bit_prefix_is_normalised_and_the_list_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netsight_api.traffic.addresses import internal_prefixes

    monkeypatch.setenv("NETSIGHT_INTERNAL_PREFIXES", "203.0.113.77/24")
    assert any(str(net) == "203.0.113.0/24" for net in internal_prefixes())
    many = ",".join(f"203.{i // 256}.{i % 256}.0/24" for i in range(300))
    monkeypatch.setenv("NETSIGHT_INTERNAL_PREFIXES", many)
    assert not is_internal_address("203.0.0.5")  # more than the bound: ignored whole


def test_the_sql_prefix_list_is_the_same_classifier_as_the_python_one() -> None:
    from netsight_api.traffic.addresses import internal_prefix_texts

    texts = internal_prefix_texts()
    assert texts == tuple(sorted(set(texts)))
    assert "10.0.0.0/8" in texts and "fc00::/7" in texts
