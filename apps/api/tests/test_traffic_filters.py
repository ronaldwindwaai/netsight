"""Flow Explorer filters: an allow-list, canonical values and nothing echoed back on a refusal."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from netsight_api.schemas_traffic import FlowFilters
from netsight_api.traffic.filters import (
    ENDPOINT_FILTERS,
    FILTER_NAMES,
    FilterError,
    FlowFilterSet,
    ip_candidates,
    parse_filters,
    reject_unknown_parameters,
)


def parse(**params: str) -> FlowFilterSet:
    return parse_filters(params)


def test_no_parameters_means_no_filters() -> None:
    filters = parse()
    assert filters.active() == ()
    assert not filters.endpoint_level()
    assert filters.to_model().model_dump() == dict.fromkeys(FILTER_NAMES)


def test_every_filter_parses_to_a_canonical_value() -> None:
    filters = parse(
        source_ip="10.001.2.3".replace("001", "1"),
        destination_ip="2001:DB8:0:0:0:0:0:1",
        device="edge-rtr-1",
        vlan="20",
        application="Microsoft 365",
        protocol="udp",
        port="53",
        country="ZA",
        asn="64500",
        direction="outbound",
    )
    assert filters.source_ip == "10.1.2.3"
    assert filters.destination_ip == "2001:db8::1"
    assert filters.vlan == 20 and filters.port == 53 and filters.asn == 64500
    assert filters.active() == FILTER_NAMES
    assert isinstance(filters.to_model(), FlowFilters)


def test_ipv4_mapped_ipv6_is_the_ipv4_address() -> None:
    assert parse(source_ip="::ffff:10.1.2.3").source_ip == "10.1.2.3"


def test_the_stored_spellings_of_an_address_are_all_candidates() -> None:
    assert ip_candidates("10.1.2.3") == ("10.1.2.3", "::ffff:10.1.2.3")
    assert ip_candidates("2001:db8::1") == ("2001:db8::1",)


ENDPOINT_SAMPLES = {
    "source_ip": "10.1.2.3",
    "destination_ip": "10.1.2.3",
    "device": "edge",
    "vlan": "10",
}


def test_the_endpoint_level_filters_are_the_two_addresses_the_device_and_the_vlan() -> None:
    # A device or a VLAN narrows a read to a handful of endpoints (a floor, a closet), so it is as
    # identifying as an address and needs the detail tier too (security review HIGH-2).
    assert ENDPOINT_FILTERS == frozenset(ENDPOINT_SAMPLES)


@pytest.mark.parametrize("name", sorted(ENDPOINT_FILTERS))
def test_endpoint_filters_are_endpoint_level(name: str) -> None:
    assert parse(**{name: ENDPOINT_SAMPLES[name]}).endpoint_level()


@pytest.mark.parametrize("name", sorted(set(FILTER_NAMES) - ENDPOINT_FILTERS))
def test_other_filters_are_not_endpoint_level(name: str) -> None:
    sample = {
        "application": "Zoom",
        "protocol": "tcp",
        "port": "443",
        "country": "ZA",
        "asn": "64500",
        "direction": "inbound",
    }
    assert not parse(**{name: sample[name]}).endpoint_level()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("source_ip", "not-an-ip"),
        ("source_ip", "10.0.0.0/8"),
        ("source_ip", "10.0.0.1%eth0"),
        ("source_ip", "10.0.0.1; DROP TABLE flows"),
        ("source_ip", "999.1.1.1"),
        ("source_ip", ""),
        ("destination_ip", "fe80::1%eth0"),
        ("destination_ip", " "),
        ("vlan", "4095"),
        ("vlan", "-1"),
        ("vlan", "1e3"),
        ("vlan", "０１"),  # full-width digits
        ("vlan", "ten"),
        ("port", "65536"),
        ("port", "-1"),
        ("port", "80.0"),
        ("port", "0x50"),
        ("asn", "0"),
        ("asn", "4294967296"),
        ("asn", "AS64500"),
        ("country", "za"),
        ("country", "ZAF"),
        ("country", "Z1"),
        ("country", ""),
        ("protocol", "TCP"),
        ("protocol", "gre"),
        ("protocol", "tcp,udp"),
        ("direction", "sideways"),
        ("direction", "unknown"),
        ("device", ""),
        ("device", " "),
        ("device", "x" * 129),
        ("device", "edge\u0000rtr"),
        ("device", "edge\nrtr"),
        ("application", "Zoom\u202e"),  # right-to-left override
        ("application", "a" * 129),
    ],
)
def test_a_value_outside_the_allow_list_is_refused(name: str, value: str) -> None:
    with pytest.raises(FilterError) as caught:
        parse(**{name: value})
    assert caught.value.field == name
    # The refusal names the filter, never the value that was sent.
    assert value.strip() == "" or value not in str(caught.value)


@pytest.mark.parametrize(
    "value",
    ["'; DROP TABLE flows; --", "a' OR '1'='1", "Zoom\\", '"quoted"', "50% off", "日本語 アプリ"],
)
def test_text_filters_carry_special_characters_as_data(value: str) -> None:
    assert parse(application=value).application == value
    assert parse(device=value).device == value


def test_text_is_stripped_but_otherwise_kept() -> None:
    assert parse(application="  Zoom  ").application == "Zoom"


def test_the_boundaries_are_inclusive() -> None:
    filters = parse(vlan="4094", port="65535", asn="4294967295")
    assert (filters.vlan, filters.port, filters.asn) == (4094, 65535, 4294967295)
    assert parse(vlan="0", port="0", asn="1").vlan == 0


def test_a_filter_outside_the_allow_list_is_refused_not_ignored() -> None:
    with pytest.raises(FilterError):
        parse_filters({"user": "alice"})
    with pytest.raises(FilterError):
        parse_filters({"source_ip": "10.0.0.1", "sort": "bytes"})


def test_repeated_parameters_are_refused() -> None:
    with pytest.raises(FilterError):
        reject_unknown_parameters([("port", "80"), ("port", "443")], frozenset({"port"}))


def test_unknown_parameter_names_are_refused_without_echoing_them() -> None:
    with pytest.raises(FilterError) as caught:
        reject_unknown_parameters([("evil<script>", "1")], frozenset({"preset"}))
    assert "evil" not in str(caught.value)
    assert caught.value.field == "parameter"


def test_known_parameters_pass() -> None:
    reject_unknown_parameters([("preset", "1h"), ("limit", "5")], frozenset({"preset", "limit"}))


def test_oversized_input_is_refused_cheaply() -> None:
    with pytest.raises(FilterError):
        parse(application="x" * 100_000)


def test_the_parser_never_mutates_its_input() -> None:
    params: Mapping[str, str] = {"port": "443"}
    parse_filters(params)
    assert params == {"port": "443"}
