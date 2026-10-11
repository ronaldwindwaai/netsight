"""WAN link configuration (Step 5): operator-declared, strict, fail closed.

Netsight never guesses which interface is a WAN link, who the ISP is or what the gateway is: the
operator declares it. Configured values are labelled as configured, never as telemetry.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from netsight_api.wan.config import (
    MAX_LINKS,
    SamplingSettings,
    load_wan_links,
)


def link(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "fibre-1",
        "name": "Primary fibre",
        "role": "primary",
        "isp": "Example ISP",
        "gateway": "192.0.2.1",
        "librenms_device": "12",
        "librenms_port": "345",
        "probe_targets": ["probe-a.example", "198.51.100.7"],
        "probe_location": "branch",
        "dns_target": "dns-check.example",
        "uptime_target_pct": 99.5,
    }
    base.update(overrides)
    return base


def load(*links: dict[str, Any]) -> Any:
    return load_wan_links({"NETSIGHT_WAN_LINKS": json.dumps(list(links))})


def test_unset_or_blank_means_not_connected_never_a_guess() -> None:
    assert load_wan_links({}).state == "not-connected"
    assert load_wan_links({"NETSIGHT_WAN_LINKS": "  "}).state == "not-connected"
    assert load_wan_links({"NETSIGHT_WAN_LINKS": "[]"}).state == "not-connected"


def test_a_valid_declaration_is_loaded_with_every_field() -> None:
    config = load(link(), link(id="lte-1", name="Backup LTE", role="backup", isp=None))
    assert config.state == "ok"
    primary, backup = config.links
    assert (primary.id, primary.role, primary.isp, primary.gateway) == (
        "fibre-1",
        "primary",
        "Example ISP",
        "192.0.2.1",
    )
    assert primary.librenms_device == "12" and primary.librenms_port == "345"
    assert primary.probe_targets == ("probe-a.example", "198.51.100.7")
    assert primary.probe_location == "branch" and primary.uptime_target_pct == 99.5
    assert backup.role == "backup" and backup.isp is None


def test_optional_fields_may_be_absent_and_become_none() -> None:
    config = load({"id": "wan-x", "name": "X", "role": "primary"})
    only = config.links[0]
    assert only.isp is None and only.gateway is None and only.librenms_device is None
    assert only.probe_targets == () and only.probe_location is None and only.dns_target is None
    assert only.uptime_target_pct is None


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "{}",
        '"x"',
        "[1]",
        "[null]",
        "[" + "{" * 5000 + "]",
    ],
)
def test_malformed_json_is_configured_but_unusable(raw: str) -> None:
    assert load_wan_links({"NETSIGHT_WAN_LINKS": raw}).state == "unknown"


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "Bad Id"},
        {"id": ""},
        {"id": "a" * 49},
        {"id": "-leading"},
        {"name": ""},
        {"name": "   "},
        {"name": "x" * 129},
        {"name": "line\nbreak"},
        {"role": "secondary"},
        {"role": None},
        {"isp": "x" * 129},
        {"isp": 5},
        {"gateway": "not-an-ip"},
        {"gateway": "192.0.2.0/24"},
        {"gateway": "gw.example"},
        {"librenms_device": "12", "librenms_port": None},
        {"librenms_device": None, "librenms_port": "3"},
        {"librenms_device": "../x", "librenms_port": "3"},
        {"librenms_device": "1", "librenms_port": "a/b"},
        {"librenms_device": 12, "librenms_port": "3"},
        {"probe_targets": "probe-a.example"},
        {"probe_targets": ["http://x.example"]},
        {"probe_targets": ["*.example"]},
        {"probe_targets": [""]},
        {"probe_targets": ["a"] * 9},
        {"probe_location": "mars"},
        {"dns_target": "bad host"},
        {"uptime_target_pct": 0},
        {"uptime_target_pct": 100.5},
        {"uptime_target_pct": "99"},
        {"uptime_target_pct": True},
        {"uptime_target_pct": float("nan")},
        {"surprise": 1},
    ],
)
def test_any_invalid_field_makes_the_whole_declaration_unusable(bad: dict[str, Any]) -> None:
    config = load(link(), {**link(id="other", name="Other", role="backup"), **bad})
    assert config.state == "unknown"
    assert config.links == ()


def test_duplicate_ids_and_two_primaries_are_refused() -> None:
    assert load(link(), link(role="backup")).state == "unknown"
    assert load(link(), link(id="second", name="Second")).state == "unknown"  # two primaries


def test_a_backup_only_declaration_is_allowed_and_the_count_is_bounded() -> None:
    assert load(link(role="backup")).state == "ok"
    many = [link(id=f"b{n}", name=f"B{n}", role="backup") for n in range(MAX_LINKS + 1)]
    assert load(*many).state == "unknown"
    assert load(*many[:MAX_LINKS]).state == "ok"


def test_the_failure_is_logged_without_the_configured_content(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_ish = "gateway-192.0.2.77-token-abc"
    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        load(link(isp=secret_ish, gateway="nope"))
    assert caplog.records
    assert secret_ish not in caplog.text and "nope" not in caplog.text


def test_the_loaded_links_are_immutable() -> None:
    config = load(link())
    with pytest.raises(AttributeError):
        config.links[0].name = "changed"  # type: ignore[misc]
    assert isinstance(config.links, tuple)


# --- sampling settings ----------------------------------------------------------------------------


def test_sampling_is_off_by_default_and_the_flag_is_strict() -> None:
    assert SamplingSettings.from_env({}) == SamplingSettings(enabled=False, interval_seconds=60)
    assert SamplingSettings.from_env({"NETSIGHT_WAN_SAMPLING_ENABLED": "true"}).enabled is True
    assert SamplingSettings.from_env({"NETSIGHT_WAN_SAMPLING_ENABLED": "off"}).enabled is False
    with pytest.raises(ValueError, match="NETSIGHT_WAN_SAMPLING_ENABLED"):
        SamplingSettings.from_env({"NETSIGHT_WAN_SAMPLING_ENABLED": "maybe"})


@pytest.mark.parametrize("value", ["29", "301", "abc", "1.5", "-60"])
def test_the_interval_is_bounded_and_an_invalid_value_is_an_error_not_a_default(
    value: str,
) -> None:
    with pytest.raises(ValueError, match="NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS"):
        SamplingSettings.from_env({"NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS": value})


def test_the_interval_bounds_are_inclusive() -> None:
    for seconds in (30, 300):
        parsed = SamplingSettings.from_env({"NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS": str(seconds)})
        assert parsed.interval_seconds == seconds
