"""The operator's NetBox role/type -> asset class map (Step 8a).

Netsight never decides what an asset is. The operator names a NetBox role slug or device-type slug
and the class it means; anything the map does not name is ``unclassified``, an asset NetBox does not
know is ``unknown-asset`` (decided elsewhere), and a map that does not validate classifies nothing
(fail closed: half a map is never applied).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsight_api.inventory.classmap import (
    CLASS_MAP_ENV,
    CLASS_MAP_FILE_ENV,
    MAX_ENTRIES,
    ClassMap,
    load_class_map,
)

VALID = {
    "version": 1,
    "roles": {"core-switch": "network-device", "web-server": "server", "wifi-ap": "access-point"},
    "device_types": {"u6-pro": "access-point", "camera-x": "cctv"},
}


def inline(document: object) -> ClassMap:
    return load_class_map({CLASS_MAP_ENV: json.dumps(document)})


def test_no_map_configured_classifies_nothing() -> None:
    class_map = load_class_map({})
    assert class_map.state == "not-configured"
    assert class_map.classify("core-switch", "u6-pro") == ("unclassified", "unmapped")


def test_a_role_maps_to_its_class_and_says_so() -> None:
    class_map = inline(VALID)
    assert class_map.state == "configured"
    assert class_map.classify("core-switch", None) == ("network-device", "role-map")


def test_a_device_type_is_used_when_the_role_is_not_mapped() -> None:
    assert inline(VALID).classify("unlisted-role", "camera-x") == ("cctv", "type-map")
    assert inline(VALID).classify(None, "u6-pro") == ("access-point", "type-map")


def test_the_role_wins_over_the_type_when_both_are_mapped() -> None:
    assert inline(VALID).classify("web-server", "u6-pro") == ("server", "role-map")


def test_an_unmapped_asset_is_unclassified_never_guessed() -> None:
    class_map = inline(VALID)
    assert class_map.classify("mystery", "other") == ("unclassified", "unmapped")
    assert class_map.classify(None, None) == ("unclassified", "unmapped")


def test_lookup_is_case_insensitive_on_the_slug_but_exact_otherwise() -> None:
    class_map = inline(VALID)
    assert class_map.classify("Core-Switch", None)[0] == "network-device"
    # No prefix or substring matching: a look-alike slug borrows nothing.
    assert class_map.classify("core-switch-2", None) == ("unclassified", "unmapped")
    assert class_map.classify("core", None) == ("unclassified", "unmapped")


@pytest.mark.parametrize(
    "document",
    [
        {"version": 2, "roles": {}},
        {"roles": {"a": "server"}},
        {"version": 1, "roles": {"a": "unknown-asset"}},
        {"version": 1, "roles": {"a": "unclassified"}},
        {"version": 1, "roles": {"a": "toaster"}},
        {"version": 1, "roles": {"A B": "server"}},
        {"version": 1, "roles": {"": "server"}},
        {"version": 1, "roles": {"a" * 101: "server"}},
        {"version": 1, "roles": ["a"]},
        {"version": 1, "roles": {"a": 5}},
        {"version": 1, "extra": {}},
        {"version": 1, "device_types": {"x": "server"}, "roles": "no"},
        [],
        "text",
        5,
    ],
)
def test_an_invalid_map_is_invalid_and_classifies_nothing(document: object) -> None:
    class_map = inline(document)
    assert class_map.state == "invalid"
    assert class_map.classify("a", "x") == ("unclassified", "unmapped")


def test_half_a_map_is_never_applied() -> None:
    document = {"version": 1, "roles": {"core-switch": "network-device", "bad": "toaster"}}
    class_map = inline(document)
    assert class_map.state == "invalid"
    assert class_map.classify("core-switch", None) == ("unclassified", "unmapped")


def test_duplicate_keys_are_refused() -> None:
    raw = '{"version": 1, "roles": {"a": "server", "a": "iot"}}'
    assert load_class_map({CLASS_MAP_ENV: raw}).state == "invalid"


def test_malformed_json_is_invalid() -> None:
    assert load_class_map({CLASS_MAP_ENV: "{not json"}).state == "invalid"


def test_too_many_entries_is_invalid() -> None:
    roles = {f"role-{i}": "server" for i in range(MAX_ENTRIES + 1)}
    assert inline({"version": 1, "roles": roles}).state == "invalid"


def test_a_file_is_read_and_validated(tmp_path: Path) -> None:
    path = tmp_path / "classes.json"
    path.write_text(json.dumps(VALID), encoding="utf-8")
    class_map = load_class_map({CLASS_MAP_FILE_ENV: str(path)})
    assert class_map.state == "configured"
    assert class_map.classify("wifi-ap", None) == ("access-point", "role-map")


def test_a_missing_or_oversized_or_directory_file_is_invalid(tmp_path: Path) -> None:
    assert load_class_map({CLASS_MAP_FILE_ENV: str(tmp_path / "nope.json")}).state == "invalid"
    assert load_class_map({CLASS_MAP_FILE_ENV: str(tmp_path)}).state == "invalid"
    big = tmp_path / "big.json"
    big.write_text(" " * (70 * 1024) + json.dumps(VALID), encoding="utf-8")
    assert load_class_map({CLASS_MAP_FILE_ENV: str(big)}).state == "invalid"


def test_naming_both_a_file_and_inline_json_is_ambiguous_and_invalid(tmp_path: Path) -> None:
    path = tmp_path / "classes.json"
    path.write_text(json.dumps(VALID), encoding="utf-8")
    env = {CLASS_MAP_FILE_ENV: str(path), CLASS_MAP_ENV: json.dumps(VALID)}
    assert load_class_map(env).state == "invalid"


def test_blank_settings_mean_not_configured() -> None:
    assert load_class_map({CLASS_MAP_ENV: "  ", CLASS_MAP_FILE_ENV: ""}).state == "not-configured"


def test_a_hostile_slug_in_a_lookup_is_just_no_match() -> None:
    class_map = inline(VALID)
    assert class_map.classify("<script>", "' OR 1=1 --") == ("unclassified", "unmapped")
