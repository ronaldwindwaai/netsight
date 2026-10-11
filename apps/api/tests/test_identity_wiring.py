"""Environment wiring for the identity sources and the correlation policy.

Unset is ``not-connected`` (a slot with no source); a set-but-unusable value never silently widens
what is read. Nothing here opens a connection: the adapters are constructed, not called.
"""

from __future__ import annotations

import pytest

from netsight_api import identity_routes
from netsight_api.adapters.netbox import NetboxClient
from netsight_api.adapters.wazuh import WazuhIndexerClient
from netsight_api.identity.model import CorrelationPolicy
from netsight_api.identity.netbox_source import (
    DEFAULT_OWNER_ROLES,
    NetboxAssignmentSource,
    owner_roles_from_env,
)
from netsight_api.identity.wazuh_source import WazuhAgentSource

ENV = (
    "WAZUH_INDEXER_URL",
    "WAZUH_INDEXER_USER",
    "WAZUH_INDEXER_PASSWORD",
    "WAZUH_INDEXER_CA_BUNDLE",
    "WAZUH_INDEXER_ALLOW_HTTP",
    "WAZUH_ALERTS_INDEX",
    "WAZUH_AGENTS_INDEX",
    "NETBOX_BASE_URL",
    "NETBOX_TOKEN",
    "NETSIGHT_NETBOX_OWNER_ROLES",
    "NETSIGHT_NETBOX_WAZUH_AGENT_FIELD",
    "NETSIGHT_IDENTITY_STATIC_CIDRS",
    "NETSIGHT_ENV",
    "NETSIGHT_IDENTITY_SHARED_CIDRS",
    "NETSIGHT_IDENTITY_INTERNAL_CIDRS",
    "NETSIGHT_IDENTITY_VPN_CIDRS",
    "NETSIGHT_IDENTITY_GUEST_CIDRS",
    "NETSIGHT_IDENTITY_GUEST_VLANS",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    identity_routes._policy_for.cache_clear()


def slots_by_name() -> dict[str, object]:
    return {slot.name: slot.source for slot in identity_routes.get_identity_slots()}


def test_nothing_configured_leaves_every_slot_empty_and_named() -> None:
    slots = identity_routes.get_identity_slots()
    assert [slot.name for slot in slots] == ["wazuh", "netbox"]
    assert all(slot.source is None for slot in slots)


def test_a_wazuh_indexer_makes_the_agent_source_with_the_default_monitoring_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example.test:9200")
    source = slots_by_name()["wazuh"]
    assert isinstance(source, WazuhAgentSource)
    client = source._client
    assert isinstance(client, WazuhIndexerClient)
    assert client.agents_index_pattern == "wazuh-monitoring-*"
    assert client.index_pattern == "wazuh-alerts-*"  # the alerts read keeps its own index


def test_the_agents_index_is_configurable_and_the_credentials_never_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example.test:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "svc")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "hunter2-not-real")
    monkeypatch.setenv("WAZUH_AGENTS_INDEX", "wazuh-monitoring-site-*")
    source = slots_by_name()["wazuh"]
    assert isinstance(source, WazuhAgentSource)
    client = source._client
    assert client.agents_index_pattern == "wazuh-monitoring-site-*"
    assert "hunter2" not in repr(client)


def test_netbox_configuration_makes_the_assignment_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETBOX_BASE_URL", "https://netbox.example.test")
    monkeypatch.setenv("NETBOX_TOKEN", "not-a-real-token")
    source = slots_by_name()["netbox"]
    assert isinstance(source, NetboxAssignmentSource)
    assert isinstance(source._client, NetboxClient)


def test_a_netbox_url_without_a_token_is_not_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETBOX_BASE_URL", "https://netbox.example.test")
    assert slots_by_name()["netbox"] is None


def test_owner_roles_default_to_owner_and_user_and_are_case_insensitive() -> None:
    assert owner_roles_from_env("") == DEFAULT_OWNER_ROLES
    assert owner_roles_from_env("  ") == DEFAULT_OWNER_ROLES
    assert owner_roles_from_env("Primary User, Assigned ,,") == frozenset(
        {"primary user", "assigned"}
    )


def test_the_policy_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_IDENTITY_SHARED_CIDRS", "10.9.9.0/24, 10.9.10.0/24")
    monkeypatch.setenv("NETSIGHT_IDENTITY_INTERNAL_CIDRS", "198.51.100.0/24")
    monkeypatch.setenv("NETSIGHT_IDENTITY_VPN_CIDRS", "10.200.0.0/16")
    monkeypatch.setenv("NETSIGHT_IDENTITY_GUEST_CIDRS", "192.168.99.0/24")
    monkeypatch.setenv("NETSIGHT_IDENTITY_GUEST_VLANS", "99, 100")
    policy = identity_routes.get_policy()
    assert policy == CorrelationPolicy(
        shared_cidrs=("10.9.9.0/24", "10.9.10.0/24"),
        internal_cidrs=("198.51.100.0/24",),
        vpn_cidrs=("10.200.0.0/16",),
        guest_cidrs=("192.168.99.0/24",),
        guest_vlans=(99, 100),
    )
    assert (
        policy is not None and policy.is_shared("10.9.9.7") and not policy.is_shared("198.51.100.9")
    )


def test_the_default_policy_treats_public_and_cgnat_addresses_as_shared() -> None:
    policy = identity_routes.get_policy()
    assert policy is not None
    for shared in ("8.8.8.8", "203.0.113.9", "100.64.0.1", "2001:db8::1"):
        assert policy.is_shared(shared), shared
    for own in ("10.0.0.1", "172.16.5.5", "192.168.1.1", "fd00::1", "169.254.1.1"):
        assert not policy.is_shared(own), own


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("NETSIGHT_IDENTITY_SHARED_CIDRS", "not-a-cidr"),
        ("NETSIGHT_IDENTITY_VPN_CIDRS", "10.0.0.0/99"),
        ("NETSIGHT_IDENTITY_GUEST_VLANS", "5000"),
        ("NETSIGHT_IDENTITY_GUEST_VLANS", "abc"),
    ],
)
def test_an_unusable_policy_is_none_never_a_silent_default(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    assert identity_routes.get_policy() is None


def test_one_shared_cache_serves_every_request() -> None:
    assert identity_routes.get_snapshot_cache() is identity_routes.get_snapshot_cache()


def test_without_an_agent_field_the_register_is_not_joined_to_agents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETBOX_BASE_URL", "https://netbox.example.test")
    monkeypatch.setenv("NETBOX_TOKEN", "not-a-real-token")
    source = slots_by_name()["netbox"]
    assert isinstance(source, NetboxAssignmentSource)
    assert source._agent_key_field is None


def test_the_agent_field_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETBOX_BASE_URL", "https://netbox.example.test")
    monkeypatch.setenv("NETBOX_TOKEN", "not-a-real-token")
    monkeypatch.setenv("NETSIGHT_NETBOX_WAZUH_AGENT_FIELD", "wazuh_agent_id")
    source = slots_by_name()["netbox"]
    assert isinstance(source, NetboxAssignmentSource)
    assert source._agent_key_field == "wazuh_agent_id"


def test_an_unusable_agent_field_means_no_join_never_a_guess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETBOX_BASE_URL", "https://netbox.example.test")
    monkeypatch.setenv("NETBOX_TOKEN", "not-a-real-token")
    monkeypatch.setenv("NETSIGHT_NETBOX_WAZUH_AGENT_FIELD", "Wazuh Agent; DROP")
    source = slots_by_name()["netbox"]
    assert isinstance(source, NetboxAssignmentSource)
    assert source._agent_key_field is None


def test_the_static_ranges_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_IDENTITY_STATIC_CIDRS", "10.0.0.0/28, 10.9.0.0/24")
    policy = identity_routes.get_policy()
    assert policy is not None and policy.static_cidrs == ("10.0.0.0/28", "10.9.0.0/24")
    assert policy.is_static_address("10.9.0.7") and not policy.is_static_address("10.9.1.7")


def test_an_invalid_static_range_makes_the_policy_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_IDENTITY_STATIC_CIDRS", "10.0.0.0/99")
    assert identity_routes.get_policy() is None
