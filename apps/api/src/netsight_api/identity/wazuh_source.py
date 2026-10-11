"""Wazuh agent inventory as identity evidence (read-only, via the existing indexer client).

What an agent proves: a device (identified by the Wazuh agent id, never by its name) was reporting
from an address. That is ``endpoint-agent`` evidence for the relation device <-> IP. It never names a
person, and it does not know the device's MAC addresses (the monitoring index does not carry them),
so a Wazuh agent alone can only ever answer "which device was at this address".

Unwired on purpose: Wazuh's own syscollector inventory (MACs, logged-in users) is not read here;
adding it needs a live Wazuh to verify the field names against.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Protocol

from netsight_api.adapters.wazuh import AdapterError, AdapterStatus, AgentInventory, WazuhAgent
from netsight_api.identity.model import (
    KIND_PROFILES,
    Assertion,
    EvidenceKind,
    EvidenceRecord,
    Relation,
    device_ref,
    ip_ref,
)
from netsight_api.identity.sources import EvidenceBatch

SOURCE_NAME = "wazuh"
# The manager sees the agent's address as it connected: right for a flat network, shared behind NAT
# (which the correlation policy then refuses to treat as identity). Below "certain" on purpose.
AGENT_CONFIDENCE = 0.85
_NOT_REPORTING = frozenset({"never_connected", "pending"})


class AgentReader(Protocol):
    async def agents(self, *, start: datetime, end: datetime, limit: int) -> AgentInventory: ...


def _record(agent: WazuhAgent) -> EvidenceRecord | None:
    """The agent's evidence, or None when it says nothing usable (no address, never connected)."""
    if agent.status in _NOT_REPORTING or agent.ip is None:
        return None
    try:
        endpoint = ip_ref(agent.ip)
    except ValueError as error:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "agent address is invalid") from error
    address = ipaddress.ip_address(endpoint.id)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return None
    ttl = KIND_PROFILES[EvidenceKind.ENDPOINT_AGENT].open_ttl
    keep_alive = agent.last_keep_alive
    valid_from = (
        keep_alive
        if keep_alive is not None and keep_alive <= agent.observed_at
        else agent.observed_at
    )
    valid_to: datetime | None = None
    if agent.status != "active":
        if keep_alive is None:
            return None  # disconnected and never seen alive: no moment to vouch for
        valid_to = keep_alive + ttl  # the evidence has an end, in the past
    device = device_ref(SOURCE_NAME, agent.agent_id, agent.name)
    return EvidenceRecord(
        source=SOURCE_NAME,
        native_id=f"agent-{agent.agent_id}",
        kind=EvidenceKind.ENDPOINT_AGENT,
        observed_at=agent.observed_at,
        valid_from=valid_from,
        valid_to=valid_to,
        confidence=AGENT_CONFIDENCE,
        assertions=(Assertion(device, Relation.DEVICE_IP, endpoint),),
    )


class WazuhAgentSource:
    name = SOURCE_NAME
    kinds = frozenset({EvidenceKind.ENDPOINT_AGENT})

    def __init__(self, client: AgentReader) -> None:
        self._client = client

    async def fetch(self, *, start: datetime, end: datetime, limit: int) -> EvidenceBatch:
        inventory = await self._client.agents(start=start, end=end, limit=limit)
        records: list[EvidenceRecord] = []
        skipped = inventory.skipped
        for agent in inventory.agents:
            try:
                record = _record(agent)
            except (AdapterError, ValueError):
                skipped += 1  # one agent with an unusable address says nothing; it blanks nothing
                continue
            if record is not None:
                records.append(record)
        if skipped > len(inventory.agents) + inventory.skipped - skipped:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "most agent rows are unusable")
        return EvidenceBatch(tuple(records), truncated=inventory.truncated, skipped=skipped)
