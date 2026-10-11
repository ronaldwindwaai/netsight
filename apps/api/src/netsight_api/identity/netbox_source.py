"""NetBox assignments as identity evidence (read-only, via the existing NetBox client).

NetBox records intent: a contact is assigned to a device, an address is assigned to an interface.
That is ``asset-assignment`` evidence, an *indirect* kind: it can make a link ``inferred`` and never
``observed``, because a register says who a device is meant for, not who is using it now. Two owners
of one device are two candidates (an ambiguity), never a silent pick.

Only contacts whose role is configured as a user of the device count (``NETSIGHT_NETBOX_OWNER_ROLES``,
default ``Owner,User``): NetBox roles are free text, and a vendor-support contact must not become
"the person behind this PC". Persons are minted from the NetBox contact id; a contact's name is a
display label only, never a key.

**Joining a NetBox device to its Wazuh agent.** The two sources name a host differently (the NetBox
device id, the Wazuh agent id) and an address has one device at a time, so without a join the same
host conflicts with itself. The only join is an explicit key an operator controls: a NetBox *device*
custom field (``NETSIGHT_NETBOX_WAZUH_AGENT_FIELD``) holding the Wazuh agent id exactly as Wazuh
shows it (for example ``001``). A keyed device is minted as the agent's device, so the register's
owner and the agent's address meet on one entity. A hostname, a device name or an agent name never
joins anything: they are text a monitored host chooses. With no field configured, or no value on
the device, or one value claimed by two devices, the devices stay separate and the answer stays
``conflicting-evidence``.

Unwired on purpose: NetBox interface MAC addresses (the field moved between NetBox 4.1 and 4.2 and
is not verified here), and any live NetBox check.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from netsight_api.adapters.netbox import (
    AGENT_KEY_PATTERN,
    CUSTOM_FIELD_NAME,
    ContactAssignmentCollection,
    DeviceAgentKeyCollection,
    IpAssignmentCollection,
)
from netsight_api.identity.model import (
    Assertion,
    EntityRef,
    EvidenceKind,
    EvidenceRecord,
    Relation,
    device_ref,
    ip_ref,
    person_ref,
)
from netsight_api.identity.sources import EvidenceBatch

SOURCE_NAME = "netbox"
DEFAULT_OWNER_ROLES = frozenset({"owner", "user"})
OWNER_ROLES_ENV = "NETSIGHT_NETBOX_OWNER_ROLES"
AGENT_FIELD_ENV = "NETSIGHT_NETBOX_WAZUH_AGENT_FIELD"
AGENT_SOURCE = "wazuh"
_LOGGER = logging.getLogger("netsight_api")
# A register entry is trustworthy intent, below "certain"; the engine caps the link at 0.7 anyway.
ASSIGNMENT_CONFIDENCE = 0.9


class AssignmentReader(Protocol):
    async def ip_assignments(self) -> IpAssignmentCollection: ...

    async def contact_assignments(self) -> ContactAssignmentCollection: ...

    async def device_agent_keys(self, field_name: str) -> DeviceAgentKeyCollection: ...


def owner_roles_from_env(raw: str) -> frozenset[str]:
    """Configured role names (case-insensitive, comma-separated); empty means the default."""
    roles = frozenset(part.strip().lower() for part in raw.split(",") if part.strip())
    return roles or DEFAULT_OWNER_ROLES


def agent_key_field_from_env(raw: str) -> str | None:
    """The configured device custom-field name; None (no join) when unset or not a valid name."""
    name = raw.strip()
    if not name:
        return None
    if CUSTOM_FIELD_NAME.fullmatch(name) is None:
        _LOGGER.warning("netbox agent-key field is invalid; devices will not be joined to agents")
        return None
    return name


def _unique_keys(keys: DeviceAgentKeyCollection) -> dict[str, str]:
    """device id -> agent id, dropping every device whose agent id another device also claims."""
    claims = Counter(item.agent_key for item in keys.items)
    ambiguous = {key for key, count in claims.items() if count > 1}
    if ambiguous:
        _LOGGER.warning(
            "netbox agent key claimed by several devices", extra={"count": len(ambiguous)}
        )
    return {
        item.device_native_id: item.agent_key
        for item in keys.items
        if item.agent_key not in ambiguous and AGENT_KEY_PATTERN.fullmatch(item.agent_key)
    }


class NetboxAssignmentSource:
    name = SOURCE_NAME
    kinds = frozenset({EvidenceKind.ASSET_ASSIGNMENT})

    def __init__(
        self,
        client: AssignmentReader,
        owner_roles: frozenset[str] = DEFAULT_OWNER_ROLES,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        agent_key_field: str | None = None,
    ) -> None:
        self._client = client
        self._agent_key_field = agent_key_field
        self._owner_roles = frozenset(role.lower() for role in owner_roles)
        self._clock = clock

    async def fetch(self, *, start: datetime, end: datetime, limit: int) -> EvidenceBatch:
        # NetBox answers with current state, so the window is not used: an assignment holds from its
        # last update (NetBox does not say when one was deleted; see IDENTITY-CORRELATION.md).
        contacts, addresses, keys = await asyncio.gather(
            self._client.contact_assignments(), self._client.ip_assignments(), self._keys()
        )
        read_at = (
            self._clock()
        )  # when Netsight saw the register, which is what the evidence vouches for
        records: list[EvidenceRecord] = []
        for contact in contacts.items:
            if contact.role is None or contact.role.lower() not in self._owner_roles:
                continue
            person = person_ref(
                SOURCE_NAME, f"contact-{contact.contact_native_id}", contact.contact_name
            )
            device = self._device(keys, contact.device_native_id, contact.device_name)
            records.append(
                self._record(
                    f"owner-{contact.contact_native_id}-{contact.device_native_id}",
                    Assertion(person, Relation.PERSON_DEVICE, device),
                    read_at,
                    contact.last_updated,
                )
            )
        for address in addresses.items:
            device = self._device(keys, address.device_native_id, address.device_name)
            records.append(
                self._record(
                    f"ip-{address.address}-{address.device_native_id}",
                    Assertion(device, Relation.DEVICE_IP, ip_ref(address.address)),
                    read_at,
                    address.last_updated,
                )
            )
        records.sort(key=lambda record: record.native_id)
        skipped = contacts.skipped + addresses.skipped
        return EvidenceBatch(
            tuple(records[:limit]), truncated=len(records) > limit, skipped=skipped
        )

    async def _keys(self) -> dict[str, str]:
        if self._agent_key_field is None:
            return {}
        return _unique_keys(await self._client.device_agent_keys(self._agent_key_field))

    @staticmethod
    def _device(keys: dict[str, str], native_id: str, label: str | None) -> EntityRef:
        """The device entity: the agent's when an operator keyed it, otherwise NetBox's own."""
        agent_id = keys.get(native_id)
        if agent_id is not None:
            return device_ref(AGENT_SOURCE, agent_id, label)
        return device_ref(SOURCE_NAME, native_id, label)

    @staticmethod
    def _record(
        native_id: str, assertion: Assertion, observed_at: datetime, last_updated: datetime | None
    ) -> EvidenceRecord:
        valid_from = (
            last_updated
            if last_updated is not None and last_updated <= observed_at
            else observed_at
        )
        return EvidenceRecord(
            source=SOURCE_NAME,
            native_id=native_id,
            kind=EvidenceKind.ASSET_ASSIGNMENT,
            observed_at=observed_at,
            valid_from=valid_from,
            valid_to=None,
            confidence=ASSIGNMENT_CONFIDENCE,
            assertions=(assertion,),
        )
