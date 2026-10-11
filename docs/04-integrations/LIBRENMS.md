# LibreNMS Integration

Purpose: network discovery, devices, interfaces, health, alerts, switching/routing/inventory.

Rules:
- adapter owns `/api` version details;
- read token by default;
- send API tokens using `Authorization: Bearer`; `X-Auth-Token` is retained by
  LibreNMS API v0 only for backwards compatibility and is not used by Netsight;
- SNMP credentials never pass through browser;
- map source IDs to canonical device/interface IDs;
- capture source freshness and errors;
- configure `LIBRENMS_TIMEZONE` with the source's IANA timezone so legacy API
  timestamps without an offset can be normalized to UTC; ambiguous or invalid
  local times fail closed rather than being guessed;
- contract-test devices, ports, alerts and topology-related data.

WAN port reading (Step 5, `wan_port`; see `docs/12-implementation/INTERNET-WAN.md`): for an operator-declared device and port the adapter reads
`GET /api/v0/devices/{id}/ports` (status, link speed, `ifInOctets_rate` and `ifOutOctets_rate` in octets per second converted to bits per second, and the
source's own `poll_time` as the counters' freshness) and `GET /api/v0/ports/{port_id}/ip` (the public IPv4 only when the port has exactly one globally routable
address). A missing, malformed or negative value is `null`, never zero; a failing address lookup loses only the address; identifiers are validated path-safe.
Confirm on the real instance that the ports list carries those columns.

Initial endpoints/capabilities to implement: device list/detail, ports/interfaces, alert list, inventory/health and network-neighbour data where available.

For FS-001, list uses `GET /api/v0/devices` and detail uses LibreNMS
`get_device` at `GET /api/v0/devices/:hostname`, passing the source-native
device ID resolved from the canonical device's `source_aliases` entry.
