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

Initial endpoints/capabilities to implement: device list/detail, ports/interfaces, alert list, inventory/health and network-neighbour data where available.

For FS-001, list uses `GET /api/v0/devices` and detail uses LibreNMS
`get_device` at `GET /api/v0/devices/:hostname`, passing the source-native
device ID resolved from the canonical device's `source_aliases` entry.
