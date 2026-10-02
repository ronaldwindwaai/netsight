# LibreNMS Integration

Purpose: network discovery, devices, interfaces, health, alerts, switching/routing/inventory.

Rules:
- adapter owns `/api` version details;
- read token by default;
- SNMP credentials never pass through browser;
- map source IDs to canonical device/interface IDs;
- capture source freshness and errors;
- contract-test devices, ports, alerts and topology-related data.

Initial endpoints/capabilities to implement: device list/detail, ports/interfaces, alert list, inventory/health and network-neighbour data where available.
