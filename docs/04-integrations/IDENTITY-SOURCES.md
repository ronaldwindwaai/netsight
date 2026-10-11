# Identity Sources

Authentication providers:
- Microsoft Entra ID
- Google Workspace

Operational identity correlation may additionally use:
- AD/Entra directory;
- RADIUS/802.1X;
- VPN;
- DHCP;
- DNS;
- Wi-Fi controllers;
- endpoint inventory.

Each correlation carries source, timestamp and confidence.

## What is wired (Step 6)
| Source | State |
|---|---|
| Wazuh agent inventory (`endpoint-agent`: device <-> IP) | wired, read-only, via the existing indexer client (`WAZUH_INDEXER_*`, `WAZUH_AGENTS_INDEX`); not verified against a live Wazuh |
| NetBox assignments (`asset-assignment`: contact -> device, static interface address -> device) | wired, read-only, via the existing NetBox client (`NETBOX_*`, `NETSIGHT_NETBOX_OWNER_ROLES`); not verified against a live NetBox |
| DHCP, RADIUS/802.1X, VPN, Wi-Fi controller, switch MAC table, DNS, Entra/Google directory and sign-in logs | **not wired**; the `EvidenceSource` interface and evidence kinds exist; only these can produce *observed* identity |

Each correlation carries source, timestamp (observed, valid from/to) and confidence; see `docs/12-implementation/IDENTITY-CORRELATION.md`.
