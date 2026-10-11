# Inventory, IPAM and the unknown-device workflow (Step 8, E03)

Status: implemented 2026-10-11 (uncommitted on `main`). Contracts: `contracts/json-schema/{inventory,ipam,unknown-devices}.schema.json`
plus `$defs/sourceStatus` in `common.schema.json`; OpenAPI paths under `/api/v1/inventory`, `/api/v1/ipam`, `/api/v1/unknown-devices`;
shared vectors `contracts/test-vectors/{inventory,ipam,unknown-devices}.vectors.json`.

**PRD reference.** The brief for this step cites PRD sections 44-46. The PRD in the repository ends around section 40, so those sections do
not exist. The sections that carry the requirements are 8 (asset classes), 9 (inventory and IPAM), 14 (unknown devices), 22 and 35 (reconcile
and NetBox as the source of truth). Nothing was built from a section that is not in the PRD.

## Principles

* **NetBox is authoritative for intended state.** Without NetBox there are no inventory rows and no IPAM rows; the response is
  `not-connected` (not configured) or `unknown` (configured, read failed) and carries no count.
* **Every value is source-reported or explicitly Unknown / not-connected.** Nothing is estimated. A count that could not be read is `null`,
  never `0`. Utilisation is computed by one rule and always carries its basis.
* **Per-field provenance** on name, site, IP and MAC: `netbox`, `discovered`, `both` (the sources agree) or `conflict` (they disagree: the
  NetBox value is shown and both readings are returned).
* **Nothing is written to NetBox or any network system.** All adapters are read-only. A quarantine is a PROPOSED record; no execution path
  exists (Step 14, the action engine, owns execution).
* **Untrusted text** (names, roles, descriptions, hostnames, comments) is returned as data and rendered as text nodes.

## Inventory (`GET /api/v1/inventory`, `/inventory/summary`, `/inventory/{id}`)

* **Classes:** network-device, server, access-point, endpoint, cctv, printer, iot, plus two the system decides: `unclassified` (a NetBox
  asset the map does not name) and `unknown-asset` (seen by telemetry, absent from NetBox). The class comes only from the operator map and
  its basis (`role-map`, `type-map`, `unmapped`, `not-in-netbox`) is returned.
* **Class map:** `NETSIGHT_INVENTORY_CLASS_MAP_FILE` (path) or `NETSIGHT_INVENTORY_CLASS_MAP` (inline JSON), at most 64 KiB, duplicate keys
  refused:

  ```json
  {"version": 1,
   "roles": {"core-switch": "network-device", "wifi-ap": "access-point"},
   "device_types": {"camera-x": "cctv"}}
  ```

  Keys are lower-case NetBox slugs, matched exactly (role first, then device type). A document that does not validate is `invalid` and
  classifies nothing (half a map is never applied): every asset is `unclassified`.
* **Joins.** NetBox <-> LibreNMS by the existing reconcile `match_key` (the same key the reconcile findings use). Two candidates for one
  key are `ambiguous` and are never merged. Wazuh agents join only through a NetBox custom field named by
  `NETSIGHT_NETBOX_WAZUH_AGENT_FIELD`; without it Wazuh is `not-connected` for inventory rather than guessed by name.
* **Reconcile status** comes from the existing reconcile findings, not a second engine.
* **Filters** (server side, strict: unknown or repeated parameters are 422): `asset_class`, `site`, `status`, `source`
  (`netbox`/`discovered`/`both`), `known`, `q`; page size is bounded (default 25, maximum 100).
* **Sources.** Every response lists NetBox, LibreNMS and Wazuh with `ok` / `not-connected` / `unknown` and the time observed. A source that
  was not read is named in the UI; the page never implies completeness.

## IPAM (`GET /api/v1/ipam`, `/ipam/prefixes`, `/ipam/vlans`, `/ipam/addresses`)

* **Prefix tree** by containment per (VRF, address family). Parent, depth and child count are computed from NetBox prefixes only.
* **Utilisation** = used addresses over capacity. Capacity: IPv4 usable hosts (a /31 is 2, a /32 is 1, a prefix marked `is_pool` counts the
  whole range); IPv6 only when it has at most 16 host bits, otherwise the capacity is **not meaningful** and utilisation is `unknown`
  (`capacity-not-meaningful`). Used = NetBox addresses plus addresses telemetry saw that NetBox does not list (`netbox-and-discovered`), or
  NetBox addresses alone when telemetry could not be read (`netbox-addresses`). A prefix NetBox marks `mark_utilized` is reported as
  `marked-utilized` (the operator declaring it full). Percent is an integer, half-up, capped at 100.
* **Reserved ranges** are NetBox IP ranges with status `reserved`; they are listed under their prefix and reduce `free`.
* **Active versus stale** (`activity` on each address): `active` = a telemetry source saw it within the window; `stale` = NetBox lists it,
  telemetry was readable and did not see it; `unknown` = telemetry could not be read (never stale); `reserved`. The window is
  `NETSIGHT_IPAM_STALE_WINDOW_HOURS` (1-168, default 24, **a default pending an owner decision**). Telemetry witnesses are LibreNMS device addresses and Wazuh agent
  addresses (last keep-alive inside the window); a source that is not connected is simply not a witness and is named in the response.
* **Bounded.** Each dataset (prefixes, VLANs, addresses) is paged separately and fails independently: a VLAN read failure does not hide the
  prefix tree.

## Unknown devices (`/api/v1/unknown-devices`)

* **Detection.** A scan collects endpoints from telemetry (IP, MAC, hostname), compares each with NetBox (IP assignment, interface MAC,
  device name) and makes a finding only when every check was made and none matched. If NetBox could not be asked about an endpoint it is
  counted as `unverified` and **no finding is raised** (a failed lookup is not evidence of an unknown device). At most 500 candidate endpoints and 100 MAC lookups per scan (the rest are `unverified` and the scan says it was truncated).
* **Evidence chain** (IP, MAC, switch or access point, port, VLAN): each hop is `observed`, `inferred` or `unknown`. Only links a source
  actually reported are values; every other hop is `unknown` with a reason (`no-evidence`, `source-unavailable`, ...). The Step 6 identity
  engine's evidence model (`EvidenceRecord`, `Relation`, `Basis`, `CorrelationPolicy`) is reused for attachment, port and VLAN. In production
  today no adapter reads switch MAC tables, DHCP leases or Wi-Fi controllers, so attachment, port and VLAN are `source-unavailable` until
  those adapters exist.
* **Severity** comes only from the operator policy (`NETSIGHT_UNKNOWN_DEVICE_POLICY_FILE` or `_POLICY`): first matching rule over CIDRs and
  observed VLANs, else the default; no policy means `unknown` severity and no quarantine recommendation. `quarantine_recommended_at` is a
  threshold for a recommendation record, nothing more.
* **Lifecycle** `new -> acknowledged -> investigating -> resolved | false-positive` (resolve or dismiss from any open state), enforced in
  the API, in the store and again in PostgreSQL by triggers and CHECK constraints. A finished finding is final; a later sighting of a
  resolved endpoint makes a new finding that points at the earlier one (`recurrence_of`); a false-positive suppresses later sightings of the
  same endpoint.
* **Storage.** Migration `0006_unknown_device_findings` creates `unknown_device_findings` and the append-only `unknown_device_events`
  (timeline). One open finding per endpoint is enforced by a partial unique index; an advisory lock per subject serialises writers; row locks
  guard transitions. The events table rejects `UPDATE`/`DELETE`/`TRUNCATE` for every role including the owner (trigger `ENABLE ALWAYS`).
  The `down` migration is guarded: the migrator refuses it while either table holds rows unless `NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1` is set. App-role grants are in `storage/grants/app_role.sql`. An in-memory
  repository backs the tests and the no-database mode (state then reads `not-connected`).
* **Writes** (acknowledge, investigate, assign, comment, resolve, scan) are human-only: authenticate, authorise (audited), CSRF and origin,
  step-up (resolve only), per-identity rate limit (60/min; scan 6/min). The audit record carries counts and names, never free text.
* **Scheduled scan** is off by default: `NETSIGHT_UNKNOWN_DEVICE_SCAN_ENABLED=true` and `NETSIGHT_UNKNOWN_DEVICE_SCAN_INTERVAL_SECONDS`
  (300-86400). A PostgreSQL advisory lock stops several workers scanning at once.
* **Proposed action.** A finding at or above the policy threshold carries `proposed_action` = `endpoint.isolate`, state `proposed`, risk
  class C, `executable: false` (a constant in every schema), `awaiting: action-engine`. The UI labels it "Quarantine proposed, not executed".
  There is no endpoint, button or code path that isolates anything.

## Routes and limits

| Route | Permission | Limit |
|---|---|---|
| `GET /inventory`, `/inventory/{id}`, `/inventory/summary` | `inventory:read` (rows), `inventory:read-summary` (counts) | 60 / 120 / 60 per min |
| `GET /ipam/prefixes`, `/vlans`, `/addresses`; `GET /ipam` | `ipam:read` (rows), `ipam:read-summary` (counts) | 60 / 60 per min |
| `GET /unknown-devices`, `/{id}`, `/{id}/timeline`, `/summary` | `unknown-devices:read` / `:read-summary` | 120 / 120 / 120 / 60 per min |
| `POST /unknown-devices/{id}/acknowledge`, `/investigate`, `/assign`, `/comment`, `/resolve` | `unknown-devices:acknowledge`, `:assign`, `:comment`, `:resolve` | 60 per min |
| `POST /unknown-devices/scan` | `unknown-devices:scan` | 6 per min |

Roles: see RBAC-MATRIX "Inventory, IPAM and unknown-device permissions (Step 8)".

## Configuration (all optional; unset means the feature reports Unknown or not-connected)

| Variable | Meaning |
|---|---|
| `NETSIGHT_INVENTORY_CLASS_MAP_FILE` / `NETSIGHT_INVENTORY_CLASS_MAP` | Role/type -> class map (above). |
| `NETSIGHT_NETBOX_WAZUH_AGENT_FIELD` | NetBox custom field holding the Wazuh agent id; the only Wazuh join. |
| `NETSIGHT_IPAM_STALE_WINDOW_HOURS` | Stale window, 1-168, default 24. |
| `NETSIGHT_UNKNOWN_DEVICE_POLICY_FILE` / `_POLICY` | Severity policy (above). |
| `NETSIGHT_UNKNOWN_DEVICE_SCAN_ENABLED` / `_SCAN_INTERVAL_SECONDS` | Scheduled scan (off by default; 300-86400 s). |

Operator documents are read with one `open` plus `fstat`, bounded to 64 KiB, with duplicate keys refused. An invalid document fails closed.

## UI

`/inventory`, `/inventory/[deviceId]`, `/ipam`, `/unknown-devices`, `/unknown-devices/[findingId]`; sidebar entries gated by the summary
permissions. Every list has the full state matrix (loading, empty, filtered-empty, not-connected, unknown, permission, unauthenticated,
rate-limited, error, partial sources). Provenance, state and severity are word plus icon, never colour alone. Management sees counts cards
and no rows. Workflow actions use the existing write-UI patterns (server action, same-origin check, CSRF added server-side, 409/422/429/503
handling, step-up link, unconfirmed-result lock). Verified by jsdom component tests, typecheck, lint and `next build`; no browser run.

## Known limits (deferrals)

* No DHCP, switch-FDB/ARP or Wi-Fi controller adapters: attachment, port and VLAN hops are Unknown in production until added.
* NetBox, LibreNMS and Wazuh response shapes are verified by mock transport only; no live NetBox was available.
* LibreNMS contributes "up now" only; there is no history, so "seen within the window" means "reported by LibreNMS at read time".
* No automatic resolution or reopening; undoing a false positive is a manual step.
* The scan response does not list per-source evidence states.
* No retention or prune for findings and events (decision pending, see DATA-RETENTION-MATRIX).
* No real-process end-to-end test of the new pages.

## Rollback

Unregister the `inventory`, `ipam` and `unknown_device` routers in `main.py` and remove the lifespan scan hook; revert the three
menu entries and pages. Contract rollback is the previous `common.schema.json`/OpenAPI (the new files are additive). Data rollback:
`0006_unknown_device_findings.down.sql` (destructive; needs `NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1` while rows exist; take a backup first). Unset the
variables above to return every feature to Unknown.
