# Identity Correlation (NS-043, PRD 10, 19-20, 36, 92)

Status: Step 6 implemented (framework, two read-only adapters, API and UI). Everything below says what is built and, as plainly, what is not.

## Problem
IP addresses change; devices are shared; users have multiple devices; NAT/VPN obscures identity. Netsight must model
**Person -> Account -> Device -> IP -> MAC -> Switch/AP -> Port -> VLAN** and **never present an uncertain correlation as fact**. An IP address alone is
never proof of identity.

## The model

### Evidence in, links out
Sources do not assert whole chains. Each source emits `EvidenceRecord`s: one or a few *relations* between two entities, for a validity window, with the
source's own confidence.

| Field | Meaning |
|---|---|
| `source`, `native_id` | who said it and what they track (a lease, a session). The same pair arriving again supersedes the earlier one (a session-stop replaces its open start) |
| `kind` | `dhcp-lease`, `radius-session`, `vpn-session`, `wifi-association`, `switch-mac-table`, `endpoint-agent`, `directory-account`, `idp-signin`, `dns-record`, `asset-assignment` |
| `observed_at` | when Netsight's source saw it |
| `valid_from`, `valid_to` | the window it speaks for. `valid_to = null` means no end was recorded: the engine trusts it only for the kind's *open TTL* after `observed_at` |
| `confidence` | 0..1, the source's own |
| `assertions` | the relations (`ip-mac`, `account-mac`, `person-account`, ...) between canonical entities |
| `guest` | the source says the endpoint is a guest/BYOD one |

A kind may only assert the relations it is declared for (`KIND_PROFILES`): an IdP sign-in cannot assert a MAC binding however the record is phrased.
A kind is **direct** (the source observed the relation) or **indirect** (a declaration or a weak association: `idp-signin`, `dns-record`,
`asset-assignment`). An indirect kind can never produce `observed`.

Entities are canonical and typed: `person-<uuid>`, `account-<uuid>`, `device-<uuid>` (a switch and an AP are devices), `port-<uuid>`, `vlan-<n>`, an IP in its one
canonical spelling (no zone id, IPv4-mapped IPv6 is the IPv4), a lower-case colon MAC, a lower-case hostname. **A person is never keyed by an e-mail address or a
display name** (ids are minted per source from the source's own id); a label is untrusted display text.

### Links, basis, time
Every output link carries `basis`, `confidence`, the validity window it holds for, the `as_of` time it was computed, the evidence list and, unless observed, a
`reason`.

| Basis | Meaning | Invariants (enforced in the domain type, pydantic, JSON Schema and the TS parser) |
|---|---|---|
| `observed` | a direct source (confidence >= 0.8) saw it, unique, in its window | target, confidence, window, >= 1 evidence; no reason |
| `inferred` | a declaration, a weak association, a low-confidence direct record, a name match, or a contested link | confidence capped at **0.7**; a reason; evidence |
| `unknown` | the evidence does not establish it | no target, no confidence, no window; a reason; `ambiguous` with **>= 2 candidates** when sources conflict (the engine never picks one) |

A chain is as strong as its **weakest hop** (basis is the minimum, confidence the minimum of the hop confidences, the window the intersection). Time is half-open:
`[valid_from, effective_end)`. An expired session ends the link; the answer says `expired` when the chain would have held at some other time, so the operator can tell
"never seen" from "no longer true".

### The rules that keep it honest (all tested in `tests/test_identity_engine.py`, 73 tests)
- **IP is not identity.** The walk from an address reaches a person only through an *account* (RADIUS/VPN/sign-in) or an *assignment*. An address with only a lease is
  `ip-only`; a device with no account is never a person.
- **DHCP churn / reuse over time.** Whoever held the address *at that instant*; the gap between two leases is `expired`, not the previous holder.
- **Overlapping leases for one address are ambiguous, never picked,** and the contest is shown from both ends: from the MAC's side the lease is downgraded to
  `inferred` / `conflicting-evidence`.
- **Shared PCs.** Used in turn: attributed by time. Used at once (two accounts on one MAC, two assigned owners): `ambiguous`, both listed.
- **Multiple devices per user.** One session per device; a disputed account has no confirmed session for anyone.
- **NAT.** Public, documentation, CGNAT and configured NAT-egress addresses are *shared*: never an identity and never a bridge between endpoints
  (`NETSIGHT_IDENTITY_SHARED_CIDRS`; an organisation's own public block is declared with `NETSIGHT_IDENTITY_INTERNAL_CIDRS`).
- **VPN.** A VPN pool address (`NETSIGHT_IDENTITY_VPN_CIDRS`) is identity only through a VPN session (`vpn-no-session` otherwise); a sign-in that disagrees with the
  VPN session is a conflict.
- **Guest / BYOD.** A guest address (`..._GUEST_CIDRS`), guest VLAN (`..._GUEST_VLANS`) or a record flagged `guest` is never attributed to a person.
  **Deployment prerequisite:** the engine cannot learn which ranges are guest or shared. A guest or NAT network that is not listed in `NETSIGHT_IDENTITY_GUEST_CIDRS` /
  `_GUEST_VLANS` / `_SHARED_CIDRS` is treated like any other internal range, so a person could be attributed on it. Fill these in before anyone relies on an answer.
- **Server / static ranges.** An agent's claim to an address inside `NETSIGHT_IDENTITY_STATIC_CIDRS` is ignored (see "Wazuh and NetBox about one host" below).
- **Attachments are never bridges.** A port, VLAN, switch or AP carries many endpoints; the walk never crosses one.
- **Mixed strengths.** Observed Alice plus an *assigned* owner Bob: Alice observed, Bob listed as inferred; nothing is hidden. Equal strength: ambiguous.
- **Deterministic and bounded.** Evidence is de-duplicated and sorted first; shuffling it changes nothing. At most 5 000 records (more is refused, not truncated).
- **Silence from a failed source is `source-unavailable`**, not `no-evidence`.

### Wazuh and NetBox about one host: what can and cannot be attributed
The two sources name the same machine differently (a Wazuh *agent id*, a NetBox *device id*), so they mint **different device entities**, and an address belongs to one device at
a time (`device-ip` is exclusive on the address side). Consequences, stated plainly:

- **Without an explicit key the two never join.** An address that Wazuh says belongs to agent `001` and NetBox says belongs to device `12` is `conflicting-evidence`: the engine
  will not guess they are the same host. The answer is at most `inferred` (capped 0.7) and carries the reason `conflicting-evidence`; it is never `observed`, and never a pick
  among differing people. **With only Wazuh and NetBox and no key, Netsight cannot confirm that the owner of a registered device is the one using the address the agent reports.**
  NetBox alone still gives `inferred` / `declared-assignment` (register intent); Wazuh alone gives a device, never a person.
- **Not by name.** A hostname, a NetBox device name or a Wazuh agent name is text the monitored host or an editor chooses; a rogue agent can call itself `CEO-LAPTOP`. Names never
  merge devices. (A *hostname lookup* still matches devices by name as an `inferred` / `name-match` at 0.5 and cites only the device's network records, never the
  person-device record.)
- **The only join is an operator-controlled key.** Create a NetBox **device** custom field (text) and put the Wazuh agent id in it exactly as Wazuh shows it (for example `001`);
  set `NETSIGHT_NETBOX_WAZUH_AGENT_FIELD=<field name>` (lower-case letters, digits, underscore). A keyed NetBox device is minted as the agent's device, so the registered owner and the
  agent's address meet on one entity and the address resolves as `inferred` / `declared-assignment`. Agent ids are assigned by the Wazuh manager, not chosen by the agent. If one
  agent id appears on two NetBox devices, **neither** is joined (and a warning is logged); an unusable value is skipped. If the field is unset, invalid or absent on a device, that
  device is simply not joined (fails safe). A failed read of the field fails the NetBox source (`unknown`), not silently un-joined. The filter `cf_<field>__empty=false` is not verified
  against a live NetBox.
- **A rogue agent reporting a registered address.** An agent can claim any address. Inside `NETSIGHT_IDENTITY_STATIC_CIDRS` (servers, static assignments) an `endpoint-agent`
  claim is ignored entirely, so it cannot weaken the register's attribution. Outside those ranges the claim is a visible conflict (the victim's attribution becomes
  `conflicting-evidence`, never the rogue's); **list the static/server ranges as a deployment prerequisite**. The rogue device itself never receives a person.

## Storage decision (c): compute on read, nothing persisted
Correlations are Netsight application state in principle (DATABASE-OWNERSHIP lists "identity correlations"), but they are *derived* from evidence the sources
already hold, and DATABASE-OWNERSHIP warns against "an uncontrolled second telemetry lake". So this step **persists nothing and adds no migration (no 0006)**:
a request gathers a bounded snapshot (<= 2 500 records per source, <= 5 000 in all, a 24 h evidence window, 15 s per source), runs the pure engine and maps the result.
A snapshot for "now" is cached for 30 s in process (one entry, shared by concurrent requests) so a search box cannot hammer Wazuh and NetBox; a question about a
past time is never cached. Consequences, stated rather than hidden:

- **History is only as long as the sources' own.** "Who had this IP on Tuesday" works up to 7 days back *if the sources still answer for that time*. NetBox answers with
  current state (an assignment holds from its `last_updated`; a deleted assignment leaves no trace). **A past-time answer that rests on the register says so**: the response
  carries `notes: ["register-is-current-state"]` and the UI shows it. PRD/IDENTITY-CORRELATION earlier said "preserve historical
  correlation for incident reconstruction": that is **not** met beyond the sources' retention. Meeting it needs a persisted, append-only correlation history
  (migration 0006) and a retention decision. **Human decision needed** (see DATA-RETENTION-MATRIX).
- **Scale.** 5 000 evidence records is the design bound; a source with more fails closed (`unknown`). A larger estate needs query-by-subject adapters or a persisted index.
- **Per-worker cache.** Like the rate limiter, the cache is per process. The people computation (the heaviest step) runs once per snapshot in a worker thread and is shared by the
  list, the detail and the summary; list and summary report `as_of` the snapshot time (at most 30 s old).
- **History cannot be cached, so it is guarded.** A question about a past time spends a global budget (20 per minute across all identities) and holds one of 2 concurrent read
  slots; over either it is refused (429 `RATE_LIMITED` / 503 `IDENTITY_BUSY`) and audited. Per worker process.

## Adapters (b)
Read-only, bounded, fail closed; unconfigured is `not-connected`, a failure is `unknown`. The interface is `EvidenceSource` (`identity/sources.py`): `fetch(start, end, limit)`
returning `EvidenceBatch`; a source may only emit records stamped with its own name and the kinds it declares; truncation, an oversized batch, a timeout or any exception
makes that source `unknown` (a partial list hides conflicts, so it is never presented as an answer).

| Source | Evidence | Wired? |
|---|---|---|
| **Wazuh agent inventory** (`identity/wazuh_source.py`, `WazuhIndexerClient.agents`) | `endpoint-agent`: device (by agent id, never name) <-> IP. Reads the monitoring index (`WAZUH_AGENTS_INDEX`, default `wazuh-monitoring-*`; `wazuh-` prefix enforced), collapsed per agent, `size = limit + 1` to detect truncation. TLS verify on, redirects refused, 8 MiB cap, https required with credentials (same client as the alerts read). **A malformed agent row (unknown status, bad timestamp, an unusable address) is skipped and counted (logged), not fatal; if most rows are malformed the read fails** | yes, mock-transport tested; **field names follow Wazuh 4.x and are not verified against a live Wazuh** |
| **NetBox assignments** (`identity/netbox_source.py`, `NetboxClient.ip_assignments/contact_assignments`) | `asset-assignment`: contact -> device (only roles in `NETSIGHT_NETBOX_OWNER_ROLES`, default `Owner,User`) and static interface address -> device. Same-origin pagination, <= 10 pages (more is a failure), 8 MiB response cap (declared length and bytes read), `Accept-Encoding: identity`. A malformed row is skipped and counted, not fatal (mostly-malformed fails the read). An optional device custom field carrying the Wazuh agent id (`NETSIGHT_NETBOX_WAZUH_AGENT_FIELD`) is the only join to the Wazuh device | yes, mock-transport tested; **response shapes follow NetBox 3.x/4.x and are not verified against a live NetBox** |
| `MemoryEvidenceSource` | any kind, fixed records | tests, and the model for later adapters |
| DHCP, RADIUS/802.1X, VPN, Wi-Fi controller, switch MAC table (LibreNMS FDB), DNS, Entra/Google directory and sign-in logs | the engine and kinds exist | **not wired**: no API in the repo, and a vendor integration that cannot be tested is not invented |

With only Wazuh and NetBox configured the product is honest about how little it knows: NetBox contacts appear as people with *assigned* devices (inferred), there are no
sessions (nothing observes who is on the network), and an address resolves to an assigned owner at best as `inferred` / `declared-assignment`, and only when the NetBox device is
keyed to the agent or no agent reports the address (otherwise `conflicting-evidence`; see above). Real "observed" answers need the RADIUS/VPN/directory adapters.

## API (d)
| Route | Permission | Notes |
|---|---|---|
| `GET /api/v1/users?page&page_size` | `users:read` | people known to the evidence, paged (<= 100/page, <= 1000 pages) |
| `GET /api/v1/users/{id}` | `users:read` | profile, accounts, assigned devices, sessions, traffic and security blocks; 404 for an unknown person |
| `GET /api/v1/users/summary` | `users:read-summary` | counts only (no names, no identifiers) |
| `GET /api/v1/identity/resolve?ip=\|mac=\|hostname=[&at=]` | `users:read` or `users:read-limited` | exactly one subject; `at` within the last 7 days |

Every response is validated against its canonical schema; `not-connected` / `unknown` carry no values. RBAC and the human-only rule are in RBAC-MATRIX. The limited rung
gets the endpoint (device, MAC, port, VLAN) with the person withheld (`restricted`) and the source's own record ids replaced by opaque stable ids: an **HMAC-SHA-256 under a server
secret** (`NETSIGHT_IDENTITY_ID_KEY`, at least 32 characters; an unkeyed hash of a guessable id would be a membership oracle). Without a key the limited rung gets `unknown` (fail
closed); only `NETSIGHT_ENV=development` generates a per-process key (logged once; ids change on restart). A native id can embed a user name; found by a test, fixed. Rate limits (per identity, after authorisation): list/detail 120/min, summary 60/min, **resolve 30/min** (the scraping vector).
`Cache-Control: no-store` on every per-user response, error responses included (API middleware for `/users*` and `/identity/*`).

**Audit (PRD 92).** `identity.users.list`, `identity.user.read`, `identity.resolve` record the actor, the target (a person id; for resolve `ip:<fingerprint>` /
`mac:<fingerprint>` / `hostname:<fingerprint>`, where the fingerprint is the audit module's short SHA-256 and **never the raw address, MAC or hostname**), the state and *counts* (results, identified persons disclosed, whether the answer was redacted, whether it was historical): never a name, an e-mail
address, a signature or any free text, and no purpose field (purpose-free by design). Denied attempts are audited (`reason=permission`, including `identity.summary` and a denied detail with its person id); so are 429s
(`reason=rate-limited`, or `global-limit` / `busy` for history) and rejected resolve input (422, `outcome=failure`, `reason=subject-count|invalid-subject|invalid-time`, nothing
echoed); an unreadable source is a `failure`. A successful aggregate is not per-user data and is not audited. Audit is still the interim JSON-lines sink (AUDIT-LOGGING.md).

## UI (e)
`/users` and `/users/[userId]`, sidebar entry gated by `users:read-summary`. There is **no approved design** for Users & Identity (DESIGN-INVENTORY "design gap"); the layout
follows SCREEN-SPECS ("Identity confidence, current devices/IPs, activity, traffic, security, history") and the incident user card in the Incident Detail design, using only
fields a source provides (no department, manager, MFA or "At Risk": none is data). Every correlation shows a basis badge (word + icon), its reason in words, confidence,
validity window, an *as of* time and an evidence drill-down; an ambiguous result lists every candidate and says none is selected. The full state matrix is covered:
loading, empty, not-connected, unknown, partial (named sources), stale (named sources), permission, unauthenticated, rate limited, error, not found. Untrusted text is rendered
as data (hostile-markup tests). The lookup is a plain GET form validated before it reaches an API path. Traffic (inferred, by address, 1 h, only where the link covers the window;
an unlisted address is "not listed", never zero) and security (events matched to a person only when the address was attributed to them *at the time of the event*) appear only
when those sources are connected. **No behaviour section**: there is no baseline data (NS-044 unbuilt).

## Not built / follow-ups
Persisted correlation history and its retention; the skipped-row count in the API (it is logged only); worker-shared global limits; DHCP/RADIUS/VPN/Wi-Fi/switch-table/DNS/IdP adapters; Wazuh syscollector (MACs, logged-in users) and NetBox interface MACs;
live Wazuh/NetBox verification; a Playwright run of the Users pages against a real stack; source-specific supersede rules (a DHCP release/new offer should end the old lease in
the adapter); site scoping and "Basic"/"Technician-assigned" narrowing; overview Users KPI; search-box integration of `/identity/resolve`; a shared (non per-worker) cache and limiter.

## Human decisions needed
1. Retention and persistence of identity history (none is stored; see above) and who may prune.
2. The RBAC reading in RBAC-MATRIX (Network Engineer holds `users:read`; Technician only the limited rung; Management only the aggregate; **Auditor none**).
3. The TTLs and thresholds (open-session trust: RADIUS/VPN/Wi-Fi/MAC table 15 min, DHCP 1 h, agent 30 min, sign-in 30 min, directory/assignment 24 h; "observed" >= 0.8; inferred cap 0.7).
4. Which NetBox contact roles mean "uses this device" (default `Owner,User`), and **whether to adopt the NetBox custom field that carries the Wazuh agent id** (without it the two
   sources conflict on every shared host) and who may edit it (anyone who can write that field can join a device to an agent).
5. The network classification (NAT egress, VPN pools, guest ranges/VLANs, internal public blocks, **server/static ranges**) for the real estate: a deployment prerequisite.
6. Whether a privacy/legal review is required before any non-Admin role browses people (PRD 92: policy before broad user surveillance features).
7. The evidence-id secret (`NETSIGHT_IDENTITY_ID_KEY`): provisioning and rotation (rotating changes every opaque id).

## Used by the Flow Explorer (Step 7)

`IdentityService.resolve_many(now, [(address, time), ...])` answers a bounded batch (<= 500 distinct questions) from the shared 30 s "now"
snapshot, off the event loop. The Flow Explorer (`traffic/attribution.py`) asks about each flow's *source address at the time the flow was
seen* and maps the answer without strengthening it: one person => `observed` / `inferred` with the engine's reason and confidence; several
persons or an ambiguous answer => `unknown` / `multiple-candidates` (nobody is picked); the `users:read-limited` level => the device and
`restricted` (the person is withheld); a flow older than the 24 h evidence window => `source-unavailable` (the sources were not asked about
that time, so "no evidence" would be false). The caller's `users:read` / `users:read-limited` decides the level; a role with neither never
reaches the service. The flow store's own user column is not used.

## Rollback
Unregister `identity_router` in `main.py` and drop the Users menu entry; nothing was persisted, there is no schema change. Unset `WAZUH_INDEXER_URL` / `NETBOX_*` to return the
sources to `not-connected`.
