# Default RBAC Matrix

| Capability | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| Overview | Full | Full | Full | Full | Summary | Read |
| Devices | Full | Full | Read | Operational | Summary | Read |
| Traffic | Full | Full | Full | Limited | Summary | Read |
| Security | Full | Read | Full | Limited | Summary | Read |
| Incidents | Full | Full | Full | Assigned | Summary | Read |
| Alert rules | Full | Scoped | Scoped | No | No | Read |
| Diagnostics | Full | Full | Security scope | Basic | No | No |
| Internet / WAN | Full | Full | Read | Read | Summary | Read |
| WAN evidence export | Yes | Yes | No | No | No | Yes |
| Config history | Full | Full | Read | Read | No | Read |
| Propose action | Yes | Scoped | Scoped | Limited | No | No |
| Approve high risk | Policy | Policy | Policy | No | No | No |
| Execute high risk | Policy | Policy | Policy | No | No | No |
| Integrations | Full | No | No | No | No | Read |
| IAM/RBAC | Full | No | No | No | No | Read |
| Audit | Full | Scoped | Scoped | Own/assigned | Summary | Full |
| Users & identity (not in the original matrix; see below) | Full | Full | Full | Endpoint only | Aggregate only | **No** |

Production roles must be mapped to least privilege and may be site-scoped.

The **Traffic** row is split into two permissions (aggregates; endpoint rows) in "Traffic permissions (Step 7)" below.

## Incident permissions (S6-2)

Backend enforcement lives in `apps/api/src/netsight_api/rbac.py`; unknown roles and permissions are denied.

| Permission | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| `incidents:read` (list, detail, timeline) | Yes | Yes | Yes | Yes | **No** | Yes |
| `incidents:read-summary` (`GET /incidents/summary`: reduced rows only) | Yes | Yes | Yes | Yes | Yes | Yes |
| `incidents:transition` (acknowledge, investigate, mitigate, close) | Yes | Yes | Yes | No | No | No |
| `incidents:assign` | Yes | Yes | Yes | No | No | No |
| `incidents:comment` (comment, evidence reference) | Yes | Yes | Yes | No | No | No |
| `incidents:resolve` (human principals only) | Yes | Yes | Yes | No | No | No |
| `incidents:reopen` (human principals only) | Yes | Yes | Yes | No | No | No |
| `incidents:write-assigned` (acknowledge/investigate/mitigate, comment, evidence on incidents assigned to the caller; never close, assign, resolve or reopen) | Yes | No | No | Yes | No | No |

Human-only: `resolve` and `reopen` record a root cause or reopen reason. They are denied to any identity whose
`principal` is not `human` (service accounts, the AI copilot), whatever role it carries. Only an interactive
server-side session yields a human principal. Technician "Assigned" is enforced for writes, inside the store under
the incident row lock; reading incidents is not yet narrowed to assigned incidents (open decision).

### Management: summary-only incident view (human decision, 2026-10-10)

Management holds `incidents:read-summary` and **no longer holds `incidents:read`**. Every other role that reads
incidents holds both (the summary is a strict subset of what the full read returns). `GET /api/v1/incidents/summary`
returns `IncidentSummary` rows: `id`, `title`, `severity`, `state`, `created_at`, `updated_at`, `assigned` (a boolean),
`resolved_at`. It never returns evidence ids, the resolution record (summary, root cause, impact, follow-ups, resolver
identity), timeline events, comments or the assignee identity, and it has no assignee filter (that would let a reader
probe who holds an incident). Management receives 403 on `GET /incidents`, `/incidents/{id}` and `/incidents/{id}/timeline`.
`title` is the one operator/alert-authored text field Management still sees (the headline); see the open decision in
BUILD-PLAN Step 3.

### Step-up authentication (human decision, 2026-10-10)

`incidents:resolve` and `incidents:reopen` additionally require a second factor proven within
`NETSIGHT_STEP_UP_MAX_AGE_SECONDS` (default 900, valid 1-86400; an invalid value is a startup/request error, never "off").
The session stores the time of the second factor itself on the session store's clock (never the session creation time) and the
age is checked against the window on every resolve/reopen. An unknown time fails closed: local sign-in stamps age 0 after a
verified TOTP or recovery code; an OIDC sign-in is stamped only when the verified token lists `mfa` in `amr` **and** carries a
numeric `auth_time` that is not in the future (beyond a 5 s skew), not older than the window and, for a step-up, later than the
moment the step-up was requested (so an older token cannot be replayed). A rejected assertion still signs the user in, unstamped,
and is audited as `auth.mfa` / `denied` with reason `auth-time-missing`, `auth-time-invalid`, `auth-time-stale`,
`auth-time-future` or `step-up-replay`. The refusal is `403 STEP_UP_REQUIRED`, distinct from `FORBIDDEN`, decided after
authorisation and CSRF/origin (so a role without the permission learns nothing about MFA recency) and before the rate
limit, and is audited as `denied` with reason `step-up`. The development identity bridge (development only, no session)
is exempt. Re-authentication is a fresh sign-in: `GET /auth/login/{provider}?step_up=true` asks the provider for
`prompt=login&max_age=0`; the local password and TOTP flow always proves a fresh second factor.

## Alert-rule and maintenance permissions (S6-3)

Backend enforcement lives in `apps/api/src/netsight_api/rbac.py`; unknown roles and permissions are denied.
"Scoped" in the matrix means site-scoped; site scoping does not exist yet, so the scoped roles may author, disable and
schedule site-level maintenance but never approve a rule or silence the whole organisation. Note that "silence the
whole organisation" is enforced on two axes, not one: `maintenance:write-organisation` is required both for a window
whose **scope** is `organisation` *and* for any window whose **evaluation** is `disable`, whatever its scope kind
(a site-scope `disable` window stops rule evaluation entirely and is therefore gated like an organisation window).

| Permission | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| `alert-rules:read` (list, get, dry-run) | Yes | Yes | Yes | No | No | Yes |
| `alert-rules:write` (create, edit a draft) | Yes | Yes | Yes | No | No | No |
| `alert-rules:approve` (activate the reviewed version) | Yes | No | No | No | No | No |
| `alert-rules:disable` | Yes | Yes | Yes | No | No | No |
| `maintenance:read` | Yes | Yes | Yes | No | No | Yes |
| `maintenance:write` (create / cancel below organisation scope) | Yes | Yes | Yes | No | No | No |
| `maintenance:write-organisation` (organisation scope **or** `evaluation: disable`, at any scope) | Yes | No | No | No | No | No |

All five write permissions are human-only (`HUMAN_ONLY_PERMISSIONS`): no service or AI principal may change monitoring
configuration, whatever role it carries. Management has "No" for alert rules in the matrix and therefore no alert-rule or
maintenance access (its incident access is the summary view above). Decisions for S6-3, recorded 2026-10-10: the creator of
a rule **may** approve it (no four-eyes rule; today's behaviour is kept and the approval is audited with the approver's
identity; the approval dialog states this when the approver is the creator). Still open: whether technicians should see
maintenance windows (the matrix says nothing, so denied).

### Step-up scope for alert rules and maintenance (decision record, 2026-10-10)

Step-up (a recent second factor, see above) applies to **incident resolve and reopen only**. Alert-rule approve and disable, rule
create/edit and maintenance-window create/cancel are **deliberately outside step-up**: each is authorised by its own permission,
human-only, CSRF- and origin-checked, rate-limited and audited with the actor, and approval is bound to the version the approver saw
(`expected_version`), so a stale or concurrent edit cannot be activated by mistake. Extending step-up to `alert-rules:approve` /
`alert-rules:disable` (the highest-impact alerting actions) is an open product decision, not an oversight; if it is taken, add
`step_up=True` to those two writer dependencies and a `STEP_UP_REQUIRED` case to the UI (the shared `WriteFeedback` already renders it).

## Session permissions for the UI

`GET /api/v1/auth/session` returns `permissions`: the sorted permission names the session's roles hold (derived from the same
`is_allowed` the routes use). The web UI uses it only to enable, disable and explain controls and to choose the summary or
full incident surface. It is advisory: the API enforces every permission, scope, state, CSRF/origin and step-up rule on each
request, and the UI shows the API's refusal (409 conflict, 422, 503, 403 `STEP_UP_REQUIRED`) if the page was stale.

## Diagnostic permissions (S7 Step 4)

One permission, `diagnostics:read`, governs starting a read-only run (`POST /diagnostics`, which also needs CSRF and the run rate limit), listing stored sessions (`GET /diagnostics`) and reading one (`GET /diagnostics/{id}`). No role can change or delete a session: there is no such route and the database refuses it.

| Permission | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| `diagnostics:read` (run, list, read a session) | Yes | Yes | Yes (see scoping) | Yes ("Basic", see scoping) | **No** | **No** |

**Decision record (2026-10-11, code and matrix now agree; fixes security review finding H1).** Until this pass `rbac.py` granted `diagnostics:read` to every role while the matrix row says Management and Auditor have no Diagnostics access. The grant is narrowed to the matrix: Management and Auditor receive `403 FORBIDDEN` on all three routes (the run is audited as a `permission` refusal), the web menu hides Diagnostics for a session without the permission and `/diagnostics` renders an access-denied surface without calling the API. Reason: a session names targets and devices and references incidents, and Management lost `incidents:read` by human decision (above), so it must not reach incident information through a diagnostic either.

"Security scope" (Security Analyst) and "Basic" (Technician) are not yet distinct: no site or security scoping exists and there is no reduced run surface, so those roles hold the same read-only diagnostics permission as Full roles. This is recorded as an open decision (what "Basic" removes: free-text symptom, stored-session history of others, a reduced check set), not as an implemented restriction. Sessions are still not scoped per owner or per site: any holder can read any session.

**Incident titles (second control, independent of the role table).** A stored session keeps an incident change only as a reference (`id`, `kind`, `severity`, `time`) and never its title; the database refuses a document that carries one. `GET /diagnostics/{id}` joins the current title at read time **only for a caller who holds `incidents:read` at that moment**; any other caller, an unreadable incident store and a missing incident all get the fixed placeholder (`title_redacted: true`). The `POST /diagnostics` response carries the run only (no change items), so it never carries an incident title. Alert titles are stored (every diagnostics role holds `alerts:read`).

## Internet / WAN permissions (Step 5)

Three permissions; no role can change anything (there is no write route). Fail closed: unknown roles, no identity and unknown
permission names are denied (`rbac.py`, `test_rbac_internet.py`).

| Permission | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| `internet:read` (`GET /internet`, `GET /internet/sla`, the `/internet` page, the overview Internet card) | Yes | Yes | Yes | Yes | Yes | Yes |
| `internet:read_detail` (the ISP name, gateway, public IP and per-link throughput; without it they are `null` with `detail_redacted`) | Yes | Yes | Yes | **No** | **No** | **No** |
| `internet:export` (`GET /internet/sla/export`: outage-window evidence for ISP disputes, CSV/JSON) | Yes | Yes | **No** | **No** | **No** | Yes |

**Decision record (2026-10-11; interpretation, to be confirmed by the human owner).** The matrix has no "Internet" row. The WAN card is an
Overview widget (PRD 6) and the matrix grants Overview to every role (Full, Summary or Read), so every role holds `internet:read`
(Technician included: it is not "Limited" like Traffic, which Technician cannot read). The evidence export is narrower on purpose: it is
a dispute artefact naming links, ISP, probe targets and outage windows, so it is held by Admin, Network Engineer and Auditor (read-only
evidence), not by Security Analyst, Technician or Management. Every route needs the permission first, then a per-identity rate limit (status 300/min, SLA 30/min, export 10/min;
authorisation first so a denied caller never learns limiter state). A denied export attempt is audited (`internet.export`, `denied`).
The session lists the names in `permissions` for the UI (advisory; the API enforces them). Not human-only: reads may be performed by
service principals.

**Decision record - `internet:read_detail` (2026-10-11, security review M2; interpretation, to be confirmed by the human owner).** The matrix row
"Internet / WAN" reads Full / Full / Read / Read / Summary / Read and cannot tell a role that sees the public IP, the gateway, the ISP and live
throughput from one that sees status and the SLA. The public IP and gateway are reconnaissance material (they name the organisation's Internet
edge) and the ISP and throughput describe its commercial relationships and usage, so they are split into their own permission, granted to the roles
that operate or defend the network: **Administrator ("Full"), Network Engineer ("Full") and Security Analyst ("Read": a Security Analyst correlates
external addresses with events)**. **Technician ("Read"), Management ("Summary") and Auditor ("Read")** keep `internet:read` and so see link
status, quality, availability and the SLA summary, and are told the rest is restricted. The withholding is done by the API (the fields are `null`
and `detail_redacted` is `true`), never only by the browser, and the export withholds the ISP name the same way (an Auditor can still export the
evidence). This resolves the earlier open question about a reduced Management view. Capacity is kept (it is the link's rating, not usage). Open for
the owner: whether Technician and Auditor should also hold the detail, whether Management should hold the export, and whether probe targets in the
export should be withheld too (they are operator-declared host names, kept today).

| Capability (RBAC-MATRIX table above) | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| Internet / WAN detail (public IP, gateway, ISP, throughput) | Full | Full | Read | **No** | **No** | **No** |

## Users and identity permissions (Step 6, 2026-10-11)

The original matrix has no Users row. This is the privacy-first interpretation (PRD 92: role restrictions are mandatory; Management is aggregate-only with no per-user browsing;
Technician is limited), recorded here to be confirmed by the human owner. Three permissions form a strict-subset ladder (a role never holds a rung without the ones below it;
`test_rbac_identity.py`). Fail closed: unknown roles, no identity and unknown permission names are denied.

| Permission | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| `users:read` (browse people, read one person, resolve an address to the person behind it) | Yes | Yes | Yes | **No** | **No** | **No** |
| `users:read-limited` (resolve an address to its endpoint: device, MAC, port, VLAN, with the person withheld) | Yes | Yes | Yes | Yes | **No** | **No** |
| `users:read-summary` (`GET /users/summary`: counts only; the `/users` page and menu entry) | Yes | Yes | Yes | Yes | Yes | **No** |

- **Human-only.** `users:read` and `users:read-limited` are in `HUMAN_ONLY_PERMISSIONS`: no service or AI principal may browse or resolve people, whatever role it carries
  (inference abuse; the AI copilot must not become a people-lookup tool). `users:read-summary` is not human-only.
- **Management** sees only aggregate counts (people known, with an observed session, with an inferred session only, without session evidence, VPN sessions): no names,
  identifiers or rows, and `403` on `/users`, `/users/{id}` and `/identity/resolve`.
- **Technician ("Limited")** may resolve an address to its endpoint (`restricted` attribution: the person is withheld and the response says so; the source's own record ids
  are replaced by opaque keyed ids - HMAC-SHA-256 under `NETSIGHT_IDENTITY_ID_KEY`, fail closed without it - because a native id can embed a user name and an unkeyed hash is guessable). Technician cannot browse or open a person.
- **Auditor holds none (open decision).** The matrix grants Auditor "Read" broadly, but PRD 4 scopes Auditor to actions, incidents, authentication, configuration changes and
  reports, and per-person network history is neither. Granting `users:read-summary` (counts) is the smallest next step; granting `users:read` needs the privacy/legal review below.
- **Open decisions.** (1) Network Engineer holds `users:read` here because "who is on this port" is core troubleshooting; the alternative is the limited rung. (2) Site and
  security scoping does not exist, so "scoped" roles see everyone. (3) Whether any non-Admin role may browse people before the privacy/legal policy PRD 92 asks for exists.
- **Every read of per-user data is audited** (`identity.users.list`, `identity.user.read`, `identity.resolve`): actor, target and counts only, no purpose field and no names;
  denied attempts too (including the summary and a denied detail with its person id), 429s and rejected resolve input, each with a static reason code. A resolve target is a fingerprint, never the
  raw subject. Per-identity limits after authorisation: list/detail 120/min, summary 60/min, resolve 30/min; a past-time resolve also spends a global (all identities) budget of 20/min. The UI uses the session `permissions` only to show or hide
  the entry and the sections; the API enforces every rule.

## Traffic permissions (Step 7, 2026-10-11)

Two permissions form a strict-subset ladder (`test_rbac_traffic.py`): `traffic:read-detail` implies `traffic:read`.
Fail closed: unknown roles, no identity and unknown permission names are denied. Naming a *person* behind an address is a separate,
human-only decision (`users:read`, above), so the traffic surface has three independent controls: aggregates, endpoint rows, people.

| Permission | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| `traffic:read` (volumes, application mix, destinations, baselines/anomalies, top destinations: nothing that names an endpoint) | Yes | Yes | Yes | **No** | Yes | Yes |
| `traffic:read-detail` (flow rows, top talkers, any filter that narrows to one address, device or VLAN, per-person traffic, destinations inside the organisation) | Yes | Yes | Yes | **No** | **No** | Yes |
| people in flow rows: `users:read` (name + basis) / `users:read-limited` (device, person withheld) | Yes / Yes | Yes / Yes | Yes / Yes | No / Yes | No / No | No / No |

* **Management ("Summary") is aggregate-only.** The Explorer answers with the aggregations and `flows_restricted: true`; for it **no flow
  row is read from the flow store at all** (the API asks the adapter for aggregates only). A filter that narrows to a place
  (`source_ip`, `destination_ip`, **`device`**, **`vlan`**) is a 403: narrowing an aggregate to one host, one exporter or one VLAN
  is a per-endpoint read in disguise. The remaining filters (application, protocol, port, country, ASN, direction) describe the
  traffic and stay open to the aggregate rung. `GET /traffic/top-talkers` is a 403.
  This **tightens** S4, where Management held `traffic:read` for every route including raw flow rows.
* **Small cohorts (aggregate rung only).** Management is never shown an answer that rests on fewer than
  `NETSIGHT_TRAFFIC_MIN_COHORT` (default 5) distinct source addresses: an Explorer answer about fewer is withheld whole, an
  `endpoints` count below the minimum is withheld, a first-seen row fewer sources reached is not listed, and each response
  says so (`cohort.state`). Destinations inside the organisation are not listed to it. The detail rung is not subject to any of this.
* **Auditor ("Read")** sees endpoint rows but never a person (it holds no `users:*` permission): attribution is `withheld`, and the
  identity service is not even consulted.
* **Technician ("Limited") still holds no traffic permission** (unchanged since S4). The matrix word "Limited" is ambiguous; the safe
  reading is kept until the owner decides what it removes. The code already supports the intermediate rung: a role holding
  `traffic:read` + `traffic:read-detail` + `users:read-limited` receives the *endpoint level* (device, person withheld); it is covered by a test
  that grants it to a role temporarily.
* **People in rows** (`users:read`, human principals only): a person is shown only with the identity service's basis (observed /
  inferred / unknown), reason and confidence; inferred is capped at 0.7; two candidate persons, or an ambiguous answer, name nobody.
  A service or AI principal with the Administrator role gets rows and never a person. The flow store's own `User` column is not read.
* **Per-person traffic** (`GET /users/{id}`, Step 6) now needs `traffic:read-detail` (it is built from source addresses). All current
  `users:read` holders hold it, so nothing changes today; a role holding one and not the other gets `not-connected` for that block.
* **Limits and audit.** Authorise first, then per-identity budgets: Explorer 30/min, Applications 30/min, Destinations 30/min,
  Anomalies 10/min (top talkers/destinations keep the shared 300/min); at most 3 heavy flow-store reads in flight across identities,
  **one per identity** (429 `TRAFFIC_CONCURRENCY`) and **the last slot reserved for `traffic:read-detail`** (503 `TRAFFIC_BUSY`
  + `Retry-After`, never queued). All four routes (`traffic.flows.read`, `.applications.read`, `.destinations.read`,
  `.anomalies.read`) and `traffic.top-talkers.read` are audited for success, failure and every refusal (permission, rate limit,
  filter needing detail, rejected input, busy), recording the actor, state, counts, the *names* of the filters used, the tier and the
  cohort verdict; never a filter value, an address or a person's name (a detail-tier lookup may add a keyed fingerprint, see
  AUDIT-LOGGING). Responses are `Cache-Control: no-store`.
* **Decisions for the owner.** (1) Management aggregate-only and the 403 on address, device and VLAN filters; the minimum cohort `k`
  (5 by default) and whether Management should see a destination inside the organisation at all. (2) Auditor sees endpoint rows (matrix: "Read")
  but not people. (3) What Technician "Limited" removes (today: all of traffic). (4) Whether any non-Admin role may see people in flow rows
  before the privacy/legal policy of PRD 92 exists. (5) Site/department scoping of traffic (does not exist).

## Inventory, IPAM and unknown-device permissions (Step 8, 2026-10-11)

The original matrix has no Inventory, IPAM or Unknown-devices row; the nearest are "Devices" (Full / Full / Read / Operational / Summary / Read) and "Security". The mapping
below is an interpretation of those rows, **to be confirmed by the human owner**. Each surface has a strict-subset ladder (`*:read` implies `*:read-summary`; `test_rbac_inventory.py`).
Fail closed: unknown roles, no identity and unknown permission names are denied.

| Permission | Admin | Network Engineer | Security Analyst | Technician | Management | Auditor |
|---|---|---|---|---|---|---|
| `inventory:read` (asset rows and per-asset detail) | Yes | Yes | Yes | Yes | **No** | Yes |
| `inventory:read-summary` (counts only) | Yes | Yes | Yes | Yes | Yes | Yes |
| `ipam:read` (prefixes, VLANs, addresses) | Yes | Yes | Yes | Yes | **No** | Yes |
| `ipam:read-summary` (counts only) | Yes | Yes | Yes | Yes | Yes | Yes |
| `unknown-devices:read` (finding rows, detail, timeline) | Yes | Yes | Yes | **No** | **No** | Yes |
| `unknown-devices:read-summary` (counts only) | Yes | Yes | Yes | Yes | Yes | Yes |
| `unknown-devices:acknowledge` (acknowledge, mark investigating) | Yes | Yes | Yes | **No** | **No** | **No** |
| `unknown-devices:assign`, `:comment` | Yes | Yes | Yes | **No** | **No** | **No** |
| `unknown-devices:resolve` (resolve or dismiss as false positive; step-up) | Yes | Yes | Yes | **No** | **No** | **No** |
| `unknown-devices:scan` (run a detection scan now) | Yes | Yes | Yes | **No** | **No** | **No** |

* **Management ("Summary") sees counts only** on all three surfaces: no asset, address, prefix or finding row, and `403` on the row routes (`/inventory`, `/inventory/{id}`,
  `/ipam/prefixes`, `/ipam/vlans`, `/ipam/addresses`, `/unknown-devices`, `/unknown-devices/{id}`, `/unknown-devices/{id}/timeline`). `GET /ipam` returns the counts block for every role with at least the summary rung.
* **Technician ("Operational") reads inventory and IPAM rows** (the same reading as Devices) **but only the finding counts**: a finding names an endpoint and the way it attaches to the network,
  and Technician has no security scope. This is a conservative reading; granting `unknown-devices:read` to Technician is one line in `rbac.py` if the owner wants it.
* **Auditor ("Read") reads rows on all three surfaces and holds no write**, including no comment (it does not change the record it audits).
* **All five finding writes are in `HUMAN_ONLY_PERMISSIONS`**: no service or AI principal may acknowledge, assign, comment, resolve or scan, whatever role it carries. The reads are not human-only.
* **Step-up on resolve.** Resolving or dismissing is the only action that closes the record and, for a false positive, suppresses later sightings of the endpoint, so it requires a recent
  multi-factor sign-in (same mechanism as incident resolution). **This is a recorded, open decision**: the alternative is no step-up for dismissal of a low-severity finding.
* **Quarantine is not a permission.** There is no quarantine or isolate grant: a proposed quarantine is a record on the finding. Execution belongs to the action engine (Step 14), which
  has its own approval permissions.
* **Order of guards.** Reads: authenticate, authorise (a refusal is audited), per-identity rate limit, strict query, `no-store`. Writes: authenticate, authorise (audited), CSRF and origin, step-up (resolve only), per-identity rate limit.
  Limits per identity per minute: inventory list/detail/summary 60/120/60; IPAM 60; findings list/detail/timeline/summary 120/120/120/60; finding writes 60; scan 6.
* **Audit.** Actions `inventory.list.read`, `.item.read`, `.summary.read`, the IPAM and unknown-device read actions, and one action per finding write: actor, outcome, counts and the *names* of the filters used;
  never an address, MAC, hostname, comment or reason text.
* **Decisions for the owner.** (1) The role mapping above, in particular Technician (finding counts only) and Auditor (rows, no comment). (2) Step-up on resolve and dismiss. (3) Whether Management should see
  inventory and IPAM counts at all. (4) Site scoping does not exist, so a "scoped" role sees every site.

## Configuration backup metadata (E08 stage 1)

`configuration:read` implements the Config history row for Administrator, Network
Engineer, Security Analyst, Technician and Auditor. Management holds no permission.
Only backup-attempt metadata and revision IDs/timestamps are exposed, with every
read authorized, rate-limited, audited and non-cacheable. This grants no access to
configuration bodies, author identities, raw diffs or remote write/restore actions.
