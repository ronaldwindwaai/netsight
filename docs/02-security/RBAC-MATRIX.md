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

Production roles must be mapped to least privilege and may be site-scoped.

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
