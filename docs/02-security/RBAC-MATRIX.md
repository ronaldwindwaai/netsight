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

## Session permissions for the UI

`GET /api/v1/auth/session` returns `permissions`: the sorted permission names the session's roles hold (derived from the same
`is_allowed` the routes use). The web UI uses it only to enable, disable and explain controls and to choose the summary or
full incident surface. It is advisory: the API enforces every permission, scope, state, CSRF/origin and step-up rule on each
request, and the UI shows the API's refusal (409 conflict, 422, 503, 403 `STEP_UP_REQUIRED`) if the page was stale.
