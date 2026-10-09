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
| `incidents:read` (list, detail, timeline) | Yes | Yes | Yes | Yes | Yes | Yes |
| `incidents:transition` (acknowledge, investigate, mitigate, close) | Yes | Yes | Yes | No | No | No |
| `incidents:assign` | Yes | Yes | Yes | No | No | No |
| `incidents:comment` (comment, evidence reference) | Yes | Yes | Yes | No | No | No |
| `incidents:resolve` (human principals only) | Yes | Yes | Yes | No | No | No |
| `incidents:reopen` (human principals only) | Yes | Yes | Yes | No | No | No |
| `incidents:write-assigned` (acknowledge/investigate/mitigate, comment, evidence on incidents assigned to the caller; never close, assign, resolve or reopen) | Yes | No | No | Yes | No | No |

Human-only: `resolve` and `reopen` record a root cause or reopen reason. They are denied to any identity whose
`principal` is not `human` (service accounts, the AI copilot), whatever role it carries. Only an interactive
server-side session yields a human principal. Technician "Assigned" is enforced for writes, inside the store under
the incident row lock; reading incidents is not yet narrowed to assigned incidents (open decision). Whether
Management should be limited to a summary view of incidents is an open human decision (today it has full `incidents:read`).

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
maintenance access; its S6-2 `incidents:read` is unchanged and whether it should be limited to a summary view remains
the open human decision recorded there. Open decisions for S6-3: whether the creator of a rule may also approve it
(no four-eyes rule today), and whether technicians should see maintenance windows (the matrix says nothing, so denied).
