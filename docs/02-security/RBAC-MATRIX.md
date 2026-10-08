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
