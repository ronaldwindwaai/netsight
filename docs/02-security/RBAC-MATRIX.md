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
