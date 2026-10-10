# Blackbox Adapter

Status: partial — bounded read-only probe client (S7-2).

Implemented: `apps/api/src/netsight_api/adapters/blackbox.py` (allowlisted DNS / TCP / HTTP/HTTPS
probes feeding `POST /api/v1/diagnostics`). Not yet implemented: ICMP, multi-vantage deployment and
baseline/dependency/recent-change sources (all answer an explicit `unknown`).

See `/docs/04-integrations/BLACKBOX.md` for configuration, security posture and rollback, and
`/skills/integration-adapter/SKILL.md` for the adapter contract (freshness, least privilege,
contract tests).
