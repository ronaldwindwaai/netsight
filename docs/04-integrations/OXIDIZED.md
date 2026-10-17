# Oxidized Integration

Purpose: versioned network-device configuration backup and diff.

Use for:
- config history;
- change detection;
- incident change correlation;
- drift investigation.

Rollback is not automatic. Any restore workflow requires explicit target validation, policy and approval.

## Read-only metadata integration (E08 stage 1)

Implemented adapter: `apps/api/src/netsight_api/adapters/oxidized.py`. Configure
`OXIDIZED_BASE_URL` and an optional reverse-proxy `OXIDIZED_TOKEN` in the server
environment; keep the upstream private. The platform reads only node backup
metadata and saved-version IDs/timestamps, not configuration bodies or author data.
See `docs/12-implementation/CONFIGURATION-INTELLIGENCE.md` for contracts, bounds,
role policy, verification limits and the remaining content/diff stages.
