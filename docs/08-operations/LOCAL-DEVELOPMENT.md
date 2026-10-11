# Local Development

Prerequisites:
- Git
- Docker + Compose
- Node.js supported by chosen Next.js/AdminLTE release
- pnpm
- Python 3.12+ recommended
- uv or pip tooling

Start with platform dependencies only:
- PostgreSQL
- Redis
- optional ClickHouse

Use mocked adapter fixtures until a lab LibreNMS/NetBox is available.

Do not connect development directly to production monitoring systems.

## Demo account and fixture data

To look around the UI without a real monitoring system, run from the repo root:

```
python scripts/demo-local.py          # API on 127.0.0.1:8000 + fixture LibreNMS on :8081
cd apps/web && npm run dev            # http://localhost:3000
```

The first run creates a local administrator (`demo.admin`) through the operator CLI and prints the
password, TOTP secret and recovery codes once, in that terminal. Only a password hash and an
encrypted TOTP secret are kept, under the git-ignored `.demo/`. `--reset` removes the account.
Only the LibreNMS fixture (devices, ports, alerts) has data; traffic, security, NetBox and the rest
show "Not connected" because nothing is wired to them. Everything binds to loopback.

## Database migrations and roles (API)

Separate database credentials, never the same one:

| Variable | Role | Used by |
|---|---|---|
| `DATABASE_MIGRATION_URL` | owner / migrator (DDL, grants, WAN month partitions) | `python -m netsight_api.storage.migrate` only |
| `DATABASE_URL` | least-privilege application role (SELECT only on the WAN evidence tables) | the running API |
| `DATABASE_APP_ROLE` | name of that application role | the migrator, to apply its grants |
| `NETSIGHT_WAN_COLLECTOR_DATABASE_URL` | WAN collector role (INSERT only on the WAN evidence tables, nothing else) | the sampling collector, only when `NETSIGHT_WAN_SAMPLING_ENABLED` is on |
| `DATABASE_WAN_COLLECTOR_ROLE` | name of that collector role (must differ from the application role) | the migrator, to apply its grants |

Create the application role out of band (login, no superuser/createdb/createrole, password from
the secrets manager, not owner of anything), then from `apps/api`:

```
python -m netsight_api.storage.migrate status
python -m netsight_api.storage.migrate up          # migrations, WAN partitions (this and next month), then grants
                                                   # for $DATABASE_APP_ROLE (and $DATABASE_WAN_COLLECTOR_ROLE if set)
python -m netsight_api.storage.migrate up --no-grants
python -m netsight_api.storage.migrate partitions  # WAN month partitions; schedule it monthly (idempotent)
```

The WAN evidence tables are partitioned by month and the runtime roles cannot create partitions, so schedule
`partitions` (cron, a systemd timer or Task Scheduler, as the migrator) at least monthly. If next month's
partition is missing the collector logs an error and records nothing until it exists (a gap, shown as unknown).

Exit codes: 0 ok, 1 migration/database failure, 2 usage or configuration error. The DSN and
database error text are never printed. `up` is idempotent and re-applies the grants each run.
Rollback SQL (`*.down.sql`) is destructive and is not packaged in the production wheel; in a
source checkout `apply_down` needs `allow_destructive=True` and, when it would drop tables that
hold rows, `NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1`. Live database tests are opt-in:
`NETSIGHT_TEST_PG_DSN=postgresql://...` (a role allowed to `CREATE ROLE`/`CREATE SCHEMA`; each
test uses a throwaway schema and role).

## OpenCode plugin (ECC port)

This repo uses OpenCode V2. `opencode.json` loads a project-local plugin from
`./.opencode/dist`, built from source under `tools/build-opencode/`.

Build it (required after cloning and after editing the plugin source):

```
npm run build:opencode
```

Notes:
- The upstream `ecc-universal@2.2.3` plugin is a V1-shaped plugin and does **not**
  load under OpenCode V2; Netsight vendors a V2 port instead (see the source
  comments in `tools/build-opencode/` for the V1→V2 mapping).
- `.opencode/dist/` is generated output but is committed on purpose, so the
  plugin works without a build step. Never hand-edit it; re-run the build.
- Runtime controls are honored: `ECC_HOOK_PROFILE` (`minimal|standard|strict`)
  and `ECC_DISABLED_HOOKS` (comma-separated hook ids).
- Auto-format on save resolves a **locally installed** Prettier and runs it via
  `process.execPath` (no shell, no `npx`/network fetch). It only runs in the
  `strict` profile and is a no-op when Prettier is not installed.

Verification helpers for the plugin:

```
node tools/build-opencode/smoke.mjs             # hooks/transforms register
node tools/build-opencode/format-path-check.mjs # shell-safe formatter path
```
