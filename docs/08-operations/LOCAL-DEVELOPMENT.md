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
