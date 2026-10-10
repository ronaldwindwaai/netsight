# Netsight Web

Next.js + React + TypeScript + AdminLTE React.

Before implementing UI, read:
- `/AGENTS.md`
- `/docs/03-ui-ux/ADMINLTE-DESIGN-SYSTEM.md`

Do not add a normal username/password form.

## Tests

- `pnpm --filter @netsight/web test:unit` runs the pure-logic tests (`src/**/*.test.ts`) on `node --test`.
- `pnpm --filter @netsight/web test:components` runs the React component tests (`src/**/*.test.tsx`): `scripts/run-component-tests.mjs`
  bundles each file with esbuild (stubbing `next/navigation` and the server actions from `src/test/`), then runs it under jsdom
  and Testing Library on `node --test`. No server, network or browser is involved.
- `pnpm --filter @netsight/web test` runs both.
