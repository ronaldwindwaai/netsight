// Runs the React component tests (src/**/*.test.tsx) on the plain `node --test` runner.
//
// Node cannot strip JSX, and the components import through the `@/` alias, Next.js modules and
// server actions. Each test file is therefore bundled with esbuild into `.test-build/` with:
//   - `@/` resolved through tsconfig paths,
//   - `next/navigation` and the server actions replaced by the controllable stubs in src/test/,
//   - jsdom left external (it is resolved from apps/web/node_modules at run time),
//   - the optional widget libraries @adminlte/react loads lazily (charts, editors, pickers) left
//     external: no tested component mounts those widgets, so they are never resolved at run time.
// The bundles are then executed by `node --test`; nothing here touches the network or a server.
import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = join(root, 'src');
const outDir = join(root, '.test-build');

const STUBS = [
  [/^next\/navigation$/, join(srcDir, 'test', 'next-navigation-stub.ts')],
  [/^@\/app\/\(dashboard\)\/(incidents\/\[incidentId\]|alerts)\/actions$/, join(srcDir, 'test', 'server-actions-stub.ts')],
  [/^@\/app\/\(dashboard\)\/diagnostics\/actions$/, join(srcDir, 'test', 'diagnostics-actions-stub.ts')],
  [/^@\/app\/\(dashboard\)\/unknown-devices\/(\[findingId\]\/)?actions$/, join(srcDir, 'test', 'unknown-device-actions-stub.ts')],
];

const OPTIONAL_WIDGET_LIBRARIES = /^(flatpickr|tom-select|sortablejs|tabulator-tables|quill|chart\.js)(\/.*)?$/;

const stubPlugin = {
  name: 'netsight-test-stubs',
  setup(pluginBuild) {
    pluginBuild.onResolve({ filter: OPTIONAL_WIDGET_LIBRARIES }, (args) => ({
      path: args.path,
      external: true,
    }));
    for (const [filter, path] of STUBS) {
      pluginBuild.onResolve({ filter }, () => ({ path }));
    }
  },
};

function findTests(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return findTests(path);
    return entry.name.endsWith('.test.tsx') ? [path] : [];
  });
}

const tests = findTests(srcDir);
if (tests.length === 0) {
  console.error('No component tests found.');
  process.exit(1);
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

await build({
  entryPoints: Object.fromEntries(
    tests.map((file) => [relative(srcDir, file).replace(/\.test\.tsx$/, '').replaceAll(/[\\/]/g, '__'), file]),
  ),
  outdir: outDir,
  outExtension: { '.js': '.test.cjs' },
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node22',
  jsx: 'automatic',
  sourcemap: 'inline',
  logLevel: 'warning',
  external: ['jsdom'],
  alias: { '@': srcDir },
  plugins: [stubPlugin],
  define: { 'process.env.NODE_ENV': '"test"' },
});

const bundles = readdirSync(outDir)
  .filter((name) => name.endsWith('.test.cjs'))
  .map((name) => join(outDir, name));
const result = spawnSync(process.execPath, ['--test', '--test-timeout=180000', '--test-force-exit', ...process.argv.slice(2), ...bundles], { stdio: 'inherit', cwd: root });
rmSync(outDir, { recursive: true, force: true });
process.exit(result.status ?? 1);
