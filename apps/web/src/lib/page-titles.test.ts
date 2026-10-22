// Guards WCAG 2.4.2: every dashboard screen names itself in the browser tab. The root layout
// supplies the "· Netsight" suffix through a title template, so a page only states its own name.
// Each page module is bundled with esbuild (the `@/` alias, Next.js navigation stubbed) and
// imported, then its exported `metadata` (or `generateMetadata`) is asserted on.
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';

import { build } from 'esbuild';

const SRC = join(import.meta.dirname, '..');
const APP = join(SRC, 'app');
const WEB = join(SRC, '..');
const OUT = mkdtempSync(join(tmpdir(), 'netsight-page-titles-'));

function pages(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return pages(path);
    return name === 'page.tsx' ? [path] : [];
  });
}

const dashboardPages = pages(join(APP, '(dashboard)'));
const nameOf = (file: string) => relative(APP, file).replaceAll(sep, '/');
const outName = (file: string) => nameOf(file).replaceAll(/[^A-Za-z0-9]/g, '_');

interface PageModule {
  metadata?: { title?: unknown };
  generateMetadata?: unknown;
}
const modules = new Map<string, PageModule>();

before(async () => {
  const stubs = {
    name: 'netsight-page-title-stubs',
    setup(b: import('esbuild').PluginBuild) {
      b.onResolve({ filter: /^server-only$/ }, (a) => ({ path: a.path, namespace: 'empty' }));
      b.onLoad({ filter: /.*/, namespace: 'empty' }, () => ({ contents: '', loader: 'js' }));
      b.onResolve({ filter: /^(flatpickr|tom-select|sortablejs|tabulator-tables|quill|chart\.js)(\/.*)?$/ }, (a) => ({
        path: a.path,
        external: true,
      }));
    },
  };
  await build({
    entryPoints: Object.fromEntries(dashboardPages.map((file) => [outName(file), file])),
    outdir: OUT,
    outExtension: { '.js': '.cjs' },
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node22',
    jsx: 'automatic',
    logLevel: 'warning',
    absWorkingDir: WEB,
    external: ['jsdom'],
    alias: { '@': SRC },
    plugins: [stubs],
    define: { 'process.env.NODE_ENV': '"test"' },
  });
  for (const file of dashboardPages) {
    const mod = (await import(pathToFileURL(join(OUT, `${outName(file)}.cjs`)).href)) as { default?: PageModule } & PageModule;
    modules.set(file, mod.default && 'metadata' in mod.default ? mod.default : mod);
  }
});

after(() => rmSync(OUT, { recursive: true, force: true }));

describe('page titles', () => {
  it('finds the dashboard pages', () => {
    assert.ok(dashboardPages.length >= 30, `found only ${dashboardPages.length}`);
  });

  for (const file of dashboardPages) {
    it(`${nameOf(file)} exports a non-empty title`, () => {
      const mod = modules.get(file);
      assert.ok(mod, 'module did not load');
      if (typeof mod.generateMetadata === 'function') return;
      const title = mod.metadata?.title;
      assert.equal(typeof title, 'string', 'missing `metadata.title` or `generateMetadata`');
      assert.ok((title as string).trim().length > 0, 'title is empty');
      assert.notEqual(title, 'Netsight');
    });
  }
});
