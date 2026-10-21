// Guards WCAG 2.4.2: every dashboard screen names itself in the browser tab. The root layout
// supplies the "· Netsight" suffix through a title template, so a page only states its own name.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { describe, it } from 'node:test';

const APP = join(import.meta.dirname, '..', 'app');

function pages(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return pages(path);
    return name === 'page.tsx' ? [path] : [];
  });
}

describe('page titles', () => {
  it('the root layout titles pages through a template ending in the product name', () => {
    const layout = readFileSync(join(APP, 'layout.tsx'), 'utf8');
    assert.match(layout, /template:\s*'%s · Netsight'/);
    assert.match(layout, /default:\s*'Netsight'/);
  });

  const dashboardPages = pages(join(APP, '(dashboard)'));

  it('finds the dashboard pages', () => {
    assert.ok(dashboardPages.length >= 30, `found only ${dashboardPages.length}`);
  });

  for (const file of dashboardPages) {
    it(`${relative(APP, file).replaceAll(sep, '/')} exports a non-empty static title`, () => {
      const text = readFileSync(file, 'utf8');
      const match = /export const metadata\s*(?::[^=]+)?=\s*\{\s*title:\s*'([^']+)'/.exec(text);
      assert.ok(match, 'missing `export const metadata = { title: ... }`');
      assert.notEqual(match[1], 'Netsight');
    });
  }
});
