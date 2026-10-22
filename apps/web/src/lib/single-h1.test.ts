import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';
import test from 'node:test';

// AppContent renders the one h1 of every dashboard page; the login page and the standalone pages
// outside the shell (404, global error) own their own. Any other component or page that writes an
// h1 would give a page two of them.
const ALLOWED = new Set([
  'components/app-content.tsx',
  'app/login/page.tsx',
  'app/not-found.tsx',
  'app/global-error.tsx',
]);

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return name.endsWith('.tsx') && !name.endsWith('.test.tsx') ? [path] : [];
  });
}

test('only AppContent and the login page write an h1', () => {
  const root = join(process.cwd(), 'src');
  const offenders = sourceFiles(root)
    .map((path) => path.slice(root.length + 1).split(sep).join('/'))
    .filter((relative) => !ALLOWED.has(relative))
    .filter((relative) => /<h1[\s>]/.test(readFileSync(join(root, relative), 'utf8')));

  assert.deepEqual(offenders, []);
});
