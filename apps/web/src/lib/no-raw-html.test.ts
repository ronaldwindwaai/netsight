import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

// Incident titles, comments, rule names and labels are untrusted text. React
// renders text nodes safely; the only way to bypass that is these APIs.
const FORBIDDEN = ['dangerouslySetInnerHTML', 'innerHTML', 'insertAdjacentHTML'];
const SOURCE_ROOT = new URL('..', import.meta.url);

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(tsx?|jsx?)$/.test(name) && !name.endsWith('.test.ts') ? [path] : [];
  });
}

test('no application source can inject raw HTML', () => {
  const root = SOURCE_ROOT.pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const files = sourceFiles(root);
  assert.ok(files.length > 0, 'expected to scan source files');
  const offenders = files.filter((file) => {
    const text = readFileSync(file, 'utf8');
    return FORBIDDEN.some((api) => text.includes(api));
  });
  assert.deepEqual(offenders, []);
});
