// Guards heading order: every card must come from AppCard (h2 title). The library Card renders its
// title as an h3 directly under the page h1, which axe reports as heading-order.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

const SRC = join(import.meta.dirname, '..');

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.tsx$/.test(name) && !/\.test\.tsx$/.test(name) ? [path] : [];
  });
}

describe('card usage', () => {
  it('no component imports Card from the library', () => {
    const offenders = sourceFiles(SRC).filter((file) => {
      const text = readFileSync(file, 'utf8');
      return /import\s*\{[^}]*\bCard\b[^}]*\}\s*from\s*'@adminlte\/react'/.test(text);
    });
    assert.deepEqual(offenders, []);
  });

  it('no hand-written card-title heading is an h3', () => {
    const offenders = sourceFiles(SRC).filter((file) => /<h3[^>]*card-title/.test(readFileSync(file, 'utf8')));
    assert.deepEqual(offenders, []);
  });
});
