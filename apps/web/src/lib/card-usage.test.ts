// Guards heading order: every card must come from AppCard (h2 title). The library Card renders its
// title as an h3 directly under the page h1, which axe reports as heading-order. ESLint
// (no-restricted-imports in eslint.config.mjs) is the primary guard; this test is a backstop.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

const SRC = join(import.meta.dirname, '..');

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(tsx?|jsx)$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : [];
  });
}

const LIBRARY = String.raw`['"]@adminlte\/react['"]`;
const IMPORT_OR_EXPORT_CARD = new RegExp(
  String.raw`(?:import|export)\s+(?:type\s+)?\{[^}]*\bCard\b[^}]*\}\s*from\s*${LIBRARY}` +
    String.raw`|import\s+(?:type\s+)?\*\s+as\s+\w+\s+from\s*${LIBRARY}` +
    String.raw`|export\s+\*\s+from\s*${LIBRARY}`,
);

export function importsLibraryCard(text: string): boolean {
  return IMPORT_OR_EXPORT_CARD.test(text);
}

describe('card usage', () => {
  it('detects every way of importing the library Card', () => {
    for (const text of [
      `import { Card } from '@adminlte/react';`,
      `import { Card } from "@adminlte/react";`,
      `import { Alert, Card as LibCard } from '@adminlte/react';`,
      `import type { Card } from '@adminlte/react';`,
      `import * as Lib from '@adminlte/react';`,
      `export { Card } from '@adminlte/react';`,
      `export * from '@adminlte/react';`,
    ]) {
      assert.equal(importsLibraryCard(text), true, text);
    }
    assert.equal(importsLibraryCard(`import { Alert, Table } from '@adminlte/react';`), false);
  });

  it('no component imports Card from the library', () => {
    const offenders = sourceFiles(SRC).filter((file) => importsLibraryCard(readFileSync(file, 'utf8')));
    assert.deepEqual(offenders, []);
  });

  // Best effort: a textual check for the one hand-written pattern seen so far, not a proof.
  it('no hand-written card-title heading is an h3 (best effort)', () => {
    const offenders = sourceFiles(SRC).filter((file) => /<h3[^>]*card-title/.test(readFileSync(file, 'utf8')));
    assert.deepEqual(offenders, []);
  });
});
