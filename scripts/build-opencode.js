#!/usr/bin/env node
/**
 * build:opencode
 *
 * Compiles the Netsight OpenCode V2 plugin (source under `tools/build-opencode/`)
 * into the project-local payload at `.opencode/dist/`.
 *
 * Why a local payload at `.opencode/dist/`:
 *   - OpenCode auto-discovers `.opencode/**` in the project.
 *   - The upstream `ecc-universal@2.2.3` plugin is a V1-shaped plugin and does
 *     not load under OpenCode V2. Netsight vendors a V2 port under
 *     `tools/build-opencode/` and compiles it here so the payload is
 *     reproducible and auditable.
 *
 * Usage: node scripts/build-opencode.js   (or: npm run build:opencode)
 */

'use strict';

const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const sourceDir = path.join(repoRoot, 'tools', 'build-opencode');
const outDir = path.join(repoRoot, '.opencode', 'dist');
const tsconfigPath = path.join(sourceDir, 'tsconfig.json');
const entrypoint = path.join(sourceDir, 'index.ts');

function fail(message) {
  console.error(`[build:opencode] ${message}`);
  process.exit(1);
}

if (!fs.existsSync(entrypoint)) {
  fail(`OpenCode plugin source was not found at ${path.relative(repoRoot, entrypoint)}.`);
}

if (!fs.existsSync(tsconfigPath)) {
  fail(`Missing plugin tsconfig at ${path.relative(repoRoot, tsconfigPath)}.`);
}

let ts;
try {
  ts = require('typescript');
} catch {
  fail(
    'The `typescript` package is required to build the OpenCode plugin but '
      + 'could not be resolved. Install it as a devDependency: '
      + '`npm install --save-dev typescript`.'
  );
}

const tsconfigFile = ts.readConfigFile(tsconfigPath, ts.sys.readFile);
if (tsconfigFile.error) {
  fail(
    `Failed to read ${path.relative(repoRoot, tsconfigPath)}: `
      + ts.flattenDiagnosticMessageText(tsconfigFile.error.messageText, '\n')
  );
}

const parsed = ts.parseJsonConfigFileContent(
  tsconfigFile.config,
  ts.sys,
  sourceDir,
  { outDir, rootDir: sourceDir, noEmit: false },
  tsconfigPath
);

const formattedOptions = {
  getCanonicalFileName: (fileName) => fileName,
  getCurrentDirectory: () => repoRoot,
  getNewLine: () => '\n',
};

if (parsed.errors.length > 0) {
  fail(
    'Invalid plugin tsconfig:\n'
      + ts.formatDiagnosticsWithColorAndContext(parsed.errors, formattedOptions)
  );
}

const program = ts.createProgram(parsed.fileNames, parsed.options);

const preEmitDiagnostics = ts.getPreEmitDiagnostics(program);
if (preEmitDiagnostics.length > 0) {
  console.error(ts.formatDiagnosticsWithColorAndContext(preEmitDiagnostics, formattedOptions));
  fail(`TypeScript reported ${preEmitDiagnostics.length} error(s); nothing written.`);
}

const emitResult = program.emit();
if (emitResult.emitSkipped) {
  fail('TypeScript emit was skipped; no payload written.');
}

const emittedIndex = path.join(outDir, 'index.js');
if (!fs.existsSync(emittedIndex)) {
  fail(`Build completed but no entrypoint was emitted at ${path.relative(repoRoot, emittedIndex)}.`);
}

// The compiled payload is ESM (the plugin source is ESM and `@opencode/plugin`
// is ESM-only). Mark the generated directory as a module scope so Node and
// OpenCode load the emitted `.js` files as ESM.
fs.writeFileSync(
  path.join(outDir, 'package.json'),
  `${JSON.stringify({ type: 'module' }, null, 2)}\n`
);

console.log(
  `[build:opencode] Wrote OpenCode plugin payload to ${path.relative(repoRoot, outDir)}`
);
