'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRequire } = require('node:module');
const test = require('node:test');

// Resolve through the installed lint stack: verify the dependency override and
// the actual Next utility, not a copy of its implementation.
const fromNext = createRequire(require.resolve('eslint-config-next', {
  paths: [path.resolve(__dirname, '../../apps/web')],
}));
const fromPlugin = createRequire(fromNext.resolve('@next/eslint-plugin-next'));
const { getRootDirs } = fromPlugin('./utils/get-root-dirs.js');

test('Next directory discovery uses the replacement glob implementation', () => {
  assert.equal(fromPlugin('fast-glob/package.json').name, 'tinyglobby');
});

test('Next root discovery preserves directory, wildcard, brace and array settings', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'netsight-lint-roots-'));
  try {
    for (const name of ['web', 'admin', 'worker']) {
      fs.mkdirSync(path.join(root, 'apps', name), { recursive: true });
    }
    fs.writeFileSync(path.join(root, 'apps', 'file.ts'), '');
    const discover = (rootDir) => getRootDirs({ cwd: root, settings: { next: { rootDir } } }).sort();
    assert.deepEqual(discover(undefined), [root]);
    assert.deepEqual(discover(`${root}/apps/*`), ['admin', 'web', 'worker'].map(n => `${root}/apps/${n}`));
    assert.deepEqual(discover(`${root}/apps/{web,admin}`), ['admin', 'web'].map(n => `${root}/apps/${n}`));
    assert.deepEqual(discover([`${root}/apps/web`, 7, `${root}/apps/admin`]), ['admin', 'web'].map(n => `${root}/apps/${n}`));
    assert.deepEqual(discover(`${root}/missing/*`), []);
    assert.deepEqual(discover(`${root}/apps/file.ts`), []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
