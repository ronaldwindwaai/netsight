'use strict';
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const test = require('node:test');
const path = require('node:path');
// Resolve through the actual lint stack, so a missing install patch fails CI.
const fromNext = createRequire(require.resolve('eslint-config-next', {
  paths: [path.resolve(__dirname, '../../apps/web')],
}));
const fromPlugin = createRequire(fromNext.resolve('@next/eslint-plugin-next'));
const fromGlob = createRequire(fromPlugin.resolve('fast-glob'));
const fromMicro = createRequire(fromGlob.resolve('micromatch'));
const braces = fromMicro('braces');

test('lint brace expansion still handles ordinary patterns', () => {
  assert.deepEqual(braces.expand('src/{app,lib}/*.{ts,tsx}'), [
    'src/app/*.ts', 'src/app/*.tsx', 'src/lib/*.ts', 'src/lib/*.tsx',
  ]);
});
for (const [open, close] of [['{', '}'], ['(', ')'], ['{(', ')}']]) {
  for (const operation of ['compile', 'expand', 'stringify']) {
    test(`${operation} rejects excessive nesting of ${open}`, () => {
      const input = open.repeat(2000) + 'a,b' + close.repeat(2000);
      assert.throws(() => braces[operation](input), {
        name: 'SyntaxError', message: /maximum depth of 100/,
      });
    });
  }
}
