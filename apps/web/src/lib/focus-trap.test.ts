import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { trapIndex } from './focus-trap.ts';

describe('trapIndex', () => {
  it('moves forward and wraps from the last element to the first', () => {
    assert.equal(trapIndex(4, 0, false), 1);
    assert.equal(trapIndex(4, 3, false), 0);
  });

  it('moves backward and wraps from the first element to the last', () => {
    assert.equal(trapIndex(4, 2, true), 1);
    assert.equal(trapIndex(4, 0, true), 3);
  });

  it('pulls focus in from outside the trap', () => {
    assert.equal(trapIndex(4, -1, false), 0);
    assert.equal(trapIndex(4, -1, true), 3);
  });

  it('has nowhere to go with no focusable elements', () => {
    assert.equal(trapIndex(0, -1, false), -1);
  });
});
