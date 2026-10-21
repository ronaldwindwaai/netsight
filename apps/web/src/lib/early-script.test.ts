import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { JSDOM } from 'jsdom';

import { EARLY_SCRIPT } from './early-script.ts';

function run(setup: (window: JSDOM['window']) => void): JSDOM['window'] {
  const { window } = new JSDOM('<!doctype html><html><body></body></html>', { runScripts: 'outside-only', url: 'https://noc.example.test/' });
  setup(window);
  window.eval(EARLY_SCRIPT);
  return window;
}

const blockStorage = (window: JSDOM['window']) =>
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    get() {
      throw new window.DOMException('blocked', 'SecurityError');
    },
  });

describe('EARLY_SCRIPT', () => {
  it('applies a stored compact density before hydration', () => {
    const window = run((w) => w.localStorage.setItem('netsight.density', 'compact'));
    assert.equal(window.document.documentElement.dataset.density, 'compact');
  });

  it('leaves the default density alone', () => {
    assert.equal(run(() => undefined).document.documentElement.dataset.density, undefined);
  });

  it('keeps the page working when storage access throws, with a flagged in-memory stand-in', () => {
    const window = run(blockStorage);
    const store = window.localStorage as unknown as Storage & { memory?: boolean };
    assert.equal(store.memory, true);
    assert.equal(store.getItem('lte-theme'), null);
    store.setItem('lte-theme', 'dark');
    assert.equal(store.getItem('lte-theme'), 'dark');
    store.removeItem('lte-theme');
    assert.equal(store.getItem('lte-theme'), null);
  });

  it('does not replace working storage', () => {
    assert.equal((run(() => undefined).localStorage as unknown as { memory?: boolean }).memory, undefined);
  });
});
