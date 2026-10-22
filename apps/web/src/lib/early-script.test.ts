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

  it('does not replace a working store whose getItem throws', () => {
    const window = run((w) => {
      Object.defineProperty(w.Storage.prototype, 'getItem', {
        configurable: true,
        value() {
          throw new w.DOMException('quota', 'QuotaExceededError');
        },
      });
    });
    assert.equal((window.localStorage as unknown as { memory?: boolean }).memory, undefined);
    assert.equal(window.document.documentElement.dataset.density, undefined);
  });

  it('keeps keys such as __proto__ as ordinary data in the stand-in', () => {
    const store = run(blockStorage).localStorage as unknown as Storage;
    assert.equal(store.getItem('__proto__'), null);
    assert.equal(store.getItem('toString'), null);
    store.setItem('__proto__', 'x');
    assert.equal(store.getItem('__proto__'), 'x');
    assert.equal(store.length, 1);
    assert.equal(store.key(0), '__proto__');
    store.removeItem('__proto__');
    assert.equal(store.getItem('__proto__'), null);
  });

  it('gives the stand-in the rest of the Storage surface: length, key and clear', () => {
    const store = run(blockStorage).localStorage as unknown as Storage;
    store.setItem('a', '1');
    store.setItem('b', '2');
    assert.equal(store.length, 2);
    assert.equal(store.key(0), 'a');
    assert.equal(store.key(1), 'b');
    assert.equal(store.key(2), null);
    store.clear();
    assert.equal(store.length, 0);
  });
});
