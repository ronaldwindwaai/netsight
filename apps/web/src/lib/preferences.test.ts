import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  DEFAULT_PREFERENCES,
  deserializePreferences,
  isStoragePersistent,
  PREFERENCE_KEYS,
  readPreferences,
  serializePreferences,
  writePreference,
} from './preferences.ts';

function memoryStore(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
    removeItem: (key: string) => void data.delete(key),
  };
}

const blocked = {
  getItem: () => {
    throw new Error('blocked');
  },
  setItem: () => {
    throw new Error('blocked');
  },
  removeItem: () => {
    throw new Error('blocked');
  },
};

describe('readPreferences', () => {
  it('returns the defaults for empty storage', () => {
    assert.deepEqual(readPreferences(memoryStore()), DEFAULT_PREFERENCES);
  });

  it('reads stored values', () => {
    const store = memoryStore({
      [PREFERENCE_KEYS.shortcuts]: 'off',
      [PREFERENCE_KEYS.density]: 'compact',
      [PREFERENCE_KEYS.pageSize]: '100',
    });
    assert.deepEqual(readPreferences(store), { shortcuts: false, density: 'compact', pageSize: 100 });
  });

  it('ignores unknown or tampered values', () => {
    const store = memoryStore({
      [PREFERENCE_KEYS.shortcuts]: 'maybe',
      [PREFERENCE_KEYS.density]: 'huge',
      [PREFERENCE_KEYS.pageSize]: '7',
    });
    assert.deepEqual(readPreferences(store), DEFAULT_PREFERENCES);
  });

  it('falls back to the defaults when storage is blocked or missing', () => {
    assert.deepEqual(readPreferences(blocked), DEFAULT_PREFERENCES);
    assert.deepEqual(readPreferences(undefined), DEFAULT_PREFERENCES);
  });
});

describe('writePreference', () => {
  it('stores non-default values and removes defaults so storage stays minimal', () => {
    const store = memoryStore();
    assert.equal(writePreference('density', 'compact', store), true);
    assert.equal(store.data.get(PREFERENCE_KEYS.density), 'compact');
    assert.equal(writePreference('density', 'comfortable', store), true);
    assert.equal(store.data.has(PREFERENCE_KEYS.density), false);
    writePreference('shortcuts', false, store);
    assert.equal(store.data.get(PREFERENCE_KEYS.shortcuts), 'off');
    writePreference('shortcuts', true, store);
    assert.equal(store.data.has(PREFERENCE_KEYS.shortcuts), false);
    writePreference('pageSize', 25, store);
    assert.equal(store.data.get(PREFERENCE_KEYS.pageSize), '25');
    writePreference('pageSize', 50, store);
    assert.equal(store.data.has(PREFERENCE_KEYS.pageSize), false);
  });

  it('reports failure instead of throwing when storage is blocked', () => {
    assert.equal(writePreference('density', 'compact', blocked), false);
    assert.equal(writePreference('density', 'compact', undefined), false);
  });
});

describe('serializePreferences', () => {
  it('is stable for equal values so it can back an external-store snapshot', () => {
    assert.equal(serializePreferences(DEFAULT_PREFERENCES), serializePreferences({ ...DEFAULT_PREFERENCES }));
  });

  it('round-trips and tolerates garbage', () => {
    const value = { shortcuts: false, density: 'compact', pageSize: 25 } as const;
    assert.deepEqual(deserializePreferences(serializePreferences(value)), value);
    assert.deepEqual(deserializePreferences('nonsense'), DEFAULT_PREFERENCES);
    assert.deepEqual(deserializePreferences(''), DEFAULT_PREFERENCES);
  });

  it('knows when storage cannot persist', () => {
    assert.equal(isStoragePersistent(memoryStore()), true);
    assert.equal(isStoragePersistent({ ...memoryStore(), memory: true }), false);
    assert.equal(isStoragePersistent(undefined), false);
  });
});
