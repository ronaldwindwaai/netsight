import { DEFAULT_PAGE_SIZE, PAGE_SIZES, pageSizeCookie } from './page-state.ts';
import { SHORTCUTS_STORAGE_KEY } from './keyboard-shortcuts.ts';

/**
 * Client-only display preferences, kept in localStorage. They are conveniences: every read and
 * write tolerates unavailable storage, and nothing here is a credential or reaches the API.
 */
export type Density = 'comfortable' | 'compact';
export const DENSITIES: readonly Density[] = ['comfortable', 'compact'];

export interface Preferences {
  readonly shortcuts: boolean;
  readonly density: Density;
  readonly pageSize: number;
}

export const DEFAULT_PREFERENCES: Preferences = {
  shortcuts: true,
  density: 'comfortable',
  pageSize: DEFAULT_PAGE_SIZE,
};

export const PREFERENCE_KEYS = {
  shortcuts: SHORTCUTS_STORAGE_KEY,
  density: 'netsight.density',
  pageSize: 'netsight.page_size',
} as const;

export interface PreferenceStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** The browser's localStorage, or undefined where touching it throws (blocked, private window). */
export function browserStore(): PreferenceStore | undefined {
  try {
    return globalThis.localStorage ?? undefined;
  } catch {
    return undefined;
  }
}

/**
 * False when choices cannot outlive the page: storage is missing, throws, or is the in-memory stand-in
 * the early script installs when the browser blocks storage (see early-script.ts).
 */
export function isStoragePersistent(store: (PreferenceStore & { memory?: boolean }) | undefined = browserStore()): boolean {
  return store !== undefined && store.memory !== true;
}

export function readPreferences(store: PreferenceStore | undefined = browserStore()): Preferences {
  if (store === undefined) return DEFAULT_PREFERENCES;
  try {
    const density = store.getItem(PREFERENCE_KEYS.density);
    const rawSize = store.getItem(PREFERENCE_KEYS.pageSize);
    const size = rawSize === null ? Number.NaN : Number(rawSize);
    return {
      shortcuts: store.getItem(PREFERENCE_KEYS.shortcuts) !== 'off',
      density: density === 'compact' ? 'compact' : 'comfortable',
      pageSize: (PAGE_SIZES as readonly number[]).includes(size) ? size : DEFAULT_PAGE_SIZE,
    };
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

/** Stable text form of the preferences, usable as an external-store snapshot. */
export function serializePreferences(preferences: Preferences): string {
  return `${preferences.shortcuts ? 'on' : 'off'}|${preferences.density}|${preferences.pageSize}`;
}

/** Inverse of `serializePreferences`; anything unrecognised falls back to the default for that field. */
export function deserializePreferences(text: string): Preferences {
  const [shortcuts, density, size] = text.split('|');
  const pageSize = Number(size);
  return {
    shortcuts: shortcuts !== 'off',
    density: density === 'compact' ? 'compact' : 'comfortable',
    pageSize: (PAGE_SIZES as readonly number[]).includes(pageSize) ? pageSize : DEFAULT_PAGE_SIZE,
  };
}

/** Stores one preference (defaults are removed so storage stays minimal). Returns false when storage fails. */
export function writePreference<K extends keyof Preferences>(
  name: K,
  value: Preferences[K],
  store: PreferenceStore | undefined = browserStore(),
): boolean {
  if (store === undefined) return false;
  const key = PREFERENCE_KEYS[name];
  const isDefault = value === DEFAULT_PREFERENCES[name];
  try {
    if (isDefault) store.removeItem(key);
    else store.setItem(key, name === 'shortcuts' ? 'off' : String(value));
    return true;
  } catch {
    return false;
  }
}

/** Mirrors the preferred list size into a cookie the server can read; failures (cookies blocked) are ignored. */
export function writePageSizeCookie(size: number): void {
  try {
    document.cookie = pageSizeCookie(size, window.location.protocol === 'https:');
  } catch {
    // The preference still works from the address; only the server-side default is lost.
  }
}
