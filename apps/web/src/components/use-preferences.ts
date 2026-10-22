'use client';

import { useSyncExternalStore } from 'react';

import {
  DEFAULT_PREFERENCES,
  deserializePreferences,
  readPreferences,
  serializePreferences,
  writePreference,
} from '@/lib/preferences';
import type { Preferences } from '@/lib/preferences';

/** Same-tab change signal; other tabs are covered by the native `storage` event. */
const CHANGED = 'netsight:preferences-changed';
const SERVER_SNAPSHOT = serializePreferences(DEFAULT_PREFERENCES);

/** Choices that could not be stored (blocked storage) still apply for the rest of this page view. */
let unsaved: Partial<Preferences> = {};

/**
 * Another tab changed storage: the stored value is now the truth again, so a stale "could not save"
 * choice no longer overrides it.
 */
function onStorageEvent(): void {
  unsaved = {};
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener(CHANGED, onChange);
  window.addEventListener('storage', onStorageEvent);
  window.addEventListener('storage', onChange);
  return () => {
    window.removeEventListener(CHANGED, onChange);
    window.removeEventListener('storage', onStorageEvent);
    window.removeEventListener('storage', onChange);
  };
}

const current = (): Preferences => ({ ...readPreferences(), ...unsaved });
const snapshot = () => serializePreferences(current());
const serverSnapshot = () => SERVER_SNAPSHOT;
const noSubscription = () => () => undefined;

function omit(from: Partial<Preferences>, name: keyof Preferences): Partial<Preferences> {
  return Object.fromEntries(Object.entries(from).filter(([key]) => key !== name));
}

/** `raw` is a stable text form, so the object keeps its identity until a value really changes. */
let cache = { raw: SERVER_SNAPSHOT, value: DEFAULT_PREFERENCES };
function parsed(raw: string): Preferences {
  if (cache.raw !== raw) cache = { raw, value: deserializePreferences(raw) };
  return cache.value;
}

export interface PreferencesApi {
  readonly preferences: Preferences;
  /** False during server render and hydration, when `preferences` are the defaults rather than the stored values. */
  readonly live: boolean;
  /** Saves one preference; resolves false when storage is unavailable (the change then lasts for this page view only). */
  readonly set: <K extends keyof Preferences>(name: K, value: Preferences[K]) => boolean;
}

/** Stored display preferences. Server and first client render use the defaults, then the stored values apply. */
export function usePreferences(): PreferencesApi {
  const raw = useSyncExternalStore(subscribe, snapshot, serverSnapshot);
  const preferences = parsed(raw);
  const live = useSyncExternalStore(noSubscription, () => true, () => false);
  return {
    preferences,
    live,
    set: (name, value) => {
      const saved = writePreference(name, value);
      unsaved = saved ? omit(unsaved, name) : { ...unsaved, [name]: value };
      window.dispatchEvent(new window.Event(CHANGED));
      return saved;
    },
  };
}
