'use client';

import { useId, useState, useSyncExternalStore } from 'react';

import { usePreferences } from '@/components/use-preferences';
import { DENSITIES, isStoragePersistent } from '@/lib/preferences';
import type { Density, Preferences } from '@/lib/preferences';
import { PAGE_SIZES } from '@/lib/page-state';

const DENSITY_LABEL: Record<Density, string> = { comfortable: 'Comfortable', compact: 'Compact' };

/**
 * Display preferences for this browser. Nothing here is sent to the server: choices are saved in
 * localStorage, and the page still works (for this view) when storage is blocked.
 */
export function PreferencesPanel() {
  const { preferences, set } = usePreferences();
  const [saveFailed, setSaveFailed] = useState(false);
  // Server and first client render assume storage works; the real answer applies right after hydration.
  const storageBlocked = useSyncExternalStore(
    () => () => undefined,
    () => !isStoragePersistent(),
    () => false,
  );
  const storageFailed = saveFailed || storageBlocked;
  const shortcutsId = useId();
  const shortcutsHint = useId();
  const sizeId = useId();
  const sizeHint = useId();

  function save<K extends keyof Preferences>(name: K, value: Preferences[K]) {
    setSaveFailed(!set(name, value));
  }

  return (
    <form className="card preferences-panel" onSubmit={(event) => event.preventDefault()}>
      <div className="card-body">
        <div className="form-check form-switch mb-1">
          <input
            aria-describedby={shortcutsHint}
            checked={preferences.shortcuts}
            className="form-check-input"
            id={shortcutsId}
            onChange={(event) => save('shortcuts', event.target.checked)}
            role="switch"
            type="checkbox"
          />
          <label className="form-check-label" htmlFor={shortcutsId}>
            Keyboard shortcuts
          </label>
        </div>
        <p className="small text-body-secondary mb-4" id={shortcutsHint}>
          Pressing <kbd>/</kbd> outside a text field jumps to the page finder. Turn this off if single-key shortcuts get in
          the way of speech input or assistive technology.
        </p>

        <fieldset className="mb-4">
          <legend className="h6">Table density</legend>
          {DENSITIES.map((density) => (
            <div className="form-check" key={density}>
              <input
                checked={preferences.density === density}
                className="form-check-input"
                id={`${sizeId}-density-${density}`}
                name="density"
                onChange={() => save('density', density)}
                type="radio"
                value={density}
              />
              <label className="form-check-label" htmlFor={`${sizeId}-density-${density}`}>
                {DENSITY_LABEL[density]}
              </label>
            </div>
          ))}
          <p className="small text-body-secondary mt-1 mb-0">Compact tightens row spacing so more rows fit on screen.</p>
        </fieldset>

        <div className="mb-2">
          <label className="form-label" htmlFor={sizeId}>
            Rows per page in lists
          </label>
          <select
            aria-describedby={sizeHint}
            className="form-select w-auto"
            id={sizeId}
            onChange={(event) => save('pageSize', Number(event.target.value))}
            value={preferences.pageSize}
          >
            {PAGE_SIZES.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
          <p className="small text-body-secondary mt-1 mb-0" id={sizeHint}>
            Used when a list address does not already say how many rows to show. A page size in the address always wins.
          </p>
        </div>

        <p className="small mb-0 mt-3" role="status">
          {storageFailed
            ? 'This browser blocked saving, so your choices apply to this page view only.'
            : 'Saved in this browser only.'}
        </p>
      </div>
    </form>
  );
}
