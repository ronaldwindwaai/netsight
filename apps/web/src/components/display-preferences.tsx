'use client';

import { useEffect } from 'react';

import { usePreferences } from '@/components/use-preferences';
import { writePageSizeCookie } from '@/lib/preferences';

/**
 * Applies the stored table density to the page and mirrors the preferred list size into a cookie the
 * server reads (so lists render at that size without a second fetch). The root layout sets the density
 * attribute before first paint; this keeps it in step when the preference changes (here or in another
 * tab). Until the stored values are live (server render and hydration use the defaults) it writes
 * nothing, so it cannot undo the early script's value; afterwards it writes only when the value differs.
 */
export function DisplayPreferences() {
  const { preferences, live } = usePreferences();
  useEffect(() => {
    if (!live) return;
    const root = document.documentElement;
    if (root.dataset.density !== preferences.density) root.dataset.density = preferences.density;
  }, [live, preferences.density]);
  useEffect(() => {
    if (live) writePageSizeCookie(preferences.pageSize);
  }, [live, preferences.pageSize]);
  return null;
}
