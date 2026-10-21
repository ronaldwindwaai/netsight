'use client';

import { useEffect } from 'react';

import { usePreferences } from '@/components/use-preferences';

/**
 * Applies the stored table density to the page. The root layout sets the attribute before first
 * paint; this keeps it in step when the preference changes (here or in another tab).
 */
export function DisplayPreferences() {
  const { preferences } = usePreferences();
  useEffect(() => {
    document.documentElement.dataset.density = preferences.density;
  }, [preferences.density]);
  return null;
}
