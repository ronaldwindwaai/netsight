import { useSyncExternalStore } from 'react';

/** Stands in for `next/navigation` in component tests: a router that only counts refreshes. */
export const routerSpy = {
  refreshCount: 0,
  pushed: [] as string[],
  /** Runs inside `refresh()`, so a test can start work that keeps the surrounding transition pending. */
  onRefresh: null as (() => void) | null,
  reset(): void {
    this.refreshCount = 0;
    this.pushed = [];
    this.onRefresh = null;
  },
};

const router = {
  refresh(): void {
    routerSpy.refreshCount += 1;
    routerSpy.onRefresh?.();
  },
  push(href: string): void {
    routerSpy.pushed = [...routerSpy.pushed, href];
    window.history.pushState(null, '', href);
  },
  replace(href: string): void {
    window.history.replaceState(null, '', href);
  },
  back(): void {
    window.history.back();
  },
  forward(): void {
    window.history.forward();
  },
  prefetch(): void {},
};

export function useRouter(): typeof router {
  return router;
}

/** The path `usePathname` reports; tests change it to simulate client-side navigation. */
export const pathnameSpy = { value: '/' };

export function usePathname(): string {
  return pathnameSpy.value;
}

// `useSearchParams` follows the jsdom location, as Next does once `history.pushState/replaceState`
// are patched. The patch below announces every change so subscribed components re-render.
/**
 * Real Next applies a URL change to `useSearchParams` inside a transition, so a component sees the
 * new value a render later. Set `deferred` to deliver changes that way (a macrotask after the call).
 */
export const locationSpy = { deferred: false };

const LOCATION_CHANGED = 'netsight:test-location-changed';

if (typeof window !== 'undefined' && !(window.history as { __patched?: boolean }).__patched) {
  for (const method of ['pushState', 'replaceState'] as const) {
    const original = window.history[method].bind(window.history);
    window.history[method] = (...args: Parameters<History['pushState']>) => {
      original(...args);
      const announce = () => window.dispatchEvent(new window.Event(LOCATION_CHANGED));
      if (locationSpy.deferred) setTimeout(announce, 0);
      else announce();
    };
  }
  (window.history as { __patched?: boolean }).__patched = true;
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener(LOCATION_CHANGED, onChange);
  window.addEventListener('popstate', onChange);
  return () => {
    window.removeEventListener(LOCATION_CHANGED, onChange);
    window.removeEventListener('popstate', onChange);
  };
}

export function useSearchParams(): URLSearchParams {
  const search = useSyncExternalStore(subscribe, () => window.location.search, () => '');
  return new URLSearchParams(search);
}
