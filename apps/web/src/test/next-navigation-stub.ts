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
  },
  replace(): void {},
  back(): void {},
  forward(): void {},
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
