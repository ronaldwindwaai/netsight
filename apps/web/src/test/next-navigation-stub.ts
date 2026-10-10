/** Stands in for `next/navigation` in component tests: a router that only counts refreshes. */
export const routerSpy = {
  refreshCount: 0,
  reset(): void {
    this.refreshCount = 0;
  },
};

const router = {
  refresh(): void {
    routerSpy.refreshCount += 1;
  },
  push(): void {},
  replace(): void {},
  back(): void {},
  forward(): void {},
  prefetch(): void {},
};

export function useRouter(): typeof router {
  return router;
}
