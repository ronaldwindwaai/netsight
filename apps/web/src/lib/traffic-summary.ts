import type { TrafficFlow } from '@/lib/api-contracts';

export interface ApplicationVolume {
  /** Source-reported application, or null for the unattributed remainder. */
  application: string | null;
  bytes: number;
  share: number;
}

/**
 * Application distribution across the *listed* high-volume flows.
 *
 * The flows endpoint returns the highest-byte flows for the window, not a
 * full application mix, so this summarises only the rows already on screen.
 * It is arithmetic over source-reported values — never an estimate.
 *
 * The denominator is the total bytes of *all* listed flows, so shares are a
 * true fraction of the listed traffic. Flows that report no application are
 * surfaced as a single `null` "unattributed" bucket rather than being dropped,
 * so the bars reconcile to the listed total and no known application is
 * overstated by a hidden remainder.
 */
export function applicationMix(flows: TrafficFlow[]): ApplicationVolume[] {
  const totals = new Map<string, number>();
  let grand = 0;

  for (const flow of flows) {
    grand += flow.bytes;
    const key = flow.application ?? "";
    totals.set(key, (totals.get(key) ?? 0) + flow.bytes);
  }

  if (grand === 0) return [];

  return Array.from(totals, ([key, bytes]) => ({
    application: key === '' ? null : key,
    bytes,
    share: bytes / grand,
  })).sort(
    (left, right) =>
      right.bytes - left.bytes ||
      (left.application ?? '').localeCompare(right.application ?? ''),
  );
}
