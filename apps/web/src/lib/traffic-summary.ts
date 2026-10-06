import type { TrafficFlow } from '@/lib/api-contracts';

export interface ApplicationVolume {
  application: string;
  bytes: number;
  share: number;
}

/**
 * Application distribution across the *listed* high-volume flows.
 *
 * The flows endpoint returns the highest-byte flows for the window, not a
 * full application mix, so this summarises only the rows already on screen.
 * It is arithmetic over source-reported values — never an estimate — and the
 * page labels it accordingly. Flows without application metadata are excluded
 * from the denominator so an unknown application never dilutes a known one.
 */
export function applicationMix(flows: TrafficFlow[]): ApplicationVolume[] {
  const totals = new Map<string, number>();
  let grand = 0;

  for (const flow of flows) {
    if (!flow.application) continue;
    totals.set(flow.application, (totals.get(flow.application) ?? 0) + flow.bytes);
    grand += flow.bytes;
  }

  if (grand === 0) return [];

  return Array.from(totals, ([application, bytes]) => ({
    application,
    bytes,
    share: bytes / grand,
  })).sort((left, right) => right.bytes - left.bytes || left.application.localeCompare(right.application));
}