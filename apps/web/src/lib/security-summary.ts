import { ALERT_SEVERITIES } from './api-contracts.ts';
import type { AlertSeverity } from './api-contracts.ts';
import type { SecurityEvent } from './api-contracts-security.ts';

export type SeverityCounts = Record<AlertSeverity, number>;

/**
 * Count the listed events per severity.
 *
 * These are counts of the events returned for the window (server-bounded to
 * 500), not totals reported by the source, and callers must label them so.
 */
export function severityCounts(events: readonly SecurityEvent[]): SeverityCounts {
  const counts = Object.fromEntries(
    ALERT_SEVERITIES.map((severity) => [severity, 0]),
  ) as SeverityCounts;
  for (const event of events) {
    counts[event.severity] += 1;
  }
  return counts;
}
