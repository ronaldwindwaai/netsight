import { DEVICE_STATUSES } from './api-contracts.ts';
import type { Device, DeviceStatus } from './api-contracts.ts';

export type DeviceSortKey = 'status' | 'name' | 'ip' | 'type' | 'site' | 'freshness';
export type SortDirection = 'asc' | 'desc';

/** Most urgent first, so an ascending status sort puts the problems on top. */
const STATUS_RANK: Readonly<Record<DeviceStatus, number>> = {
  critical: 0,
  offline: 1,
  degraded: 2,
  warning: 3,
  unknown: 4,
  maintenance: 5,
  healthy: 6,
};

const FRESHNESS_RANK = { stale: 0, unknown: 1, fresh: 2 } as const;

/** A missing value sorts after every real one in both directions. */
function compareText(a: string | null, b: string | null, direction: SortDirection): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  const result = a.localeCompare(b, 'en', { numeric: true, sensitivity: 'base' });
  return direction === 'asc' ? result : -result;
}

function compareNumber(a: number, b: number, direction: SortDirection): number {
  return direction === 'asc' ? a - b : b - a;
}

function compareBy(key: DeviceSortKey, direction: SortDirection) {
  return (a: Device, b: Device): number => {
    switch (key) {
      case 'status':
        return compareNumber(STATUS_RANK[a.status], STATUS_RANK[b.status], direction);
      case 'freshness':
        return compareNumber(
          FRESHNESS_RANK[a.freshness.state],
          FRESHNESS_RANK[b.freshness.state],
          direction,
        );
      case 'ip':
        return compareText(a.ip_addresses[0] ?? null, b.ip_addresses[0] ?? null, direction);
      case 'type':
        return compareText(a.type || null, b.type || null, direction);
      case 'site':
        return compareText(a.site_id, b.site_id, direction);
      default:
        return compareText(a.name, b.name, direction);
    }
  };
}

/** A new array: the input is never reordered. Ties keep the order the API returned. */
export function sortDevices(
  devices: readonly Device[],
  key: DeviceSortKey,
  direction: SortDirection,
): Device[] {
  const compare = compareBy(key, direction);
  return devices
    .map((device, index) => ({ device, index }))
    .sort((a, b) => compare(a.device, b.device) || a.index - b.index)
    .map((entry) => entry.device);
}

/** Count per status for the rows given; every status is present so a zero is explicit. */
export function countByStatus(devices: readonly Device[]): Record<DeviceStatus, number> {
  const counts = Object.fromEntries(DEVICE_STATUSES.map((s) => [s, 0])) as Record<DeviceStatus, number>;
  for (const device of devices) counts[device.status] += 1;
  return counts;
}

export interface SortState {
  key: DeviceSortKey;
  direction: SortDirection;
}

/** First click on a column sorts ascending; clicking the sorted column again flips it. */
export function nextSort(current: SortState | null, key: DeviceSortKey): SortState {
  if (current === null || current.key !== key) return { key, direction: 'asc' };
  return { key, direction: current.direction === 'asc' ? 'desc' : 'asc' };
}

/** What sorting and filtering cover, given how many devices this page holds of the total. */
export function pageScopeNote(loaded: number, total: number): string {
  if (loaded === 0) return 'No devices are loaded on this page.';
  const noun = loaded === 1 ? 'device' : 'devices';
  const lead = `Sorting and filters apply to the ${loaded} ${noun} loaded on this page`;
  if (total > loaded) return `${lead}; use the page controls below for the other ${total - loaded}.`;
  return `${lead}, which is all of them.`;
}
