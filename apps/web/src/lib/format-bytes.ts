/**
 * Human-readable byte-volume formatting for traffic windows.
 *
 * An unreported volume renders as "Not reported" rather than "0 B": a missing
 * measurement must never read as a measured absence of traffic.
 */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const;

export const BYTES_UNREPORTED = 'Not reported';

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) {
    return BYTES_UNREPORTED;
  }

  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${rounded} ${UNITS[unit]}`;
}

export function formatShare(share: number | null | undefined): string {
  if (share === null || share === undefined || !Number.isFinite(share)) {
    return 'share not reported';
  }
  return `${Math.round(share * 1000) / 10}%`;
}