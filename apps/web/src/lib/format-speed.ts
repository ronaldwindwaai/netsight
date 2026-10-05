/**
 * Human-readable link speed formatting.
 *
 * An unreported speed is rendered as "Not reported" rather than 0 bps: a
 * missing measurement must never read as a measured absence of bandwidth.
 */

const UNITS = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'] as const;

export const SPEED_UNREPORTED = 'Not reported';

export function formatSpeed(speedBps: number | null | undefined): string {
  if (speedBps === null || speedBps === undefined || !Number.isFinite(speedBps)) {
    return SPEED_UNREPORTED;
  }
  if (speedBps < 0) return SPEED_UNREPORTED;

  let value = speedBps;
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${rounded} ${UNITS[unit]}`;
}