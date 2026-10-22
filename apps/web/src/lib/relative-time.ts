const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
const RELATIVE_LIMIT_DAYS = 30;
const CLOCK_SKEW_MS = MINUTE_MS;

function unit(ms: number): string {
  if (ms < HOUR_MS) return `${Math.max(1, Math.floor(ms / MINUTE_MS))} min`;
  if (ms < DAY_MS) return `${Math.floor(ms / HOUR_MS)} h`;
  return `${Math.floor(ms / DAY_MS)} d`;
}

/** "3 min ago", "2 h ago", "5 d ago"; a date beyond 30 days. The exact UTC value belongs in a title. */
export function formatRelativeTime(value: string, nowMs: number): string {
  const instant = Date.parse(value);
  if (Number.isNaN(instant)) return 'Unknown time';
  const delta = nowMs - instant;
  if (Math.abs(delta) < CLOCK_SKEW_MS) return 'just now';
  if (delta < 0) return `in ${unit(-delta)}`;
  if (delta >= RELATIVE_LIMIT_DAYS * DAY_MS) return new Date(instant).toISOString().slice(0, 10);
  return `${unit(delta)} ago`;
}
