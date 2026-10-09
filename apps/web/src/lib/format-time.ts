const UNKNOWN_TIME = 'Unknown time';

/**
 * Fixed-format UTC rendering of an RFC 3339 instant.
 *
 * Deterministic (no locale or ICU dependence) so server and client render the
 * same text. An unparseable value is never echoed back.
 */
export function formatUtcTimestamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return UNKNOWN_TIME;
  return `${parsed.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}
