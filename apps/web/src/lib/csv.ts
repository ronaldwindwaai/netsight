/** Client-side CSV helpers. Cells that a spreadsheet could read as a formula are neutralised. */

export type CsvValue = string | number | boolean | null | undefined;

const FORMULA_LEAD = /^[=+\-@\t\r]/;
const NEEDS_QUOTES = /[",\r\n]/;

/** One RFC 4180 cell, with a leading quote added to anything starting = + - @ (or tab/CR). */
export function csvCell(value: CsvValue): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : '';
  const text = String(value);
  const safe = FORMULA_LEAD.test(text) ? `'${text}` : text;
  return NEEDS_QUOTES.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

export function toCsv(headers: readonly string[], rows: readonly (readonly CsvValue[])[]): string {
  const lines = [headers, ...rows].map((row) => row.map(csvCell).join(','));
  return `${lines.join('\r\n')}\r\n`;
}

/** `devices-uk-2026-10-21.csv`: lowercase, hyphenated, dated in UTC. */
export function csvFilename(label: string, now: Date): string {
  const slug = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return `${slug || 'export'}-${now.toISOString().slice(0, 10)}.csv`;
}
