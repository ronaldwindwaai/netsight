'use client';

import { csvFilename, toCsv } from '@/lib/csv';
import type { CsvValue } from '@/lib/csv';

interface ExportCsvButtonProps {
  /** Names the file: `<label>-<yyyy-mm-dd>.csv`. */
  readonly label: string;
  readonly headers: readonly string[];
  /** The rows exactly as currently filtered and sorted on screen. */
  readonly rows: readonly (readonly CsvValue[])[];
}

function download(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** Exports the rows in view as CSV, built in the browser; formula-looking cells are neutralised. */
export function ExportCsvButton({ label, headers, rows }: ExportCsvButtonProps) {
  return (
    <button
      className="btn btn-sm btn-outline-secondary"
      disabled={rows.length === 0}
      onClick={() => download(csvFilename(label, new Date()), toCsv(headers, rows))}
      title={`Download the ${rows.length} rows currently shown as a CSV file`}
      type="button"
    >
      <i className="bi bi-download me-1" aria-hidden="true" />
      Export CSV
    </button>
  );
}
