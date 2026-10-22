'use client';

import { useId } from 'react';

import { csvFilename, toCsv } from '@/lib/csv';
import type { CsvValue } from '@/lib/csv';

interface ExportCsvButtonProps {
  /** Names the file: `<label>-<yyyy-mm-dd>.csv`. */
  readonly label: string;
  readonly headers: readonly string[];
  /** The rows exactly as currently filtered and sorted on screen. */
  readonly rows: readonly (readonly CsvValue[])[];
}

/** Excel reads a BOM-less UTF-8 file as ANSI; the BOM lives in the Blob so `toCsv` stays clean. */
const UTF8_BOM = '﻿';
/** The click has already handed the blob to the browser; keep the URL alive a moment for slow starts. */
export const REVOKE_DELAY_MS = 1000;

function download(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([UTF8_BOM, text], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), REVOKE_DELAY_MS);
}

/** Exports the rows in view as CSV, built in the browser; formula-looking cells are neutralised. */
export function ExportCsvButton({ label, headers, rows }: ExportCsvButtonProps) {
  const empty = rows.length === 0;
  const noteId = useId();
  return (
    <>
      <button
        aria-describedby={empty ? noteId : undefined}
        aria-disabled={empty}
        aria-label={`Export CSV, ${rows.length} ${label}`}
        className={`btn btn-sm btn-outline-secondary${empty ? ' disabled' : ''}`}
        onClick={() => {
          if (!empty) download(csvFilename(label, new Date()), toCsv(headers, rows));
        }}
        title={empty ? undefined : `Download the ${rows.length} rows currently shown as a CSV file`}
        type="button"
      >
        <i className="bi bi-download me-1" aria-hidden="true" />
        Export CSV
      </button>
      {empty ? (
        <span className="small text-body-secondary" id={noteId}>
          Nothing to export
        </span>
      ) : null}
    </>
  );
}
