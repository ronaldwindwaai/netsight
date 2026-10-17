'use client';
export function PrintReport({ readable }: {readable: boolean}) {
  return <div className="mb-3" data-report-controls>
    <button className="btn btn-outline-secondary" type="button" disabled={!readable} onClick={() => window.print()}>
      <i className="bi bi-printer me-1" aria-hidden="true" />Print / save PDF
    </button>
    {!readable ? <p className="small text-body-secondary mt-2">A readable report is required before printing.</p> : null}
  </div>;
}
