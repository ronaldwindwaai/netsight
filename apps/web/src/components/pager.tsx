import Link from 'next/link';

import type { PageHrefs } from '@/lib/incident-view';

/** Previous/next paging; a missing direction renders as a disabled, non-focusable control. */
export function Pager({ label, hrefs }: { label: string; hrefs: PageHrefs }) {
  if (hrefs.previous === null && hrefs.next === null) return null;
  return (
    <nav className="d-flex align-items-center justify-content-between p-3" aria-label={label}>
      {hrefs.previous === null ? (
        <span className="btn btn-outline-secondary btn-sm disabled" aria-disabled="true">
          <i className="bi bi-chevron-left me-1" aria-hidden="true" />
          Previous
        </span>
      ) : (
        <Link className="btn btn-outline-secondary btn-sm" href={hrefs.previous}>
          <i className="bi bi-chevron-left me-1" aria-hidden="true" />
          Previous
        </Link>
      )}
      {hrefs.next === null ? (
        <span className="btn btn-outline-secondary btn-sm disabled" aria-disabled="true">
          Next
          <i className="bi bi-chevron-right ms-1" aria-hidden="true" />
        </span>
      ) : (
        <Link className="btn btn-outline-secondary btn-sm" href={hrefs.next}>
          Next
          <i className="bi bi-chevron-right ms-1" aria-hidden="true" />
        </Link>
      )}
    </nav>
  );
}
