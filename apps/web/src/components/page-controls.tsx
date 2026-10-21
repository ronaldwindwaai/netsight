'use client';

import Link from 'next/link';
import { usePathname, useSearchParams } from 'next/navigation';

import { PAGE_SIZES, describeRange, pageHref } from '@/lib/page-state';

interface PageControlsProps {
  /** What the rows are, plural: "devices". */
  readonly noun: string;
  readonly page: number;
  readonly pageSize: number;
  readonly total: number;
  /** Rows returned on this page. */
  readonly count: number;
  /** Accessible name of the pager landmark. */
  readonly label: string;
}

function Step({ href, disabled, children }: { href: string; disabled: boolean; children: React.ReactNode }) {
  if (disabled) {
    return (
      <span className="btn btn-outline-secondary btn-sm disabled" aria-disabled="true">
        {children}
      </span>
    );
  }
  return (
    <Link className="btn btn-outline-secondary btn-sm" href={href}>
      {children}
    </Link>
  );
}

/**
 * Page and page-size controls for a server-paginated list. The page and size live in the URL and
 * every other parameter (search, filters, sort) is kept. The summary says plainly when only part of
 * the data is loaded, because the API has no server-side filter: a search covers this page only.
 */
export function PageControls({ noun, page, pageSize, total, count, label }: PageControlsProps) {
  const pathname = usePathname();
  const params = useSearchParams();
  const range = describeRange({ page, pageSize, total, count });
  const hrefFor = (nextPage: number, nextSize = pageSize) =>
    pageHref(pathname, params, { page: nextPage, pageSize: nextSize });

  return (
    <nav className="page-controls d-flex flex-wrap align-items-center justify-content-between gap-2 mt-3" aria-label={label}>
      <p className="small text-body-secondary mb-0" role="status">
        {range.total === 0
          ? `No ${noun}.`
          : count === 0
            ? `Page ${page} is past the end: ${range.total.toLocaleString('en-GB')} ${noun} in ${range.pages} pages.`
            : `Showing ${range.from.toLocaleString('en-GB')}–${range.to.toLocaleString('en-GB')} of ${range.total.toLocaleString('en-GB')} ${noun}.`}
        {range.partial ? ` Search and filters only look at the ${count} loaded on this page.` : ''}
      </p>
      <div className="d-flex flex-wrap align-items-center gap-2">
        <div className="btn-group btn-group-sm" role="group" aria-label={`${noun} per page`}>
          {PAGE_SIZES.map((size) => (
            <Link
              aria-current={size === pageSize ? 'true' : undefined}
              aria-label={`${size} per page`}
              className={`btn btn-outline-secondary ${size === pageSize ? 'active' : ''}`}
              href={hrefFor(1, size)}
              key={size}
            >
              {size}
            </Link>
          ))}
        </div>
        <Step disabled={!range.hasPrevious} href={hrefFor(Math.max(1, page - 1))}>
          <i className="bi bi-chevron-left me-1" aria-hidden="true" />
          Previous
        </Step>
        <span className="small text-body-secondary">
          Page {page} of {range.pages}
        </span>
        <Step disabled={!range.hasNext} href={hrefFor(page + 1)}>
          Next
          <i className="bi bi-chevron-right ms-1" aria-hidden="true" />
        </Step>
      </div>
    </nav>
  );
}
