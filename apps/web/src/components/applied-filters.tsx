import Link from 'next/link';

import type { FilterName } from '@/lib/api-contracts-traffic-explorer';
import { FILTER_LABELS } from '@/lib/traffic-filter-labels';
import { trafficHref } from '@/lib/traffic-view';
import type { FilterValues, TrafficWindow } from '@/lib/traffic-view';

const FILTER_ORDER = Object.keys(FILTER_LABELS) as FilterName[];

function without(values: FilterValues, name: FilterName): FilterValues {
  const rest = { ...values };
  delete rest[name];
  return rest;
}

/**
 * What the current view is narrowed by, in words: the time window (always) and every applied
 * filter, each with a link that removes just that filter. Values are validated upstream and are
 * rendered as text. The chips carry the filter name, so meaning never rests on colour.
 */
export function AppliedFilters({
  window,
  values,
}: {
  window: TrafficWindow;
  values: FilterValues;
}) {
  const names = FILTER_ORDER.filter((name) => values[name] !== undefined);
  return (
    <section aria-label="Applied filters" className="traffic-applied mb-3">
      <ul className="list-inline mb-0 d-flex flex-wrap align-items-center gap-2">
        <li className="list-inline-item m-0">
          <span className="badge text-bg-light border">
            <i className="bi bi-clock me-1" aria-hidden="true" />
            Time range: {window.label}
          </span>
        </li>
        {names.map((name) => {
          const text = `${FILTER_LABELS[name]}: ${values[name]}`;
          return (
            <li className="list-inline-item m-0" key={name}>
              <span className="badge text-bg-primary d-inline-flex align-items-center gap-1">
                <span>{text}</span>
                <Link
                  className="text-reset text-decoration-none"
                  href={trafficHref('flows', window, without(values, name))}
                  aria-label={`Remove filter ${text}`}
                  title="Remove this filter"
                >
                  <i className="bi bi-x-lg" aria-hidden="true" />
                </Link>
              </span>
            </li>
          );
        })}
        {names.length === 0 ? (
          <li className="list-inline-item m-0 small text-body-secondary">
            No other filters applied
          </li>
        ) : (
          <li className="list-inline-item m-0 small">
            <Link href={trafficHref('flows', window)}>Clear all filters</Link>
          </li>
        )}
      </ul>
    </section>
  );
}
