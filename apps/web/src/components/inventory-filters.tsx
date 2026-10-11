import Link from 'next/link';

import { ASSET_CLASSES, DEVICE_STATUSES, ITEM_SOURCES } from '@/lib/api-contracts-inventory';
import { classLabel, filtersInUse, type InventoryQuery } from '@/lib/inventory-view';

const SOURCE_OPTIONS = { netbox: 'NetBox only', discovered: 'Telemetry only', both: 'Both' } as const;

/**
 * A plain GET form: the filters live in the URL, so a view can be bookmarked and shared, and nothing
 * here needs a script. The values are validated again on the server before they reach the API.
 */
export function InventoryFilters({ query }: { query: InventoryQuery }) {
  return (
    <form method="get" action="/inventory" className="row g-2 align-items-end mb-3" aria-label="Inventory filters">
      <div className="col-12 col-md-3">
        <label className="form-label small mb-1" htmlFor="inventory-q">
          Search name, address or MAC
        </label>
        <input
          id="inventory-q"
          name="q"
          type="search"
          className="form-control form-control-sm"
          maxLength={64}
          defaultValue={query.q ?? ''}
          autoComplete="off"
        />
      </div>
      <div className="col-6 col-md-2">
        <label className="form-label small mb-1" htmlFor="inventory-class">
          Class
        </label>
        <select id="inventory-class" name="asset_class" className="form-select form-select-sm" defaultValue={query.assetClass ?? ''}>
          <option value="">All classes</option>
          {ASSET_CLASSES.map((value) => (
            <option key={value} value={value}>
              {classLabel(value)}
            </option>
          ))}
        </select>
      </div>
      <div className="col-6 col-md-2">
        <label className="form-label small mb-1" htmlFor="inventory-site">
          Site
        </label>
        <input
          id="inventory-site"
          name="site"
          type="text"
          className="form-control form-control-sm"
          maxLength={255}
          defaultValue={query.site ?? ''}
          autoComplete="off"
        />
      </div>
      <div className="col-6 col-md-2">
        <label className="form-label small mb-1" htmlFor="inventory-status">
          Observed status
        </label>
        <select id="inventory-status" name="status" className="form-select form-select-sm" defaultValue={query.status ?? ''}>
          <option value="">Any status</option>
          {DEVICE_STATUSES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>
      <div className="col-6 col-md-2">
        <label className="form-label small mb-1" htmlFor="inventory-source">
          Seen by
        </label>
        <select id="inventory-source" name="source" className="form-select form-select-sm" defaultValue={query.source ?? ''}>
          <option value="">Any source</option>
          {ITEM_SOURCES.map((value) => (
            <option key={value} value={value}>
              {SOURCE_OPTIONS[value]}
            </option>
          ))}
        </select>
      </div>
      <div className="col-6 col-md-2">
        <label className="form-label small mb-1" htmlFor="inventory-known">
          Known to NetBox
        </label>
        <select
          id="inventory-known"
          name="known"
          className="form-select form-select-sm"
          defaultValue={query.known === null ? '' : String(query.known)}
        >
          <option value="">Known and unknown</option>
          <option value="true">Known</option>
          <option value="false">Unknown</option>
        </select>
      </div>
      <div className="col-12 col-md-auto d-flex gap-2">
        <button type="submit" className="btn btn-primary btn-sm">
          <i className="bi bi-funnel me-1" aria-hidden="true" />
          Apply filters
        </button>
        {filtersInUse(query) ? (
          <Link className="btn btn-outline-secondary btn-sm" href="/inventory">
            Clear
          </Link>
        ) : null}
      </div>
    </form>
  );
}
