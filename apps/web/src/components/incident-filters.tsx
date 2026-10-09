import Link from 'next/link';

import {
  INCIDENT_SEVERITIES,
  INCIDENT_STATES,
} from '@/lib/api-contracts-incident';
import { severityLabel, stateLabel } from '@/lib/incident-view';
import type { IncidentFilters } from '@/lib/incident-view';

/**
 * Plain GET form: works without JavaScript, every control is natively keyboard
 * operable, and submitting always restarts paging at the first page.
 */
export function IncidentFiltersForm({ filters }: { filters: IncidentFilters }) {
  const active = filters.state !== null || filters.severity !== null || filters.assigneeId !== null;
  return (
    <form
      method="get"
      action="/incidents"
      className="row g-2 align-items-end mb-3"
      aria-label="Filter incidents"
    >
      <div className="col-6 col-md-3">
        <label htmlFor="incident-filter-state" className="form-label small mb-1">
          State
        </label>
        <select
          id="incident-filter-state"
          name="state"
          className="form-select form-select-sm"
          defaultValue={filters.state ?? ''}
        >
          <option value="">All states</option>
          {INCIDENT_STATES.map((state) => (
            <option key={state} value={state}>
              {stateLabel(state)}
            </option>
          ))}
        </select>
      </div>
      <div className="col-6 col-md-3">
        <label htmlFor="incident-filter-severity" className="form-label small mb-1">
          Severity
        </label>
        <select
          id="incident-filter-severity"
          name="severity"
          className="form-select form-select-sm"
          defaultValue={filters.severity ?? ''}
        >
          <option value="">All severities</option>
          {INCIDENT_SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {severityLabel(severity)}
            </option>
          ))}
        </select>
      </div>
      <div className="col-12 col-md-3">
        <label htmlFor="incident-filter-assignee" className="form-label small mb-1">
          Assignee
        </label>
        <input
          id="incident-filter-assignee"
          name="assignee_id"
          type="text"
          maxLength={255}
          className="form-control form-control-sm"
          defaultValue={filters.assigneeId ?? ''}
          placeholder="Exact assignee id"
          autoComplete="off"
        />
      </div>
      <div className="col-12 col-md-3 d-flex gap-2">
        <button type="submit" className="btn btn-primary btn-sm">
          <i className="bi bi-funnel me-1" aria-hidden="true" />
          Apply filters
        </button>
        {active ? (
          <Link className="btn btn-outline-secondary btn-sm" href="/incidents">
            Clear
          </Link>
        ) : null}
      </div>
    </form>
  );
}
