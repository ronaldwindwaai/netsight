import Link from 'next/link';

import { TRAFFIC_PRESET_OPTIONS, trafficHref } from '@/lib/traffic-view';
import type { FilterValues, TrafficSection, TrafficWindow } from '@/lib/traffic-view';

/**
 * Time-range picker: presets as plain links and a custom UTC range as a plain GET form, so it works
 * without client script and the selected window is always in the address. The server re-checks the
 * bounds (31 days, 7 for the baseline surface); a range it would refuse is replaced by the default and
 * this says so.
 */
export function TimeRangePicker({
  section,
  window,
  maxDays,
  filters = {},
}: {
  section: Exclude<TrafficSection, 'overview'> | 'overview';
  window: TrafficWindow;
  maxDays: number;
  filters?: FilterValues;
}) {
  const action = section === 'overview' ? '/traffic' : `/traffic/${section}`;
  const hidden = Object.entries(filters).sort(([a], [b]) => a.localeCompare(b));
  return (
    <div className="traffic-time-range d-flex flex-wrap align-items-end gap-3">
      <div className="btn-group btn-group-sm" role="group" aria-label="Time range">
        {TRAFFIC_PRESET_OPTIONS.map((option) => {
          const active = window.preset === option.id;
          return (
            <Link
              key={option.id}
              href={trafficHref(section, { ...window, query: `preset=${option.id}` }, filters)}
              className={`btn btn-outline-secondary${active ? ' active' : ''}`}
              aria-current={active ? 'true' : undefined}
            >
              {option.label}
            </Link>
          );
        })}
      </div>
      <form
        method="get"
        action={action}
        role="search"
        aria-label="Custom time range"
        className="d-flex flex-wrap align-items-end gap-2"
      >
        {hidden.map(([name, value]) => (
          <input key={name} type="hidden" name={name} value={value} />
        ))}
        <div>
          <label className="form-label small mb-0" htmlFor={`${section}-from`}>
            From (UTC)
          </label>
          <input
            id={`${section}-from`}
            className="form-control form-control-sm"
            type="datetime-local"
            name="from"
            defaultValue={window.fromInput}
            required
          />
        </div>
        <div>
          <label className="form-label small mb-0" htmlFor={`${section}-to`}>
            To (UTC)
          </label>
          <input
            id={`${section}-to`}
            className="form-control form-control-sm"
            type="datetime-local"
            name="to"
            defaultValue={window.toInput}
            required
          />
        </div>
        <button type="submit" className="btn btn-sm btn-outline-primary">
          Apply
        </button>
        <span className="small text-body-secondary align-self-center">
          at most {maxDays} days, not in the future
        </span>
      </form>
      {window.adjusted ? (
        <p className="small text-body-secondary mb-0" role="status">
          The requested time range could not be used, so the default ({window.label}) is shown.
        </p>
      ) : null}
    </div>
  );
}
