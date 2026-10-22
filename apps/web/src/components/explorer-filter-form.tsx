import Link from 'next/link';

import type { FilterName } from '@/lib/api-contracts-traffic-explorer';
import { FILTER_LABELS } from '@/lib/traffic-filter-labels';
import { trafficHref } from '@/lib/traffic-view';
import type { FilterValues, TrafficWindow } from '@/lib/traffic-view';

function Field({
  name,
  hint,
  children,
}: {
  name: FilterName;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="col-sm-6 col-lg-3 col-xl-2">
      <label className="form-label small mb-0" htmlFor={`filter-${name}`}>
        {FILTER_LABELS[name]}
      </label>
      {children}
      {hint ? <div className="form-text">{hint}</div> : null}
    </div>
  );
}

function textInput(
  name: FilterName,
  values: FilterValues,
  extra: Record<string, string | number> = {},
) {
  return (
    <input
      id={`filter-${name}`}
      className="form-control form-control-sm"
      name={name}
      defaultValue={values[name] ?? ''}
      autoComplete="off"
      {...extra}
    />
  );
}

/**
 * The Flow Explorer filters: an allow-listed set of fields in a plain GET form, so a filtered view
 * is a link. Address, device and VLAN filters narrow the read to a few endpoints and are offered
 * only to a viewer who holds the endpoint-level permission; the API refuses them otherwise. A value
 * the server would refuse is not sent, and the field name (never the value) is listed.
 */
export function ExplorerFilterForm({
  window,
  values,
  refused,
  detail,
}: {
  window: TrafficWindow;
  values: FilterValues;
  refused: readonly FilterName[];
  detail: boolean;
}) {
  return (
    <form
      method="get"
      action="/traffic/flows"
      role="search"
      aria-label="Flow filters"
      className="card card-body mb-3"
    >
      {window.preset !== null ? (
        <input type="hidden" name="preset" value={window.preset} />
      ) : (
        <>
          <input type="hidden" name="from" value={window.fromInput} />
          <input type="hidden" name="to" value={window.toInput} />
        </>
      )}
      <div className="row g-2 align-items-end">
        {detail ? (
          <>
            <Field name="source_ip">
              {textInput('source_ip', values, { maxLength: 45, inputMode: 'text' })}
            </Field>
            <Field name="destination_ip">
              {textInput('destination_ip', values, { maxLength: 45, inputMode: 'text' })}
            </Field>
            <Field name="device">{textInput('device', values, { maxLength: 128 })}</Field>
            <Field name="vlan">
              {textInput('vlan', values, {
                type: 'number',
                min: 0,
                max: 4094,
                inputMode: 'numeric',
              })}
            </Field>
          </>
        ) : null}
        <Field name="application">{textInput('application', values, { maxLength: 128 })}</Field>
        <Field name="protocol">
          <select
            id="filter-protocol"
            className="form-select form-select-sm"
            name="protocol"
            defaultValue={values.protocol ?? ''}
          >
            <option value="">Any</option>
            {['tcp', 'udp', 'icmp', 'other'].map((protocol) => (
              <option key={protocol} value={protocol}>
                {protocol}
              </option>
            ))}
          </select>
        </Field>
        <Field name="port" hint="Matches the destination port">
          {textInput('port', values, { type: 'number', min: 0, max: 65535, inputMode: 'numeric' })}
        </Field>
        <Field name="country" hint="Two letters, upper case">
          {textInput('country', values, { maxLength: 2, pattern: '[A-Z]{2}' })}
        </Field>
        <Field name="asn">
          {textInput('asn', values, { type: 'number', min: 1, max: 4294967295, inputMode: 'numeric' })}
        </Field>
        <Field name="direction" hint="Only where the source classifies interfaces">
          <select
            id="filter-direction"
            className="form-select form-select-sm"
            name="direction"
            defaultValue={values.direction ?? ''}
          >
            <option value="">Any</option>
            {['inbound', 'outbound', 'internal'].map((direction) => (
              <option key={direction} value={direction}>
                {direction}
              </option>
            ))}
          </select>
        </Field>
        <div className="col-auto">
          <button type="submit" className="btn btn-sm btn-primary">
            Apply filters
          </button>{' '}
          <Link className="btn btn-sm btn-outline-secondary" href={trafficHref('flows', window)}>
            Clear filters
          </Link>
        </div>
      </div>
      {detail ? null : (
        <p className="small text-body-secondary mt-2 mb-0">
          Filtering by address, exporter (device) or VLAN needs the traffic:read-detail permission,
          which your role does not hold: those filters can narrow a read to a handful of machines.
        </p>
      )}
      {refused.length > 0 ? (
        <p className="small text-body-secondary mt-2 mb-0" role="status">
          Not applied (not valid, or not allowed for your role):{' '}
          {refused.map((name) => FILTER_LABELS[name]).join(', ')}.
        </p>
      ) : null}
    </form>
  );
}
