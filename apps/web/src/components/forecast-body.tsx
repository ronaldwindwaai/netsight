/**
 * The capacity forecast page body for every outcome of the read: permission, unauthenticated,
 * error, nothing connected, unknown, not enough history and the forecast itself. Nothing here reads
 * an API. The forecast notice comes before any figure, series states are words with icons, a
 * forecast is never drawn or listed as a measurement, and recommendations are advice with their
 * evidence and no control. Series names and advice text are untrusted data rendered as text.
 */
import { AppCard } from '@/components/app-card';

import { DataFailure } from '@/components/data-state';
import { ForecastSeriesCard } from '@/components/forecast-series-card';
import { StateSurface } from '@/components/state-surface';
import { NOTICE, type ForecastResponse } from '@/lib/api-contracts-forecast';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  HISTORY_OPTIONS,
  HORIZON_OPTIONS,
  exportPath,
  pageSurface,
  type ForecastQuery,
} from '@/lib/forecast-view';
import type { FetchState } from '@/lib/api-response';

function Notice() {
  return (
    <div className="alert alert-info d-flex align-items-start gap-2 mb-3" role="note">
      <i className="bi bi-info-circle mt-1" aria-hidden="true" />
      <div>
        <strong>Forecast, not measurement.</strong>{' '}
        {NOTICE.replace('Forecast, not measurement. ', '')} Nothing here changes a device or a
        setting.
      </div>
    </div>
  );
}

function Controls({ query, canExport }: { query: ForecastQuery; canExport: boolean }) {
  return (
    <div className="d-flex flex-wrap align-items-end gap-3 mb-3">
      <form method="get" action="/forecast" className="d-flex flex-wrap align-items-end gap-2">
        <div>
          <label className="form-label small mb-1" htmlFor="forecast-horizon">
            Forecast ahead
          </label>
          <select
            id="forecast-horizon"
            name="horizon_days"
            className="form-select form-select-sm"
            defaultValue={String(query.horizon)}
          >
            {HORIZON_OPTIONS.map((days) => (
              <option key={days} value={String(days)}>
                {days} days
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="form-label small mb-1" htmlFor="forecast-history">
            Measured history
          </label>
          <select
            id="forecast-history"
            name="history_days"
            className="form-select form-select-sm"
            defaultValue={String(query.history)}
          >
            {HISTORY_OPTIONS.map((days) => (
              <option key={days} value={String(days)}>
                {days} days
              </option>
            ))}
          </select>
        </div>
        <button type="submit" className="btn btn-sm btn-outline-primary">
          Update
        </button>
      </form>
      {canExport && (
        <a className="btn btn-sm btn-outline-secondary" href={exportPath(query)}>
          <i className="bi bi-download me-1" aria-hidden="true" />
          Download capacity report (CSV)
        </a>
      )}
    </div>
  );
}

const OVERALL: Record<'not-connected' | 'unknown' | 'insufficient-data', { icon: string; title: string; detail: string }> = {
  'not-connected': {
    icon: 'bi bi-plug',
    title: 'No forecast can be made',
    detail:
      'No series has a source that reports its history. This is not the same as having no traffic: nothing is estimated in its place.',
  },
  unknown: {
    icon: 'bi bi-question-circle',
    title: 'Forecast state unknown',
    detail:
      'A configured source could not be read. Nothing is estimated in its place, and this is not a statement that capacity is fine.',
  },
  'insufficient-data': {
    icon: 'bi bi-hourglass-split',
    title: 'No forecast can be made yet',
    detail:
      'There is not enough recent history to project from. The measured days are shown; no projected value is.',
  },
};

function Recommendations({ data }: { data: ForecastResponse }) {
  return (
    <section aria-labelledby="forecast-recommendations" className="mt-3">
      <AppCard title="Recommendations" icon="bi bi-lightbulb" variant="outline" theme="secondary">
        <h2 id="forecast-recommendations" className="visually-hidden">
          Recommendations
        </h2>
        <p className="small text-body-secondary">
          Advisory only. Netsight does not act on these, and none becomes an action request by
          itself. Each line shows the numbers it came from.
        </p>
        {data.recommendations.length === 0 ? (
          <p className="mb-0">
            No recommendations. This is not a statement that capacity is fine: only a few explicit
            rules are checked, and only on series that have a forecast.
          </p>
        ) : (
          <ul className="list-unstyled mb-0">
            {data.recommendations.map((item) => (
              <li key={item.id} className="mb-3">
                <p className="mb-1">
                  <span className="badge text-bg-secondary me-2">Advisory</span>
                  <strong className="text-break">{item.title}</strong>
                </p>
                <p className="mb-1 text-break">{item.advice}</p>
                <ul className="small text-body-secondary mb-0">
                  {item.evidence.map((line) => (
                    <li key={line} className="text-break">
                      {line}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        )}
      </AppCard>
    </section>
  );
}

export function ForecastBody({
  state,
  query,
  canExport,
}: {
  state: FetchState<ForecastResponse>;
  query: ForecastQuery;
  canExport: boolean;
}) {
  const surface = pageSurface(state);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="Capacity forecasts are not available to your role"
          detail="Reading forecasts needs the forecast:read permission, which your role does not hold. Access is enforced by the Netsight API."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  const overall = data.state === 'ok' ? null : OVERALL[data.state];
  return (
    <div>
      <Notice />
      <Controls query={query} canExport={canExport} />
      {overall !== null && (
        <div className="mb-3">
          <StateSurface icon={overall.icon} title={overall.title} detail={overall.detail} />
        </div>
      )}
      {data.series.map((series) => (
        <ForecastSeriesCard key={series.id} series={series} />
      ))}
      <Recommendations data={data} />
      <p className="small text-body-secondary mt-3 mb-0">
        Generated {formatUtcTimestamp(data.generated_at)}
        {data.history_through === null ? '' : `; measured history runs to ${data.history_through}`}. Days
        are whole UTC days.
      </p>
    </div>
  );
}

