import { Badge, Card } from '@adminlte/react';

import { ForecastChart } from '@/components/forecast-chart';
import type { ForecastSeries } from '@/lib/api-contracts-forecast';
import { formatUtcTimestamp } from '@/lib/format-time';
import { formatAmount, reasonText, statePresentation, uniqueNotes } from '@/lib/forecast-view';

function StateBadge({ series }: { series: ForecastSeries }) {
  const view = statePresentation(series.state);
  return (
    <span data-state-badge title={view.explanation}>
      <Badge theme={view.theme} pill>
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        {view.label}
      </Badge>
    </span>
  );
}

function LimitLine({ series }: { series: ForecastSeries }) {
  if (series.threshold === null || series.crossing === null) return null;
  const limit = formatAmount(series.threshold.value, series.unit);
  const { point_day: point, upper_day: upper } = series.crossing;
  let text = `The limit you configured (${limit}) is not reached within the forecast.`;
  if (point !== null) {
    text = `The forecast reaches the limit you configured (${limit}) on ${point}${
      upper !== null && upper !== point ? `; the upper edge of its range reaches it on ${upper}` : ''
    }.`;
  } else if (upper !== null) {
    text = `Only the upper edge of the range reaches the limit you configured (${limit}), on ${upper}.`;
  }
  return <p className="mb-2">{text}</p>;
}

function Method({ series }: { series: ForecastSeries }) {
  const method = series.method;
  if (method === null) return null;
  return (
    <dl className="row small mb-0">
      <dt className="col-sm-3">Method</dt>
      <dd className="col-sm-9">
        {method.name === 'linear-trend' ? 'Linear trend' : 'Weekly repeat'} (a transparent calculation,
        not a model)
      </dd>
      <dt className="col-sm-3">Why this method</dt>
      <dd className="col-sm-9 text-break">{method.why}</dd>
      <dt className="col-sm-3">History used</dt>
      <dd className="col-sm-9">
        {method.observed_days} measured days
        {series.history_missing_days > 0
          ? `, ${series.history_missing_days} days without data left out (never filled in)`
          : ''}
        .
      </dd>
      <dt className="col-sm-3">Range</dt>
      <dd className="col-sm-9">
        Approximate 95 %, from how far past values sat from the method. It does not allow for a
        change in behaviour.
      </dd>
      {series.source_observed_at !== null && (
        <>
          <dt className="col-sm-3">Source</dt>
          <dd className="col-sm-9">Newest data read {formatUtcTimestamp(series.source_observed_at)}.</dd>
        </>
      )}
    </dl>
  );
}

function WithoutForecast({ series }: { series: ForecastSeries }) {
  const view = statePresentation(series.state);
  return (
    <div role="status" className="small">
      <p className="mb-1">{view.explanation}</p>
      {uniqueNotes([series.reason === null ? null : reasonText(series.reason), series.detail]).map((note) => (
        <p key={note} className="mb-1 text-break">
          {note}
        </p>
      ))}
    </div>
  );
}

/** One series: its state as a word and icon, the chart when there are measured days, the method. */
export function ForecastSeriesCard({ series }: { series: ForecastSeries }) {
  return (
    <Card
      title={series.name}
      icon="bi bi-graph-up"
      variant="outline"
      theme="primary"
      tools={<StateBadge series={series} />}
    >
      <ForecastChart series={series} />
      {series.state === 'ok' ? (
        <>
          <LimitLine series={series} />
          <Method series={series} />
        </>
      ) : (
        <WithoutForecast series={series} />
      )}
    </Card>
  );
}
