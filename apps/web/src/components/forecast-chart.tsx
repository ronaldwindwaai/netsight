import { useId } from 'react';

import type { ForecastSeries } from '@/lib/api-contracts-forecast';
import { buildChart, describeSeries, formatAmount, tableRows } from '@/lib/forecast-view';

/**
 * A series as an accessible chart: measured days as a solid line, the forecast as a separate
 * dashed line with a hatched approximate-95 % band (so it differs by shape and pattern, not only by
 * colour), a break where days are missing, and never a point where the source reported none. The
 * svg has a name and a description saying what is measured and what is forecast, and the same
 * numbers are available as a table. Series names and values are untrusted text rendered as text.
 */
export function ForecastChart({ series }: { series: ForecastSeries }) {
  const raw = useId();
  const id = raw.replace(/[^a-zA-Z0-9_-]/g, '');
  const chart = buildChart(series);
  if (chart === null) return null;
  const hatch = `forecast-hatch-${id}`;
  const rows = tableRows(series);
  return (
    <figure className="forecast-chart mb-3">
      <svg
        role="img"
        viewBox={`0 0 ${chart.width} ${chart.height}`}
        aria-labelledby={`forecast-title-${id}`}
        aria-describedby={`forecast-desc-${id}`}
        focusable="false"
      >
        <title id={`forecast-title-${id}`}>{`${series.name}: measured and forecast`}</title>
        <desc id={`forecast-desc-${id}`}>{describeSeries(series)}</desc>
        <defs>
          <pattern id={hatch} width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <line x1="0" y1="0" x2="0" y2="6" className="forecast-hatch-line" strokeWidth="2" />
          </pattern>
        </defs>
        {chart.yTicks.map((tick) => (
          <g key={tick.value}>
            <line className="forecast-grid" x1={chart.plot.left} x2={chart.plot.right} y1={tick.position} y2={tick.position} />
            <text className="forecast-axis" x={chart.plot.left - 6} y={tick.position + 4} textAnchor="end">
              {tick.label}
            </text>
          </g>
        ))}
        {chart.xTicks.map((tick, index) => (
          <text
            key={tick.label}
            className="forecast-axis"
            x={tick.x}
            y={chart.plot.bottom + 18}
            textAnchor={index === 0 ? 'start' : 'end'}
          >
            {tick.label}
          </text>
        ))}
        {chart.bandPath !== null && (
          <path data-forecast-band d={chart.bandPath} fill={`url(#${hatch})`} className="forecast-band" />
        )}
        {chart.thresholdY !== null && (
          <line
            className="forecast-limit"
            x1={chart.plot.left}
            x2={chart.plot.right}
            y1={chart.thresholdY}
            y2={chart.thresholdY}
            strokeDasharray="2 4"
          />
        )}
        {chart.forecastPath !== null && (
          <>
            <line className="forecast-boundary" x1={chart.boundaryX} x2={chart.boundaryX} y1={chart.plot.top} y2={chart.plot.bottom} />
            <path data-forecast-line d={chart.forecastPath} className="forecast-line" strokeDasharray="7 5" fill="none" />
          </>
        )}
        {chart.measuredPaths.map((path) => (
          <path key={path} data-measured-line d={path} className="measured-line" fill="none" />
        ))}
        {chart.isolated.map((dot) => (
          <circle key={`${dot.x}-${dot.y}`} className="measured-dot" cx={dot.x} cy={dot.y} r="3" />
        ))}
      </svg>
      <ul className="forecast-key list-inline small text-body-secondary mb-2" aria-label="Chart key">
        <li className="list-inline-item">
          <span className="forecast-key__swatch forecast-key__swatch--measured" aria-hidden="true" /> Measured (solid line)
        </li>
        {series.forecast.length > 0 && (
          <>
            <li className="list-inline-item">
              <span className="forecast-key__swatch forecast-key__swatch--forecast" aria-hidden="true" /> Forecast (dashed line)
            </li>
            <li className="list-inline-item">
              <span className="forecast-key__swatch forecast-key__swatch--band" aria-hidden="true" /> Approximate 95 % range (hatched)
            </li>
          </>
        )}
        {chart.thresholdY !== null && series.threshold !== null && (
          <li className="list-inline-item">
            Limit you configured (dotted): {formatAmount(series.threshold.value, series.unit)}
          </li>
        )}
      </ul>
      <figcaption className="visually-hidden">{describeSeries(series)}</figcaption>
      <details className="small">
        <summary>Data table ({rows.length} days)</summary>
        <div className="table-responsive">
          <table className="table table-sm table-striped mb-0">
            <caption className="visually-hidden">{`${series.name}: measured and forecast days`}</caption>
            <thead>
              <tr>
                <th scope="col">Day</th>
                <th scope="col">Kind</th>
                <th scope="col">Value</th>
                <th scope="col">Approximate 95 % range</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.kind}-${row.day}`} data-kind={row.kind}>
                  <td>{row.day}</td>
                  <td>{row.kind === 'measured' ? 'Measured' : 'Forecast'}</td>
                  <td>{row.value}</td>
                  <td>{row.range ?? 'Not applicable'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}
