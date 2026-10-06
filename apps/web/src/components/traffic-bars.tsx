import { formatBytes, formatShare } from '@/lib/format-bytes';
import type { TrafficItem } from '@/lib/api-contracts';

/**
 * Ranked bandwidth bars for a traffic aggregate.
 *
 * The source label is untrusted text and is rendered as data only. When the
 * source cannot compute a share, the bar falls back to a scale relative to the
 * largest row so the ranking stays readable without inventing a percentage.
 */
export function TrafficBars({ items }: { items: TrafficItem[] }) {
  const largest = Math.max(1, ...items.map((item) => item.bytes));

  return (
    <ol className="traffic-bars list-unstyled mb-0" aria-label="Bandwidth ranking">
      {items.map((item) => {
        const ratio = item.share ?? item.bytes / largest;
        const width = Math.max(2, Math.min(100, ratio * 100));
        return (
          <li className="traffic-bars__row" key={`${item.rank}:${item.label}`}>
            <div className="traffic-bars__meta">
              <span className="traffic-bars__rank" aria-hidden="true">
                {item.rank}
              </span>
              <span className="traffic-bars__label" title={item.label}>
                {item.label}
              </span>
              <span className="traffic-bars__value">
                {formatBytes(item.bytes)}
                <span className="text-body-secondary"> · {formatShare(item.share)}</span>
              </span>
            </div>
            <div className="progress traffic-bars__progress" role="presentation">
              <div className="progress-bar" style={{ width: `${width}%` }} />
            </div>
          </li>
        );
      })}
    </ol>
  );
}