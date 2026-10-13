import { formatBytes, formatShare } from '@/lib/format-bytes';

/** One ranked row. `bytes` is null for a row the server withheld for a small group. */
export interface BarItem {
  rank: number;
  /** Source-reported and untrusted: rendered as text only. */
  label: string;
  bytes: number | null;
  share: number | null;
}

/**
 * Ranked bandwidth bars for a traffic aggregate.
 *
 * The source label is untrusted text and is rendered as data only. When the
 * source cannot compute a share, the bar falls back to a scale relative to the
 * largest row so the ranking stays readable without inventing a percentage. A
 * withheld row (too few endpoints stood behind it) shows the word and no bar: it
 * has no volume to draw, and zero would be a claim.
 */
export function TrafficBars({
  items,
  withheldText = 'Withheld (too few endpoints)',
}: {
  items: readonly BarItem[];
  withheldText?: string;
}) {
  const largest = Math.max(1, ...items.map((item) => item.bytes ?? 0));

  return (
    <ol className="traffic-bars list-unstyled mb-0" aria-label="Bandwidth ranking">
      {items.map((item) => {
        const bytes = item.bytes;
        const ratio = bytes === null ? 0 : (item.share ?? bytes / largest);
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
                {bytes === null ? (
                  <span className="text-body-secondary">{withheldText}</span>
                ) : (
                  <>
                    {formatBytes(bytes)}
                    <span className="text-body-secondary"> · {formatShare(item.share)}</span>
                  </>
                )}
              </span>
            </div>
            {bytes === null ? null : (
              <div className="progress traffic-bars__progress" role="presentation">
                <div className="progress-bar" style={{ width: `${width}%` }} />
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}
