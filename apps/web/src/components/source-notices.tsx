import type { DataSourceStatus } from '@/lib/api-contracts-sources';
import { degradedSources, sourceLabel } from '@/lib/inventory-view';

const STATE_TEXT = {
  'not-connected': 'is not connected',
  unknown: 'is configured but could not be read',
  ok: 'was read',
} as const;

/**
 * Names every source that was not read this time, so a missing source is never invisible and
 * never looks like a healthy empty result. Nothing is shown when every source was read.
 */
export function SourceNotices({
  sources,
  consequence = 'Values and comparisons that depend on it are absent or marked "Not checked"; nothing is estimated in their place.',
}: {
  sources: readonly DataSourceStatus[];
  consequence?: string;
}) {
  const degraded = degradedSources(sources);
  if (degraded.length === 0) return null;
  return (
    <div className="alert alert-warning py-2" role="status">
      <p className="fw-semibold mb-1">
        <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
        {degraded.length === 1 ? 'A source was not read' : 'Some sources were not read'}
      </p>
      <ul className="mb-1">
        {degraded.map((source) => (
          <li key={source.source}>
            {sourceLabel(source.source)} {STATE_TEXT[source.state]}.
          </li>
        ))}
      </ul>
      <p className="small mb-0">{consequence}</p>
    </div>
  );
}

/** "NetBox read 12:00:00 UTC · LibreNMS not connected": the sources behind a figure, in one line. */
export function SourceLine({ sources, formatTime }: { sources: readonly DataSourceStatus[]; formatTime: (iso: string) => string }) {
  return (
    <p className="small text-body-secondary mt-2 mb-0">
      Sources:{' '}
      {sources
        .map((s) =>
          s.state === 'ok' && s.observed_at !== null
            ? `${sourceLabel(s.source)} read ${formatTime(s.observed_at)}`
            : `${sourceLabel(s.source)} ${s.state === 'unknown' ? 'unreadable' : 'not connected'}`,
        )
        .join(' · ')}
      .
    </p>
  );
}
