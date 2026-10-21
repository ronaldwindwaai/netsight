/**
 * Recent-changes panel of a stored diagnostic session (S7 Step 4c). Known changes near the failure
 * are listed as things that may correlate with it: temporal correlation is not causation. A source
 * that is not connected is said to be so (never "no changes"). Titles are untrusted text nodes.
 * An incident is shown as a reference (kind, severity, time): its title is not stored with the
 * session and is revealed only to a caller holding incidents:read, so a withheld title is said so.
 */
import { AppCard } from '@/components/app-card';

import { StateSurface } from '@/components/state-surface';
import type { DiagnosticRecentChanges } from '@/lib/api-contracts-diagnostic-session';
import { changeKindLabel, changeScopeLabel } from '@/lib/diagnostic-session-view';
import { formatUtcTimestamp } from '@/lib/format-time';
import { severityLabel } from '@/lib/incident-view';

const SOURCE_LABELS = {
  incidents: 'Incidents',
  alerts: 'Alerts',
  'configuration-changes': 'Configuration changes',
} as const;

const SOURCE_STATE_TEXT = {
  ok: 'read',
  'not-connected': 'not connected',
  unknown: 'could not be read',
} as const;

function SourceList({ sources }: { sources: DiagnosticRecentChanges['sources'] }) {
  return (
    <ul className="list-inline small text-body-secondary mb-0 mt-3" aria-label="Change sources">
      {sources.map((source) => (
        <li key={source.source} className="list-inline-item me-3">
          {SOURCE_LABELS[source.source]}: {SOURCE_STATE_TEXT[source.state]}
        </li>
      ))}
    </ul>
  );
}

function Body({ changes }: { changes: DiagnosticRecentChanges }) {
  if (changes.state === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title="Change source not connected"
        detail="No change source is connected, so this run cannot be compared with recent changes. This is not the same as there being no changes."
      />
    );
  }
  if (changes.state === 'unknown') {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="Recent changes unknown"
        detail="A connected change source could not be read, so nothing is shown in its place."
      />
    );
  }
  if (changes.items.length === 0) {
    return (
      <p className="mb-0">
        No changes were recorded by the connected sources in the window before the failure.
      </p>
    );
  }
  return (
    <ul className="list-group list-group-flush" aria-label="Changes near the failure">
      {changes.items.map((item) => (
        <li key={`${item.kind}-${item.ref_id}`} className="list-group-item px-0">
          <div className="d-flex flex-wrap align-items-center gap-2">
            <span className="badge text-bg-light border">{changeKindLabel(item.kind)}</span>
            {item.severity !== null ? (
              <span className="badge text-bg-secondary">{severityLabel(item.severity)}</span>
            ) : null}
            <span className={item.title_redacted ? 'fst-italic text-body-secondary' : 'fw-semibold'}>
              {item.title}
            </span>
            <span className="badge text-bg-info ms-auto">May correlate</span>
          </div>
          <div className="small text-body-secondary">
            {formatUtcTimestamp(item.occurred_at)} · {changeScopeLabel(item.scope)}
          </div>
          {item.title_redacted ? (
            <div className="small text-body-secondary">
              The incident title is withheld: it is not stored with this session and needs the
              incidents:read permission to be shown.
            </div>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function RecentChangesPanel({ changes }: { changes: DiagnosticRecentChanges }) {
  return (
    <section aria-label="Recent changes" className="mb-3">
      <AppCard
        className="operational-card"
        title="Recent changes"
        icon="bi bi-clock-history"
        variant="outline"
        theme="secondary"
        bodyClass="p-3"
      >
        <Body changes={changes} />
        <SourceList sources={changes.sources} />
        <p className="small text-body-secondary mb-0 mt-2">
          Window {formatUtcTimestamp(changes.window_start)} to {formatUtcTimestamp(changes.window_end)}.
          Temporal correlation is not causation: a change listed here may correlate with the failure
          and is not shown as its cause.
        </p>
      </AppCard>
    </section>
  );
}
