import { AppContent } from '@adminlte/react';

import { DiagnosticSessionList } from '@/components/diagnostic-session-list';
import { DiagnosticsAccessDenied } from '@/components/diagnostics-access-denied';
import { DiagnosticsRunner } from '@/components/diagnostics-runner';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseDiagnosticSessionListResponse } from '@/lib/api-contracts-diagnostic-session';
import { parseListOffset, sessionListPath } from '@/lib/diagnostic-session-view';
import { canUseDiagnostics, viewerFromSession } from '@/lib/viewer';

const TARGET_LIMIT = 255;

export default async function DiagnosticsPage({
  searchParams,
}: {
  searchParams: Promise<{ target?: string | string[]; offset?: string | string[] }>;
}) {
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  if (!canUseDiagnostics(viewer)) {
    // Management and Auditor hold no diagnostics permission: no form, and no API call to be refused.
    return (
      <AppContent
        title="Root cause analysis"
        breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Diagnostics' }]}
      >
        <DiagnosticsAccessDenied />
      </AppContent>
    );
  }
  const params = await searchParams;
  const offset = parseListOffset(params.offset);
  const sessions = await apiGet(sessionListPath(offset), parseDiagnosticSessionListResponse);
  const requested = params.target;
  const initialTarget =
    typeof requested === 'string' && requested.trim().length > 0
      ? requested.trim().slice(0, TARGET_LIMIT)
      : null;

  return (
    <AppContent
      title="Root cause analysis"
      breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Diagnostics' }]}
    >
      <div className="page-intro">
        <p className="lead mb-1">Why is the target unreachable or degraded?</p>
        <p className="text-body-secondary mb-0">
          Read-only blackbox diagnostics: bounded checks from the configured probe locations,
          correlated into a probable fault domain. Every result is evidence — checks that cannot be answered report
          unknown instead of guessing, and a probable cause is only named when the evidence narrows
          to one.
        </p>
      </div>

      <DiagnosticsRunner initialTarget={initialTarget} />

      <DiagnosticSessionList state={sessions} offset={offset} />
    </AppContent>
  );
}
