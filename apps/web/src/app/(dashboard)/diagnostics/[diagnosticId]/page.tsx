import { AppContent } from '@/components/app-content';

import { DiagnosticSessionPage } from '@/components/diagnostic-session-page';
import { DiagnosticsAccessDenied } from '@/components/diagnostics-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseDiagnosticSessionResponse } from '@/lib/api-contracts-diagnostic-session';
import { sessionApiPath } from '@/lib/diagnostic-session-view';
import { canUseDiagnostics, viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'Diagnostic session' };

/**
 * A stored diagnostic session, read-only. The identifier from the address is checked against the
 * exact session id format before any request is made, and the API response must satisfy the
 * session contract or the page shows an explicit error instead of a guess.
 */
export default async function DiagnosticSessionRoute({
  params,
}: {
  params: Promise<{ diagnosticId: string }>;
}) {
  const { diagnosticId } = await params;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const allowed = canUseDiagnostics(
    viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null),
  );
  const path = sessionApiPath(diagnosticId);
  // Without diagnostics:read the API would refuse anyway; do not ask, and say why.
  const state = !allowed || path === null ? null : await apiGet(path, parseDiagnosticSessionResponse);

  return (
    <AppContent
      title="Diagnostic session"
      breadcrumbs={[
        { label: 'Overview', href: '/overview' },
        { label: 'Diagnostics', href: '/diagnostics' },
        { label: 'Session' },
      ]}
    >
      {allowed ? (
        <DiagnosticSessionPage state={state} nowMs={new Date().getTime()} />
      ) : (
        <DiagnosticsAccessDenied />
      )}
    </AppContent>
  );
}
