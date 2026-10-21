import { AppContent } from '@/components/app-content';
import { notFound } from 'next/navigation';

import { ActionDecisionPanel } from '@/components/action-decision-panel';
import { ActionDetailBody } from '@/components/action-detail-body';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { actionPath } from '@/lib/actions-view';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { ACTION_ID, parseActionDetail, parseActionStatus } from '@/lib/api-contracts-actions';
import { canReadActions, viewerFromSession } from '@/lib/viewer';

export default async function ActionPage({ params }: { params: Promise<{ actionId: string }> }) {
  const { actionId } = await params;
  // A malformed id never reaches the API path: it is a 404 here.
  const path = ACTION_ID.test(actionId) ? actionPath(actionId) : null;
  if (path === null) notFound();

  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [
    { label: 'Overview', href: '/overview' },
    { label: 'Action requests', href: '/actions' },
    { label: 'Request' },
  ];
  if (!canReadActions(viewer)) {
    return (
      <AppContent title="Action request" breadcrumbs={crumbs}>
        <Step8AccessDenied surface="Action requests" permission="actions:read" />
      </AppContent>
    );
  }
  const [detail, status] = await Promise.all([
    apiGet(path, parseActionDetail),
    apiGet('/api/v1/actions/status', parseActionStatus),
  ]);
  const statusData = status.kind === 'ok' ? status.data : null;
  return (
    <AppContent title="Action request" breadcrumbs={crumbs}>
      <ActionDetailBody
        state={detail}
        status={statusData}
        viewer={viewer}
        panel={
          detail.kind === 'ok' ? (
            <ActionDecisionPanel
              request={detail.data.request}
              viewer={viewer}
              status={statusData}
              currentPath={`/actions/${actionId}`}
            />
          ) : null
        }
      />
    </AppContent>
  );
}
