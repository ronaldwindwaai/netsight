import { AppContent } from '@adminlte/react';
import { notFound } from 'next/navigation';

import { Step8AccessDenied } from '@/components/step8-access-denied';
import { UnknownDeviceActionsPanel } from '@/components/unknown-device-actions-panel';
import { UnknownDeviceDetailBody } from '@/components/unknown-device-detail-body';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import {
  FINDING_ID,
  parseUnknownDeviceDetail,
  parseUnknownDeviceTimeline,
} from '@/lib/api-contracts-unknown-devices';
import { timelinePath } from '@/lib/unknown-device-view';
import { canReadFindings, canReadFindingsSummary, viewerFromSession } from '@/lib/viewer';

export default async function UnknownDevicePage({ params }: { params: Promise<{ findingId: string }> }) {
  const { findingId } = await params;
  // A malformed id never reaches the API path: it is a 404 here.
  if (!FINDING_ID.test(findingId)) notFound();

  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [
    { label: 'Overview', href: '/overview' },
    { label: 'Unknown devices', href: '/unknown-devices' },
    { label: 'Finding' },
  ];
  if (!canReadFindings(viewer)) {
    // Management holds only the counts; it has no per-finding page.
    return (
      <AppContent title="Unknown device" breadcrumbs={crumbs}>
        {canReadFindingsSummary(viewer) ? (
          <UnknownDeviceDetailBody
            state={{ kind: 'forbidden', code: 'FORBIDDEN', message: '', correlationId: 'n/a', status: 403 }}
            actions={null}
            timeline={null}
          />
        ) : (
          <Step8AccessDenied surface="Unknown devices" permission="unknown-devices:read-summary" />
        )}
      </AppContent>
    );
  }
  const [detail, timeline] = await Promise.all([
    apiGet(`/api/v1/unknown-devices/${encodeURIComponent(findingId)}`, parseUnknownDeviceDetail),
    apiGet(timelinePath(findingId), parseUnknownDeviceTimeline),
  ]);
  const item = detail.kind === 'ok' ? detail.data.item : null;
  return (
    <AppContent title="Unknown device" breadcrumbs={crumbs}>
      <UnknownDeviceDetailBody
        state={detail}
        timeline={timeline}
        actions={
          item === null ? null : (
            <UnknownDeviceActionsPanel
              finding={{ id: item.id, state: item.state, assignee_id: item.assignee_id }}
              viewer={viewer}
              currentPath={`/unknown-devices/${findingId}`}
            />
          )
        }
      />
    </AppContent>
  );
}
