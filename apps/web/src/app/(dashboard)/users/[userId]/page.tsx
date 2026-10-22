import { AppContent } from '@/components/app-content';
import { notFound } from 'next/navigation';

import { UserDetailBody } from '@/components/user-detail-body';
import { UsersAccessDenied } from '@/components/users-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseUserDetailResponse } from '@/lib/api-contracts-identity';
import { detailPath } from '@/lib/identity-view';
import {
  canReadInventory,
  canReadPeople,
  canReadTrafficDetail,
  canReadUsersSummary,
  viewerFromSession,
} from '@/lib/viewer';

export default async function UserDetailPage({ params }: { params: Promise<{ userId: string }> }) {
  const { userId } = await params;
  // A malformed id never reaches the API path: it is a 404 here.
  const path = detailPath(userId);
  if (path === null) notFound();

  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [
    { label: 'Overview', href: '/overview' },
    { label: 'Users & Identity', href: '/users' },
    { label: 'Person' },
  ];
  if (!canReadPeople(viewer)) {
    // Browsing a person needs users:read; Management and Technician see no per-person page.
    return (
      <AppContent title="Person" breadcrumbs={crumbs}>
        {canReadUsersSummary(viewer) ? (
          <UserDetailBody state={{ kind: 'forbidden', code: 'FORBIDDEN', message: '', correlationId: 'n/a', status: 403 }} />
        ) : (
          <UsersAccessDenied />
        )}
      </AppContent>
    );
  }
  const detail = await apiGet(path, parseUserDetailResponse);
  return (
    <AppContent title="Person" breadcrumbs={crumbs}>
      <UserDetailBody
        state={detail}
        inspectFlows={canReadTrafficDetail(viewer)}
        access={{ people: true, devices: canReadInventory(viewer) }}
      />
    </AppContent>
  );
}
