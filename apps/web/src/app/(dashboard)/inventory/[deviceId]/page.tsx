import { AppContent } from '@/components/app-content';
import { notFound } from 'next/navigation';

import { InventoryDetailBody } from '@/components/inventory-detail-body';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseInventoryDetail } from '@/lib/api-contracts-inventory';
import { isInventoryId } from '@/lib/inventory-view';
import { canReadInventory, canReadInventorySummary, viewerFromSession } from '@/lib/viewer';

export default async function InventoryItemPage({ params }: { params: Promise<{ deviceId: string }> }) {
  const { deviceId } = await params;
  // A malformed id never reaches the API path: it is a 404 here.
  if (!isInventoryId(deviceId)) notFound();

  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [
    { label: 'Overview', href: '/overview' },
    { label: 'Inventory', href: '/inventory' },
    { label: 'Asset' },
  ];
  if (!canReadInventory(viewer)) {
    // Management holds only the counts; it has no per-asset page.
    return (
      <AppContent title="Asset" breadcrumbs={crumbs}>
        {canReadInventorySummary(viewer) ? (
          <InventoryDetailBody
            state={{ kind: 'forbidden', code: 'FORBIDDEN', message: '', correlationId: 'n/a', status: 403 }}
            permissions={viewer?.permissions ?? null}
          />
        ) : (
          <Step8AccessDenied surface="Inventory" permission="inventory:read-summary" />
        )}
      </AppContent>
    );
  }
  const detail = await apiGet(`/api/v1/inventory/${encodeURIComponent(deviceId)}`, parseInventoryDetail);
  return (
    <AppContent title="Asset" breadcrumbs={crumbs}>
      <InventoryDetailBody state={detail} permissions={viewer?.permissions ?? null} />
    </AppContent>
  );
}
