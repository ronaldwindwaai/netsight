import { AppContent } from '@/components/app-content';

import { InventoryBody } from '@/components/inventory-body';
import { InventoryFilters } from '@/components/inventory-filters';
import { InventorySummaryCard } from '@/components/counts-cards';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseInventoryList, parseInventorySummaryResponse } from '@/lib/api-contracts-inventory';
import { inventoryPath, parseInventoryQuery } from '@/lib/inventory-view';
import { canReadInventory, canReadInventorySummary, viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'Inventory' };

type Params = Record<string, string | string[] | undefined>;

export default async function InventoryPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [{ label: 'Overview', href: '/overview' }, { label: 'Inventory' }];

  if (!canReadInventorySummary(viewer)) {
    // No inventory permission at all: no form and no API call to be refused.
    return (
      <AppContent title="Inventory" breadcrumbs={crumbs}>
        <Step8AccessDenied surface="Inventory" permission="inventory:read-summary" />
      </AppContent>
    );
  }

  const rows = canReadInventory(viewer);
  // The query is validated before it can reach an API path: an unusable filter is dropped.
  const query = parseInventoryQuery(params);
  const [list, summary] = await Promise.all([
    rows ? apiGet(inventoryPath(query), parseInventoryList) : null,
    rows ? null : apiGet('/api/v1/inventory/summary', parseInventorySummaryResponse),
  ]);

  return (
    <AppContent title="Inventory" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Every asset NetBox intends, merged with what monitoring telemetry discovers. NetBox is the
          authority for intended state: where telemetry disagrees the NetBox value is shown and both
          readings are listed. The class comes only from the operator&apos;s NetBox role and type map;
          anything it does not name is unclassified, and an asset NetBox does not know is an unknown
          asset. Nothing here is written back to NetBox.
        </p>
      </div>
      {summary !== null ? <InventorySummaryCard state={summary} /> : null}
      {list !== null ? (
        <>
          <InventoryFilters query={query} />
          <InventoryBody state={list} query={query} />
        </>
      ) : null}
    </AppContent>
  );
}
