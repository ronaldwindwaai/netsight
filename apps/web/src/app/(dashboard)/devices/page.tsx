import { Suspense } from 'react';
import { AppContent } from '@/components/app-content';

import { DataFailure, EmptyState, FreshnessNotice, LoadingState } from '@/components/data-state';
import { DeviceTable } from '@/components/device-table';
import { PageControls } from '@/components/page-controls';
import { SourceHealth } from '@/components/source-health';
import { apiGet } from '@/lib/api';
import { parseDeviceList, parseSourceHealth } from '@/lib/api-contracts';
import { parsePageParams } from '@/lib/page-state';

export const metadata = { title: 'Devices' };

export default async function DevicesPage({
  searchParams,
}: {
  searchParams: Promise<{ page?: string | string[]; page_size?: string | string[] }>;
}) {
  const { page, pageSize } = parsePageParams(await searchParams);
  const [sourceHealthState, devicesState] = await Promise.all([
    apiGet('/api/v1/sources/librenms/health', parseSourceHealth),
    apiGet(`/api/v1/devices?page=${page}&page_size=${pageSize}`, parseDeviceList),
  ]);

  return (
    <AppContent
      title="Devices"
      breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Devices' }]}
    >
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Canonical, read-only device records from approved monitoring sources.
        </p>
      </div>

      <SourceHealth state={sourceHealthState} />

      {devicesState.kind !== 'ok' ? (
        <DataFailure state={devicesState} />
      ) : (
        <>
          <FreshnessNotice freshness={devicesState.data.freshness} />
          {devicesState.data.items.length === 0 && devicesState.data.total === 0 ? (
            <EmptyState />
          ) : (
            <>
              <Suspense fallback={<LoadingState label="Loading devices" />}>
                <DeviceTable devices={devicesState.data.items} total={devicesState.data.total} />
              </Suspense>
              <PageControls
                count={devicesState.data.items.length}
                label="Device pages"
                noun="devices"
                page={devicesState.data.page}
                pageSize={devicesState.data.page_size}
                total={devicesState.data.total}
              />
            </>
          )}
        </>
      )}
    </AppContent>
  );
}
