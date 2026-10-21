import Link from 'next/link';
import { AppContent } from '@/components/app-content';

import { DataFailure, EmptyState, FreshnessNotice } from '@/components/data-state';
import { DeviceTable } from '@/components/device-table';
import { SourceHealth } from '@/components/source-health';
import { apiGet } from '@/lib/api';
import { parseDeviceList, parseSourceHealth } from '@/lib/api-contracts';

const PAGE_SIZE = 50;

function requestedPage(raw: string | string[] | undefined): number {
  const value = Array.isArray(raw) ? raw[0] : raw;
  const parsed = Number(value ?? '1');
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 1;
}

export default async function DevicesPage({
  searchParams,
}: {
  searchParams: Promise<{ page?: string | string[] }>;
}) {
  const page = requestedPage((await searchParams).page);
  const [sourceHealthState, devicesState] = await Promise.all([
    apiGet('/api/v1/sources/librenms/health', parseSourceHealth),
    apiGet(`/api/v1/devices?page=${page}&page_size=${PAGE_SIZE}`, parseDeviceList),
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
              <DeviceTable devices={devicesState.data.items} total={devicesState.data.total} />
              <nav className="d-flex align-items-center justify-content-between mt-3" aria-label="Device pages">
                <Link
                  aria-disabled={devicesState.data.page <= 1}
                  className={`btn btn-outline-secondary btn-sm ${devicesState.data.page <= 1 ? 'disabled' : ''}`}
                  href={`/devices?page=${Math.max(1, devicesState.data.page - 1)}`}
                  tabIndex={devicesState.data.page <= 1 ? -1 : undefined}
                >
                  <i className="bi bi-chevron-left me-1" aria-hidden="true" />
                  Previous
                </Link>
                <span className="small text-body-secondary">
                  Page {devicesState.data.page} of{' '}
                  {Math.max(
                    1,
                    Math.ceil(devicesState.data.total / devicesState.data.page_size),
                  )}
                </span>
                <Link
                  aria-disabled={
                    devicesState.data.page * devicesState.data.page_size >= devicesState.data.total
                  }
                  className={`btn btn-outline-secondary btn-sm ${
                    devicesState.data.page * devicesState.data.page_size >= devicesState.data.total
                      ? 'disabled'
                      : ''
                  }`}
                  href={`/devices?page=${devicesState.data.page + 1}`}
                  tabIndex={
                    devicesState.data.page * devicesState.data.page_size >= devicesState.data.total
                      ? -1
                      : undefined
                  }
                >
                  Next
                  <i className="bi bi-chevron-right ms-1" aria-hidden="true" />
                </Link>
              </nav>
            </>
          )}
        </>
      )}
    </AppContent>
  );
}
