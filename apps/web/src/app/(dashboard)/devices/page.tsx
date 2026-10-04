import Link from 'next/link';
import { AppContent } from '@adminlte/react';

import { DataFailure, EmptyState, FreshnessNotice } from '@/components/data-state';
import { DeviceTable } from '@/components/device-table';
import { apiGet } from '@/lib/api';
import { parseDeviceList } from '@/lib/api-contracts';

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
  const state = await apiGet(
    `/api/v1/devices?page=${page}&page_size=${PAGE_SIZE}`,
    parseDeviceList,
  );

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

      {state.kind !== 'ok' ? (
        <DataFailure state={state} />
      ) : (
        <>
          <FreshnessNotice freshness={state.data.freshness} />
          {state.data.items.length === 0 && state.data.total === 0 ? (
            <EmptyState />
          ) : (
            <>
              <DeviceTable devices={state.data.items} total={state.data.total} />
              <nav className="d-flex align-items-center justify-content-between mt-3" aria-label="Device pages">
                <Link
                  aria-disabled={state.data.page <= 1}
                  className={`btn btn-outline-secondary btn-sm ${state.data.page <= 1 ? 'disabled' : ''}`}
                  href={`/devices?page=${Math.max(1, state.data.page - 1)}`}
                  tabIndex={state.data.page <= 1 ? -1 : undefined}
                >
                  <i className="bi bi-chevron-left me-1" aria-hidden="true" />
                  Previous
                </Link>
                <span className="small text-body-secondary">
                  Page {state.data.page} of {Math.max(1, Math.ceil(state.data.total / state.data.page_size))}
                </span>
                <Link
                  aria-disabled={state.data.page * state.data.page_size >= state.data.total}
                  className={`btn btn-outline-secondary btn-sm ${
                    state.data.page * state.data.page_size >= state.data.total ? 'disabled' : ''
                  }`}
                  href={`/devices?page=${state.data.page + 1}`}
                  tabIndex={
                    state.data.page * state.data.page_size >= state.data.total ? -1 : undefined
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
