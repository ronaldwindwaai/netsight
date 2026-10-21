import type { Metadata } from 'next';
import Link from 'next/link';
import { AppCard } from '@/components/app-card';
import { AppContent } from '@/components/app-content';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { DeviceDetailTabs } from '@/components/device-detail-tabs';
import { apiGet } from '@/lib/api';
import { parseDeviceDetail, parseInterfaceList, parseSessionInfo } from '@/lib/api-contracts';

/**
 * Names the tab after the device when the detail call succeeds (same GET as the page, so Next
 * memoises it within the request); any failure falls back to the generic "Device" title.
 */
export async function generateMetadata({
  params,
}: {
  params: Promise<{ deviceId: string }>;
}): Promise<Metadata> {
  const { deviceId } = await params;
  const state = await apiGet(
    `/api/v1/devices/${encodeURIComponent(deviceId.slice(0, 256))}`,
    parseDeviceDetail,
  );
  return { title: state.kind === 'ok' ? state.data.item.name : 'Device' };
}

export default async function DeviceDetailPage({
  params,
}: {
  params: Promise<{ deviceId: string }>;
}) {
  const { deviceId } = await params;
  const boundedDeviceId = deviceId.slice(0, 256);
  const [state, interfaces, session] = await Promise.all([
    apiGet(`/api/v1/devices/${encodeURIComponent(boundedDeviceId)}`, parseDeviceDetail),
    apiGet(
      `/api/v1/devices/${encodeURIComponent(boundedDeviceId)}/interfaces`,
      parseInterfaceList,
    ),
    apiGet('/api/v1/auth/session', parseSessionInfo),
  ]);
  const permissions = session.kind === 'ok' ? session.data.permissions : null;

  return (
    <AppContent
      title={state.kind === 'ok' ? state.data.item.name : 'Device detail'}
      breadcrumbs={[
        { label: 'Overview', href: '/overview' },
        { label: 'Devices', href: '/devices' },
        { label: state.kind === 'ok' ? state.data.item.name : 'Device detail' },
      ]}
    >
      <div className="page-intro d-flex align-items-center justify-content-between gap-3">
        <p className="text-body-secondary mb-0">
          Canonical identity: <code>{deviceId}</code>
        </p>
        <Link className="btn btn-outline-secondary btn-sm" href="/devices">
          <i className="bi bi-arrow-left me-1" aria-hidden="true" />
          All devices
        </Link>
      </div>

      {state.kind !== 'ok' ? (
        <DataFailure state={state} />
      ) : (
        <>
          <FreshnessNotice freshness={state.data.item.freshness} />
          <AppCard
            title="Device profile"
            icon="bi bi-hdd-network"
            variant="outline"
            theme="primary"
          >
            <DeviceDetailTabs
              device={state.data.item}
              interfaces={interfaces}
              permissions={permissions}
            />
          </AppCard>
        </>
      )}
    </AppContent>
  );
}
