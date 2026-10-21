import Link from 'next/link';
import { AppCard } from '@/components/app-card';
import { AppContent } from '@/components/app-content';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { DeviceDetailTabs } from '@/components/device-detail-tabs';
import { apiGet } from '@/lib/api';
import { parseDeviceDetail, parseInterfaceList, parseSessionInfo } from '@/lib/api-contracts';

export const metadata = { title: 'Device' };

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
