import Link from 'next/link';
import { AppContent, Card } from '@adminlte/react';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { DeviceDetailTabs } from '@/components/device-detail-tabs';
import { apiGet } from '@/lib/api';
import { parseDeviceDetail } from '@/lib/api-contracts';

export default async function DeviceDetailPage({
  params,
}: {
  params: Promise<{ deviceId: string }>;
}) {
  const { deviceId } = await params;
  const state = await apiGet(
    `/api/v1/devices/${encodeURIComponent(deviceId.slice(0, 256))}`,
    parseDeviceDetail,
  );

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
          <Card
            title="Device profile"
            icon="bi bi-hdd-network"
            variant="outline"
            theme="primary"
          >
            <DeviceDetailTabs device={state.data.item} />
          </Card>
        </>
      )}
    </AppContent>
  );
}
