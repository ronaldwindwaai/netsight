import { AppContent } from '@/components/app-content';

import { FindingsSummaryCard } from '@/components/counts-cards';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { UnknownDeviceScanPanel } from '@/components/unknown-device-scan-panel';
import { FindingsFilters, UnknownDevicesBody } from '@/components/unknown-devices-body';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseUnknownDeviceList, parseUnknownDeviceSummary } from '@/lib/api-contracts-unknown-devices';
import { findingsPath, parseFindingsQuery } from '@/lib/unknown-device-view';
import {
  canReadFindings,
  canReadFindingsSummary,
  canScanForUnknownDevices,
  viewerFromSession,
} from '@/lib/viewer';

export const metadata = { title: 'Unknown devices' };

type Params = Record<string, string | string[] | undefined>;

export default async function UnknownDevicesPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [{ label: 'Overview', href: '/overview' }, { label: 'Unknown devices' }];

  if (!canReadFindingsSummary(viewer)) {
    return (
      <AppContent title="Unknown devices" breadcrumbs={crumbs}>
        <Step8AccessDenied surface="Unknown devices" permission="unknown-devices:read-summary" />
      </AppContent>
    );
  }

  const rows = canReadFindings(viewer);
  const query = parseFindingsQuery(params);
  const [list, summary] = await Promise.all([
    rows ? apiGet(findingsPath(query), parseUnknownDeviceList) : null,
    rows ? null : apiGet('/api/v1/unknown-devices/summary', parseUnknownDeviceSummary),
  ]);

  return (
    <AppContent title="Unknown devices" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Endpoints that monitoring telemetry sees and NetBox does not know. Each finding lists only the
          links actually observed (IP, MAC, switch or access point, port, VLAN); every other hop is
          Unknown. Severity comes from the operator policy. A quarantine is only ever a recommendation
          shown on a finding; nothing here isolates a device.
        </p>
      </div>
      {summary !== null ? <FindingsSummaryCard state={summary} /> : null}
      {list !== null ? (
        <>
          {canScanForUnknownDevices(viewer) ? <UnknownDeviceScanPanel /> : null}
          <FindingsFilters query={query} />
          <UnknownDevicesBody state={list} query={query} />
        </>
      ) : null}
    </AppContent>
  );
}
