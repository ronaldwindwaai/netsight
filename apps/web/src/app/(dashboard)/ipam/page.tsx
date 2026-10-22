import { AppContent } from '@/components/app-content';

import { IpamSummaryCard } from '@/components/counts-cards';
import { IpamAddressesCard, IpamPrefixesCard, IpamVlansCard } from '@/components/ipam-body';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import {
  parseIpamAddressList,
  parseIpamPrefixList,
  parseIpamSummary,
  parseIpamVlanList,
} from '@/lib/api-contracts-ipam';
import { addressesPath, parseIpamQuery, prefixesPath, vlansPath } from '@/lib/ipam-view';
import { canReadIpam, canReadIpamSummary, viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'IPAM' };

type Params = Record<string, string | string[] | undefined>;

export default async function IpamPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [{ label: 'Overview', href: '/overview' }, { label: 'IPAM' }];

  if (!canReadIpamSummary(viewer)) {
    // No IPAM permission at all: no API call to be refused.
    return (
      <AppContent title="IPAM" breadcrumbs={crumbs}>
        <Step8AccessDenied surface="IPAM" permission="ipam:read-summary" />
      </AppContent>
    );
  }

  const rows = canReadIpam(viewer);
  // The query is validated before it can reach an API path: an unusable filter is dropped.
  const query = parseIpamQuery(params);
  const [prefixes, vlans, addresses, summary] = await Promise.all([
    rows ? apiGet(prefixesPath(query), parseIpamPrefixList) : null,
    rows ? apiGet(vlansPath(query), parseIpamVlanList) : null,
    rows ? apiGet(addressesPath(query), parseIpamAddressList) : null,
    rows ? null : apiGet('/api/v1/ipam', parseIpamSummary),
  ]);

  return (
    <AppContent title="IPAM" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Prefixes, VLANs and addresses as NetBox intends them, with how much of each prefix is used and
          on what basis. An address is active only when monitoring telemetry saw it within the window and
          stale only when telemetry was readable and did not; when telemetry cannot be read nothing is
          judged. Nothing here is written back to NetBox.
        </p>
      </div>
      {summary !== null ? <IpamSummaryCard state={summary} /> : null}
      {prefixes !== null ? <IpamPrefixesCard state={prefixes} query={query} /> : null}
      {vlans !== null ? <IpamVlansCard state={vlans} query={query} /> : null}
      {addresses !== null ? <IpamAddressesCard state={addresses} query={query} /> : null}
    </AppContent>
  );
}
