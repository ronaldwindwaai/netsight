import { AppContent } from '@/components/app-content';
import Link from 'next/link';
import { ConfigurationVersionsBody } from '@/components/configuration-read';
import { DataFailure } from '@/components/data-state';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { StateSurface } from '@/components/state-surface';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { CONFIG_NODE_ID, parseConfigurationNodes, parseConfigurationVersions } from '@/lib/api-contracts-configuration';

export const metadata = { title: 'Change history' };

type Params = Record<string, string | string[] | undefined>;

const NAME_LOOKUP_PAGES = 5;

/** The device name for an opaque node id, from the existing node list; null when not found. */
async function lookupNodeName(id: string): Promise<string | null> {
  for (let page = 1; page <= NAME_LOOKUP_PAGES; page += 1) {
    const nodes = await apiGet(`/api/v1/config/nodes?page=${page}&page_size=100`, parseConfigurationNodes);
    if (nodes.kind !== 'ok') return null;
    const match = nodes.data.items.find((item) => item.id === id);
    if (match) return match.name;
    if (!nodes.data.has_more) return null;
  }
  return null;
}

export default async function ConfigurationChangesPage({ searchParams }: { searchParams: Promise<Params> }) {
  const session = await apiGet('/api/v1/auth/session', parseSessionInfo);
  if (session.kind !== 'ok') return <AppContent title="Change history"><DataFailure state={session} /></AppContent>;
  if (!session.data.permissions.includes('configuration:read')) return <AppContent title="Change history"><Step8AccessDenied surface="Change history" permission="configuration:read" /></AppContent>;
  const params = await searchParams;
  const id = params.node;
  const page = typeof params.page === 'string' && /^[1-9][0-9]{0,3}$/.test(params.page) && Number(params.page) <= 2000 ? Number(params.page) : 1;
  const valid = typeof id === 'string' && CONFIG_NODE_ID.test(id);
  const nodeName = valid ? await lookupNodeName(id) : null;
  const state = valid ? await apiGet(`/api/v1/config/nodes/${encodeURIComponent(id)}/versions?page=${page}&page_size=50`, parseConfigurationVersions) : null;
  return <AppContent title="Change history" breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Configuration', href: '/config' }, { label: 'Change history' }]}>
    <div className="page-intro">
      <p className="text-body-secondary mb-1">Saved revisions reported by Oxidized. Author identities and commit messages are withheld. No change is classified as a cause of an incident from timing alone.</p>
      <p className="mb-0"><Link href="/config">Choose a configuration backup</Link></p>
    </div>
    {state ? <ConfigurationVersionsBody state={state} nodeId={typeof id === "string" ? id : ""} nodeName={nodeName} permissions={session.data.permissions} /> : <StateSurface icon="bi bi-clock-history" title="Choose a device" detail="Open a device from Configuration to see its saved versions." />}
  </AppContent>;
}
