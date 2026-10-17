import { AppContent } from '@adminlte/react';
import { ConfigurationNodesBody } from '@/components/configuration-read';
import { DataFailure } from '@/components/data-state';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseConfigurationNodes } from '@/lib/api-contracts-configuration';

export default async function ConfigurationPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const params = await searchParams;
  const page = typeof params.page === 'string' && /^[1-9][0-9]{0,3}$/.test(params.page) && Number(params.page) <= 2000 ? Number(params.page) : 1;
  const session = await apiGet('/api/v1/auth/session', parseSessionInfo);
  if (session.kind !== 'ok') return <AppContent title="Configuration"><DataFailure state={session} /></AppContent>;
  if (!session.data.permissions.includes('configuration:read')) return <AppContent title="Configuration"><Step8AccessDenied surface="Configuration" permission="configuration:read" /></AppContent>;
  const state = await apiGet(`/api/v1/config/nodes?page=${page}&page_size=50`, parseConfigurationNodes);
  return <AppContent title="Configuration" breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Configuration' }]}>
    <p className="text-body-secondary">Read-only backup status and saved version history. Configuration contents and source credentials are withheld. A saved version is evidence of a backup, not proof that the current device configuration matches it.</p>
    <ConfigurationNodesBody state={state} />
  </AppContent>;
}
