import { AppContent } from '@/components/app-content';
import { ReportCatalog } from '@/components/report-catalog';
import { DataFailure } from '@/components/data-state';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';

export const metadata = { title: 'Reports' };
export default async function ReportsPage() {
  const session = await apiGet('/api/v1/auth/session', parseSessionInfo);
  if (session.kind !== 'ok') return <AppContent title="Reports"><DataFailure state={session} /></AppContent>;
  return <AppContent title="Reports" breadcrumbs={[{label:'Overview',href:'/overview'},{label:'Reports'}]}>
    {!session.data.permissions.includes('reports:read') ? <Step8AccessDenied surface="Reports" permission="reports:read" /> : <>
      <div className="page-intro"><p className="text-body-secondary mb-0">Review bounded source evidence by reporting period. Results and downloads follow your current permissions.</p></div>
      <ReportCatalog permissions={session.data.permissions} />
    </>}
  </AppContent>;
}
