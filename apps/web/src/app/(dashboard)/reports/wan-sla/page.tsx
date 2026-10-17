import { AppContent } from '@adminlte/react';
import { notFound } from 'next/navigation';
import { DataFailure } from '@/components/data-state';
import { InternetSlaPanel } from '@/components/internet-sla-panel';
import { PrintReport } from '@/components/print-report';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseSlaResponse } from '@/lib/api-contracts-internet';
import { monthOptions, requestedMonth, slaPath } from '@/lib/internet-view';
import { reportTemplate, visibleReports } from '@/lib/report-catalog';

export default async function ReportPage({searchParams}: {
  searchParams: Promise<{month?: string | string[]}>;
}) {
  const report = reportTemplate("wan-sla");
  if (!report) notFound();
  const session = await apiGet('/api/v1/auth/session', parseSessionInfo);
  if (session.kind !== 'ok') return <AppContent title="Report"><DataFailure state={session} /></AppContent>;
  if (!visibleReports(session.data.permissions).some(item => item.id === report.id)) return <AppContent title="Report"><Step8AccessDenied surface="Report" permission="reports:read and internet:read" /></AppContent>;
  const now = new Date();
  const {month,adjusted} = requestedMonth((await searchParams).month,now);
  const state = await apiGet(slaPath(month),parseSlaResponse);
  const readable = state.kind === 'ok' && state.data.state === 'ok';
  return <AppContent title={report.title} breadcrumbs={[{label:'Reports',href:'/reports'},{label:report.title}]}>
    <div data-print-report>
      <p className="text-body-secondary">Source-backed monthly availability. Unknown intervals are included in the evidence; a gap is never reported as uptime. This view reflects the current source read rather than an archived snapshot.</p>
      <PrintReport readable={readable} />
      <InternetSlaPanel monthAction="/reports/wan-sla" state={state} month={month} months={monthOptions(now)} adjusted={adjusted} canExport={session.data.permissions.includes('internet:export')} />
    </div>
  </AppContent>;
}
