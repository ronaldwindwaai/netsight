import { AppCard } from '@/components/app-card';
import Link from 'next/link';
import { StateSurface } from '@/components/state-surface';
import { visibleReports } from '@/lib/report-catalog';
export function ReportCatalog({ permissions }: {permissions: readonly string[]}) {
  const reports = visibleReports(permissions);
  if (!reports.length) return <StateSurface icon="bi bi-file-earmark-lock" title="No reports available to this role" detail="Reports require permission to read both the report and its underlying evidence." />;
  return <div className="row">
    {reports.map(report => <div className="col-12 col-lg-6" key={report.id}>
      <AppCard title={report.title}>
        <p>{report.description}</p>
        <p className="small text-body-secondary">Choose a month to review the evidence. Missing samples remain unknown.</p>
        <Link className="btn btn-outline-primary" href={`/reports/${report.id}`}>Open report</Link>
      </AppCard>
    </div>)}
  </div>;
}
