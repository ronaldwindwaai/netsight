import { AppContent, Card } from '@adminlte/react';

import { DiagnosticsRunner } from '@/components/diagnostics-runner';
import { StateSurface } from '@/components/state-surface';

const TARGET_LIMIT = 255;

export default async function DiagnosticsPage({
  searchParams,
}: {
  searchParams: Promise<{ target?: string | string[] }>;
}) {
  const params = await searchParams;
  const requested = params.target;
  const initialTarget =
    typeof requested === 'string' && requested.trim().length > 0
      ? requested.trim().slice(0, TARGET_LIMIT)
      : null;

  return (
    <AppContent
      title="Root cause analysis"
      breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Diagnostics' }]}
    >
      <div className="page-intro">
        <p className="lead mb-1">Why is the target unreachable or degraded?</p>
        <p className="text-body-secondary mb-0">
          Read-only blackbox diagnostics: bounded checks from a configured vantage, correlated into a
          probable fault domain. Every result is evidence — checks that cannot be answered report
          unknown instead of guessing, and a probable cause is only named when the evidence narrows
          to one.
        </p>
      </div>

      <DiagnosticsRunner initialTarget={initialTarget} />

      <Card
        className="operational-card mt-3"
        title="Recent changes"
        icon="bi bi-clock-history"
        variant="outline"
        theme="secondary"
        bodyClass="p-3"
      >
        <StateSurface
          icon="bi bi-plug"
          title="Change source not connected"
          detail="Configuration and change history is not connected yet, so this run cannot correlate against recent changes. This is not the same as there being no changes."
        />
      </Card>
    </AppContent>
  );
}
