import { AppContent } from '@adminlte/react';

import { ForecastBody } from '@/components/forecast-body';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseForecastResponse } from '@/lib/api-contracts-forecast';
import { forecastPath, parseForecastQuery } from '@/lib/forecast-view';
import { canExportForecast, canReadForecast, viewerFromSession } from '@/lib/viewer';

type Params = Record<string, string | string[] | undefined>;

export default async function ForecastPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [{ label: 'Overview', href: '/overview' }, { label: 'Capacity forecast' }];

  if (!canReadForecast(viewer)) {
    // No forecast permission: no controls and no API call to be refused.
    return (
      <AppContent title="Capacity forecast" breadcrumbs={crumbs}>
        <Step8AccessDenied surface="Capacity forecast" permission="forecast:read" />
      </AppContent>
    );
  }
  const query = parseForecastQuery(params);
  const forecast = await apiGet(forecastPath(query), parseForecastResponse);
  return (
    <AppContent title="Capacity forecast" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-3">
          What the next days may look like if recent source-reported history continues. A simple,
          stated calculation: a straight-line trend or a repeat of the same weekday, with an
          approximate range. Read-only advice: nothing here changes a device, a setting or a limit.
        </p>
      </div>
      <ForecastBody state={forecast} query={query} canExport={canExportForecast(viewer)} />
    </AppContent>
  );
}
