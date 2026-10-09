import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function IncidentsLoading() {
  return (
    <AppContent title="Incidents">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading incidents" />
      </div>
    </AppContent>
  );
}
