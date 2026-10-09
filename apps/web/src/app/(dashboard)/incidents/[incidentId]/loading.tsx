import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function IncidentDetailLoading() {
  return (
    <AppContent title="Incident">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading incident" />
      </div>
    </AppContent>
  );
}
