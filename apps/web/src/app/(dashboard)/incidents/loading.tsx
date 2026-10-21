import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function IncidentsLoading() {
  return (
    <AppContent title="Incidents">
      <LoadingState label="Loading incidents" />
    </AppContent>
  );
}
