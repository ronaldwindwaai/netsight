import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function IncidentDetailLoading() {
  return (
    <AppContent title="Incident">
      <LoadingState label="Loading incident" />
    </AppContent>
  );
}
