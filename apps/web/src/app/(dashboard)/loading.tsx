import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function DashboardLoading() {
  return (
    <AppContent title="Loading">
      <LoadingState />
    </AppContent>
  );
}
