import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function DashboardLoading() {
  return (
    <AppContent title="Loading">
      <LoadingState />
    </AppContent>
  );
}
