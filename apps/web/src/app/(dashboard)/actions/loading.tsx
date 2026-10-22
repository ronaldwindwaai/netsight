import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function ActionsLoading() {
  return (
    <AppContent title="Action requests">
      <LoadingState label="Loading action requests" />
    </AppContent>
  );
}
