import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function ActionsLoading() {
  return (
    <AppContent title="Action requests">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading action requests" />
      </div>
    </AppContent>
  );
}
