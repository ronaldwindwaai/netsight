import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function ActionLoading() {
  return (
    <AppContent title="Action request">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading the action request" />
      </div>
    </AppContent>
  );
}
