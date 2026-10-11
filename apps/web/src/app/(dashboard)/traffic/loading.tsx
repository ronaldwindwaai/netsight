import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function TrafficLoading() {
  return (
    <AppContent title="Traffic intelligence">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading traffic" />
      </div>
    </AppContent>
  );
}
