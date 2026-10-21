import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function DevicesLoading() {
  return (
    <AppContent title="Devices">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading devices" />
      </div>
    </AppContent>
  );
}
