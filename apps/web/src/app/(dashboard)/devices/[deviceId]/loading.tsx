import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function DeviceDetailLoading() {
  return (
    <AppContent title="Device detail">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading the device" />
      </div>
    </AppContent>
  );
}
