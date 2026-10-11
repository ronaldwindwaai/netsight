import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function UnknownDeviceLoading() {
  return (
    <AppContent title="Unknown device">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading finding" />
      </div>
    </AppContent>
  );
}
