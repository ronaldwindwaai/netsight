import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function UnknownDevicesLoading() {
  return (
    <AppContent title="Unknown devices">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading unknown devices" />
      </div>
    </AppContent>
  );
}
