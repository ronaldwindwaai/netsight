import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function UnknownDeviceLoading() {
  return (
    <AppContent title="Unknown device">
      <LoadingState label="Loading finding" />
    </AppContent>
  );
}
