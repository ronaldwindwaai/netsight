import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function DeviceDetailLoading() {
  return (
    <AppContent title="Device detail">
      <LoadingState label="Loading the device" />
    </AppContent>
  );
}
