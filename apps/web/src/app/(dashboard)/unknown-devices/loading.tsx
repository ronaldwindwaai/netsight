import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function UnknownDevicesLoading() {
  return (
    <AppContent title="Unknown devices">
      <LoadingState label="Loading unknown devices" />
    </AppContent>
  );
}
