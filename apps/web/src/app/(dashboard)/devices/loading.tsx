import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function DevicesLoading() {
  return (
    <AppContent title="Devices">
      <LoadingState label="Loading devices" />
    </AppContent>
  );
}
