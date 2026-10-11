import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function IpamLoading() {
  return (
    <AppContent title="IPAM">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading IPAM" />
      </div>
    </AppContent>
  );
}
