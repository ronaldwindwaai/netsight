import { AppContent } from '@/components/app-content';

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
