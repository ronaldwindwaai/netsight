import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function IpamLoading() {
  return (
    <AppContent title="IPAM">
      <LoadingState label="Loading IPAM" />
    </AppContent>
  );
}
