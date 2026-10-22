import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function TrafficLoading() {
  return (
    <AppContent title="Traffic intelligence">
      <LoadingState label="Loading traffic" />
    </AppContent>
  );
}
