import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function TrafficLoading() {
  return (
    <AppContent title="Traffic intelligence">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading traffic" />
      </div>
    </AppContent>
  );
}
