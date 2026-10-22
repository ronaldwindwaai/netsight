import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function ActionLoading() {
  return (
    <AppContent title="Action request">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading the action request" />
      </div>
    </AppContent>
  );
}
