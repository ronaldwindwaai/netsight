import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function UserDetailLoading() {
  return (
    <AppContent title="Person">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading person" />
      </div>
    </AppContent>
  );
}
