import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function UsersLoading() {
  return (
    <AppContent title="Users & Identity">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading users and identity" />
      </div>
    </AppContent>
  );
}
