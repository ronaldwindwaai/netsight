import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function InternetLoading() {
  return (
    <AppContent title="Internet / WAN">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading Internet status" />
      </div>
    </AppContent>
  );
}
