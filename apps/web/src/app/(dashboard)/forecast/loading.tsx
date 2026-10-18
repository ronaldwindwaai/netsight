import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function ForecastLoading() {
  return (
    <AppContent title="Capacity forecast">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading capacity forecast" />
      </div>
    </AppContent>
  );
}
