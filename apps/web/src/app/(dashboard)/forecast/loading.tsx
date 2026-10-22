import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function ForecastLoading() {
  return (
    <AppContent title="Capacity forecast">
      <LoadingState label="Loading capacity forecast" />
    </AppContent>
  );
}
