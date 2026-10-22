import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function MapLoading() {
  return (
    <AppContent title="Live network map">
      <LoadingState label="Loading the topology" />
    </AppContent>
  );
}
