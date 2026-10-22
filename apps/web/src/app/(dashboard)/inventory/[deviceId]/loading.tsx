import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function InventoryItemLoading() {
  return (
    <AppContent title="Asset">
      <LoadingState label="Loading the asset" />
    </AppContent>
  );
}
