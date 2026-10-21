import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function InventoryItemLoading() {
  return (
    <AppContent title="Asset">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading the asset" />
      </div>
    </AppContent>
  );
}
