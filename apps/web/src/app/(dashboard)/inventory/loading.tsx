import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function InventoryLoading() {
  return (
    <AppContent title="Inventory">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading the inventory" />
      </div>
    </AppContent>
  );
}
