import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function InventoryLoading() {
  return (
    <AppContent title="Inventory">
      <LoadingState label="Loading the inventory" />
    </AppContent>
  );
}
