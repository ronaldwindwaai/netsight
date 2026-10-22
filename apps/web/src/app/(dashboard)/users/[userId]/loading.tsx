import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function UserDetailLoading() {
  return (
    <AppContent title="Person">
      <LoadingState label="Loading person" />
    </AppContent>
  );
}
