import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function UsersLoading() {
  return (
    <AppContent title="Users & Identity">
      <LoadingState label="Loading users and identity" />
    </AppContent>
  );
}
