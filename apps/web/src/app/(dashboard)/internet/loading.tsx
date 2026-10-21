import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function InternetLoading() {
  return (
    <AppContent title="Internet / WAN">
      <LoadingState label="Loading Internet status" />
    </AppContent>
  );
}
