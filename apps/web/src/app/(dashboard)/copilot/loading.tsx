import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function CopilotLoading() {
  return (
    <AppContent title="Ask Netsight">
      <LoadingState label="Loading the copilot" />
    </AppContent>
  );
}
