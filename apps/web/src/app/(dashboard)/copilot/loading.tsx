import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function CopilotLoading() {
  return (
    <AppContent title="Ask Netsight">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading the copilot" />
      </div>
    </AppContent>
  );
}
