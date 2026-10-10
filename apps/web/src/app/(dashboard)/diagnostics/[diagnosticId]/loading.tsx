import { AppContent } from '@adminlte/react';

import { LoadingState } from '@/components/data-state';

export default function DiagnosticSessionLoading() {
  return (
    <AppContent title="Diagnostic session">
      <div role="status" aria-live="polite">
        <LoadingState label="Loading diagnostic session" />
      </div>
    </AppContent>
  );
}
