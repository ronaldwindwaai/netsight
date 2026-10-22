import { AppContent } from '@/components/app-content';

import { LoadingState } from '@/components/data-state';

export default function DiagnosticSessionLoading() {
  return (
    <AppContent title="Diagnostic session">
      <LoadingState label="Loading diagnostic session" />
    </AppContent>
  );
}
