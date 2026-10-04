'use client';

import { AppContent, Alert, Button } from '@adminlte/react';

export default function DashboardError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <AppContent title="Unable to display this screen">
      <Alert theme="danger" title="Unexpected interface error" icon="bi bi-exclamation-triangle">
        <p>Netsight could not render this screen. No missing telemetry has been inferred.</p>
        <Button onClick={reset} outline size="sm" theme="danger">
          Try again
        </Button>
      </Alert>
    </AppContent>
  );
}
