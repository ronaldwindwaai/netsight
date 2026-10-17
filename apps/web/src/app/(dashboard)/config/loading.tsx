import { AppContent } from '@adminlte/react';
import { LoadingState } from '@/components/data-state';
export default function ConfigurationLoading() {
  return <AppContent title="Configuration"><div role="status" aria-live="polite"><LoadingState label="Loading configuration backup metadata" /></div></AppContent>;
}
