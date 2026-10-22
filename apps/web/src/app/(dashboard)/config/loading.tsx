import { AppContent } from '@/components/app-content';
import { LoadingState } from '@/components/data-state';
export default function ConfigurationLoading() {
  return <AppContent title="Configuration"><LoadingState label="Loading configuration backup metadata" /></AppContent>;
}
