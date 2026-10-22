import { AppContent } from '@/components/app-content';
import { LoadingState } from '@/components/data-state';
export default function ReportsLoading() {
  return <AppContent title="Reports"><div role="status" aria-live="polite"><LoadingState label="Loading report evidence" /></div></AppContent>;
}
