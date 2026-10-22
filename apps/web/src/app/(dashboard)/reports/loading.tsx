import { AppContent } from '@/components/app-content';
import { LoadingState } from '@/components/data-state';
export default function ReportsLoading() {
  return <AppContent title="Reports"><LoadingState label="Loading report evidence" /></AppContent>;
}
