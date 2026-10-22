import { AppContent } from '@/components/app-content';
import { PreferencesPanel } from '@/components/preferences-panel';

export const metadata = { title: 'Preferences' };

export default function PreferencesPage() {
  return (
    <AppContent title="Preferences" breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Preferences' }]}>
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Display settings for this browser: keyboard shortcuts, table density and list size.
        </p>
      </div>
      <PreferencesPanel />
    </AppContent>
  );
}
