import Link from 'next/link';

import { AppContent } from '@/components/app-content';

/** A known page whose record does not exist (notFound()), kept inside the dashboard shell. */
export default function DashboardNotFound() {
  return (
    <AppContent title="Not found" breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Not found' }]}>
      <div className="alert alert-secondary" role="status">
        <p className="mb-2">
          Netsight has no record at this address. It may have been removed, or the address may be mistyped.
        </p>
        <Link href="/overview">Back to Overview</Link>
      </div>
    </AppContent>
  );
}
