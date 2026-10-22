import { AppContent } from '@/components/app-content';

import { CopilotBody } from '@/components/copilot-body';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseCopilotStatus } from '@/lib/api-contracts-copilot';
import { canAskCopilot, viewerFromSession } from '@/lib/viewer';

export const metadata = { title: 'Ask Netsight' };

export default async function CopilotPage() {
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [{ label: 'Overview', href: '/overview' }, { label: 'Ask Netsight' }];

  if (!canAskCopilot(viewer)) {
    // No permission: no form and no API call to be refused.
    return (
      <AppContent title="Ask Netsight" breadcrumbs={crumbs}>
        <Step8AccessDenied surface="Ask Netsight" permission="copilot:ask" />
      </AppContent>
    );
  }
  const status = await apiGet('/api/v1/copilot/status', parseCopilotStatus);
  return (
    <AppContent title="Ask Netsight" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-3">
          Ask a question about your network. Answers are built only from evidence the copilot reads
          with your permissions and cite it. Text from logs, devices and documents is treated as
          data, never as instructions.
        </p>
      </div>
      <CopilotBody state={status} />
    </AppContent>
  );
}
