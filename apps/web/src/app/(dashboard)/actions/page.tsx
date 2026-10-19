import { AppContent } from '@adminlte/react';

import { ActionKillSwitchPanel } from '@/components/action-kill-switch-panel';
import { ActionsBody, ActionsFilters } from '@/components/actions-body';
import { ActionsStatusCard } from '@/components/actions-status-card';
import { Step8AccessDenied } from '@/components/step8-access-denied';
import { actionsPath, parseActionsQuery } from '@/lib/actions-view';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { parseActionList, parseActionStatus } from '@/lib/api-contracts-actions';
import { canReadActions, canUseActionKillSwitch, viewerFromSession } from '@/lib/viewer';

type Params = Record<string, string | string[] | undefined>;

export default async function ActionsPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [{ label: 'Overview', href: '/overview' }, { label: 'Action requests' }];

  if (!canReadActions(viewer)) {
    // No permission: no list, no controls and no API call to be refused.
    return (
      <AppContent title="Action requests" breadcrumbs={crumbs}>
        <Step8AccessDenied surface="Action requests" permission="actions:read" />
      </AppContent>
    );
  }

  const query = parseActionsQuery(params);
  const [status, list] = await Promise.all([
    apiGet('/api/v1/actions/status', parseActionStatus),
    apiGet(actionsPath(query), parseActionList),
  ]);
  const engaged = status.kind === 'ok' && status.data.kill_switch.engaged;
  const fromEnvironment = status.kind === 'ok' && status.data.kill_switch.source === 'environment';

  return (
    <AppContent title="Action requests" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-3">
          Controlled remote actions. A request names one allow-listed action, a target and a reason, waits for a
          different person to approve it with a recent multi-factor sign-in, and can then be run. Only a dry-run
          executor exists: running a request records what would happen and changes nothing.
        </p>
      </div>
      <ActionsStatusCard state={status} />
      {canUseActionKillSwitch(viewer) && status.kind === 'ok' && status.data.state === 'ok' ? (
        <ActionKillSwitchPanel engaged={engaged} fromEnvironment={fromEnvironment} currentPath="/actions" />
      ) : null}
      <ActionsFilters query={query} />
      <ActionsBody state={list} query={query} />
    </AppContent>
  );
}
