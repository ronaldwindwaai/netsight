import { AppContent } from '@/components/app-content';

import { ResolvePanel } from '@/components/resolve-panel';
import { UsersAccessDenied } from '@/components/users-access-denied';
import { UsersListBody } from '@/components/users-list-body';
import { UsersSummaryCard } from '@/components/users-summary-card';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import {
  parseResolveResponse,
  parseUserListResponse,
  parseUsersAggregateResponse,
} from '@/lib/api-contracts-identity';
import {
  DEFAULT_PAGE_SIZE,
  listPath,
  lookupPath,
  parseLookup,
  parsePage,
} from '@/lib/identity-view';
import {
  canReadInventory,
  canReadPeople,
  canReadUsersSummary,
  canResolveIdentity,
  viewerFromSession,
} from '@/lib/viewer';

export const metadata = { title: 'Users & Identity' };

type Params = {
  page?: string | string[];
  kind?: string | string[];
  value?: string | string[];
};

export default async function UsersPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const viewer = viewerFromSession(sessionState.kind === 'ok' ? sessionState.data : null);
  const crumbs = [{ label: 'Overview', href: '/overview' }, { label: 'Users & Identity' }];

  if (!canReadUsersSummary(viewer)) {
    // No users permission at all (Auditor, today): no form and no API call to be refused.
    return (
      <AppContent title="Users & Identity" breadcrumbs={crumbs}>
        <UsersAccessDenied />
      </AppContent>
    );
  }

  const browse = canReadPeople(viewer);
  const access = { people: browse, devices: canReadInventory(viewer) };
  const resolve = canResolveIdentity(viewer);
  const attempted = params.kind !== undefined || params.value !== undefined;
  // The lookup is validated before it can reach an API path: an unusable one makes no request.
  const lookup = resolve && attempted ? parseLookup({ kind: params.kind, value: params.value }) : null;
  const page = parsePage(params.page);
  const [people, resolved, summary] = await Promise.all([
    browse ? apiGet(listPath(page, DEFAULT_PAGE_SIZE), parseUserListResponse) : null,
    lookup !== null && lookup.ok ? apiGet(lookupPath(lookup), parseResolveResponse) : null,
    browse ? null : apiGet('/api/v1/users/summary', parseUsersAggregateResponse),
  ]);

  return (
    <AppContent title="Users & Identity" breadcrumbs={crumbs}>
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Who is on the network, according to evidence. Every link between a person, an account, a
          device and an address shows how it is known (observed, inferred or unknown), the evidence
          behind it and when it holds. An IP address alone is never treated as an identity. Reads of
          per-person data are audited.
        </p>
      </div>

      {resolve ? <ResolvePanel lookup={lookup} state={resolved} access={access} /> : null}
      {summary !== null ? <UsersSummaryCard state={summary} /> : null}
      {people !== null ? (
        <UsersListBody state={people} page={page} pageSize={DEFAULT_PAGE_SIZE} />
      ) : null}
    </AppContent>
  );
}
