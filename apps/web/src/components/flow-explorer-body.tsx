import { Alert } from '@adminlte/react';

import { FreshnessNotice } from '@/components/data-state';
import { CohortNotice } from '@/components/cohort-notice';
import { Aggregations, FlowRowsTable } from '@/components/flow-explorer-parts';
import type { FlowLinker } from '@/components/flow-explorer-parts';
import { StateSurface } from '@/components/state-surface';
import { TrafficGate } from '@/components/traffic-surface';
import type { TrafficFlowsResponse } from '@/lib/api-contracts-traffic-explorer';
import type { EntityAccess } from '@/lib/identity-view';
import type { FetchState } from '@/lib/api-response';
import { attributionNotice } from '@/lib/traffic-view';

function unsupportedDetail(
  data: TrafficFlowsResponse,
): { title: string; detail: string } | null {
  if (data.unsupported.length === 0) return null;
  return {
    title: 'The flow source does not report a requested filter',
    detail: `The flow source does not report: ${data.unsupported.join(', ')}. The read was not run unfiltered, so no rows or totals are shown. Remove those filters, or ask an administrator which flow fields are collected.`,
  };
}

/**
 * The Flow Explorer for every outcome of the read. Rows, people and aggregates are separate
 * decisions: a role without row access still sees the aggregates, a role without a users permission
 * sees rows without people, and the identity service being absent or failing never removes the flows.
 */
export function FlowExplorerBody({
  state,
  filtered,
  linkTo,
  access,
}: {
  state: FetchState<TrafficFlowsResponse>;
  /** True when at least one filter is applied (changes the wording of an empty result). */
  filtered: boolean;
  /** When given, addresses in the rows link to the view narrowed by that address. */
  linkTo?: FlowLinker;
  /** Which entity pages the viewer may open (users:read, inventory:read). */
  access?: EntityAccess;
}) {
  return (
    <TrafficGate
      state={state}
      noun="flows"
      permission="traffic:read"
      unknownDetail={unsupportedDetail}
    >
      {(data) => {
        const notice = attributionNotice(data.attribution, data.flows.length > 0);
        return (
          <>
            <FreshnessNotice freshness={data.freshness} />
            {data.flows_restricted ? (
              <Alert theme="info" title="Flow rows are restricted" icon="bi bi-lock">
                {' '}
                <span>
                  Listing individual flows needs the traffic:read-detail permission, which your role
                  does not hold. The aggregates below (aggregates only) are computed without reading
                  any flow row.
                </span>
              </Alert>
            ) : null}
            <CohortNotice cohort={data.cohort} noun="figures" />
            {data.aggregations !== null ? <Aggregations data={data.aggregations} /> : null}
            {data.flows_restricted ? null : (
              <section
                aria-label="Flows"
                className="card card-outline card-primary operational-card"
              >
                <div className="card-header">
                  <h2 className="card-title h6 mb-0">
                    <i className="bi bi-list-columns me-1" aria-hidden="true" />
                    Flows (largest first)
                  </h2>
                </div>
                {notice !== '' ? (
                  <p className="small text-body-secondary px-3 pt-2 mb-0">{notice}</p>
                ) : null}
                {data.flows.length === 0 ? (
                  <StateSurface
                    icon="bi bi-inboxes"
                    title={filtered ? 'No flows match these filters' : 'No flows in this window'}
                    detail={
                      filtered
                        ? 'The flow source reported a valid empty result for these filters in this window. Widen the window or remove a filter.'
                        : 'The flow source reported a valid empty result for this window.'
                    }
                  />
                ) : (
                  <FlowRowsTable flows={data.flows} status={data.attribution} linkTo={linkTo} access={access} />
                )}
              </section>
            )}
          </>
        );
      }}
    </TrafficGate>
  );
}
