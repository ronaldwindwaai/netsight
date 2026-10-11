/**
 * The Internet/WAN status surface for every outcome of the read: permission, unauthenticated,
 * error, not-connected, unknown, empty, and the data itself with partial and stale notices.
 * Nothing here reads an API; it renders what the page fetched, as data.
 */
import { Alert } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import { InternetLinkCard } from '@/components/internet-link-card';
import { StateSurface } from '@/components/state-surface';
import type { FetchState } from '@/lib/api-response';
import type { InternetResponse, WanFailover, WanLink } from '@/lib/api-contracts-internet';
import { formatUtcTimestamp } from '@/lib/format-time';
import { internetSurface, nonOkBlocks } from '@/lib/internet-view';

const FAILOVER_TEXT: Record<WanFailover['state'], { title: string; detail: string }> = {
  'single-link': {
    title: 'Single link',
    detail: 'Only one link is declared, so there is nothing to fail over to.',
  },
  normal: { title: 'Normal', detail: 'The primary link is carrying a working status.' },
  'failed-over': {
    title: 'Failed over',
    detail: 'The primary link is down and a backup link is up.',
  },
  'all-down': { title: 'All links down', detail: 'Every declared link reports down.' },
  unknown: {
    title: 'Unknown',
    detail: 'At least one link has no current evidence, so failover cannot be stated.',
  },
};

export function FailoverCard({ failover }: { failover: WanFailover }) {
  const text = FAILOVER_TEXT[failover.state];
  return (
    <section aria-label="Failover state" className="alert alert-light border d-flex gap-2 mb-3">
      <i className="bi bi-shuffle" aria-hidden="true" />
      <div>
        <p className="fw-semibold mb-0">Failover: {text.title}</p>
        <p className="small text-body-secondary mb-0">
          {text.detail}{' '}
          {failover.basis === 'inferred'
            ? 'Inferred from link status only; routing and the gateway are not read.'
            : 'Nothing is assumed.'}
        </p>
      </div>
    </section>
  );
}

function partialLinks(links: readonly WanLink[]): string[] {
  return links
    .map((link) => ({ link, blocks: nonOkBlocks(link) }))
    .filter(({ blocks }) => blocks.length > 0)
    .map(({ link, blocks }) => `${link.name}: ${blocks.join(', ')}`);
}

function hasStale(links: readonly WanLink[]): boolean {
  return links.some((link) =>
    [link.interface.freshness, link.quality.freshness, link.availability.freshness].some(
      (freshness) => freshness.state === 'stale',
    ),
  );
}

function Notices({ data }: { data: InternetResponse }) {
  const partial = partialLinks(data.links);
  return (
    <>
      {data.detail_redacted ? (
        <Alert theme="info" title="Some detail is restricted" icon="bi bi-lock">
          {' '}
          <span>
            The ISP name, gateway, public IP and throughput need the internet:read_detail
            permission, which your role does not hold. Status, quality and availability are shown.
          </span>
        </Alert>
      ) : null}
      {partial.length > 0 ? (
        <Alert theme="warning" title="Partial data" icon="bi bi-exclamation-triangle">
          {' '}
          <span>
            Some sources are not connected or could not be read, so those blocks show no values:{' '}
            {partial.join('; ')}.
          </span>
        </Alert>
      ) : null}
      {hasStale(data.links) ? (
        <Alert theme="warning" title="Stale monitoring data" icon="bi bi-clock-history">
          {' '}
          <span>
            Some blocks show last-known values, not current telemetry. Each block names its source
            and when it was last observed.
          </span>
        </Alert>
      ) : null}
    </>
  );
}

export function InternetStatusBody({ state }: { state: FetchState<InternetResponse> }) {
  const surface = internetSurface(state);
  if (state.kind !== 'ok') {
    if (surface === 'permission') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="Internet status is not available to your role"
          detail="Reading the Internet surface needs the internet:read permission. Access is enforced by the Netsight API."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (surface === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title="No WAN links declared"
        detail="Netsight does not guess which interface is an Internet link. An administrator declares the links (and the LibreNMS port and probe targets for each) in the Netsight configuration."
      />
    );
  }
  if (surface === 'unknown') {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="WAN state unknown"
        detail="The WAN declaration is not usable or a source could not be read. Nothing is estimated in its place."
      />
    );
  }
  if (surface === 'empty') {
    return (
      <StateSurface
        icon="bi bi-inboxes"
        title="No WAN links reported"
        detail="The API answered without any link. This is not the same as every link being healthy."
      />
    );
  }
  return (
    <>
      <p className="small text-body-secondary">Retrieved {formatUtcTimestamp(data.generated_at)}.</p>
      <Notices data={data} />
      <FailoverCard failover={data.failover} />
      {data.links.map((link) => (
        <InternetLinkCard key={link.id} link={link} detailRedacted={data.detail_redacted} />
      ))}
    </>
  );
}
