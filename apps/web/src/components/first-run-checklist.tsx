import Link from 'next/link';

import type { ChecklistItem, FirstRunChecklist as Checklist, SourceStatus } from '@/lib/first-run';

const STATUS: Record<SourceStatus, { label: string; className: string; icon: string }> = {
  connected: { label: 'Connected', className: 'text-bg-success', icon: 'bi-check-circle' },
  'not-connected': { label: 'Not connected', className: 'text-bg-secondary', icon: 'bi-circle' },
  unknown: { label: 'Could not be read', className: 'text-bg-warning', icon: 'bi-question-circle' },
  restricted: { label: 'Not shown to your role', className: 'text-bg-secondary', icon: 'bi-shield-lock' },
  unchecked: { label: 'Not checked here', className: 'text-bg-light border', icon: 'bi-dash-circle' },
};

function Item({ item }: { item: ChecklistItem }) {
  const status = STATUS[item.status];
  return (
    <li className="first-run__item">
      <div className="d-flex flex-wrap align-items-baseline justify-content-between gap-2">
        <h3 className="h6 mb-0">{item.name}</h3>
        <span className={`badge ${status.className}`}>
          <i className={`bi ${status.icon} me-1`} aria-hidden="true" />
          {status.label}
        </span>
      </div>
      <p className="mb-1 mt-1">{item.purpose}</p>
      <p className="small text-body-secondary mb-1">
        Set on the API: <code>{item.setup}</code>
      </p>
      <p className="small mb-0">
        Guide: <code>{item.docs}</code>
        <span aria-hidden="true"> · </span>
        <Link href={item.page.href}>{item.page.label} page</Link>
      </p>
    </li>
  );
}

/**
 * Shown on the overview before the device source is configured. It explains what to connect and in
 * what order instead of leaving a wall of "unavailable" tiles. Read-only sources only: Netsight
 * never asks for write access, and credentials are set on the API server, not in the browser.
 */
export function FirstRunChecklist({ checklist }: { checklist: Checklist }) {
  if (!checklist.show) return null;
  return (
    <section className="card first-run mb-3" aria-labelledby="first-run-title">
      <div className="card-body">
        <h2 className="h5" id="first-run-title">
          Connect your first data source
        </h2>
        <p className="text-body-secondary">
          Netsight has nothing to show yet because no monitoring source is connected. Connect them read-only, starting
          with LibreNMS; each one lights up its own pages. Until then those pages say &ldquo;Not connected&rdquo;
          rather than guessing.
        </p>
        <ol className="first-run__list">
          {checklist.items.map((item) => (
            <Item item={item} key={item.id} />
          ))}
        </ol>
        <p className="small text-body-secondary mb-0">
          Credentials are kept on the API server and are never sent to the browser. See{' '}
          <code>docs/08-operations/LOCAL-DEVELOPMENT.md</code> to try the fixture demo without a real system.
        </p>
      </div>
    </section>
  );
}
