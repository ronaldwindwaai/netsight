import type { ReactNode } from 'react';

import { RetryButton } from '@/components/retry-button';

/**
 * Distinct empty / not-connected / unknown surfaces. "No rows" and "no data
 * source" must never look alike, and no count is ever shown for a non-ok state.
 */
export function StateSurface({
  icon,
  title,
  detail,
  action,
}: {
  icon: string;
  title: string;
  detail: string;
  /** An optional next step (a link or button) shown under the explanation, outside the live region. */
  action?: ReactNode;
}) {
  return (
    <div className="traffic-state text-center">
      <div role="status">
        <i className={`${icon} fs-2 text-body-secondary`} aria-hidden="true" />
        <p className="fw-semibold mb-1 mt-3">{title}</p>
        <p className="small text-body-secondary mb-0">{detail}</p>
      </div>
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  );
}

export function StoreStateSurface({
  state,
  noun,
  store,
}: {
  state: 'not-connected' | 'unknown';
  noun: string;
  store: string;
}) {
  if (state === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title={`${store} not connected`}
        detail={`No ${noun} are shown because the ${store.toLowerCase()} is not configured. This is not the same as having none.`}
      />
    );
  }
  return (
    <StateSurface
      icon="bi bi-question-circle"
      title={`${store} state unknown`}
      detail={`The ${store.toLowerCase()} is configured but could not be read. Nothing is estimated in place of ${noun}.`}
      action={<RetryButton />}
    />
  );
}
