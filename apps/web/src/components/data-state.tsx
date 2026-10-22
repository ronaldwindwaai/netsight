import { Alert } from '@adminlte/react';
import Link from 'next/link';
import { AppCard } from '@/components/app-card';
import { RetryButton } from '@/components/retry-button';

import type { FetchState } from '@/lib/api';
import type { Freshness } from '@/lib/api-contracts';

function Reference({ correlationId }: { correlationId: string }) {
  return (
    <small className="d-block mt-2 text-body-secondary">
      Reference: <code>{correlationId}</code>
    </small>
  );
}

function Retry() {
  return (
    <div className="mt-2">
      <RetryButton />
    </div>
  );
}

export function DataFailure<T>({ state }: { state: Exclude<FetchState<T>, { kind: 'ok' }> }) {
  if (state.kind === 'unauthenticated') {
    return (
      <Alert theme="info" title="Federated sign-in required" icon="bi bi-person-lock">
        {' '}
        <span>
          Your Netsight session is missing, expired, or was not accepted. Sign in through the
          configured identity provider and try again.
        </span>
        <div className="mt-2">
          <a className="btn btn-sm btn-outline-primary" href="/login">
            <i className="bi bi-box-arrow-in-right me-1" aria-hidden="true" />
            Sign in
          </a>
        </div>
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'forbidden') {
    return (
      <Alert theme="danger" title="Permission denied" icon="bi bi-shield-lock">
        {' '}
        <span>
          Your current role is not permitted to view this data. Access is enforced by the Netsight
          API.
        </span>
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'not_found') {
    return (
      <Alert theme="warning" title="Requested resource not found" icon="bi bi-question-circle">
        {' '}
        <span>The requested resource is not available in Netsight.</span>
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'rate_limited') {
    return (
      <Alert theme="warning" title="Too many requests" icon="bi bi-hourglass-split">
        {' '}
        <span>
          {state.message ||
            'This action was rate limited. Wait a moment and try again.'}
        </span>
        <Retry />
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'maintenance') {
    return (
      <Alert theme="info" title="Source under maintenance" icon="bi bi-tools">
        {' '}
        <span>
          Current monitoring data is unavailable while the source is under maintenance.
        </span>
        <Retry />
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'invalid_source_data') {
    return (
      <Alert theme="danger" title="Invalid monitoring source data" icon="bi bi-database-x">
        {' '}
        <span>
          The monitoring source returned data that Netsight could not safely map to its canonical
          contract. The data was rejected and is not shown as current telemetry.
        </span>
        <Retry />
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'source_unavailable') {
    return (
      <Alert theme="warning" title="Monitoring source unavailable" icon="bi bi-cloud-slash">
        {' '}
        <span>
          Current monitoring data could not be obtained. Netsight will not substitute an empty or
          healthy result.
        </span>
        <Retry />
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'invalid_response') {
    return (
      <Alert theme="danger" title="Invalid Netsight API response" icon="bi bi-exclamation-octagon">
        {' '}
        <span>
          The Netsight API response was unreadable or did not match the canonical contract.
        </span>
        <Retry />
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  return (
    <Alert theme="danger" title="Unable to load data" icon="bi bi-exclamation-triangle">
      {' '}
      <span>{state.message}</span>
      <Retry />
      <Reference correlationId={state.correlationId} />
    </Alert>
  );
}

export function FreshnessNotice({ freshness }: { freshness: Freshness }) {
  if (freshness.state === 'fresh') return null;

  return (
    <Alert
      theme={freshness.state === 'stale' ? 'warning' : 'secondary'}
      title={freshness.state === 'stale' ? 'Stale monitoring data' : 'Freshness unknown'}
      icon={freshness.state === 'stale' ? 'bi bi-clock-history' : 'bi bi-question-circle'}
    >
      {' '}
      <span>
        {freshness.state === 'stale'
          ? 'These are last-known values, not current telemetry.'
          : 'Netsight cannot confirm when this device data was observed.'}
      </span>
    </Alert>
  );
}

export function EmptyState({ filtered = false }: { filtered?: boolean }) {
  return (
    <AppCard className="text-center" bodyClass="py-5">
      <i className="bi bi-hdd-network fs-2 text-body-secondary" aria-hidden="true" />
      <h2 className="h5 mt-3">{filtered ? 'No devices match these filters' : 'No devices found'}</h2>
      <p className="text-body-secondary">
        {filtered
          ? 'Adjust the search text or status filter.'
          : 'The source returned a valid empty device inventory.'}
      </p>
      {filtered ? (
        <Link className="btn btn-sm btn-outline-primary" href="/devices">
          Clear filters
        </Link>
      ) : (
        <RetryButton label="Refresh" />
      )}
    </AppCard>
  );
}

const SKELETON_WIDTHS: readonly string[] = ['w-75', 'w-100', 'w-50', 'w-100'];

/**
 * One loading surface for every screen: a skeleton that hints at the shape of the content, plus a
 * single polite status region so assistive technology hears "Loading ..." once.
 */
export function LoadingState({ label = 'Loading device data' }: { label?: string }) {
  return (
    <AppCard bodyClass="py-4">
      <div role="status" aria-live="polite">
        <span className="visually-hidden">{label}…</span>
        {SKELETON_WIDTHS.map((width, index) => (
          <div key={index} className={`skeleton-line ${width}`} aria-hidden="true" />
        ))}
      </div>
    </AppCard>
  );
}
