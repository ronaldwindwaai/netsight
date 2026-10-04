import { Alert, Card, Spinner } from '@adminlte/react';

import type { FetchState } from '@/lib/api';
import type { Freshness } from '@/lib/api-contracts';

function Reference({ correlationId }: { correlationId: string }) {
  return (
    <small className="d-block mt-2 text-body-secondary">
      Reference: <code>{correlationId}</code>
    </small>
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

  if (state.kind === 'maintenance') {
    return (
      <Alert theme="info" title="Source under maintenance" icon="bi bi-tools">
        {' '}
        <span>
          Current device data is unavailable while the monitoring source is under maintenance.
        </span>
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'invalid_source_data') {
    return (
      <Alert theme="danger" title="Invalid monitoring source data" icon="bi bi-database-x">
        {' '}
        <span>
          The monitoring source returned data that Netsight could not safely map to the canonical
          device contract. The data was rejected and is not shown as current telemetry.
        </span>
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'source_unavailable') {
    return (
      <Alert theme="warning" title="Monitoring source unavailable" icon="bi bi-cloud-slash">
        {' '}
        <span>
          Current device data could not be obtained. Netsight will not substitute an empty or
          healthy result.
        </span>
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  if (state.kind === 'invalid_response') {
    return (
      <Alert theme="danger" title="Invalid Netsight API response" icon="bi bi-exclamation-octagon">
        {' '}
        <span>
          The Netsight API response was unreadable or did not match the canonical device contract.
        </span>
        <Reference correlationId={state.correlationId} />
      </Alert>
    );
  }

  return (
    <Alert theme="danger" title="Unable to load data" icon="bi bi-exclamation-triangle">
      {' '}
      <span>{state.message}</span>
      <Reference correlationId={state.correlationId} />
    </Alert>
  );
}

export function FreshnessNotice({ freshness }: { freshness: Freshness }) {
  if (freshness.state === 'fresh') return null;

  return (
    <Alert
      theme={freshness.state === 'stale' ? 'warning' : 'secondary'}
      title={freshness.state === 'stale' ? 'Stale device data' : 'Freshness unknown'}
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
    <Card className="text-center" bodyClass="py-5">
      <i className="bi bi-hdd-network fs-2 text-body-secondary" aria-hidden="true" />
      <h2 className="h5 mt-3">{filtered ? 'No devices match these filters' : 'No devices found'}</h2>
      <p className="mb-0 text-body-secondary">
        {filtered
          ? 'Adjust the search text or status filter.'
          : 'The source returned a valid empty device inventory.'}
      </p>
    </Card>
  );
}

export function LoadingState({ label = 'Loading device data' }: { label?: string }) {
  return (
    <Card className="text-center" bodyClass="py-5">
      <Spinner theme="primary" label={label} />
      <p className="mt-3 mb-0 text-body-secondary">
        {label}…
      </p>
    </Card>
  );
}
