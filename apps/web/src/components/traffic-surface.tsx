import type { ReactNode } from 'react';

import { DataFailure } from '@/components/data-state';
import { StateSurface } from '@/components/state-surface';
import type { Freshness } from '@/lib/api-contracts';
import type { FetchState } from '@/lib/api-response';

type Readable = { state: 'not-connected' | 'ok' | 'unknown'; freshness: Freshness };

/**
 * One gate for every traffic read: each outcome of the request has its own surface, and the
 * children are rendered only for an `ok` read. A failed or absent source is never shown as an empty
 * list, a zero or a healthy result, and nothing is estimated in place of a value.
 */
export function TrafficGate<T extends Readable>({
  state,
  noun,
  permission,
  unknownDetail,
  children,
}: {
  state: FetchState<T>;
  /** Lower-case plural noun for the data ("flows", "applications"). */
  noun: string;
  /** The permission the API requires, named so the refusal is explainable. */
  permission: string;
  /** Replaces the generic unknown text, e.g. to name a filter the source could not honour. */
  unknownDetail?: (data: T) => { title: string; detail: string } | null;
  children: (data: T) => ReactNode;
}) {
  if (state.kind === 'forbidden') {
    return (
      <StateSurface
        icon="bi bi-shield-lock"
        title={`Traffic ${noun} are not available to your role`}
        detail={`Reading ${noun} needs the ${permission} permission, which your role does not hold. Access is enforced by the Netsight API.`}
      />
    );
  }
  if (state.kind !== 'ok') return <DataFailure state={state} />;
  const { data } = state;
  if (data.state === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title="Flow source not connected"
        detail={`No ${noun} are shown because no flow source (Akvorado/ClickHouse) is configured. This is not the same as having none.`}
      />
    );
  }
  if (data.state === 'unknown') {
    const specific = unknownDetail?.(data) ?? null;
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title={specific?.title ?? 'Traffic state unknown'}
        detail={
          specific?.detail ??
          `A flow source is configured but its current state could not be confirmed. Nothing is estimated in place of ${noun}.`
        }
      />
    );
  }
  return <>{children(data)}</>;
}
