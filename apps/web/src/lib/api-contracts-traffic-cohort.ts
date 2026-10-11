import { exact, isTrafficState } from './api-contracts-traffic-guards.ts';
import { isIntegerInRange, isOneOf } from './contract-guards.ts';
import {
  COHORT_STATES,
  COHORT_MAX,
  COHORT_MIN,
  type CohortState,
} from './api-contracts-traffic-shared.ts';

/**
 * The small-cohort rule as applied to an answer (traffic.schema.json#/$defs/cohort).
 *
 * `not-applied`: the caller holds the detail tier (or nothing was read). `sufficient`: the aggregate
 * tier, and the figures describe at least `minimum` source addresses. `too-few-sources`: the aggregate
 * tier, and something was withheld because fewer than `minimum` source addresses stood behind it.
 */
export interface CohortStatus {
  state: CohortState;
  minimum: number | null;
}

export function parseCohort(value: unknown): CohortStatus | null {
  if (!exact(value, ['state', 'minimum']) || !isOneOf(value.state, COHORT_STATES)) return null;
  if (value.state === 'not-applied') {
    return value.minimum === null ? { state: value.state, minimum: null } : null;
  }
  if (!isIntegerInRange(value.minimum, COHORT_MIN, COHORT_MAX)) return null;
  return { state: value.state, minimum: value.minimum };
}

/** A read that returned nothing applied no cohort rule. */
export function cohortMatchesState(state: unknown, cohort: CohortStatus): boolean {
  return !isTrafficState(state) || state === 'ok' || cohort.state === 'not-applied';
}

/**
 * Under the cohort rule no listed endpoint count is below the minimum (a withheld count is null), and
 * a `too-few-sources` answer withholds at least one.
 */
export function endpointCountsFollowCohort(
  cohort: CohortStatus,
  counts: readonly (number | null)[],
): boolean {
  if (cohort.state === 'sufficient' && cohort.minimum !== null) {
    const minimum = cohort.minimum;
    if (counts.some((value) => value !== null && value < minimum)) return false;
  }
  if (cohort.state === 'too-few-sources' && counts.every((value) => value !== null)) return false;
  return true;
}
