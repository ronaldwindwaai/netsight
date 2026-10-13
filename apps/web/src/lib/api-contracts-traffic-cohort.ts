import { exact, isTrafficState } from './api-contracts-traffic-guards.ts';
import { isIntegerInRange, isOneOf } from './contract-guards.ts';
import {
  COHORT_STATES,
  COHORT_MAX,
  COHORT_MIN,
  type CohortState,
  type RowVisibility,
} from './api-contracts-traffic-shared.ts';

/**
 * The small-cohort rule as applied to an answer (traffic.schema.json#/$defs/cohort).
 *
 * `not-applied`: the caller holds the detail tier (or nothing was read). `sufficient`: the aggregate
 * tier, and every figure describes at least `minimum` internal endpoints. `too-few-sources`: the
 * aggregate tier, and something was withheld (a whole answer, a row, a series, a first-seen
 * destination) because fewer than `minimum` internal endpoints stood behind it.
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

/** A row the cohort rule applies to. */
export interface CountedRow {
  visibility: RowVisibility;
  endpoints: number | null;
}

/**
 * A withheld row carries none of its figures; a shown row carries the ones it must. `figures` are the
 * values a withheld row must not have (all null); `required` are the values a shown row must have.
 */
export function figuresFollowVisibility(
  visibility: RowVisibility,
  figures: readonly unknown[],
  required: readonly unknown[],
): boolean {
  if (visibility === 'withheld') return figures.every((figure) => figure === null);
  return required.every((figure) => figure !== null);
}

/** Withheld rows are listed after the shown ones, so a position says nothing about a volume. */
export function withheldLast(rows: readonly CountedRow[]): boolean {
  return rows.every(
    (row, index) =>
      index === 0 || !(rows[index - 1].visibility === 'withheld' && row.visibility === 'shown'),
  );
}

/**
 * The per-row cohort rule of every list the aggregate tier is shown. The detail tier sees every row
 * shown. The aggregate tier sees a row only with an endpoint count that meets the minimum; anything
 * else is withheld, withheld rows come last, and the answer says `too-few-sources` exactly when it
 * withheld a row.
 */
export function rowsFollowCohort(cohort: CohortStatus, rows: readonly CountedRow[]): boolean {
  const anyWithheld = rows.some((row) => row.visibility === 'withheld');
  if (cohort.state === 'not-applied') return !anyWithheld;
  const minimum = cohort.minimum ?? COHORT_MIN;
  const below = rows.some(
    (row) => row.visibility === 'shown' && (row.endpoints === null || row.endpoints < minimum),
  );
  if (below) return false;
  if (cohort.state === 'sufficient' && anyWithheld) return false;
  if (cohort.state === 'too-few-sources' && !anyWithheld) return false;
  return withheldLast(rows);
}
