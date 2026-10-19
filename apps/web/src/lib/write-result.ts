import type { WriteFailure } from './write-outcome.ts';

/**
 * What a write server action returns to the browser: serialisable plain data only.
 * `rejected` means the input never left the server (validation or origin); `failed` means the
 * API was called and answered (or could not be reached) and carries the operator-facing account.
 */
export type WriteActionResult =
  | {
      ok: true;
      /** The id of the record the write created, when it created one. */
      id?: string;
      /** The state the record is in after the write, when the API reported one. */
      state?: string;
    }
  | { ok: false; kind: 'rejected'; message: string }
  | { ok: false; kind: 'failed'; failure: WriteFailure };

export const NOT_SAME_ORIGIN_MESSAGE = 'The request did not come from this site, so it was not sent.';
