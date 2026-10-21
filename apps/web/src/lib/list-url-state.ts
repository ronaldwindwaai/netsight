/**
 * Filter, search and sort state for list tables, kept in the URL so a view can be shared and the
 * back button works. Pure: the components own reading `useSearchParams` and calling `router.replace`.
 *
 * Wire format: `q=<text>`, one parameter per filter (`status=critical`), `sort=name` (ascending) or
 * `sort=-name` (descending). Anything not in the spec is ignored and unrelated parameters are kept.
 */

export const MAX_QUERY_LENGTH = 128;

export type SortDirection = 'asc' | 'desc';

export interface ListSort {
  readonly key: string;
  readonly direction: SortDirection;
}

export interface ListSpec {
  /** Filter name to the values it accepts; a missing parameter means "all". */
  readonly filters: Readonly<Record<string, readonly string[]>>;
  readonly sortKeys: readonly string[];
}

export interface ListState {
  readonly q: string;
  readonly filters: Readonly<Record<string, string>>;
  readonly sort: ListSort | null;
}

export const EMPTY_LIST_STATE: ListState = { q: '', filters: {}, sort: null };

interface ParamReader {
  get(name: string): string | null;
}

function parseSort(raw: string | null, spec: ListSpec): ListSort | null {
  if (raw === null) return null;
  const direction: SortDirection = raw.startsWith('-') ? 'desc' : 'asc';
  const key = raw.startsWith('-') ? raw.slice(1) : raw;
  return spec.sortKeys.includes(key) ? { key, direction } : null;
}

export function parseListState(params: ParamReader, spec: ListSpec): ListState {
  const filters: Record<string, string> = {};
  for (const [name, allowed] of Object.entries(spec.filters)) {
    const value = params.get(name);
    if (value !== null && allowed.includes(value)) filters[name] = value;
  }
  return {
    // Not trimmed: this value feeds a controlled input, and trimming would swallow typed spaces.
    q: (params.get('q') ?? '').slice(0, MAX_QUERY_LENGTH),
    filters,
    sort: parseSort(params.get('sort'), spec),
  };
}

/** The `?query` string for `state`, preserving parameters the list does not own (e.g. `page`). */
export function listStateToSearch(current: URLSearchParams, state: ListState, spec: ListSpec): string {
  const next = new URLSearchParams(current);
  for (const name of ['q', 'sort', ...Object.keys(spec.filters)]) next.delete(name);
  if (state.q.trim().length > 0) next.set('q', state.q.slice(0, MAX_QUERY_LENGTH));
  for (const name of Object.keys(spec.filters)) {
    const value = state.filters[name];
    if (value !== undefined) next.set(name, value);
  }
  if (state.sort !== null) {
    next.set('sort', `${state.sort.direction === 'desc' ? '-' : ''}${state.sort.key}`);
  }
  const text = next.toString();
  return text.length === 0 ? '' : `?${text}`;
}

/** First click on a column sorts ascending; clicking the sorted column again flips it. */
export function toggleSort(current: ListSort | null, key: string): ListSort {
  if (current === null || current.key !== key) return { key, direction: 'asc' };
  return { key, direction: current.direction === 'asc' ? 'desc' : 'asc' };
}
