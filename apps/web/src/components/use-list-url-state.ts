'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

import { MAX_QUERY_LENGTH, listStateToSearch, parseListState } from '@/lib/list-url-state';
import type { ListSpec, ListState } from '@/lib/list-url-state';

/** How long typing pauses before the search text is written to the URL. */
export const SEARCH_URL_DEBOUNCE_MS = 250;

export interface ListUrlState {
  /** Search text is the live input value; the other fields come from the URL. */
  readonly state: ListState;
  /**
   * Merge `patch` into the URL. Discrete choices such as a status chip, a sort or "Clear filters"
   * use `push` so Back undoes them. A `q` patch goes through the debounced, history-neutral search
   * path instead. Next wires `history.pushState/replaceState` into `useSearchParams`, so no server
   * round trip occurs.
   */
  readonly update: (patch: Partial<ListState>, mode?: 'push' | 'replace') => void;
  readonly clear: () => void;
  readonly isFiltering: boolean;
}

/** What the URL holds for a search text: blank text is dropped, anything else is kept verbatim. */
function urlQuery(text: string): string {
  return text.trim().length === 0 ? '' : text.slice(0, MAX_QUERY_LENGTH);
}

export function useListUrlState(spec: ListSpec): ListUrlState {
  const params = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const searchText = params.toString();
  const urlState = useMemo(() => parseListState(new URLSearchParams(searchText), spec), [searchText, spec]);

  // The input owns its text. Binding it straight to the URL drops characters and swallows spaces
  // because the URL round trip is asynchronous; the URL follows the input, not the other way round.
  const [search, setSearchText] = useState(urlState.q);
  const searchRef = useRef(search);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cancelTimer = useCallback(() => {
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = null;
  }, []);

  // A search or filter change starts again at page 1. Dropping `page` changes which rows the server
  // returns, so that case goes through the router (which refetches); the history API alone only
  // updates the URL. Sort changes keep the page, as does every other parameter (page_size, ...).
  const commit = useCallback(
    (next: ListState, mode: 'push' | 'replace', resetPage = false) => {
      const query = new URLSearchParams(window.location.search);
      const refetch = resetPage && query.has('page');
      if (refetch) query.delete('page');
      const url = `${pathname}${listStateToSearch(query, next, spec)}`;
      if (refetch) router[mode](url);
      else if (mode === 'push') window.history.pushState(null, '', url);
      else window.history.replaceState(null, '', url);
    },
    [pathname, router, spec],
  );

  const readUrl = useCallback(
    () => parseListState(new URLSearchParams(window.location.search), spec),
    [spec],
  );

  const setSearch = useCallback(
    (text: string) => {
      searchRef.current = text;
      setSearchText(text);
      cancelTimer();
      timer.current = setTimeout(() => {
        timer.current = null;
        if (urlQuery(searchRef.current) !== readUrl().q) {
          commit({ ...readUrl(), q: searchRef.current }, 'replace', true);
        }
      }, SEARCH_URL_DEBOUNCE_MS);
    },
    [cancelTimer, commit, readUrl],
  );

  // Back/Forward: take the URL's search text, but only when it differs from what the input holds.
  useEffect(() => {
    const onPopState = () => {
      const fromUrl = readUrl().q;
      if (fromUrl === urlQuery(searchRef.current)) return;
      cancelTimer();
      searchRef.current = fromUrl;
      setSearchText(fromUrl);
    };
    window.addEventListener('popstate', onPopState);
    return () => {
      window.removeEventListener('popstate', onPopState);
      cancelTimer();
    };
  }, [cancelTimer, readUrl]);

  const update = useCallback(
    (patch: Partial<ListState>, mode: 'push' | 'replace' = 'push') => {
      const { q, ...rest } = patch;
      if (q !== undefined) setSearch(q);
      if (Object.keys(rest).length === 0) return;
      // A discrete change carries the text typed so far, so it is neither lost nor reordered.
      cancelTimer();
      commit({ ...readUrl(), ...rest, q: searchRef.current }, mode, rest.filters !== undefined);
    },
    [cancelTimer, commit, readUrl, setSearch],
  );

  const clear = useCallback(() => {
    cancelTimer();
    searchRef.current = '';
    setSearchText('');
    commit({ q: '', filters: {}, sort: urlState.sort }, 'push', true);
  }, [cancelTimer, commit, urlState.sort]);

  const state = useMemo(() => ({ ...urlState, q: search }), [urlState, search]);
  const isFiltering = search.trim().length > 0 || Object.keys(urlState.filters).length > 0;
  return { state, update, clear, isFiltering };
}
