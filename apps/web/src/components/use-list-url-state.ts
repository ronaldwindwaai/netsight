'use client';

import { useCallback, useMemo } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';

import { listStateToSearch, parseListState } from '@/lib/list-url-state';
import type { ListSpec, ListState } from '@/lib/list-url-state';

export interface ListUrlState {
  readonly state: ListState;
  /**
   * Merge `patch` into the URL. Typing uses `replace` (no history entry per keystroke); discrete
   * choices such as a status chip, a sort or "Clear filters" use `push` so Back undoes them. Next
   * wires `history.pushState/replaceState` into `useSearchParams`, so no server round trip occurs.
   */
  readonly update: (patch: Partial<ListState>, mode?: 'push' | 'replace') => void;
  readonly clear: () => void;
  readonly isFiltering: boolean;
}

export function useListUrlState(spec: ListSpec): ListUrlState {
  const params = useSearchParams();
  const pathname = usePathname();
  const searchText = params.toString();
  const state = useMemo(() => parseListState(new URLSearchParams(searchText), spec), [searchText, spec]);

  const commit = useCallback(
    (next: ListState, mode: 'push' | 'replace') => {
      const search = listStateToSearch(new URLSearchParams(window.location.search), next, spec);
      const url = `${pathname}${search}`;
      if (mode === 'push') window.history.pushState(null, '', url);
      else window.history.replaceState(null, '', url);
    },
    [pathname, spec],
  );

  const update = useCallback(
    (patch: Partial<ListState>, mode: 'push' | 'replace' = 'push') => {
      const current = parseListState(new URLSearchParams(window.location.search), spec);
      commit({ ...current, ...patch }, mode);
    },
    [commit, spec],
  );

  const clear = useCallback(() => commit({ q: '', filters: {}, sort: state.sort }, 'push'), [commit, state.sort]);

  const isFiltering = state.q.trim().length > 0 || Object.keys(state.filters).length > 0;
  return { state, update, clear, isFiltering };
}
