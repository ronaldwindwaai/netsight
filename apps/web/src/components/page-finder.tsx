'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useId, useMemo, useState } from 'react';
import type { FormEvent, KeyboardEvent } from 'react';

import { findPages } from '@/lib/page-finder';
import type { PageTarget } from '@/lib/page-finder';

/**
 * Jump to a Netsight page by name. This is deliberately a page finder, not a global search: no
 * search API exists yet, so it never claims to look up hostnames, users, IPs or incidents.
 */
export function PageFinder({ pages }: { pages: readonly PageTarget[] }) {
  const [query, setQuery] = useState('');
  const router = useRouter();
  const hintId = useId();
  const listId = useId();
  const results = useMemo(() => findPages(pages, query), [pages, query]);
  const searching = query.trim().length > 0;

  function open(event: FormEvent) {
    event.preventDefault();
    const first = results[0];
    if (first === undefined) return;
    setQuery('');
    router.push(first.href);
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Escape') setQuery('');
  }

  return (
    <form className="page-finder" role="search" onSubmit={open}>
      <label className="visually-hidden" htmlFor={`${listId}-input`}>
        Find a page
      </label>
      <div className="input-group input-group-sm">
        <span className="input-group-text" aria-hidden="true">
          <i className="bi bi-search" />
        </span>
        <input
          id={`${listId}-input`}
          type="search"
          className="form-control"
          placeholder="Find a page…"
          autoComplete="off"
          value={query}
          aria-describedby={hintId}
          aria-controls={listId}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={onKeyDown}
        />
      </div>
      <span id={hintId} className="visually-hidden">
        Searches page names only, not devices, users or incidents. Press Enter to open the first match.
      </span>
      {searching ? (
        <div className="page-finder__panel">
          <p className="page-finder__status small text-body-secondary mb-1" role="status">
            {results.length === 0
              ? 'No page matches. Search covers page names only.'
              : `${results.length} ${results.length === 1 ? 'page' : 'pages'} · page names only`}
          </p>
          <ul id={listId} className="page-finder__list list-unstyled mb-0">
            {results.map((page) => (
              <li key={page.href}>
                <Link href={page.href} onClick={() => setQuery('')}>
                  {page.label}
                  <small className="text-body-secondary ms-2">{page.group}</small>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="visually-hidden" role="status">
          Pages only
        </p>
      )}
    </form>
  );
}
