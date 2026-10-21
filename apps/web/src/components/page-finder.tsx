'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import type { FocusEvent, FormEvent, KeyboardEvent } from 'react';

import { isFocusSearchShortcut } from '@/lib/keyboard-shortcuts';
import { findPages } from '@/lib/page-finder';
import type { PageMatches, PageTarget } from '@/lib/page-finder';

function statusText(query: string, matches: PageMatches): string {
  if (query.trim().length === 0) return '';
  if (matches.total === 0) return 'No page matches. Search covers page and section names only.';
  if (matches.total > matches.items.length) {
    return `Showing ${matches.items.length} of ${matches.total} pages`;
  }
  return `${matches.total} ${matches.total === 1 ? 'page' : 'pages'}`;
}

/**
 * Jump to a Netsight page by name. This is deliberately a page finder, not a global search: no
 * search API exists yet, so it never claims to look up hostnames, users, IPs or incidents.
 */
export function PageFinder({ pages }: { pages: readonly PageTarget[] }) {
  const [query, setQuery] = useState('');
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const hintId = useId();
  const listId = useId();
  const inputId = useId();
  const matches = useMemo(() => findPages(pages, query), [pages, query]);
  const open = query.trim().length > 0;
  const showList = open && matches.items.length > 0;

  useEffect(() => {
    function onDocumentKeyDown(event: globalThis.KeyboardEvent) {
      if (!isFocusSearchShortcut(event)) return;
      event.preventDefault();
      inputRef.current?.focus();
    }
    document.addEventListener('keydown', onDocumentKeyDown);
    return () => document.removeEventListener('keydown', onDocumentKeyDown);
  }, []);

  function submit(event: FormEvent) {
    event.preventDefault();
    const first = matches.items[0];
    if (first === undefined) return;
    setQuery('');
    router.push(first.href);
  }

  function onKeyDown(event: KeyboardEvent<HTMLFormElement>) {
    if (event.key !== 'Escape' || !open) return;
    event.preventDefault();
    setQuery('');
    inputRef.current?.focus();
  }

  function onBlur(event: FocusEvent<HTMLFormElement>) {
    const next = event.relatedTarget;
    if (next instanceof Node && event.currentTarget.contains(next)) return;
    setQuery('');
  }

  return (
    <form className="page-finder" role="search" onSubmit={submit} onKeyDown={onKeyDown} onBlur={onBlur}>
      <label className="visually-hidden" htmlFor={inputId}>
        Find a page
      </label>
      <div className="input-group input-group-sm">
        <span className="input-group-text" aria-hidden="true">
          <i className="bi bi-search" />
        </span>
        <input
          ref={inputRef}
          id={inputId}
          type="search"
          className="form-control"
          placeholder="Find a page…"
          autoComplete="off"
          value={query}
          aria-describedby={hintId}
          aria-keyshortcuts="/"
          aria-controls={showList ? listId : undefined}
          onChange={(event) => setQuery(event.target.value)}
        />
        <kbd className="input-group-text page-finder__key" aria-hidden="true">
          /
        </kbd>
      </div>
      <span id={hintId} className="visually-hidden">
        Searches page and section names only, not devices, users or incidents. Press / to focus this box from
        anywhere, Enter to open the first match, Escape to close.
      </span>
      <div className={open ? 'page-finder__panel' : 'visually-hidden'}>
        <p className="page-finder__status small text-body-secondary mb-1" role="status">
          {statusText(query, matches)}
        </p>
        {showList ? (
          <ul id={listId} className="page-finder__list list-unstyled mb-0">
            {matches.items.map((page) => (
              <li key={page.href}>
                <Link href={page.href} onClick={() => setQuery('')}>
                  {page.label}
                  <small className="text-body-secondary ms-2">{page.group}</small>
                </Link>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </form>
  );
}
