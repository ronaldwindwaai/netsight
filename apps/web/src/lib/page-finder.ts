import type { MenuNode } from '@adminlte/react';

export interface PageTarget {
  label: string;
  href: string;
  group: string;
}

/** Flatten a menu into navigable pages, each tagged with the group header it sits under. */
export function pageTargetsFrom(items: readonly MenuNode[]): PageTarget[] {
  const targets: PageTarget[] = [];
  let group = '';
  for (const node of items) {
    if (node.type === 'header') group = node.text;
    else if (node.type === 'item' && node.href !== undefined) {
      targets.push({ label: node.text, href: node.href, group });
    }
  }
  return targets;
}

const MAX_RESULTS = 8;

export interface PageMatches {
  /** At most MAX_RESULTS matches, in menu order. */
  items: PageTarget[];
  /** Every match, so a truncated list can say how many it is hiding. */
  total: number;
}

const NO_MATCHES: PageMatches = { items: [], total: 0 };

/**
 * Pages whose name or group (section) contains every word of the query. This searches the names of
 * pages the session may open, nothing else: it never looks at devices, users or incidents.
 */
export function findPages(targets: readonly PageTarget[], query: string): PageMatches {
  const words = query.toLowerCase().split(/\s+/).filter((word) => word.length > 0);
  if (words.length === 0) return NO_MATCHES;
  const matches = targets.filter((target) => {
    const haystack = `${target.label} ${target.group}`.toLowerCase();
    return words.every((word) => haystack.includes(word));
  });
  return { items: matches.slice(0, MAX_RESULTS), total: matches.length };
}
