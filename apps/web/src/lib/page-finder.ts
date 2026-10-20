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

/**
 * Pages whose name or group contains every word of the query. This searches the names of pages the
 * session may open, nothing else: it never looks at devices, users or incidents.
 */
export function findPages(targets: readonly PageTarget[], query: string): PageTarget[] {
  const words = query.toLowerCase().split(/\s+/).filter((word) => word.length > 0);
  if (words.length === 0) return [];
  return targets
    .filter((target) => {
      const haystack = `${target.label} ${target.group}`.toLowerCase();
      return words.every((word) => haystack.includes(word));
    })
    .slice(0, MAX_RESULTS);
}
