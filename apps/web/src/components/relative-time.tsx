'use client';

import { useSyncExternalStore } from 'react';

import { formatUtcTimestamp } from '@/lib/format-time';
import { formatRelativeTime } from '@/lib/relative-time';

const TICK_MS = 30_000;

function subscribe(onTick: () => void): () => void {
  const id = window.setInterval(onTick, TICK_MS);
  return () => window.clearInterval(id);
}

/** Coarse enough to be stable between reads, fresh enough to keep "3 min ago" honest. */
function clientNow(): number {
  return Math.floor(Date.now() / TICK_MS) * TICK_MS;
}

function useNow(): number | null {
  // The server (and hydration) renders the absolute time; the browser then switches to relative.
  return useSyncExternalStore(subscribe, clientNow, () => null);
}

/** "3 min ago" with the exact UTC instant in the tooltip and in `dateTime`. */
export function RelativeTime({ value, className }: { value: string; className?: string }) {
  const now = useNow();
  const absolute = formatUtcTimestamp(value);
  return (
    <time className={className} dateTime={value} title={absolute}>
      {now === null ? absolute : formatRelativeTime(value, now)}
    </time>
  );
}
