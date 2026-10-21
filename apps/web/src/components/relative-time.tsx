'use client';

import { useSyncExternalStore } from 'react';

import { formatUtcTimestamp } from '@/lib/format-time';
import { formatRelativeTime } from '@/lib/relative-time';

export const TICK_MS = 30_000;

// One timer for every mounted <RelativeTime>: it runs only while at least one is subscribed.
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | null = null;

function subscribe(onTick: () => void): () => void {
  listeners.add(onTick);
  if (timer === null) {
    timer = setInterval(() => {
      for (const listener of listeners) listener();
    }, TICK_MS);
  }
  return () => {
    listeners.delete(onTick);
    if (listeners.size === 0 && timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };
}

/** Number of live subscribers; exposed so a test can prove rows share one timer. */
export function relativeTimeSubscriberCount(): number {
  return listeners.size;
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
