import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render } from '@testing-library/react';

import { RelativeTime, TICK_MS } from '@/components/relative-time';

afterEach(() => cleanup());

describe('RelativeTime', () => {
  it('shares one interval across every mounted row and clears it with the last one', () => {
    const started: unknown[] = [];
    const cleared: unknown[] = [];
    const realSet = globalThis.setInterval;
    const realClear = globalThis.clearInterval;
    globalThis.setInterval = ((handler: () => void, ms?: number) => {
      const id = realSet(handler, ms);
      if (ms === TICK_MS) started.push(id);
      return id;
    }) as typeof setInterval;
    globalThis.clearInterval = ((id: Parameters<typeof clearInterval>[0]) => {
      if (started.includes(id)) cleared.push(id);
      realClear(id);
    }) as typeof clearInterval;
    try {
      const value = new Date(Date.now() - 120_000).toISOString();
      const { unmount } = render(
        <>
          {Array.from({ length: 25 }, (_, i) => (
            <RelativeTime key={i} value={value} />
          ))}
        </>,
      );
      assert.equal(started.length, 1, '25 rows, one timer');
      unmount();
      assert.equal(cleared.length, 1, 'the timer stops when no row is mounted');
    } finally {
      globalThis.setInterval = realSet;
      globalThis.clearInterval = realClear;
    }
  });
});
