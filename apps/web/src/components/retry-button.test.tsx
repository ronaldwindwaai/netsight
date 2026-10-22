import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';
import { Suspense, use, useEffect, useState } from 'react';

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';

import { RetryButton } from '@/components/retry-button';
import { routerSpy } from '@/test/next-navigation-stub';

afterEach(() => {
  cleanup();
  routerSpy.reset();
});

function Gate({ gate }: { gate: Promise<void> | null }) {
  if (gate) use(gate);
  return null;
}

/** Simulates router.refresh(): a transition update that suspends until the "server" answers. */
function Harness({ register }: { register: (refresh: () => void) => void }) {
  const [gate, setGate] = useState<Promise<void> | null>(null);
  useEffect(() => register(() => setGate(pendingServer)), [register]);
  return (
    <>
      <RetryButton />
      <Suspense fallback={null}>
        <Gate gate={gate} />
      </Suspense>
    </>
  );
}

let release: () => void = () => {};
const pendingServer = new Promise<void>((resolve) => {
  release = resolve;
});

it('is disabled, busy and relabelled while the refresh is pending, then recovers', async () => {
  render(
    <Harness
      register={(refresh) => {
        routerSpy.onRefresh = refresh;
      }}
    />,
  );
  const button = screen.getByRole('button', { name: 'Try again' });
  assert.equal(button.hasAttribute('disabled'), false);
  assert.equal(button.getAttribute('aria-busy'), 'false');

  await act(async () => {
    fireEvent.click(button);
  });
  const busy = screen.getByRole('button', { name: 'Retrying…' });
  assert.equal(busy.hasAttribute('disabled'), true);
  assert.equal(busy.getAttribute('aria-busy'), 'true');
  assert.equal(routerSpy.refreshCount, 1);

  await act(async () => {
    release();
    await pendingServer;
  });
  const done = screen.getByRole('button', { name: 'Try again' });
  assert.equal(done.hasAttribute('disabled'), false);
});

it('honours a custom label', () => {
  render(<RetryButton label="Refresh" />);
  assert.ok(screen.getByRole('button', { name: 'Refresh' }));
});
