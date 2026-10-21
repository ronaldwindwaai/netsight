import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { DataFailure, EmptyState, LoadingState } from '@/components/data-state';
import { StoreStateSurface } from '@/components/state-surface';
import { routerSpy } from '@/test/next-navigation-stub';

afterEach(() => {
  cleanup();
  routerSpy.reset();
});

const failure = (kind: string, message = 'boom') =>
  ({ kind, message, correlationId: 'corr-1' }) as unknown as Parameters<typeof DataFailure>[0]['state'];

describe('LoadingState', () => {
  it('is one polite status region with a screen-reader label and a visual skeleton', () => {
    render(<LoadingState label="Loading devices" />);
    const region = screen.getByRole('status');
    assert.equal(region.getAttribute('aria-busy'), 'true');
    assert.match(region.textContent ?? '', /Loading devices/);
    assert.ok(document.querySelectorAll('.skeleton-line').length >= 3);
    assert.equal(document.querySelector('.skeleton-line')?.getAttribute('aria-hidden'), 'true');
  });

  it('does not nest a second status region', () => {
    render(<LoadingState />);
    assert.equal(screen.getAllByRole('status').length, 1);
  });
});

describe('DataFailure retry', () => {
  for (const kind of ['source_unavailable', 'invalid_response', 'error', 'rate_limited', 'maintenance']) {
    it(`offers a retry that re-fetches the page for ${kind}`, async () => {
      render(<DataFailure state={failure(kind)} />);
      await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
      assert.equal(routerSpy.refreshCount, 1);
    });
  }

  for (const kind of ['forbidden', 'not_found', 'unauthenticated']) {
    it(`does not offer a pointless retry for ${kind}`, () => {
      render(<DataFailure state={failure(kind)} />);
      assert.equal(screen.queryByRole('button', { name: 'Try again' }), null);
    });
  }

  it('still shows the correlation reference', () => {
    render(<DataFailure state={failure('error')} />);
    assert.match(document.body.textContent ?? '', /corr-1/);
  });
});

describe('EmptyState next actions', () => {
  it('offers to clear filters when filtered', () => {
    render(<EmptyState filtered />);
    assert.equal(screen.getByRole('link', { name: 'Clear filters' }).getAttribute('href'), '/devices');
  });

  it('offers a refresh when the source is genuinely empty', async () => {
    render(<EmptyState />);
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    assert.equal(routerSpy.refreshCount, 1);
  });
});

describe('StoreStateSurface', () => {
  it('offers a retry when the store state is unknown', async () => {
    render(<StoreStateSurface state="unknown" noun="incidents" store="Incident store" />);
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    assert.equal(routerSpy.refreshCount, 1);
  });

  it('does not offer a retry when the store is simply not connected', () => {
    render(<StoreStateSurface state="not-connected" noun="incidents" store="Incident store" />);
    assert.equal(screen.queryByRole('button'), null);
  });
});
