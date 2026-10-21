import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { OverviewRefresh } from '@/components/overview-refresh';
import { routerSpy } from '@/test/next-navigation-stub';

beforeEach(() => routerSpy.reset());
afterEach(() => cleanup());

describe('OverviewRefresh', () => {
  it('shows when the page was built, relative, with the exact UTC time as the tooltip', () => {
    const updatedAt = new Date(Date.now() - 5 * 60_000).toISOString();
    const { container } = render(<OverviewRefresh updatedAt={updatedAt} />);
    const time = container.querySelector('time');
    assert.equal(time?.getAttribute('dateTime'), updatedAt);
    assert.match(time?.getAttribute('title') ?? '', /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$/);
    assert.match(time?.textContent ?? '', /^[45] min ago$/);
  });

  it('re-runs the server render when Refresh is pressed', async () => {
    render(<OverviewRefresh updatedAt={new Date().toISOString()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    assert.equal(routerSpy.refreshCount, 1);
  });
});
