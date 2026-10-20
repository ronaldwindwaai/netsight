import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { PageFinder } from '@/components/page-finder';
import { routerSpy } from '@/test/next-navigation-stub';

const PAGES = [
  { label: 'Devices', href: '/devices', group: 'Network' },
  { label: 'Network Map', href: '/network/map', group: 'Network' },
  { label: 'Incidents', href: '/incidents', group: 'Operations' },
];

afterEach(() => {
  cleanup();
  routerSpy.reset();
});

describe('the page finder', () => {
  it('is honestly labelled as a page finder, not a data search', () => {
    render(<PageFinder pages={PAGES} />);
    const input = screen.getByRole('searchbox', { name: /find a page/i });
    assert.match(input.getAttribute('placeholder') ?? '', /page/i);
    assert.ok(screen.getByText(/pages only/i));
  });

  it('lists matching pages as links and announces the count', async () => {
    render(<PageFinder pages={PAGES} />);
    await userEvent.type(screen.getByRole('searchbox'), 'net');
    const links = screen.getAllByRole('link');
    assert.deepEqual(links.map((l) => l.getAttribute('href')), ['/devices', '/network/map']);
    assert.match(screen.getByRole('status').textContent ?? '', /2 pages/);
  });

  it('says plainly when nothing matches and never invents a result', async () => {
    render(<PageFinder pages={PAGES} />);
    await userEvent.type(screen.getByRole('searchbox'), '10.0.0.1');
    assert.equal(screen.queryAllByRole('link').length, 0);
    assert.match(screen.getByRole('status').textContent ?? '', /no page matches/i);
  });

  it('opens the first match on Enter and clears on Escape', async () => {
    render(<PageFinder pages={PAGES} />);
    const input = screen.getByRole('searchbox');
    await userEvent.type(input, 'incid{Enter}');
    assert.deepEqual(routerSpy.pushed, ['/incidents']);
    await userEvent.type(input, 'abc{Escape}');
    assert.equal((input as HTMLInputElement).value, '');
  });
});
