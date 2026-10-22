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

const MANY = Array.from({ length: 20 }, (_, i) => ({ label: `Report ${i}`, href: `/r${i}`, group: 'Analytics' }));

afterEach(() => {
  cleanup();
  routerSpy.reset();
});

const input = () => screen.getByRole('searchbox', { name: 'Find a page' }) as HTMLInputElement;
const status = () => screen.getByRole('status');

describe('the page finder', () => {
  it('is labelled as a page finder and its description says names only', () => {
    render(<PageFinder pages={PAGES} />);
    assert.equal(input().getAttribute('placeholder'), 'Find a page…');
    const hint = document.getElementById(input().getAttribute('aria-describedby') ?? '');
    assert.match(hint?.textContent ?? '', /page and section names only/);
  });

  it('has one persistent status region, empty until the user types', async () => {
    render(<PageFinder pages={PAGES} />);
    assert.equal(screen.getAllByRole('status').length, 1);
    assert.equal(status().textContent, '');
    await userEvent.type(input(), 'net');
    assert.equal(screen.getAllByRole('status').length, 1);
    assert.equal(status().textContent, '2 pages');
  });

  it('lists matching pages as links and only references the list while it exists', async () => {
    render(<PageFinder pages={PAGES} />);
    assert.equal(input().getAttribute('aria-controls'), null);
    await userEvent.type(input(), 'net');
    assert.deepEqual(screen.getAllByRole('link').map((l) => l.getAttribute('href')), ['/devices', '/network/map']);
    assert.equal(input().getAttribute('aria-controls'), screen.getByRole('list').id);
  });

  it('says how many it is hiding when the list is truncated', async () => {
    render(<PageFinder pages={MANY} />);
    await userEvent.type(input(), 'report');
    assert.equal(screen.getAllByRole('link').length, 8);
    assert.equal(status().textContent, 'Showing 8 of 20 pages');
  });

  it('says plainly when nothing matches and never invents a result', async () => {
    render(<PageFinder pages={PAGES} />);
    await userEvent.type(input(), '10.0.0.1');
    assert.equal(screen.queryAllByRole('link').length, 0);
    assert.equal(input().getAttribute('aria-controls'), null);
    assert.equal(status().textContent, 'No page matches. Search covers page and section names only.');
  });

  it('opens the first match on Enter', async () => {
    render(<PageFinder pages={PAGES} />);
    await userEvent.type(input(), 'incid{Enter}');
    assert.deepEqual(routerSpy.pushed, ['/incidents']);
    assert.equal(input().value, '');
  });

  it('closes on Escape from the input and from a result, returning focus to the input', async () => {
    render(<PageFinder pages={PAGES} />);
    await userEvent.type(input(), 'net{Escape}');
    assert.equal(input().value, '');
    assert.equal(screen.queryAllByRole('link').length, 0);
    await userEvent.type(input(), 'net');
    screen.getAllByRole('link')[0].focus();
    await userEvent.keyboard('{Escape}');
    assert.equal(input().value, '');
    assert.equal(document.activeElement, input());
  });

  it('closes when focus leaves the form, but not when it moves to a result', async () => {
    render(
      <>
        <PageFinder pages={PAGES} />
        <button type="button">Elsewhere</button>
      </>,
    );
    await userEvent.type(input(), 'net');
    await userEvent.tab();
    assert.equal(screen.getAllByRole('link').length, 2, 'focus on a result keeps the list open');
    await userEvent.click(screen.getByRole('button', { name: 'Elsewhere' }));
    assert.equal(input().value, '');
    assert.equal(screen.queryAllByRole('link').length, 0);
  });

  it('clears the query when a result is clicked', async () => {
    render(<PageFinder pages={PAGES} />);
    await userEvent.type(input(), 'incid');
    await userEvent.click(screen.getByRole('link', { name: /Incidents/ }));
    assert.equal(input().value, '');
  });

  describe('the "/" shortcut', () => {
    it('focuses the search box from anywhere outside a text field', async () => {
      render(
        <>
          <PageFinder pages={PAGES} />
          <button type="button">Elsewhere</button>
        </>,
      );
      screen.getByRole('button', { name: 'Elsewhere' }).focus();
      await userEvent.keyboard('/');
      assert.equal(document.activeElement, input());
      assert.equal(input().value, '', 'the slash itself is not typed into the box');
    });

    it('does not steal a slash typed into another field', async () => {
      render(
        <>
          <PageFinder pages={PAGES} />
          <textarea aria-label="Note" />
        </>,
      );
      const note = screen.getByLabelText('Note') as HTMLTextAreaElement;
      note.focus();
      await userEvent.keyboard('a/b');
      assert.equal(note.value, 'a/b');
      assert.notEqual(document.activeElement, input());
    });

    it('lets a slash through when it is part of the query', async () => {
      render(<PageFinder pages={PAGES} />);
      await userEvent.type(input(), 'a/b');
      assert.equal(input().value, 'a/b');
    });

    it('ignores modified slashes', async () => {
      render(<PageFinder pages={PAGES} />);
      await userEvent.keyboard('{Control>}/{/Control}');
      assert.notEqual(document.activeElement, input());
    });

    it('advertises itself with a visible hint and aria-keyshortcuts, and stops listening on unmount', async () => {
      const { unmount } = render(<PageFinder pages={PAGES} />);
      assert.equal(input().getAttribute('aria-keyshortcuts'), '/');
      const hint = document.querySelector('kbd.page-finder__key');
      assert.equal(hint?.textContent, '/');
      assert.equal(hint?.getAttribute('aria-hidden'), 'true');
      const hidden = document.getElementById(input().getAttribute('aria-describedby') ?? '');
      assert.match(hidden?.textContent ?? '', /Press \/ to focus/);
      unmount();
      await userEvent.keyboard('/');
      assert.equal(document.activeElement, document.body);
    });
  });
});
