import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { AppCard } from '@/components/app-card';

afterEach(cleanup);

describe('AppCard', () => {
  it('renders the title as a level-two heading with the card-title class', () => {
    render(<AppCard title="Engine">body</AppCard>);

    const heading = screen.getByRole('heading', { level: 2, name: 'Engine' });
    assert.ok(heading.classList.contains('card-title'));
    assert.equal(screen.queryByRole('heading', { level: 3 }), null);
  });

  it('keeps the library card classes for outline cards, body and footer', () => {
    const { container } = render(
      <AppCard title="T" variant="outline" theme="primary" bodyClass="p-0" footer="foot" className="x">
        body
      </AppCard>,
    );

    const card = container.firstElementChild as HTMLElement;
    assert.ok(card.classList.contains('card-outline'));
    assert.ok(card.classList.contains('card-primary'));
    assert.ok(card.classList.contains('x'));
    assert.ok(container.querySelector('.card-body.p-0'));
    assert.equal(container.querySelector('.card-footer')?.textContent, 'foot');
  });

  it('renders no header when there is neither a title nor tools', () => {
    const { container } = render(<AppCard>body</AppCard>);

    assert.equal(container.querySelector('.card-header'), null);
  });
});
