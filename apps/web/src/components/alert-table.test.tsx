import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';

import { cleanup, render } from '@testing-library/react';

import { AlertTable } from '@/components/alert-table';
import type { Alert } from '@/lib/api-contracts';

afterEach(() => cleanup());

const base = {
  id: 'alert-1',
  title: 'Link down',
  device_id: null,
  observed_at: '2026-10-18T12:00:00Z',
} as unknown as Alert;

it('each severity and state has its own icon and word, so none depends on colour', () => {
  const alerts: Alert[] = [
    { ...base, id: 'a1', severity: 'critical', state: 'open' },
    { ...base, id: 'a2', severity: 'low', state: 'suppressed' },
  ];
  const { container } = render(<AlertTable alerts={alerts} total={2} />);
  const icons = Array.from(container.querySelectorAll('tbody .badge i.bi')).map((i) => i.className);
  assert.equal(new Set(icons).size, icons.length, 'badge icons are distinct');
  const text = container.querySelector('tbody')?.textContent ?? '';
  for (const word of ['Critical', 'Open', 'Low', 'Suppressed']) assert.match(text, new RegExp(word));
});

it('says that a suppressed alert is not a resolved one', () => {
  const { container } = render(<AlertTable alerts={[{ ...base, severity: 'low', state: 'suppressed' } as Alert]} total={1} />);
  const badge = container.querySelector('tbody td:nth-child(4) .visually-hidden');
  assert.match(badge?.textContent ?? '', /not resolved/i);
});

it('puts the state meaning in text a screen reader reads, not only in a tooltip', () => {
  const { container } = render(<AlertTable alerts={[{ ...base, severity: 'low', state: 'suppressed' } as Alert]} total={1} />);
  assert.match(container.querySelector('tbody .visually-hidden')?.textContent ?? '', /not resolved/i);
});
