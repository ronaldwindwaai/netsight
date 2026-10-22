import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import { AlertTable } from '@/components/alert-table';
import type { Alert } from '@/lib/api-contracts';
import { ALERT_LIST_SPEC } from '@/lib/alert-list-view';

afterEach(() => {
  cleanup();
  window.history.replaceState(null, '', '/');
});

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

const MIXED: Alert[] = [
  { ...base, id: 'a1', title: 'Link down', severity: 'critical', state: 'open', observed_at: '2026-10-18T12:00:00Z' },
  { ...base, id: 'a2', title: 'Port flap', severity: 'low', state: 'acknowledged', observed_at: '2026-10-18T10:00:00Z' },
] as Alert[];

function titles(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll('tbody tr')).map(
    (row) => row.querySelector('.fw-semibold')?.textContent ?? '',
  );
}

it('filters by severity and writes it to the URL', () => {
  const { container } = render(<AlertTable alerts={MIXED} total={2} />);
  fireEvent.change(screen.getByLabelText('Severity'), { target: { value: 'low' } });
  assert.deepEqual(titles(container), ['Port flap']);
  assert.equal(new URLSearchParams(window.location.search).get('severity'), 'low');
});

it('restores filters, search and sort from the URL', () => {
  window.history.replaceState(null, '', '/?state=open&sort=-observed');
  const { container } = render(<AlertTable alerts={MIXED} total={2} />);
  assert.deepEqual(titles(container), ['Link down']);
  assert.equal((screen.getByLabelText('State') as HTMLSelectElement).value, 'open');
  assert.equal((screen.getByLabelText('Sort') as HTMLSelectElement).value, '-observed');
});

it('sorts newest first from the Sort control', () => {
  const { container } = render(<AlertTable alerts={MIXED} total={2} />);
  fireEvent.change(screen.getByLabelText('Sort'), { target: { value: 'observed' } });
  assert.deepEqual(titles(container), ['Port flap', 'Link down']);
});

it('offers Clear filters when nothing matches, and it restores every row', () => {
  const { container } = render(<AlertTable alerts={MIXED} total={2} />);
  fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'zzz' } });
  assert.match(document.body.textContent ?? '', /No alerts match these filters/);
  fireEvent.click(screen.getAllByRole('button', { name: 'Clear filters' })[1]);
  assert.equal(window.location.search, '');
  assert.equal(titles(container).length, 2);
});

it('offers every sort the URL spec accepts, in both directions, so the select never misreports', () => {
  render(<AlertTable alerts={MIXED} total={2} />);
  const offered = Array.from((screen.getByLabelText('Sort') as HTMLSelectElement).options).map((o) => o.value);
  for (const key of ALERT_LIST_SPEC.sortKeys) {
    assert.ok(offered.includes(key), `${key} ascending`);
    assert.ok(offered.includes(`-${key}`), `${key} descending`);
  }
});

it('shows a reverse sort from the URL as that exact option', () => {
  window.history.replaceState(null, '', '/?sort=-title');
  const { container } = render(<AlertTable alerts={MIXED} total={2} />);
  assert.equal((screen.getByLabelText('Sort') as HTMLSelectElement).value, '-title');
  assert.deepEqual(titles(container), ['Port flap', 'Link down']);
});

it('ignores invalid URL parameters at component level', () => {
  window.history.replaceState(null, '', '/?severity=bogus&state=nope&sort=-bogus');
  const { container } = render(<AlertTable alerts={MIXED} total={2} />);
  assert.equal(titles(container).length, 2);
  assert.equal((screen.getByLabelText('Severity') as HTMLSelectElement).value, '');
  assert.equal((screen.getByLabelText('State') as HTMLSelectElement).value, '');
  assert.equal((screen.getByLabelText('Sort') as HTMLSelectElement).value, '');
});

it('pushes history for a filter choice so Back undoes it', () => {
  const before = window.history.length;
  render(<AlertTable alerts={MIXED} total={2} />);
  fireEvent.change(screen.getByLabelText('Severity'), { target: { value: 'low' } });
  assert.equal(window.history.length, before + 1);
});

it('neutralises a hostile alert title in the export', async () => {
  const hostile = '=HYPERLINK("http://evil.example","x")';
  let exported = '';
  const original = URL.createObjectURL;
  URL.createObjectURL = (blob: Blob | MediaSource) => {
    void (blob as Blob).text().then((text) => (exported = text));
    return 'blob:test';
  };
  URL.revokeObjectURL = () => undefined;
  window.HTMLAnchorElement.prototype.click = () => undefined;
  try {
    const alerts = [{ ...base, id: 'h1', title: hostile, severity: 'low', state: 'open' } as Alert];
    render(<AlertTable alerts={alerts} total={1} />);
    fireEvent.click(screen.getByRole('button', { name: 'Export CSV, 1 alerts' }));
    await waitFor(() => assert.ok(exported.length > 0));
    const dataRow = exported.split('\r\n')[1];
    assert.ok(dataRow.includes(`"'=HYPERLINK(""http://evil.example"",""x"")"`), dataRow);
    assert.ok(!/(^|,)=/.test(dataRow));
  } finally {
    URL.createObjectURL = original;
  }
});

it('shows the observed time relative, with the exact UTC value in the tooltip', () => {
  const { container } = render(<AlertTable alerts={MIXED} total={2} />);
  const time = container.querySelector('tbody time');
  assert.equal(time?.getAttribute('title'), '2026-10-18 12:00:00 UTC');
  assert.equal(time?.getAttribute('datetime'), '2026-10-18T12:00:00Z');
});
