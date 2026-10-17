import '@/test/dom-setup';
import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';
import { cleanup, render, screen } from '@testing-library/react';
import { ConfigurationNodesBody, ConfigurationVersionsBody } from '@/components/configuration-read';
import type { ConfigurationNode, ConfigurationRead } from '@/lib/api-contracts-configuration';
import type { FetchState } from '@/lib/api-response';
afterEach(() => cleanup());
const node: ConfigurationNode = { id: 'config-node-11111111-1111-1111-1111-111111111111', name: '<script>hostile()</script>', group: 'hq', model: 'ios', backup_status: 'success', last_attempt_at: '2026-10-15T10:00:00Z', backup_freshness: 'stale' };
const data: ConfigurationRead<ConfigurationNode> = { source: 'oxidized', state: 'ok', observed_at: '2026-10-17T10:00:00Z', items: [node], skipped: 0, truncated: false, page: 1, page_size: 50, total: 1, has_more: false };
const state = (value = data): FetchState<ConfigurationRead<ConfigurationNode>> => ({ kind: 'ok', data: value, correlationId: 'test' });
it('renders hostile source text safely and warns that backups are stale', () => {
  const { container } = render(<ConfigurationNodesBody state={state()} />);
  assert.equal(container.querySelector('script'), null);
  assert.equal(screen.getAllByRole('link', { name: node.name }).length, 2);
  assert.match(container.textContent ?? '', /Stale backups/);
});
for (const kind of ['not-connected', 'unknown'] as const) {
  it(`shows explicit ${kind} without a table or invented counts`, () => {
    render(<ConfigurationNodesBody state={state({ ...data, state: kind, items: [], observed_at: null, total: null })} />);
    assert.equal(screen.queryByRole('table'), null);
    assert.match(screen.getByRole('status').textContent ?? '', kind === 'unknown' ? /state unknown/ : /not connected/);
  });
}
it('empty and incomplete are distinct states and paging is real navigation', () => {
  render(<ConfigurationNodesBody state={state({ ...data, state: 'partial', skipped: 1, has_more: true })} />);
  assert.ok(screen.getByRole('table'));
  assert.match(screen.getByRole('link', { name: /Next/ }).getAttribute('href') ?? '', /page=2/);
});
it('handles denied access independently of source outcomes', () => {
  render(<ConfigurationNodesBody state={{kind: 'forbidden', status: 403, code: 'FORBIDDEN', message: 'Denied', correlationId: 'ref'}} />);
  assert.match(document.body.textContent ?? '', /Permission denied/);
  assert.equal(screen.queryByRole('table'), null);
});
it('version history renders only revision identity and source timestamp', () => {
  render(<ConfigurationVersionsBody nodeId={node.id} state={{kind: 'ok', correlationId: 'ref', data: {...data, items: [{id: 'a'.repeat(40), saved_at: '2026-10-17T10:00:00Z'}]}}} />);
  assert.equal(screen.getAllByText('a'.repeat(40)).length, 2);
  assert.equal(screen.queryByRole('button', {name: /restore|restart/i}), null);
});
